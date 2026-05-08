# sfw fuzz harnesses (v1 — full translator dispatch)

libFuzzer harnesses for SFW that drive the **full** NAT64 packet
translators end-to-end (v0 covers only the pure RFC-6052 prefix
arithmetic and the inner-packet rewrite callbacks in isolation).

## Layout

```
fuzz/sfw_full/
├── Dockerfile                       # FROM audit-tools:vpp-fuzz
├── build.sh                         # compile sfw_nat64.c + harnesses
├── harness_glue.c                   # sfw_main + portable checksum_fp
├── harness_buffer.h                 # vlib_buffer_t fixture
├── fuzz_translate_v6_to_v4.c        # full v6→v4 translator harness
├── fuzz_translate_v4_to_v6.c        # full v4→v6 translator harness
├── triggers/
│   ├── F*_*.c                       # standalone executable reproducers
│   └── dump_corpus_seeds.py         # writes corpus/<harness>/closed/*.bin
├── corpus/
│   └── <harness>/closed/<id>.bin    # libFuzzer-format closed-finding seeds
│                                    # replayed by audit-tools/regression-check.sh
└── README.md                        # this file
```

## Closed-finding regression corpus

Every fixed finding (F8, F9, F9.1, F10, F11) has its minimal trigger
committed twice:

- as a standalone executable C reproducer in `triggers/<id>.c` for ad-hoc
  inspection (`./out/F8_v6_to_v4` etc.);
- as a raw libFuzzer-format byte file in `corpus/<harness>/closed/<id>.bin`
  for `regression-check.sh` to replay on every commit.

`triggers/dump_corpus_seeds.py` is the source of truth for the binary
seeds: re-run it after a new finding is closed to refresh the corpus.

```bash
# Inside audit-tools:vpp-fuzz container (the harnesses link
# libvppinfra.so.25.10, only present in the container):
podman run --rm -v ~/code/sfw:/src:Z -v ~/code/audit-tools:/audit:Z \
    localhost/audit-tools:vpp-fuzz \
    -c "/audit/regression-check.sh /src"
# exit 0 = clean, exit 1 = a closed finding has reopened.
```

Last validated 2026-05-08: 6 seeds across 2 harnesses replay clean
against `master` (`11c5227`).

## Build

On the IMP build host:

```bash
cd ~/code/sfw/fuzz/sfw_full
podman build -t audit-tools:vpp-fuzz-full .   # one-time, < 5s

# Build harnesses (uses the audit-tools:vpp-fuzz parent layer)
cd ~/code/sfw
podman run --rm -v $PWD:/src:Z audit-tools:vpp-fuzz \
    -c "fuzz/sfw_full/build.sh"

# Artefacts at fuzz/sfw_full/out/
ls fuzz/sfw_full/out
```

## Run

```bash
cd ~/code/sfw/fuzz/sfw_full

# Fresh fuzz pass (≥10 min recommended for v1; coverage takes longer
# to plateau than v0 since the input space is much wider)
./out/fuzz_translate_v6_to_v4 -max_total_time=600 -print_final_stats=1
./out/fuzz_translate_v4_to_v6 -max_total_time=600 -print_final_stats=1

# Replay a captured trigger artefact
./out/fuzz_translate_v6_to_v4 ./crash-<sha>

# Run a known-finding standalone reproducer (post-fix verification)
./out/F8_v6_to_v4
./out/F8_v4_to_v6
```

## What v1 covers vs. v0

| Path                                  | v0 (`fuzz/`)        | v1 (`fuzz/sfw_full/`) |
|---------------------------------------|---------------------|-----------------------|
| `sfw_nat64_embed_v4` / `extract_v4`   | yes (mirrored)      | yes (transitively)    |
| `sfw_api_copy_fixed_string`           | yes (mirrored)      | no                    |
| `sfw_nat64_v6_to_v4_outer_cb`         | yes (mirrored)      | yes (via translator)  |
| `sfw_nat64_v6_to_v4_inner_cb`         | yes (mirrored)      | yes (via translator)  |
| `sfw_nat64_v4_to_v6_inner_cb`         | yes (mirrored)      | yes (via translator)  |
| `sfw_nat64_translate_v6_to_v4`        | **no**              | **yes (new)**         |
| `sfw_nat64_translate_v4_to_v6`        | **no**              | **yes (new)**         |
| `icmp6_to_icmp` / `icmp_to_icmp6`     | **no**              | **yes (new — header inlined)** |
| `ip6_parse` / `ip6_ext_header_walk`   | **no**              | **yes (new — header inlined)** |
| Packet path (`sfw_ip4_node` etc.)     | no                  | no (v2)               |
| Binary API handlers (`sfw_api.c`)     | partial (one fn)    | no (v2)               |

## Architecture

v1 compiles the real `sfw_nat64.c` with `-fsanitize=fuzzer-no-link,
address,undefined`, then links each harness against:

- `sfw_nat64.o` — the sanitised translator code
- `harness_glue.o` — provides the two symbols sfw_nat64.c reaches that
  aren't header-inline:
  - `sfw_main` — zero-initialised global; v4→v6 harness manually
    populates `sfw_main.nat_pools[0]` with a 64:ff9b::/96 fake pool.
  - `vnet_incremental_checksum_fp` — VPP normally swaps this in at
    `vlib_init` time with a CPU-feature-detected SIMD impl; we provide
    a portable RFC-1071 ones-complement implementation. Fuzzer perf
    is not the goal; correctness is.
- `libvppinfra` — the same library v0 already links.

`vlib_buffer_t` is constructed via the `fuzz_buffer_init` helper in
`harness_buffer.h`, which wraps `vlib_buffer_t` in a union sized to
2 KB of trailing data (matches VPP's `VLIB_BUFFER_DEFAULT_DATA_SIZE`).
ASan sees the storage as a stack object — any read past
`b->data[FUZZ_BUFFER_DATA_SIZE]` lands in red-zone and trips a
stack-buffer-overflow report. That's exactly what surfaced F8 below.

`vlib_main_t *vm = NULL` is safe in both translator entry points: the
parameter is plumbed through to `ip6_parse → ip6_ext_header_walk`,
both of which dereference only `b`. (Verified by reading the
`always_inline` bodies in `/usr/include/vlib/buffer.h` and
`/usr/include/vnet/ip/ip6_packet.h` shipped with the audit-tools:vpp
base image.)

## Why ASan-backed buffer fixture beats `malloc`

Stack-allocated `fuzz_buffer_t` is bounded exactly by ASan's frame
red-zones. A heap-allocated buffer would also be bounded by ASan,
but the redzones are a fixed 32 bytes per side, so a small overrun
might fall inside the redzone of the next allocation. Stack objects
are isolated by ~128-byte mid-redzones and 64-byte right-redzones
(see ASan output), giving a wider catch radius for off-by-many bugs.

## Findings to date (this directory)

| ID | Surface                          | Status |
|----|----------------------------------|--------|
| F8 | ICMP6→4 / ICMP4→6 outer-checksum recompute walks attacker-controlled length past buffer (CWE-125 + CWE-200) | **open** — see `~/code/audit-tools/reports/sfw-2026-05-08-fuzz-v1.md` |

Findings F1-F7 were closed by v0 (and manual review); see
`../../.claude/audit.md` for the full sfw history.

## Roadmap to v2

v1's gap: the **packet-path nodes** (`sfw_ip4_node`, `sfw_ip6_node`)
and the **binary API handlers** (`sfw_api.c`). Both need real
`vlib_main_t` + worker thread state + bihash session tables
populated. Two routes for v2:

1. **Plugin-link harness** — load `sfw_plugin.so` via `dlopen`, run
   a stripped-down `vlib_main` long enough to invoke the node, drive
   it with synthetic packets via `vlib_frame` injection. Heavy.
2. **AFL++ binary fuzz of vpp_main** — instrumented `vpp` with
   AFL++/honggfuzz harness sending packets through a memif loopback.
   Lower fidelity to the C-level bug detection ASan provides, higher
   coverage of integration paths.

The v1 mirror approach + this object-link approach together cover
~90% of the security-interesting attack surface of the sfw NAT64
implementation. The remaining 10% (zone/policy state machine,
session table races) is what v2 has to reach.
