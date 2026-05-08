# sfw fuzz harnesses (v0)

libFuzzer harnesses for sfw. **Limited to pure functions today**;
full packet-path fuzzing is deferred (see "Scope and limitations"
below).

## Layout

```
fuzz/
├── Dockerfile                  # FROM audit-tools:vpp + libclang-rt-dev
├── build.sh                    # mirror-drift check + clang -fsanitize=fuzzer build
├── sfw_pure.c                  # MIRRORED copy of pure functions from sfw_nat64.c
├── fuzz_nat64_roundtrip.c      # harness for RFC 6052 embed/extract roundtrip
└── README.md                   # this file
```

## Build

On the IMP build host:

```bash
cd ~/code/sfw/fuzz
podman build -t audit-tools:vpp-fuzz .   # one-time, ~30s

cd ~/code/sfw
podman run --rm \
    -v $PWD:/src:Z \
    -v $PWD/fuzz/out:/src/fuzz/out:Z \
    audit-tools:vpp-fuzz -c "fuzz/build.sh"
```

The build does a **mirror-drift check first**: it diffs the
`sfw_nat64_embed_v4` and `sfw_nat64_extract_v4` bodies in `sfw_pure.c`
against the originals in `../sfw_nat64.c`. Any divergence aborts the
build with the diff. If you intentionally changed both, re-running
clears the check.

## Run

```bash
cd ~/code/sfw/fuzz
./out/fuzz_nat64_roundtrip -max_total_time=30 -print_final_stats=1
```

A successful run prints libFuzzer stats and exits 0. A crash drops
the trigger input under `./` (libFuzzer's default) plus full ASan/UBSan
stack trace to stderr.

## Scope and limitations

**v0 covers**: pure-function targets that can be linked without the
full VPP runtime — currently the RFC 6052 NAT64 prefix
embed/extract functions. The harness builds against `libvppinfra`
only; no `vlib`, no `vnet`, no plugin loader, no sfw_main_t.

**v0 does NOT cover**:

- The packet-path nodes (`sfw_ip4_node`, `sfw_ip6_node`). These
  require `vlib_buffer_t`, `vlib_main_t`, sfw's bihash session
  table, zone tables, and policy state to be initialised before
  any per-packet handler can be called. Building a libFuzzer
  harness around them needs either:
  1. Full VPP runtime stubs (substantial scaffolding — vlib worker
     thread state, frame allocators, etc.), or
  2. AFL++-style binary fuzzing of an instrumented `vpp_main` with
     synthetic-packet injection.
  Neither is built yet.
- The binary API handlers in `sfw_api.c`. Each handler is a small
  wrapper around a `sfw_*_add_del` call and a `REPLY_MACRO`; the
  attacker-controlled inputs (zone names, prefixes, NAT pool config)
  flow through the full sfw_main_t state machine. Fuzzing them
  needs the same runtime scaffolding as the packet path.
- The `sfw_nat64_v4_to_v6_inner_cb` / `..._outer_cb` callbacks.
  These take `vlib_buffer_t *` arguments and access packet bytes
  via `vlib_buffer_get_current` etc. Same blocker as the packet
  path.

**Roadmap to deeper coverage**:

1. Add a `fuzz/sfw_full/` subdir with a Dockerfile that mirrors
   `audit-tools:vpp`'s VPP-source-clone setup, builds the sfw plugin
   with `-fsanitize=fuzzer-no-link,address,undefined`, and links a
   harness that fakes minimal `vlib_main_t` + worker state.
2. Author a `fuzz_nat64_translate_v6_to_v4` harness that wraps the
   full v6→v4 translator. The trigger input from `sfw_nat64.c:482`
   (the `os_panic` finding fixed in `a467542`) becomes a regression
   test corpus seed.
3. Same shape for the v4→v6 direction and for the binary API
   handlers.

The mirror approach in v0 is intentionally cheap. If the v0 harness
finds anything, that already pays for the scaffolding investment.
If it doesn't (likely — these functions have been heavily reviewed
during the F2 / F3 fixes), v0 still demonstrates the pattern and
unblocks the harder harnesses.

## Mirror-drift policy

`sfw_pure.c` carries copies of pure functions from `sfw_nat64.c`.
`build.sh` refuses to build if they diverge. When intentionally
changing the originals:

1. Update `sfw_pure.c` to match.
2. Re-run `build.sh` — passes mirror check.
3. Re-fuzz: any pre-existing crash artefacts under `artifacts/` may
   no longer reproduce; re-discover with the new code.

The functions chosen for mirroring are RFC-frozen wire-format
arithmetic — they should rarely change. If a real bugfix lands in
`sfw_nat64.c`, the build's drift check forces an explicit lockstep
update in this directory and a fresh fuzz pass.
