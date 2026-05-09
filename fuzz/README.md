# sfw fuzz harnesses

libFuzzer harnesses for sfw, organised in four tiers from
narrowest-and-cheapest (this directory — pure functions) to
deepest (the subdirectories — full translators, full node bodies,
binary-API handlers). Pick the tier that matches the surface you're
testing; each subdir has its own README with build / run / status.

## Tiers

| Tier | Path                | Surface                                                                 |
|------|---------------------|-------------------------------------------------------------------------|
| 0    | `fuzz/` (this dir)  | Pure functions linked against `libvppinfra` only — RFC 6052 prefix arithmetic, NAT64 inner/outer-callback bodies (mirrored), `sfw_api_copy_fixed_string` |
| 1    | `fuzz/sfw_full/`    | The full NAT64 translators (`sfw_nat64_translate_v{6,4}_to_v{4,6}`) compiled with sanitisers and driven via a synthesised `vlib_buffer_t` |
| 2    | `fuzz/sfw_node/`    | The full packet-path node bodies (`sfw_ip{4,6}_inline`) — classify, FIB lookup, bihash session search/insert, zone-pair policy match, NAT44 SNAT + DNAT static, multi-buffer frames |
| 2    | `fuzz/sfw_api/`     | The binary-API handlers (`vl_api_sfw_*_t_handler`) — control-plane mutators that touch sfw_main's pools, vecs, port allocator, bihash |

## What's in this directory

The tier-0 harnesses link against `libvppinfra` only — no `vlib`,
no `vnet`, no plugin loader, no `sfw_main_t`. They cover code paths
that can be teased out as standalone functions:

```
fuzz/
├── Dockerfile                          # FROM audit-tools:vpp + libclang-rt-dev
├── build.sh                            # mirror-drift check + clang -fsanitize=fuzzer build
├── sfw_pure.c                          # MIRRORED bodies of the functions below
├── fuzz_nat64_roundtrip.c              # RFC 6052 embed/extract roundtrip
├── fuzz_nat64_outer_cb.c               # NAT64 v6→v4 outer-header callback
├── fuzz_nat64_inner_cb_v6_to_v4.c      # NAT64 inner-header callback (v6→v4)
├── fuzz_nat64_inner_cb_v4_to_v6.c      # NAT64 inner-header callback (v4→v6)
├── fuzz_api_copy_fixed_string.c        # sfw.api fixed-size string decoder
├── sfw_full/                           # tier 1 — see subdir README
├── sfw_node/                           # tier 2 — see subdir README
├── sfw_api/                            # tier 2 — see subdir README
└── README.md                           # this file
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

The build does a **mirror-drift check first**: it diffs each
mirrored function body in `sfw_pure.c` against its origin in
`../sfw_nat64.c` or `../sfw_api.c`. Any divergence aborts the build
with the diff. If you intentionally changed both, re-running clears
the check.

## Run

```bash
cd ~/code/sfw/fuzz
./out/fuzz_nat64_roundtrip          -max_total_time=30 -print_final_stats=1
./out/fuzz_nat64_outer_cb           -max_total_time=30 -print_final_stats=1
./out/fuzz_nat64_inner_cb_v6_to_v4  -max_total_time=30 -print_final_stats=1
./out/fuzz_nat64_inner_cb_v4_to_v6  -max_total_time=30 -print_final_stats=1
./out/fuzz_api_copy_fixed_string    -max_total_time=30 -print_final_stats=1
```

A successful run prints libFuzzer stats and exits 0. A crash drops
the trigger input under `./` (libFuzzer's default) plus full ASan /
UBSan stack trace to stderr.

## Mirror-drift policy

`sfw_pure.c` carries copies of pure functions from `sfw_nat64.c`
and `sfw_api.c`. `build.sh` refuses to build if they diverge. When
intentionally changing the originals:

1. Update `sfw_pure.c` to match.
2. Re-run `build.sh` — passes mirror check.
3. Re-fuzz: any pre-existing crash artefacts may no longer
   reproduce; re-discover with the new code.

The functions chosen for mirroring are RFC-frozen wire-format
arithmetic and a fixed-size string decoder — they should rarely
change. If a real bugfix lands in the originals, the build's drift
check forces an explicit lockstep update in this directory and a
fresh fuzz pass.

## Where deeper coverage lives

The tier-0 harnesses don't reach the full packet path, the full
translator dispatch, or the binary-API handlers. Those live in the
subdirectories:

- **NAT64 translator end-to-end** → `sfw_full/README.md`. Compiles
  the real `sfw_nat64.c` with sanitisers and drives both
  translators against fuzzer-supplied IP packets in a synthesised
  `vlib_buffer_t`. Closed findings F8–F11 ship as standalone
  reproducers + libFuzzer corpus seeds replayed by
  `audit-tools/regression-check.sh`.
- **Packet-path node bodies** → `sfw_node/README.md`. Compiles the
  full sfw plugin (minus the IPv6-RA glue) with sanitisers and
  drives `sfw_ip{4,6}_inline` through the classify branches: zone
  resolution from FIB lookup, policy match, action dispatch
  (permit / deny / NAT / NAT64), per-thread LRU bookkeeping,
  multi-buffer per frame.
- **Binary-API handlers** → `sfw_api/README.md`. Drives all nine
  `vl_api_sfw_*_t_handler` entrypoints with attacker-controlled
  message structs against a seeded `sfw_main`. First two minutes of
  the v1 run surfaced an OOM in `sfw_nat_pool_add_del` and three
  `1u << 32` UB sites — see the subdir README and
  `audit-tools/reports/sfw-2026-05-08-fuzz-v2-api.md`.

The next steps for each tier (deterministic-NAT slot scan,
cross-iteration session reuse, multi-message API sequences, etc.)
are tracked in the subdir READMEs, not here.
