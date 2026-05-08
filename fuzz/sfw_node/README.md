# sfw fuzz harnesses (v2 — full node body, chassis)

libFuzzer harnesses for the **sfw IPv4 / IPv6 node bodies** —
`sfw_ip4_inline` / `sfw_ip6_inline` in `sfw_node.c`. v2 covers the
classifier-side coverage gap that v1 (`../sfw_full/`) doesn't reach:
zone resolution from FIB lookup, bihash session search/insert,
zone-pair policy match, action dispatch (permit / deny / NAT / NAT64
forward / NAT64 return), and the per-thread LRU bookkeeping.

## Status

**v2.0 (this commit): chassis only — linker-clean.**

The full sfw plugin (sfw.c, sfw_node.c, sfw_session.c, sfw_rules.c,
sfw_nat.c, sfw_nat64.c) compiles with `-fsanitize=address,undefined,
fuzzer-no-link`, the `bihash_48_8` template instantiates standalone,
the chassis stub layer (`harness_glue.c`) provides every other extern
symbol the sfw .c files reach for. Two harnesses build successfully:

```
$ ./out/fuzz_sfw_ip4_node -max_total_time=2
#1794452  DONE   cov: 1 ft: 1   exec/s: 598150
$ ./out/fuzz_sfw_ip6_node -max_total_time=2
#1791337  DONE   cov: 1 ft: 1   exec/s: 597112
```

`cov: 1 ft: 1` = just the entry/exit edge of the placeholder body.
v2.0's job is to prove the chassis assembles; v2.1 will fill in the
fixture so the fuzzer actually drives the node.

## Layout

```
fuzz/sfw_node/
├── Dockerfile                      # FROM audit-tools:vpp-fuzz
├── build.sh                        # compile sfw .c + chassis + harnesses
├── bihash_inst.c                   # 2-line clib_bihash_48_8 instantiation
├── harness_glue.c                  # VPP runtime globals + stub functions
├── fuzz_sfw_ip4_node.c             # v2.0 placeholder (returns 0)
├── fuzz_sfw_ip6_node.c             # v2.0 placeholder (returns 0)
├── corpus/
│   └── <harness>/closed/<id>.bin   # post-v2.1 closed-finding seeds
└── README.md                       # this file
```

## Build

On the IMP build host, inside `audit-tools:vpp-fuzz`:

```bash
podman run --rm -v ~/code/sfw:/src:Z \
    localhost/audit-tools:vpp-fuzz \
    -c "/src/fuzz/sfw_node/build.sh"

# Artefacts at fuzz/sfw_node/out/
ls fuzz/sfw_node/out
```

The build skips `sfw_pref64.c` and `sfw_rdnss.c` because they
`#include <vnet/ip6-nd/ip6_ra.h>` which isn't in the `vpp-dev`
package (the IPv6-RA option-register API ships only as a runtime
hook). `harness_glue.c` stubs both modules' init/enable/disable
entrypoints with the same signatures so the linker resolves cleanly.

## v1 vs. v2 coverage

| Path                                  | v0 (`fuzz/`)        | v1 (`sfw_full/`)         | v2 (here)                |
|---------------------------------------|---------------------|--------------------------|--------------------------|
| `sfw_nat64_translate_v{4,6}_to_v{6,4}` | mirrored only      | yes (sanitised dispatch) | yes (transitively)       |
| ICMP{4,6}-translate helpers           | mirrored only       | yes (header-inlined)     | yes (header-inlined)     |
| `sfw_ip4_inline` parse + classify     | no                  | no                       | **chassis ready (v2.0)** |
| Bihash session search/insert          | no                  | no                       | **chassis ready (v2.0)** |
| Zone-pair policy match                | no                  | no                       | **chassis ready (v2.0)** |
| Action dispatch (permit/deny/NAT)     | no                  | no                       | **chassis ready (v2.0)** |
| LRU bookkeeping (multi-iter)          | no                  | no                       | v2.2+ (stateful fuzzer)  |
| `sfw_api.c` handler mutators          | partial (one fn)    | no                       | **see `../sfw_api/` (Tier 2 #5)** |

## Architecture

v2 compiles the full sfw plugin minus IPv6-RA glue, with sanitisers,
then links each harness against:

- `sfw.o`, `sfw_node.o`, `sfw_session.o`, `sfw_rules.o`, `sfw_nat.o`,
  `sfw_nat64.o` — sanitised plugin code
- `bihash_inst.o` — 2-line file that includes
  `<vppinfra/bihash_48_8.h>` then `<vppinfra/bihash_template.c>`,
  emitting the `clib_bihash_{init,search,add_del}_48_8` template
  instances the plugin reaches. libvppinfra ships the templates but
  not the 48/8 instantiation; in a regular VPP build that lives in
  libvlib.
- `harness_glue.o` — the chassis stub layer, two halves:
    1. **Runtime data globals**: zero-initialised storage for
       `vlib_global_main`, `vlib_thread_main`, `vlib_buffer_func_main`,
       `vlib_thread_stacks`, `feature_main`, `ip4_main`, `ip6_main`,
       `ip4_fib_16s`, `ip4_ply_pool`, `ip6_fib_fwding_table`,
       `load_balance_pool`, plus the v1-style portable
       `vnet_incremental_checksum_fp`. Everything sfw_ip{4,6}_inline
       reaches for is *present* but *empty*; v2.1 populates the bits
       the inline node body actually reads.
    2. **Function stubs**: `vnet_get_main`, `vnet_feature_enable_disable`,
       `vlib_buffer_length_in_chain_slow_path`, `vlib_cli_output`,
       `vlib_add_trace`, `vlib_worker_thread_barrier_*`,
       `format_vnet_sw_if_index_name`, `unformat_vnet_sw_interface`,
       `adj_get_sw_if_index`, plus stubs for the sfw IPv6-RA module
       entrypoints (`sfw_pref64_*`, `sfw_rdnss_*`, `sfw_plugin_api_hookup`)
       whose source is excluded.
- `libvppinfra` — same as v1.

## Roadmap to v2.1

What v2.0 does **not** yet do: invoke `sfw_ip4_inline` /
`sfw_ip6_inline`. The harness body is currently `return 0`. Three
steps to lift this:

1. **vlib_buffer fixture**. VPP's `vlib_get_buffers(vm, from, b, n)`
   is `static_always_inline` and dereferences `vm->buffer_main` to
   resolve buffer-index → `vlib_buffer_t*`. Either:
   - mock `vm->buffer_main` to point at a hand-rolled
     `vlib_buffer_main_t` whose `buffer_pool_main_by_index_id[]`
     resolves a single buffer-index 0 to a `fuzz_buffer_t`-style
     fixture (matches v1's storage shape but indexed via VPP's
     pool-id math); or
   - object-link a thin replacement for the inline that takes our
     fixture directly (we'd need to either fork the inline or use
     `--wrap` link-time symbol interposition).

2. **vlib_frame_t fixture**. `vlib_frame_t` ends in a flexible
   `vector_args[]` array; `vlib_frame_vector_args(frame)` returns
   the `u32 *` of buffer indices. A 64-byte struct with one
   `n_vectors=1` entry is sufficient.

3. **Per-fixture state**: populate `ip4_main.fib_index_by_sw_if_index`
   (v6 mirror), wire `feature_main` so `vnet_feature_next()` returns
   a sane next-node, initialise `sfw_main` via `sfw_feature_init()`
   adapted (drop the `vlib_num_workers()` / `vec_validate` calls that
   need the threading subsystem, hand-fill the bihash + LRU vecs
   with `nworkers=0`).

The hardest of those is (1). The v1 chassis sidesteps it by calling
`sfw_nat64_translate_v{4,6}_to_v{6,4}` directly (no buffer-pool
lookup); v2 cannot, because the whole point is the per-frame body.

Once (1)-(3) land, the fuzzer's `data` parameter is reinterpreted as
the IPv4/IPv6 packet content; the harness loads it into the buffer
fixture, sets `vnet_buffer(b)->sw_if_index[VLIB_RX] = 0` (or fuzzer-
chosen), and invokes the inline node body. New coverage opens on
parse + classify + bihash + policy + dispatch — a meaningfully
different attack surface from v1's NAT64 translator focus.

## Findings to date

None — placeholder body, no real fuzzing yet.

## Why the chassis is worth shipping at v2.0

- **Reproducibility on a clean host.** A future contributor running
  `build.sh` on the build host gets the exact same linker-clean state
  in one command. No archaeology over which extern symbols are
  needed.
- **Reuse for vpp-pcap v2 (PLAN.md item #6).** vpp-pcap's plugin
  nodes reach for the same `vlib_main_t` / `vnet_main_t` /
  `feature_main` / FIB globals. A working chassis here is the
  template — the heavy work is v2.1's vlib_buffer fixture, which
  vpp-pcap inherits unchanged.
- **The diff for v2.1 is now scoped.** Adding the buffer/frame
  fixture is one focused change against this directory; PRs against
  v2.1 don't bury the chassis in noise.
