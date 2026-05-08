# sfw fuzz harnesses (v2 — full node body)

libFuzzer harnesses for the **sfw IPv4 / IPv6 node bodies** —
`sfw_ip4_inline` / `sfw_ip6_inline` in `sfw_node.c`. v2 covers the
classifier-side coverage gap that v1 (`../sfw_full/`) doesn't reach:
zone resolution from FIB lookup, bihash session search/insert,
zone-pair policy match, action dispatch (permit / deny / NAT / NAT64
forward / NAT64 return), and the per-thread LRU bookkeeping.

## Status

**v2.1: driveable — sfw_ip{4,6}_inline runs against fuzzer input.**

The full sfw plugin (sfw.c, sfw_node.c, sfw_session.c, sfw_rules.c,
sfw_nat.c, sfw_nat64.c) compiles with `-fsanitize=address,undefined,
fuzzer-no-link`, the `bihash_48_8` template instantiates standalone,
and the chassis (`harness_glue.c` + `harness_init.h`) brings up just
enough VPP runtime — buffer arena + `vm->buffer_main`, `node_main` /
`error_main` for `vlib_node_increment_counter`, a no-op
`buffer_enqueue_to_next_fn`, `feature_main.feature_config_mains[0]`
for `vnet_feature_next`, `ip{4,6}_main.fib_index_by_sw_if_index`, and
`sfw_main` via `sfw_feature_init` (nworkers=0) — so the per-frame
inline node body runs against a single synthesised buffer.

```
$ ./out/fuzz_sfw_ip4_node -max_total_time=5
#1570852  DONE  cov: 342 ft: 343  exec/s: 261808
$ ./out/fuzz_sfw_ip6_node -max_total_time=5
#1596352  DONE  cov: 310 ft: 311  exec/s: 266058
```

342 / 310 covered edges (versus `cov:1` in v2.0) means the parser,
L4 extractor, and bihash search all see the fuzzer's input on every
iteration. The session-create / NAT / NAT64 / policy paths remain
unreached because `sm->if_config` is empty — `src_zone` resolves to
`SFW_ZONE_NONE` and the per-packet loop falls through PERMIT. Lifting
that is v2.2+ work (see "Roadmap to v2.2" below).

## Layout

```
fuzz/sfw_node/
├── Dockerfile                      # FROM audit-tools:vpp-fuzz
├── build.sh                        # compile sfw .c + chassis + harnesses
├── bihash_inst.c                   # 2-line clib_bihash_48_8 instantiation
├── harness_glue.c                  # VPP runtime globals + stubs + v2.1 fixture
├── harness_init.h                  # public surface: harness_init_once,
│                                   # harness_load_packet, fuzz_get_main, ...
├── fuzz_sfw_ip4_node.c             # drives sfw_ip4_node_fn on fuzzer input
├── fuzz_sfw_ip6_node.c             # drives sfw_ip6_node_fn on fuzzer input
├── corpus/
│   └── <harness>/closed/<id>.bin   # closed-finding regression seeds
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
| `sfw_ip{4,6}_inline` parse + L4-extract | no                | no                       | **yes (v2.1)**           |
| Bihash session search                 | no                  | no                       | **yes (v2.1)**           |
| Zone-pair policy match                | no                  | no                       | v2.2+ (needs if_config)  |
| Action dispatch (permit/deny/NAT)     | no                  | no                       | v2.2+ (needs if_config)  |
| Bihash session insert / LRU update    | no                  | no                       | v2.2+ (needs policy hit) |
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
- `harness_glue.o` — chassis layer, three halves:
    1. **Runtime data globals**: storage for `vlib_global_main`,
       `vlib_thread_main`, `vlib_buffer_func_main`,
       `vlib_thread_stacks`, `feature_main`, `ip4_main`, `ip6_main`,
       `ip4_fib_16s`, `ip4_ply_pool`, `ip6_fib_fwding_table`,
       `load_balance_pool`, plus the portable
       `vnet_incremental_checksum_fp`.
    2. **Function stubs**: `vnet_get_main`,
       `vnet_feature_enable_disable`,
       `vlib_buffer_length_in_chain_slow_path`, `vlib_cli_output`,
       `vlib_add_trace`, `vlib_worker_thread_barrier_*`,
       `format_vnet_sw_if_index_name`, `unformat_vnet_sw_interface`,
       `adj_get_sw_if_index`, plus stubs for the sfw IPv6-RA module
       entrypoints (`sfw_pref64_*`, `sfw_rdnss_*`,
       `sfw_plugin_api_hookup`) whose source is excluded.
    3. **v2.1 fixture (`harness_init_once` / `harness_load_packet`)**:
       brings up the vppinfra main heap (`clib_mem_init_thread_safe`),
       a single `vlib_buffer_t` slot at `vm->buffer_main->buffer_mem_start`,
       a `vlib_frame_t` carrying buffer index 0, `vm->node_main.nodes[0]`
       + `vm->error_main.counters[]` so `vlib_node_increment_counter`
       lands somewhere, a no-op
       `vlib_buffer_func_main.buffer_enqueue_to_next_fn`, an
       `feature_main.feature_config_mains[0]` whose
       `config_string_heap[0]=0` makes `vnet_feature_next` return
       `next0=0`, `ip{4,6}_main.fib_index_by_sw_if_index = vec[1]={0}`,
       and `sfw_main` via `sfw_feature_init` after pinning
       `vlib_thread_main.n_vlib_mains=1` (so `vlib_num_workers()=0`).
- `libvppinfra` — same as v1.

## Roadmap to v2.2

What v2.1 does **not** yet do: cover policy match, action dispatch,
session create / NAT translation, or the LRU update path. The reason:
`sm->if_config` is empty, so `src_zone == SFW_ZONE_NONE` for every
packet and the inline body falls through PERMIT before reaching any
of those branches. To open that coverage:

1. **Populate `sm->if_config`**. `sfw_enable_disable_interface` does
   this in production but reaches into `sm->vnet_main->interface_main.
   sw_interfaces` (a pool). For the harness, hand-fill
   `sm->if_config` directly via `vec_validate` + assign zone_id to
   index 0 (and a second non-zero index if we want to fuzz cross-zone
   policy too).

2. **Install one zone-pair policy**. `sfw_zone_pair_set` materialises
   `sm->zone_pairs_by_table[fib_index]` and the rule chain.  Hand-fill
   one pair (e.g. zone 1 → zone 2, action permit-stateful + a single
   tuple rule) so policy-match and the SNAT path become reachable.

3. **Optional: NAT pool init**. Without `sm->nat_pools` populated,
   `sfw_nat_translate_source` returns failure, so the harness only
   reaches the SFW_ACTION_DENY branch on NAT exhaustion.  Adding one
   deterministic pool would also light up the deterministic-NAT slot
   scan we have at `sfw_node.c:736`.

The FIB-lookup path inside `sfw_resolve_dst_zone4`/`...zone6` is the
hard one: it reaches `ip4_fib_forwarding_lookup` which dereferences
`ip4_main.fibs[]`, `ip4_fib_16s`, and the mtrie ply pool. Stubbing
the resolver via `--wrap=sfw_resolve_dst_zone4` (and v6 mirror) is
likely cheaper than building a real FIB.

## Findings to date

None yet. The harness has only run for ~10 wall-clock seconds at
v2.1 wiring time; an extended overnight run is the next thing to
schedule.

## Why this chassis is worth maintaining

- **Reproducibility on a clean host.** A future contributor running
  `build.sh` on the build host gets the same fixture in one command;
  no archaeology over which extern symbols or runtime fields VPP
  needs.
- **Reuse for vpp-pcap v2 (PLAN.md item #6).** vpp-pcap's plugin
  nodes reach for the same `vlib_main_t` / `vnet_main_t` /
  `feature_main` / FIB globals. The chassis here is the template;
  the v2.1 buffer/frame/node-runtime fixture transplants unchanged.
- **The v2.2 diff is now scoped.** Lifting policy / NAT / FIB
  coverage is hand-filling `sm->if_config` and one zone-pair, which
  is one focused change against this directory.
