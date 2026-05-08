# sfw fuzz harnesses (v2 — full node body)

libFuzzer harnesses for the **sfw IPv4 / IPv6 node bodies** —
`sfw_ip4_inline` / `sfw_ip6_inline` in `sfw_node.c`. v2 covers the
classifier-side coverage gap that v1 (`../sfw_full/`) doesn't reach:
zone resolution from FIB lookup, bihash session search/insert,
zone-pair policy match, action dispatch (permit / deny / NAT / NAT64
forward / NAT64 return), and the per-thread LRU bookkeeping.

## Status

**v2.3: full classify + stateful-NAT path covered.**

The full sfw plugin (sfw.c, sfw_node.c, sfw_session.c, sfw_rules.c,
sfw_nat.c, sfw_nat64.c) compiles with `-fsanitize=address,undefined,
fuzzer-no-link`, the `bihash_{48,24}_8` templates instantiate
standalone, and the chassis (`harness_glue.c` + `harness_init.h`)
brings up enough VPP runtime to drive `sfw_ip{4,6}_inline` against
fuzzer-supplied bytes through every classify branch. v2.3 adds a
NAT44 dynamic pool + flips the default action to
`PERMIT_STATEFUL_NAT`, so `sfw_nat_translate_source` and the SNAT
session-insert branch fire on every parse-success packet.

```
$ ./out/fuzz_sfw_ip4_node -max_total_time=10
#2427744  DONE  cov: 495 ft: 496  exec/s: 220704
$ ./out/fuzz_sfw_ip6_node -max_total_time=10
#2398921  DONE  cov: 485 ft: 486  exec/s: 218083
```

Coverage progression across versions:

| Version | IPv4 cov | IPv6 cov | What's reachable |
|---------|---------:|---------:|------------------|
| v2.0    |        1 |        1 | placeholder (entry/exit only) |
| v2.1    |      342 |      310 | parse + L4-extract + bihash search |
| v2.2    |      445 |      455 | + policy match + session create + FIB lookup |
| v2.3    |      495 |      485 | + SNAT translate (sfw_nat_translate_source, port allocator) |

## Layout

```
fuzz/sfw_node/
├── Dockerfile                      # FROM audit-tools:vpp-fuzz
├── build.sh                        # compile sfw .c + chassis + harnesses
├── bihash_inst.c                   # clib_bihash_48_8 (sfw session table)
├── bihash_inst_24_8.c              # clib_bihash_24_8 (ip6_fib_fwding_table)
├── harness_glue.c                  # VPP runtime globals + stubs + v2.{1,2} fixture
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
| Zone-pair policy match                | no                  | no                       | **yes (v2.2)**           |
| Action dispatch (permit/deny/NAT)     | no                  | no                       | **yes (v2.2)**           |
| FIB lookup (mtrie / bihash24_8)       | no                  | no                       | **yes (v2.2)**           |
| Bihash session insert                 | no                  | no                       | **yes (v2.2)**           |
| Stateful NAT path (SNAT translate)    | no                  | no                       | **yes (v2.3)**           |
| Port allocator (per-thread bitmap)    | no                  | no                       | **yes (v2.3)**           |
| DNAT static lookup                    | no                  | no                       | v2.4+ (needs DNAT statics) |
| Deterministic-NAT slot scan           | no                  | no                       | v2.4+ (det pool)         |
| LRU bookkeeping (multi-iter)          | no                  | no                       | v2.4+ (stateful fuzzer)  |
| Multi-buffer per frame (n_vectors > 1) | no                 | no                       | v2.4+                    |
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
    3. **v2.1 chassis (`harness_init_once` / `harness_load_packet`)**:
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
    4. **v2.2 policy + FIB fixture (`harness_setup_policy_fib_fixture`)**:
       assigns `sm->if_config[0].zone_id = 2` ("external"), declares
       zone 2 in `sm->zones[]`, binds zone-pair (2 → 1) and (1 → 2)
       to a wildcard `permit-stateful` policy, then constructs the
       minimal FIB so `sfw_resolve_dst_zone{4,6}` returns
       `SFW_ZONE_LOCAL`:
         - **IPv4**: `pool_get_zero(ip4_fib_16s)` for the FIB; mtrie
           `root_ply.leaves[i] = (0<<1)|1` (terminal, LB index 0) for
           every 16-bit slot.
         - **IPv6**: `clib_bihash_init_24_8(&ip6_fib_fwding_table.
           ip6_hash, ...)` plus a default-route entry, with
           `prefix_lengths_in_search_order = [0]`.
         - **Both**: `pool_get_zero(load_balance_pool)` for LB index
           0 with `lb_n_buckets=1` and the inline bucket's
           `dpoi_type = DPO_RECEIVE`.
    5. **v2.3 NAT pool**: hand-fills one NAT44 dynamic pool covering
       internal `0.0.0.0/0` → external `203.0.113.0/24`, registers
       the shared `sfw_v4_port_alloc_t` via
       `sfw_v4_port_alloc_ref_or_create`, and flips the default
       policy action to `SFW_ACTION_PERMIT_STATEFUL_NAT` so
       `sfw_nat_translate_source` fires on every classify-match.
- `libvppinfra` — same as v1.

## Roadmap to v2.4

v2.3 covers SNAT translation but leaves three branches dark:

1. **DNAT static lookup.** `sfw_nat_find_dnat` is unreached because
   `sm->nat_static_dnat_v4` is empty.  Hand-fill one DNAT static
   (e.g. external 203.0.113.10:80 → internal 10.0.0.5:8080) so the
   pre-classify DNAT path + the
   `SFW_ACTION_PERMIT_STATEFUL_NAT`-with-`dnat`-set branch lights
   up.

2. **Deterministic-NAT slot scan.** Add a second pool with
   `mode=SFW_NAT_MODE_DETERMINISTIC` so `sfw_nat_translate_source`
   takes the deterministic mod-port path; combined with corpus
   evolution that produces colliding source ports, the
   `det collision check` slot scan in `sfw_node.c` lights up.

3. **Multi-iteration / multi-vector frame.** libfuzzer's single-
   shot model means each iteration's bihash starts in the state the
   previous iteration left it; LRU-touch activates only when a
   later iteration matches an earlier session.  Bumping
   `frame->n_vectors` from 1 to 4-8 (with the same bytes copied
   into N buffers, or fuzzer-controlled per-buffer slicing) would
   exercise per-frame boundary handling.  v1's NAT64 trigger F12
   was a frame-boundary bug — ensuring v2 has frame-boundary
   coverage is a regression-defence priority.

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
