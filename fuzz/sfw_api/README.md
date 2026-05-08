# sfw_api fuzz harness

libFuzzer harness for the sfw plugin's binary-API handlers
(`sfw_api.c`).  Cross-cuts the v2 packet-path harness in
`../sfw_node/`: this one drives the *control plane* (operator
mutators that touch `sfw_main_t`'s bihash, vec pools, port
allocator) where v2 drives the *data plane* (per-frame node body).

## Status

**v1.0: 9 handlers reachable, real findings on first run.**

All nine `vl_api_sfw_*_t_handler` entrypoints are dispatched from
one libFuzzer harness; the fuzzer's first byte selects the handler
(`op_id % 9`) and the remaining bytes are memcpy'd into the
appropriate `vl_api_sfw_*_t` message struct.

```
$ ./out/fuzz_sfw_api -max_total_time=60
==2== ERROR: libFuzzer: deadly signal
   ... sfw_v4_port_alloc_ref_or_create
   ... vl_api_sfw_nat_pool_add_del_t_handler   (sfw_api.c:383)
```

First two minutes of fuzzing surfaced (see `reports/sfw-2026-05-08-
fuzz-v2-api.md`):
- crashes on `sfw_nat_pool_add_del` with attacker-controlled
  `external_plen` (small plen → enormous `n_external_addrs` →
  `vec_validate` exhausts heap).
- UndefinedBehaviorSanitizer reports for `1u << 32` shifts when
  `plen == 0` in three sites (sfw_api.c:366, 368; sfw_nat.c:106).
- UBSan reports for non-{0,1} bool fields in sfw_api.c struct
  loads (less interesting — production decode would have
  normalised these; harness bypasses that decode).

## Layout

```
fuzz/sfw_api/
├── Dockerfile                  # FROM audit-tools:vpp-fuzz
├── build.sh                    # generate sfw.api*.h + compile + link
├── bihash_inst.c               # 48_8 instantiation (sm->session_hash)
├── harness_glue.c              # VPP runtime stubs + sfw_main fixture +
│                               # 9-handler dispatch table
├── harness_init.h              # public surface
├── sfw_api_dispatch.c          # `#define static` then #include sfw_api.c
├── sfw/sfw.api.c               # stub shadowing the generated message-
│                               # id setup (we only call handlers
│                               # directly; vl_msg_api_* registration
│                               # apparatus would pull hundreds of
│                               # libvlibmemory undefineds)
├── fuzz_sfw_api.c              # LLVMFuzzerTestOneInput → harness_dispatch
├── corpus/
│   └── fuzz_sfw_api/closed/    # closed-finding regression seeds (empty
│                               # until findings are fixed)
└── README.md
```

## Build

```bash
podman run --rm -v ~/code/sfw:/src:Z \
    localhost/audit-tools:vpp-fuzz \
    -c "/src/fuzz/sfw_api/build.sh"
```

Three things make this harness non-obvious:

1. **`sfw.api*.h` is generated, not in the repo.**  The plugin's
   normal build pipeline (`add_vpp_plugin`) runs `vppapigen` to
   produce them; the harness's `build.sh` does the same step
   inline, then symlinks `$OUT/include/sfw/sfw.h` so sfw_api.c's
   `#include <sfw/sfw.h>` and `#include <sfw/sfw.api_enum.h>` both
   resolve.

2. **`sfw_api.c` handlers are file-scope `static`.**
   `sfw_api_dispatch.c` is a thin wrapper TU that does:
   ```c
   #define static
   #include "../../sfw_api.c"
   ```
   neutralising the `static` qualifier so the handlers become
   externally linkable for the harness body.  `STATIC_ASSERT` is
   `_Static_assert` (single C11 keyword), unaffected.  No file-scope
   static *variables* exist in sfw_api.c, so the redefinition has
   no other side effects.

3. **`sfw_api.c` includes `<sfw/sfw.api.c>` at the bottom**, which
   pulls a giant message-id registration table that references
   ~80 undefined libvlibmemory symbols.  We don't need those for
   the direct-handler-call harness, so `fuzz/sfw_api/sfw/sfw.api.c`
   is a stub that shadows the generated file (the build's `-I`
   order puts `$HERE` before `$OUT/include`).  The stub provides a
   no-op `setup_message_id_table()` so `sfw_plugin_api_hookup`
   (also exposed by the `static` redefinition) links cleanly.

## Architecture

The harness is intentionally lighter than the v2 packet-path
chassis — control-plane handlers don't process packets, so we
skip:
- the synthesised buffer arena,
- the `vlib_frame_t` fixture,
- the `feature_main.feature_config_mains` arc,
- the FIB / load_balance / mtrie pools.

What we keep (essentially the same shape as sfw_node v2.4 minus
the buffer/frame parts):
- `clib_mem_init_thread_safe(64MB)` — backing for vec_validate /
  bihash arenas.
- `vlib_thread_main.n_vlib_mains = 1` so `vlib_num_workers() = 0`.
- `vlib_global_main.vlib_mains[0] = &fuzz_vm` so handlers calling
  `vlib_get_main()` resolve to a real vlib_main_t.
- `sfw_feature_init(&sfw_main)` to set up the per-thread vecs and
  bihash.
- An if_config[0] in zone 2, zones[2] declared, one seed policy
  (heap-allocated to match production — `sfw_policy_delete` calls
  `clib_mem_free`), one zone-pair (2→1), one NAT44 dynamic pool,
  one DNAT static.

The seed state mirrors what sfw_node v2.3/v2.4 set up, so add/del
cycles + collision paths are exercised against a non-empty plugin
from the first iteration.

The 9-handler dispatch (`harness_glue.c::harness_dispatch`) wraps
each handler in a trampoline that:
1. Allocates a stack buffer of `sizeof(vl_api_sfw_X_t)`.
2. Zeroes it, then memcpy's up to that many fuzzer bytes in.
3. Forces `mp->client_index = 0` so `REPLY_MACRO` sees no
   registration (`vl_api_client_index_to_registration` returns
   NULL via our stub of its lower-level `vl_socket_*` /
   `vl_mem_api_*` callees) and early-returns instead of
   alloc+endian+send.
4. Calls the handler.

## Findings

See `audit-tools/reports/sfw-2026-05-08-fuzz-v2-api.md`.

## Roadmap

1. **Reach the wire-format decoder.** Currently we hand the
   handlers an already-decoded `vl_api_sfw_*_t` struct.  The real
   VPP API runtime decodes from a length-prefixed wire format that
   includes endian normalisation + length validation.  A
   higher-fidelity harness would drive the decode layer instead,
   so bugs there (e.g. malformed length fields) become reachable.

2. **Compose multi-message sequences.** Each iteration currently
   dispatches one handler; multi-step sequences (add policy → add
   rules → del policy → re-add) interact in ways one-shot fuzzing
   doesn't expose.  A custom `LLVMFuzzerCustomMutator` that emits
   N concatenated messages would surface ordering / refcounting
   bugs in the slabs.

3. **Full VPP wire-format integration test.** Out of scope for the
   chassis here — would need a real VPP runtime and the binary
   API socket, which the CLI fuzz already covers integrationally
   (sfw_test.c).
