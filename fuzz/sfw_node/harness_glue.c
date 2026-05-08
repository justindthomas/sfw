/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * harness_glue.c — extern symbols sfw_node.c (and its sibling sfw .c
 * files) reach for that aren't present in libvppinfra.  Two
 * categories:
 *
 *   1. **VPP runtime data** — `vlib_global_main`, `vlib_thread_main`,
 *      `ip4_main`, `ip6_main`, `feature_main`, the FIB pools, etc.
 *      VPP normally allocates and populates these at vlib_init time;
 *      we provide zero-initialised storage so the linker resolves
 *      them.  Anything reaching into these at runtime needs explicit
 *      setup in `harness_init` (see harness_init.h) before invoking
 *      the sfw node.
 *
 *   2. **VPP runtime functions** — `vlib_*` / `vnet_*` / `format_*` /
 *      `unformat_*` / sfw plugin glue that we don't need at runtime.
 *      Stubs return harmless defaults; calls during fuzzing fall
 *      through cleanly so we can iterate towards real coverage.
 *
 * v2.1 scope (this file): the chassis is now driveable.  In addition
 * to the link-time storage, harness_init_once() populates the runtime
 * fields that sfw_ip{4,6}_inline actually reads — buffer arena +
 * vm->buffer_main, vm->node_main.nodes / error_main.counters for
 * vlib_node_increment_counter, the buffer_enqueue_to_next_fn stub,
 * feature_main.feature_config_mains[0] for vnet_feature_next, and
 * ip4_main / ip6_main fib_index_by_sw_if_index.  sfw_main is brought
 * up via sfw_feature_init with nworkers=0.
 *
 * The harness body invokes sfw_ip{4,6}_inline against this fixture;
 * with sm->if_config still empty, src_zone resolution returns
 * SFW_ZONE_NONE and the FIB-lookup branch (sfw_resolve_dst_zone*) stays
 * out of reach — that is intentional v2.1 scope.  Coverage focus is
 * the parse / L4-extract / bihash-search path; v2.2+ will populate
 * if_config so policy + FIB land too.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/feature/feature.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip_packet.h>
#include <vppinfra/time.h>
#include <vppinfra/vec.h>
#include <vppinfra/pool.h>
#include <vppinfra/bihash_24_8.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/dpo.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip4_fib_16.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip4_mtrie.h>
#include <sfw/sfw.h>

#include "harness_init.h"

/* ============================================================ */
/*  Category 1: VPP runtime globals                              */
/* ============================================================ */

vlib_global_main_t vlib_global_main;
vlib_thread_main_t vlib_thread_main;
vlib_buffer_func_main_t vlib_buffer_func_main;
u8 **vlib_thread_stacks;

vnet_feature_main_t feature_main;

ip4_main_t ip4_main;
ip6_main_t ip6_main;
ip4_fib_16_t *ip4_fib_16s;
ip4_mtrie_8_ply_t *ip4_ply_pool;
ip6_fib_fwding_table_instance_t ip6_fib_fwding_table;
load_balance_t *load_balance_pool;

/* sfw_main is defined in sfw.c (which we compile in here, unlike the
 * v1 sfw_full chassis that only compiled sfw_nat64.c).  No second
 * definition needed. */

/* The CPU-feature-detected SIMD checksum that VPP swaps in at
 * vlib_init time.  Reuse the v1 portable RFC-1071 implementation. */
static ip_csum_t
fuzz_incremental_checksum_portable (ip_csum_t csum, void *data_arg,
				    uword n_bytes)
{
  uint8_t *p = data_arg;
  while (n_bytes >= sizeof (uint32_t))
    {
      uint32_t w;
      __builtin_memcpy (&w, p, sizeof (w));
      csum = ip_csum_with_carry (csum, w);
      p += sizeof (uint32_t);
      n_bytes -= sizeof (uint32_t);
    }
  if (n_bytes > 0)
    {
      uint32_t tmp = 0;
      __builtin_memcpy (&tmp, p, n_bytes);
      csum = ip_csum_with_carry (csum, tmp);
    }
  return csum;
}

ip_csum_t (*vnet_incremental_checksum_fp) (ip_csum_t, void *, uword) =
  fuzz_incremental_checksum_portable;

/* ============================================================ */
/*  Category 2: VPP runtime function stubs                       */
/* ============================================================ */

/* Single zero-initialised vnet_main_t the stub vnet_get_main()
 * returns.  Callers use it primarily for `interface_main.sw_interfaces`
 * lookups; harness_init can populate one entry's worth of pool storage
 * if the harness needs to drive sw_if_index validation. */
static vnet_main_t fuzz_vnet_main;

vnet_main_t *
vnet_get_main (void)
{
  return &fuzz_vnet_main;
}

/* Feature-arc enable/disable is a no-op in fuzz: every interface is
 * "enabled" by virtue of the harness invoking the node directly. */
int
vnet_feature_enable_disable (const char *arc_name, const char *node_name,
			     u32 sw_if_index, int enable_disable,
			     void *feature_config,
			     u32 n_feature_config_bytes)
{
  (void) arc_name;
  (void) node_name;
  (void) sw_if_index;
  (void) enable_disable;
  (void) feature_config;
  (void) n_feature_config_bytes;
  return 0;
}

/* sfw plugin glue we don't compile in.  Stubs satisfy the linker; if
 * anything actually calls these in the harness, the abort makes it
 * obvious so we can wire it through. */
__attribute__((noreturn)) static void
fuzz_unimplemented (const char *name)
{
  fprintf (stderr, "harness: unimplemented stub %s called — wire it through\n",
	   name);
  abort ();
}

void
sfw_pref64_init (void)
{
}

int
sfw_pref64_enable (sfw_main_t *sm, u32 sw_if_index,
		   const ip6_address_t *prefix, u8 prefix_len,
		   u16 lifetime_sec)
{
  (void) sm;
  (void) sw_if_index;
  (void) prefix;
  (void) prefix_len;
  (void) lifetime_sec;
  return 0;
}

int
sfw_pref64_disable (sfw_main_t *sm, u32 sw_if_index)
{
  (void) sm;
  (void) sw_if_index;
  return 0;
}

void
sfw_rdnss_init (void)
{
}

int
sfw_rdnss_enable (sfw_main_t *sm, u32 sw_if_index,
		  const ip6_address_t *servers, u8 n_servers,
		  u32 lifetime_sec)
{
  (void) sm;
  (void) sw_if_index;
  (void) servers;
  (void) n_servers;
  (void) lifetime_sec;
  return 0;
}

int
sfw_rdnss_disable (sfw_main_t *sm, u32 sw_if_index)
{
  (void) sm;
  (void) sw_if_index;
  return 0;
}

clib_error_t *
sfw_plugin_api_hookup (vlib_main_t *vm)
{
  (void) vm;
  return NULL;
}

/* vlib runtime stubs.  None of these get reached by sfw_ip{4,6}_inline
 * unless the harness explicitly arranges for it (e.g., trace mode). */
uword
vlib_buffer_length_in_chain_slow_path (vlib_main_t *vm, vlib_buffer_t *b)
{
  (void) vm;
  return b ? b->current_length : 0;
}

void
vlib_cli_output (vlib_main_t *vm, char *fmt, ...)
{
  (void) vm;
  (void) fmt;
}

void *
vlib_add_trace (vlib_main_t *vm, vlib_node_runtime_t *r, vlib_buffer_t *b,
		u32 n_data_bytes)
{
  (void) vm;
  (void) r;
  (void) b;
  (void) n_data_bytes;
  /* Returning NULL here is fine for the non-trace path; the harness
   * runs with `node->flags = 0`, so VLIB_NODE_FLAG_TRACE is clear and
   * sfw_ip{4,6}_inline never invokes vlib_add_trace anyway. */
  return NULL;
}

void
vlib_worker_thread_barrier_sync_int (vlib_main_t *vm, const char *func_name)
{
  (void) vm;
  (void) func_name;
}

void
vlib_worker_thread_barrier_release (vlib_main_t *vm)
{
  (void) vm;
}

/* adj layer / formatting / unformatting — used in CLI paths from
 * sfw.c, not the node body.  Stubs panic to flag accidental reach. */
u32
adj_get_sw_if_index (u32 ai)
{
  (void) ai;
  fuzz_unimplemented ("adj_get_sw_if_index");
}

u8 *
format_vnet_sw_if_index_name (u8 *s, va_list *args)
{
  (void) args;
  return s;
}

uword
unformat_vnet_sw_interface (unformat_input_t *input, va_list *args)
{
  (void) input;
  (void) args;
  return 0;
}

/* ============================================================ */
/*  v2.1: chassis fixture (driveable harness)                   */
/* ============================================================ */

/* One synthetic buffer slot.  vlib_get_buffers()-via-
 * vlib_get_buffers_with_offset computes the buffer pointer as
 * `buffer_mem_start + (bi << CLIB_LOG2_CACHE_LINE_BYTES)`, so for
 * bi=0 the buffer sits at offset 0.  The slot must be cache-line
 * aligned (CLIB_CACHE_LINE_BYTES=64); a 64-byte alignment is
 * stricter than VPP's actual pool alignment but is sufficient. */
#define FUZZ_BUFFER_DATA_SIZE 2048
#define FUZZ_BUFFER_SLOT_SIZE \
  (sizeof (vlib_buffer_t) + FUZZ_BUFFER_DATA_SIZE)

static u8 fuzz_buffer_storage[FUZZ_BUFFER_SLOT_SIZE]
  __attribute__ ((aligned (64)));

/* The vlib_main_t the harness body passes to sfw_ip{4,6}_inline.
 * Distinct from the link-time `vlib_global_main` (vlib_global_main_t,
 * a separate type that holds vlib_main_t** + global registrations).
 * Nothing in sfw_ip{4,6}_inline reaches into vlib_global_main, so
 * keeping fuzz_vm fully separate keeps the wiring simple. */
static vlib_main_t fuzz_vm;
static vlib_buffer_main_t fuzz_bm;
static vlib_buffer_pool_t *fuzz_buffer_pools_vec; /* vppinfra vec */

/* node_main.nodes[0] = &fuzz_node so vlib_get_node(vm, 0) resolves.
 * vlib_node_increment_counter reads node->error_heap_index (=0) and
 * indexes vm->error_main.counters[base + counter_index].  We size the
 * counters vec to fit every sfw error counter (N_SFW_COUNTERS=64,
 * comfortably above the SFW_N_ERROR=14 the .c files emit).  The
 * runtime's `errors[]` vector stores the u32 vlib_error_t values that
 * land in `b->error` on drop paths — the values are opaque to us. */
#define N_SFW_COUNTERS 64
static vlib_node_t fuzz_node;
static vlib_node_runtime_t fuzz_node_runtime;
static vlib_error_t fuzz_node_errors[N_SFW_COUNTERS];

/* vlib_frame_t header + vector_args u32[N].  We reuse one frame each
 * iteration, resetting n_vectors to 1 in harness_load_packet().  The
 * vector_offset must be non-zero (vlib_frame_vector_args ASSERTs); we
 * point it just past the header, padding to a u32 boundary. */
#define FUZZ_FRAME_STORAGE_SIZE 256
static u8 fuzz_frame_storage[FUZZ_FRAME_STORAGE_SIZE]
  __attribute__ ((aligned (16)));

/* feature_main.feature_config_mains[0] config heap.  vnet_feature_next
 * reads `cm->config_main.config_string_heap[current_config_index]` and
 * uses it as the next-node index.  We make config_string_heap a
 * 1-element vec set to 0, so `next0 = 0` (SFW_NEXT_DROP) for every
 * packet that doesn't take a NAT64 fast path. */
static u32 *fuzz_config_string_heap;

static int fuzz_initialized = 0;

vlib_main_t *
fuzz_get_main (void)
{
  return &fuzz_vm;
}

vlib_node_runtime_t *
fuzz_get_node_runtime (void)
{
  return &fuzz_node_runtime;
}

vlib_frame_t *
fuzz_get_frame (void)
{
  return (vlib_frame_t *) fuzz_frame_storage;
}

/* No-op replacement for the dispatch-time "send these N buffers to
 * their nexts" routine.  In fuzz, we don't drain the frame to actual
 * graph nodes — counters get stamped, traces don't run, the buffer is
 * recycled by the next harness_load_packet call. */
static void
fuzz_buffer_enqueue_to_next_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
				u32 *buffers, u16 *nexts, uword count)
{
  (void) vm;
  (void) node;
  (void) buffers;
  (void) nexts;
  (void) count;
}

/* ============================================================ */
/*  v2.2: policy + FIB fixture                                  */
/* ============================================================ */

/* v2.1 leaves sm->if_config empty, so src_zone resolves to
 * SFW_ZONE_NONE for sw_if_index=0 and the per-packet loop short-
 * circuits PERMIT before reaching the FIB / policy / NAT branches.
 * v2.2 closes that gap with three pieces:
 *
 *   1. sm->if_config[0].zone_id = 2 ("external"), zone 2 declared in
 *      sm->zones[].  src_zone now resolves to 2.
 *
 *   2. Minimal FIB fixture so sfw_resolve_dst_zone4/_zone6 return
 *      SFW_ZONE_LOCAL (zone 1) instead of OOB-reading or asserting:
 *        - ip4_fib_16s pool[0] with mtrie root_ply.leaves[i] = (0<<1)|1
 *          (terminal leaf, LB index 0) for every 16-bit slot.
 *        - ip6_fib_fwding_table.ip6_hash with one default-route entry
 *          (key=(0,0,fib_index<<32|0)) → LB index 0; prefix_lengths_in_
 *          search_order = [0]; ip6_main.fib_masks[0] is zeroed so the
 *          loop's mask-and yields the default route key.
 *        - load_balance_pool[0] with lb_n_buckets=1, the inline bucket
 *          set to dpoi_type=DPO_RECEIVE so resolve_dst_zone returns
 *          SFW_ZONE_LOCAL.
 *
 *   3. One zone-pair (2→1) bound to a wildcard policy whose
 *      default_action is SFW_ACTION_PERMIT_STATEFUL.  That makes the
 *      action-dispatch + session-create + bihash-insert path
 *      reachable on every packet whose IP/L4 parse succeeds.
 */

static sfw_policy_t fuzz_default_policy;

static void
harness_setup_policy_fib_fixture (void)
{
  /* --- if_config + zones --- */
  vec_validate_init_empty (sfw_main.if_config, 0,
			   (sfw_if_config_t){ 0 });
  sfw_main.if_config[0].zone_id = 2;
  sfw_main.if_config[0].feature_on = 1;

  /* sfw_feature_init already populated zone 1 (LOCAL).  Add zone 2.
   * sm->n_zones = 2 after init; we extend to 3 so reverse iteration
   * in sfw_zone_lookup hits the new entry. */
  strncpy (sfw_main.zones[2].name, "external",
	   sizeof (sfw_main.zones[2].name) - 1);
  sfw_main.zones[2].zone_id = 2;
  if (sfw_main.n_zones < 3)
    sfw_main.n_zones = 3;

  /* --- policy: zone 2 → zone 1, default_action permit-stateful --- */
  /* Wildcard rule covering both AFs and any L4 — match-rules always
   * returns SFW_ACTION_PERMIT_STATEFUL via the default action even
   * with rules vec empty, so we don't strictly need a rule; the
   * empty vec exercises sfw_match_rules's default-action path. */
  memset (&fuzz_default_policy, 0, sizeof (fuzz_default_policy));
  fuzz_default_policy.rules = 0; /* empty vec */
  fuzz_default_policy.default_action = SFW_ACTION_PERMIT_STATEFUL;
  fuzz_default_policy.implicit_icmpv6 = 1;
  fuzz_default_policy.from_zone_id = 2;
  fuzz_default_policy.to_zone_id = 1;
  fuzz_default_policy.table_id = 0;
  strncpy (fuzz_default_policy.name, "fuzz",
	   sizeof (fuzz_default_policy.name) - 1);

  /* zone_pairs slab: vec [SFW_MAX_ZONES * SFW_MAX_ZONES] of pointers.
   * idx = from_zone * MAX + to_zone.  We bind both 2→1 and 1→2 so
   * either is_from_zone branch in sfw_node.c lights up. */
  vec_validate (sfw_main.zone_pairs_by_table, 0);
  sfw_zone_pair_slab_t *slab = &sfw_main.zone_pairs_by_table[0];
  vec_validate (slab->zone_pairs, SFW_MAX_ZONES * SFW_MAX_ZONES - 1);
  slab->zone_pairs[2 * SFW_MAX_ZONES + 1].policy = &fuzz_default_policy;
  slab->zone_pairs[1 * SFW_MAX_ZONES + 2].policy = &fuzz_default_policy;
  slab->n_policies = 1;
  vec_add1 (sfw_main.policies, &fuzz_default_policy);

  /* --- IPv4 FIB fixture --- */
  /* pool_get_zero allocates one element from the pool, returning a
   * pointer.  The element is at index 0 since the pool was empty.
   * After this, ip4_fib_get(0) (which is pool_elt_at_index(ip4_fib_16s,
   * 0)) resolves cleanly. */
  ip4_fib_16_t *fib4;
  pool_get_zero (ip4_fib_16s, fib4);
  /* mtrie: every 16-bit prefix slot = (0 << 1) | 1 = 1 = "terminal
   * leaf, LB index 0".  ip4_mtrie_16_lookup_step_one returns this
   * directly; subsequent step()s see is_terminal=1 and return the
   * leaf unchanged.  Final ip4_mtrie_leaf_get_adj_index = 0. */
  for (u32 i = 0; i < (1u << 16); i++)
    fib4->mtrie.root_ply.leaves[i] = 1;

  /* load_balance_pool[0] with one DPO_RECEIVE bucket (inline). */
  load_balance_t *lb;
  pool_get_zero (load_balance_pool, lb);
  lb->lb_n_buckets = 1;
  lb->lb_n_buckets_minus_1 = 0;
  lb->lb_buckets_inline[0].dpoi_type = DPO_RECEIVE;
  lb->lb_buckets_inline[0].dpoi_index = 0;

  /* --- IPv6 FIB fixture --- */
  /* ip6_fib_table_fwding_lookup walks
   * ip6_fib_fwding_table.prefix_lengths_in_search_order; an empty vec
   * trips ASSERT(0) in the "default route always present" branch.
   * Install one prefix length (0 = default) and add a 0::/0 entry
   * mapping to LB index 0. */
  vec_add1 (ip6_fib_fwding_table.prefix_lengths_in_search_order, 0);

  /* ip6_main.fib_masks[0] = all-zero is what we want for prefix
   * length 0 — the lookup masks the dst with all-zeros to derive the
   * key.  The default zero-init satisfies this. */

  /* Initialise the bihash for the IPv6 fwding table. */
  clib_bihash_init_24_8 (&ip6_fib_fwding_table.ip6_hash,
			 "fuzz ip6 fwding", 1024, 16ULL << 20);

  /* Insert the default route: key = (0, 0, fib_index << 32 | 0),
   * value = LB index 0. */
  clib_bihash_kv_24_8_t kv6;
  memset (&kv6, 0, sizeof (kv6));
  kv6.key[0] = 0;
  kv6.key[1] = 0;
  kv6.key[2] = ((u64) 0) << 32 | 0; /* fib_index=0, prefix_len=0 */
  kv6.value = 0;		    /* LB index 0 */
  clib_bihash_add_del_24_8 (&ip6_fib_fwding_table.ip6_hash, &kv6,
			    1 /* add */);
}

void
harness_init_once (void)
{
  if (fuzz_initialized)
    return;

  /* 0. vppinfra main heap.  vec_validate() / clib_bihash_init() reach
   *    into clib_mem_get_heap() which dereferences the per-thread
   *    main_heap pointer.  Without clib_mem_init_thread_safe() it's
   *    NULL and the very first allocation segfaults at
   *    clib_mem_heap_alloc_aligned offset 0x368ef.  64 MB is plenty
   *    for the bihash arena (16 MB) plus the various vecs. */
  clib_mem_init_thread_safe (0, 64ULL << 20);

  /* 1. clib_time + thread index.  vlib_time_now() reads
   *    clib_time_now(&vm->clib_time) and ASSERTs vm->thread_index ==
   *    os_get_thread_index() (TLS, default 0). */
  clib_time_init (&fuzz_vm.clib_time);
  fuzz_vm.thread_index = 0;

  /* 2. Buffer arena.  vlib_get_buffers_with_offset() resolves
   *    `bi << 6` from buffer_mem_start, so bi=0 → start of slot. */
  fuzz_vm.buffer_main = &fuzz_bm;
  fuzz_bm.buffer_mem_start = (uword) fuzz_buffer_storage;
  fuzz_bm.buffer_mem_size = sizeof (fuzz_buffer_storage);
  fuzz_bm.default_data_size = FUZZ_BUFFER_DATA_SIZE;
  vec_validate (fuzz_buffer_pools_vec, 0);
  fuzz_buffer_pools_vec[0].start = (uword) fuzz_buffer_storage;
  fuzz_buffer_pools_vec[0].size = sizeof (fuzz_buffer_storage);
  fuzz_buffer_pools_vec[0].data_size = FUZZ_BUFFER_DATA_SIZE;
  fuzz_buffer_pools_vec[0].alloc_size = sizeof (fuzz_buffer_storage);
  fuzz_buffer_pools_vec[0].n_buffers = 1;
  fuzz_bm.buffer_pools = fuzz_buffer_pools_vec;

  /* 3. vlib_thread_main: vlib_num_workers() = n_vlib_mains - 1.
   *    Setting n_vlib_mains=1 → vlib_num_workers()=0, which is what
   *    sfw_feature_init's vec_validate(...) wants for the per-thread
   *    vecs (sessions, lru_head, lru_tail, ...). */
  vlib_thread_main.n_vlib_mains = 1;

  /* 4. node_main.nodes[0] + error_main.counters[].
   *    vlib_node_increment_counter calls vlib_get_node(vm, 0) which is
   *    vec_elt(vm->node_main.nodes, 0).  We populate one entry. */
  fuzz_node.error_heap_index = 0;
  vec_add1 (fuzz_vm.node_main.nodes, &fuzz_node);
  vec_validate (fuzz_vm.error_main.counters, N_SFW_COUNTERS - 1);

  /* 5. node_runtime.errors[].  Values are vlib_error_t (opaque u32),
   *    stamped into b->error on drop paths.  Index range matches
   *    sfw_error_t enum. */
  for (u32 i = 0; i < N_SFW_COUNTERS; i++)
    fuzz_node_errors[i] = i;
  fuzz_node_runtime.errors = fuzz_node_errors;
  fuzz_node_runtime.node_index = 0;
  fuzz_node_runtime.flags = 0;

  /* 6. Frame.  vector_offset must be non-zero (asserted), and points
   *    `(void*)f + vector_offset` at the u32 buffer-index array. */
  vlib_frame_t *frame = (vlib_frame_t *) fuzz_frame_storage;
  memset (frame, 0, FUZZ_FRAME_STORAGE_SIZE);
  frame->vector_offset = sizeof (vlib_frame_t);
  /* Round up to u32 alignment (ASSERT-only; sizeof is already 4-byte
   * aligned but make it explicit). */
  if (frame->vector_offset & 3)
    frame->vector_offset = (frame->vector_offset + 3) & ~3u;
  frame->n_vectors = 1;
  u32 *vec_args = (u32 *) ((u8 *) frame + frame->vector_offset);
  vec_args[0] = 0;

  /* 7. buffer_func_main.buffer_enqueue_to_next_fn.  Without this set,
   *    vlib_buffer_enqueue_to_next would dereference NULL. */
  vlib_buffer_func_main.buffer_enqueue_to_next_fn =
    fuzz_buffer_enqueue_to_next_fn;

  /* 8. feature_main with one valid arc.  vnet_feature_next reads
   *    feature_arc_index from vnet_buffer(b) (=0) and indexes
   *    feature_config_mains[0]. */
  vec_validate (feature_main.feature_config_mains, 0);
  vec_validate (fuzz_config_string_heap, 0);
  fuzz_config_string_heap[0] = 0; /* SFW_NEXT_DROP */
  feature_main.feature_config_mains[0].config_main.config_string_heap =
    fuzz_config_string_heap;

  /* 9. ip4_main / ip6_main fib_index_by_sw_if_index.  Needed by the
   *    rx_fib_index lookup at the head of sfw_ip{4,6}_inline. */
  vec_validate (ip4_main.fib_index_by_sw_if_index, 0);
  ip4_main.fib_index_by_sw_if_index[0] = 0;
  vec_validate (ip6_main.fib_index_by_sw_if_index, 0);
  ip6_main.fib_index_by_sw_if_index[0] = 0;

  /* 10. sfw_main.  hash_buckets / hash_memory cap bihash arena to a
   *     fuzz-friendly size (16 MB instead of the default 256 MB so
   *     ASan shadow memory stays manageable).  sfw_feature_init does
   *     the per-thread vec_validate's keyed off vlib_num_workers(). */
  sfw_main.hash_buckets = 1024;
  sfw_main.hash_memory = 16ULL << 20;
  sfw_main.session_timeout = 30.0;
  sfw_main.vnet_main = vnet_get_main ();
  sfw_feature_init (&sfw_main);

  /* 11. v2.2 — policy + FIB fixture so the inline body's classify
   *     path actually fires.  See harness_setup_policy_fib_fixture
   *     for the layout. */
  harness_setup_policy_fib_fixture ();

  fuzz_initialized = 1;
}

void
harness_load_packet (const uint8_t *data, size_t size)
{
  vlib_buffer_t *b = (vlib_buffer_t *) fuzz_buffer_storage;

  size_t cap = FUZZ_BUFFER_DATA_SIZE;
  size_t n = size > cap ? cap : size;

  /* Zero the header (template fields + opaque/opaque2) and copy bytes
   * into b->data[].  current_data=0 means b->data[0..n-1] is the
   * packet content.  flags=0 keeps NEXT_PRESENT/TOTAL_LENGTH_VALID
   * clear so vlib_buffer_length_in_chain() returns current_length
   * directly. */
  memset (b, 0, sizeof (*b));
  if (n > 0)
    memcpy (b->data, data, n);
  b->current_data = 0;
  b->current_length = (u16) n;
  b->flags = 0;
  b->ref_count = 1;
  b->buffer_pool_index = 0;
  b->error = 0;
  b->current_config_index = 0;

  vnet_buffer_opaque_t *vb = vnet_buffer (b);
  vb->sw_if_index[VLIB_RX] = 0;
  vb->sw_if_index[VLIB_TX] = (u32) ~0;
  vb->feature_arc_index = 0;

  vlib_frame_t *frame = (vlib_frame_t *) fuzz_frame_storage;
  frame->n_vectors = 1;
  frame->frame_flags = 0;
  frame->flags = 0;
  u32 *vec_args = (u32 *) ((u8 *) frame + frame->vector_offset);
  vec_args[0] = 0;
}
