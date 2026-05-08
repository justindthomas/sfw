/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * harness_glue.c — VPP runtime symbols sfw.c / sfw_api.c reach for
 * that aren't present in libvppinfra, plus the per-call message
 * dispatch table.  Slimmer than sfw_node v2 — control-plane
 * handlers don't process packets, so no buffer arena / vlib_frame /
 * feature_main config heap.
 *
 * Three categories:
 *
 *   1. **VPP runtime data** — vlib_global_main, vlib_thread_main,
 *      ip4_main, ip6_main, feature_main.  Storage; sfw_feature_init
 *      doesn't reach into them but sfw_enable_disable_interface
 *      does (via sm->vnet_main).
 *
 *   2. **VPP runtime functions** — the same list as sfw_node v2,
 *      minus the buffer/frame stubs.  Plus VPP API shims:
 *      vl_api_client_index_to_registration → NULL (so REPLY_MACRO
 *      early-returns), vl_msg_api_alloc → malloc (linker
 *      satisfier — REPLY_MACRO never reaches it on the NULL-rp
 *      path), vl_api_send_msg → no-op, vlib_get_thread_main and
 *      friends.
 *
 *   3. **Per-call dispatch** — harness_dispatch routes the fuzzer's
 *      bytes to one of 9 vl_api_sfw_*_t_handler functions.  Each
 *      message is allocated on the stack at sizeof(struct), zeroed,
 *      then the fuzzer's bytes are memcpy'd in (capped at struct
 *      size).  client_index is set to 0 after the copy so REPLY_MACRO
 *      never tries to send a reply.
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
#include <vnet/fib/ip4_fib_16.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip4_mtrie.h>
#include <vnet/ip/ip_packet.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/time.h>
#include <vppinfra/vec.h>
#include <vppinfra/pool.h>
#include <sfw/sfw.h>

#include "sfw/sfw.api_enum.h"
#include "sfw/sfw.api_types.h"

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

/* vnet_main_t with one fake sw_interface in the pool so
 * sfw_enable_disable_interface's `pool_is_free_index` lookup
 * resolves cleanly.  The handlers reach through sm->vnet_main->
 * interface_main.sw_interfaces; an empty pool would fail the
 * pool_is_free_index check and the handler would early-return
 * VNET_API_ERROR_INVALID_INTERFACE — covering only that error
 * branch.  We populate one interface so the success-path code
 * also fires. */
static vnet_main_t fuzz_vnet_main;

vnet_main_t *
vnet_get_main (void)
{
  return &fuzz_vnet_main;
}

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

/* sfw IPv6-RA glue stubs (sfw_pref64.c, sfw_rdnss.c not compiled). */
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

/* sfw_plugin_api_hookup is owned by sfw_api.c (last function in the
 * file).  It calls setup_message_id_table, which our sfw/sfw.api.c
 * stub returns 0 from — so the real definition resolves cleanly
 * here and we don't need a glue stub. */

/* vlib runtime pieces sfw.c / sfw_api.c reach for. */
void
vlib_cli_output (vlib_main_t *vm, char *fmt, ...)
{
  (void) vm;
  (void) fmt;
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

u32
adj_get_sw_if_index (u32 ai)
{
  (void) ai;
  return (u32) ~0;
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

/* sfw_api.c uses ip_prefix_decode and ip_address_decode to
 * translate wire-format addresses into kernel-internal types.
 * Both live in libvnet which we don't link.  Provide minimal
 * decoders that copy the address bytes + prefix length so the
 * mutator branch is reached with sane args; address-family
 * handling is the only branch we approximate. */
void
ip_prefix_decode (const vl_api_prefix_t *in, fib_prefix_t *out)
{
  memset (out, 0, sizeof (*out));
  if (in->address.af == ADDRESS_IP4)
    {
      out->fp_proto = FIB_PROTOCOL_IP4;
      memcpy (&out->fp_addr.ip4, &in->address.un.ip4, sizeof (ip4_address_t));
    }
  else
    {
      out->fp_proto = FIB_PROTOCOL_IP6;
      memcpy (&out->fp_addr.ip6, &in->address.un.ip6, sizeof (ip6_address_t));
    }
  out->fp_len = in->len;
}

void
ip_address_decode (const vl_api_address_t *in, ip46_address_t *out)
{
  memset (out, 0, sizeof (*out));
  if (in->af == ADDRESS_IP4)
    memcpy (&out->ip4, &in->un.ip4, sizeof (ip4_address_t));
  else
    memcpy (&out->ip6, &in->un.ip6, sizeof (ip6_address_t));
}

/* VPP API plumbing.  vl_api_client_index_to_registration is
 * `always_inline` in <vlibmemory/api.h> — we can't redefine it.
 * But it calls two extern functions:
 *
 *   vl_socket_api_registration_handle_is_valid(u32) → u8
 *   vl_mem_api_client_index_to_registration(u32) → vl_api_registration_t *
 *
 * Stubbing both to "no registration" means the inline returns NULL
 * for any client_index, REPLY_MACRO sees NULL and `return`s, so
 * the handlers never reach the alloc + send path. */
u8
vl_socket_api_registration_handle_is_valid (u32 reg_index)
{
  (void) reg_index;
  return 0;
}

vl_api_registration_t *
vl_mem_api_client_index_to_registration (u32 handle)
{
  (void) handle;
  return NULL;
}

vl_api_registration_t *
vl_socket_api_client_handle_to_registration (u32 idx)
{
  (void) idx;
  return NULL;
}

void
vl_socket_api_send (vl_api_registration_t *rp, u8 *elem)
{
  (void) rp;
  (void) elem;
}

/* vl_msg_api_alloc / vl_msg_api_send_shmem are reached only on the
 * non-NULL-rp path REPLY_MACRO never takes here, but link them so
 * the executable resolves cleanly. */
void *
vl_msg_api_alloc (int n_bytes)
{
  return malloc (n_bytes);
}

void
vl_msg_api_free (void *msg)
{
  free (msg);
}

void
vl_msg_api_send_shmem (svm_queue_t *q, u8 *elem)
{
  (void) q;
  (void) elem;
}

/* api_main_t is referenced via the api_helper_macros expansion's
 * REPLY_MACRO_DETAILS which reads `am->msg_data[t]`.  Our
 * REPLY_MACRO uses the constant-size variant which doesn't touch
 * msg_data, but the build still needs my_api_main to link
 * (vlibapi_get_main is `always_inline` and reads it). */
static api_main_t fuzz_api_main;

__thread api_main_t *my_api_main = &fuzz_api_main;

/* ============================================================ */
/*  Category 3: harness_init_once + dispatch                    */
/* ============================================================ */

static int fuzz_initialized = 0;
/* The vlib_main_t the handlers reach for via vlib_get_main(). */
static vlib_main_t fuzz_vm;

void
harness_init_once (void)
{
  if (fuzz_initialized)
    return;

  /* 1. vppinfra heap. */
  clib_mem_init_thread_safe (0, 64ULL << 20);

  /* 2. Threading: nworkers=0.  vlib_get_main() reads
   *    vlib_global_main.vlib_mains[thread_index]; populate that
   *    with a single entry pointing at our fuzz_vm so the handlers
   *    that call vlib_get_main() don't NULL-deref. */
  vlib_thread_main.n_vlib_mains = 1;
  clib_time_init (&fuzz_vm.clib_time);
  vec_add1 (vlib_global_main.vlib_mains, &fuzz_vm);

  /* 3. sm config defaults + sfw_feature_init.  Same canonical state
   *    as sfw_node v2.4 so the fuzz can drive add → del cycles
   *    against an already-non-empty plugin: zone 2 ("external") in
   *    sm->zones, one zone-pair (2 → 1) bound to a permit-stateful
   *    policy, one DNAT static, one NAT44 dynamic pool. */
  sfw_main_t *sm = &sfw_main;
  sm->hash_buckets = 1024;
  sm->hash_memory = 16ULL << 20;
  sm->session_timeout = 30.0;
  sm->vnet_main = &fuzz_vnet_main;
  sfw_feature_init (sm);

  /* sw_interface pool entry so sfw_enable_disable_interface's
   * pool_is_free_index check passes for sw_if_index=0.  Pool
   * gymnastics below mirror VPP's interface-init path. */
  vnet_sw_interface_t *si;
  pool_get_zero (fuzz_vnet_main.interface_main.sw_interfaces, si);
  si->sw_if_index = 0;

  /* if_config[0] = zone 2 ("external") so policy lookups succeed. */
  vec_validate_init_empty (sm->if_config, 0, (sfw_if_config_t){ 0 });
  sm->if_config[0].zone_id = 2;
  strncpy (sm->zones[2].name, "external",
	   sizeof (sm->zones[2].name) - 1);
  sm->zones[2].zone_id = 2;
  if (sm->n_zones < 3)
    sm->n_zones = 3;

  /* One existing policy 'fuzz' so policy_add_del's exists/find
   * paths get exercised (for is_add=0 and is_add=1 colliding
   * names).  Allocate on the heap (clib_mem_alloc) to match
   * production — sfw_policy_delete calls clib_mem_free at the end,
   * and freeing a stack/BSS pointer would crash inside vppinfra
   * before any real handler logic ran. */
  sfw_policy_t *fuzz_seed_policy =
    clib_mem_alloc_aligned (sizeof (*fuzz_seed_policy),
			    CLIB_CACHE_LINE_BYTES);
  memset (fuzz_seed_policy, 0, sizeof (*fuzz_seed_policy));
  fuzz_seed_policy->default_action = SFW_ACTION_PERMIT_STATEFUL;
  fuzz_seed_policy->implicit_icmpv6 = 1;
  fuzz_seed_policy->from_zone_id = 2;
  fuzz_seed_policy->to_zone_id = 1;
  fuzz_seed_policy->table_id = 0;
  strncpy (fuzz_seed_policy->name, "seed",
	   sizeof (fuzz_seed_policy->name) - 1);
  vec_add1 (sm->policies, fuzz_seed_policy);

  vec_validate (sm->zone_pairs_by_table, 0);
  sfw_zone_pair_slab_t *slab = &sm->zone_pairs_by_table[0];
  vec_validate (slab->zone_pairs, SFW_MAX_ZONES * SFW_MAX_ZONES - 1);
  slab->zone_pairs[2 * SFW_MAX_ZONES + 1].policy = fuzz_seed_policy;
  slab->n_policies = 1;

  /* One existing NAT pool so add-collision and del paths are
   * reachable from the start. */
  sfw_nat_pool_t pool;
  memset (&pool, 0, sizeof (pool));
  pool.kind = SFW_POOL_KIND_NAT44;
  pool.external_addr.as_u32 = clib_host_to_net_u32 (0xCB007100);
  pool.external_plen = 24;
  pool.internal_addr.as_u32 = clib_host_to_net_u32 (0x0A000000);
  pool.internal_plen = 8;
  pool.mode = SFW_NAT_MODE_DYNAMIC;
  pool.port_range_start = 1024;
  pool.port_range_end = 65535;
  pool.n_external_addrs = 256;
  pool.n_internal_addrs = 1u << 24;
  pool.ports_per_host = 64;
  pool.table_id = 0;
  pool.v4_alloc_idx = sfw_v4_port_alloc_ref_or_create (
    sm, &pool.external_addr, pool.external_plen,
    pool.port_range_start, pool.port_range_end);
  vec_add1 (sm->nat_pools, pool);

  /* One existing DNAT static. */
  sfw_nat_static_t dnat;
  memset (&dnat, 0, sizeof (dnat));
  dnat.external_addr.as_u32 = clib_host_to_net_u32 (0xCB007163);
  dnat.external_port = 0;
  dnat.internal_addr.as_u32 = clib_host_to_net_u32 (0x0A000005);
  dnat.internal_port = 80;
  dnat.protocol = 0;
  dnat.table_id = 0;
  vec_add1 (sm->nat_statics, dnat);

  fuzz_initialized = 1;
}

/* ============================================================ */
/*  Per-handler dispatch                                         */
/* ============================================================ */

/* Forward decls — sfw_api.c's handlers are static in the source,
 * but our sfw_api_dispatch.c #define's `static` to nothing before
 * #include'ing it, so they're externally linkable here. */
extern void
vl_api_sfw_enable_disable_t_handler (vl_api_sfw_enable_disable_t *mp);
extern void
vl_api_sfw_zone_interface_add_del_t_handler (
  vl_api_sfw_zone_interface_add_del_t *mp);
extern void
vl_api_sfw_policy_add_del_t_handler (vl_api_sfw_policy_add_del_t *mp);
extern void
vl_api_sfw_policy_rule_add_del_t_handler (
  vl_api_sfw_policy_rule_add_del_t *mp);
extern void
vl_api_sfw_nat_pool_add_del_t_handler (vl_api_sfw_nat_pool_add_del_t *mp);
extern void
vl_api_sfw_nat64_pool_add_del_t_handler (
  vl_api_sfw_nat64_pool_add_del_t *mp);
extern void
vl_api_sfw_pref64_advertise_add_del_t_handler (
  vl_api_sfw_pref64_advertise_add_del_t *mp);
extern void
vl_api_sfw_rdnss_advertise_add_del_t_handler (
  vl_api_sfw_rdnss_advertise_add_del_t *mp);
extern void
vl_api_sfw_nat_static_add_del_t_handler (
  vl_api_sfw_nat_static_add_del_t *mp);

/* Per-handler trampoline: zero a stack buffer of the message
 * struct's size, copy fuzzer bytes into it (capped at struct
 * size), force client_index = 0 so REPLY_MACRO sees no
 * registration and early-returns, then invoke the handler. */
#define DISPATCH_HANDLER(api_name)                                  \
  do                                                                \
    {                                                               \
      vl_api_##api_name##_t mp;                                     \
      memset (&mp, 0, sizeof (mp));                                 \
      size_t copy = size < sizeof (mp) ? size : sizeof (mp);        \
      if (copy > 0)                                                 \
	memcpy (&mp, data, copy);                                   \
      mp.client_index = 0;                                          \
      vl_api_##api_name##_t_handler (&mp);                          \
    }                                                               \
  while (0)

void
harness_dispatch (uint8_t op_id, const uint8_t *data, size_t size)
{
  switch (op_id % 9)
    {
    case 0:
      DISPATCH_HANDLER (sfw_enable_disable);
      break;
    case 1:
      DISPATCH_HANDLER (sfw_zone_interface_add_del);
      break;
    case 2:
      DISPATCH_HANDLER (sfw_policy_add_del);
      break;
    case 3:
      DISPATCH_HANDLER (sfw_policy_rule_add_del);
      break;
    case 4:
      DISPATCH_HANDLER (sfw_nat_pool_add_del);
      break;
    case 5:
      DISPATCH_HANDLER (sfw_nat64_pool_add_del);
      break;
    case 6:
      DISPATCH_HANDLER (sfw_pref64_advertise_add_del);
      break;
    case 7:
      DISPATCH_HANDLER (sfw_rdnss_advertise_add_del);
      break;
    case 8:
      DISPATCH_HANDLER (sfw_nat_static_add_del);
      break;
    }
}
