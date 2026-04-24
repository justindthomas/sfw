/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * Binary API handlers for the sfw plugin.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/format_fns.h>
#include <vnet/interface.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/fib/fib_types.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <sfw/sfw.h>

/* Generated types + msg IDs (produced at build time from sfw.api) */
#include <sfw/sfw.api_enum.h>
#include <sfw/sfw.api_types.h>

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* Helper: copy a fixed-size `string name[N]` wire field (flat u8[N],
 * NUL-padded) into a caller-provided zero-terminated buffer of size
 * buf_len. */
static void
sfw_api_copy_fixed_string (char *buf, size_t buf_len, const void *wire,
			   size_t wire_len)
{
  size_t n = wire_len < buf_len - 1 ? wire_len : buf_len - 1;
  memset (buf, 0, buf_len);
  memcpy (buf, wire, n);
  buf[buf_len - 1] = 0;
}

/* --- sfw_enable_disable --- */

static void
vl_api_sfw_enable_disable_t_handler (vl_api_sfw_enable_disable_t *mp)
{
  sfw_main_t *sm = &sfw_main;
  vl_api_sfw_enable_disable_reply_t *rmp;
  int rv;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  int enable = mp->enable_disable ? 1 : 0;

  rv = sfw_enable_disable_interface (sm, sw_if_index, enable);

  REPLY_MACRO (VL_API_SFW_ENABLE_DISABLE_REPLY);
}

/* --- sfw_zone_interface_add_del --- */

static void
vl_api_sfw_zone_interface_add_del_t_handler (
  vl_api_sfw_zone_interface_add_del_t *mp)
{
  sfw_main_t *sm = &sfw_main;
  vl_api_sfw_zone_interface_add_del_reply_t *rmp;
  int rv = 0;

  sfw_feature_init (sm);

  u32 sw_if_index = ntohl (mp->sw_if_index);
  char zone_name[33];
  sfw_api_copy_fixed_string (zone_name, sizeof (zone_name), mp->zone_name,
			     sizeof (mp->zone_name));

  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto done;
    }

  if (mp->is_add)
    {
      if (strcmp (zone_name, "local") == 0)
	{
	  rv = VNET_API_ERROR_INVALID_VALUE;
	  goto done;
	}

      u32 zone_id = sfw_zone_find_or_create (sm, zone_name);
      if (zone_id == SFW_ZONE_NONE)
	{
	  rv = VNET_API_ERROR_TABLE_TOO_BIG;
	  goto done;
	}

      vec_validate_init_empty (sm->if_config, sw_if_index,
			       (sfw_if_config_t){ 0 });
      sm->if_config[sw_if_index].zone_id = zone_id;

      /* Enable the feature arc on this interface if any policy
       * already references its zone. */
      u32 i;
      for (i = 0; i < SFW_MAX_ZONES * SFW_MAX_ZONES; i++)
	{
	  sfw_policy_t *p = sm->zone_pairs[i].policy;
	  if (p && (p->from_zone_id == zone_id || p->to_zone_id == zone_id))
	    {
	      sfw_enable_disable_interface (sm, sw_if_index, 1);
	      break;
	    }
	}
    }
  else
    {
      if (sw_if_index < vec_len (sm->if_config))
	sm->if_config[sw_if_index].zone_id = SFW_ZONE_NONE;
      sfw_enable_disable_interface (sm, sw_if_index, 0);
    }

done:
  REPLY_MACRO (VL_API_SFW_ZONE_INTERFACE_ADD_DEL_REPLY);
}

/* --- sfw_policy_add_del --- */

static void
vl_api_sfw_policy_add_del_t_handler (vl_api_sfw_policy_add_del_t *mp)
{
  sfw_main_t *sm = &sfw_main;
  vl_api_sfw_policy_add_del_reply_t *rmp;
  int rv = 0;

  sfw_feature_init (sm);

  char policy_name[65], from_zone[33], to_zone[33];
  sfw_api_copy_fixed_string (policy_name, sizeof (policy_name),
			     mp->policy_name, sizeof (mp->policy_name));
  sfw_api_copy_fixed_string (from_zone, sizeof (from_zone), mp->from_zone,
			     sizeof (mp->from_zone));
  sfw_api_copy_fixed_string (to_zone, sizeof (to_zone), mp->to_zone,
			     sizeof (mp->to_zone));

  if (policy_name[0] == 0)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  sfw_policy_t *existing = sfw_policy_find (sm, policy_name);

  if (mp->is_add)
    {
      if (existing)
	{
	  rv = VNET_API_ERROR_VALUE_EXIST;
	  goto done;
	}
      if (from_zone[0] == 0 || to_zone[0] == 0)
	{
	  rv = VNET_API_ERROR_INVALID_VALUE;
	  goto done;
	}
      u32 from_id = sfw_zone_find_or_create (sm, from_zone);
      u32 to_id = sfw_zone_find_or_create (sm, to_zone);
      if (from_id == SFW_ZONE_NONE || to_id == SFW_ZONE_NONE)
	{
	  rv = VNET_API_ERROR_TABLE_TOO_BIG;
	  goto done;
	}

      sfw_policy_t *p = sfw_policy_create (sm, policy_name, from_id, to_id);
      if (!p)
	{
	  rv = VNET_API_ERROR_UNSPECIFIED;
	  goto done;
	}
      if (mp->default_action <= SFW_ACTION_PERMIT_STATEFUL_NAT)
	p->default_action = mp->default_action;
      p->implicit_icmpv6 = mp->implicit_icmpv6 ? 1 : 0;
    }
  else
    {
      if (!existing)
	{
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	  goto done;
	}
      sfw_policy_delete (sm, existing);
    }

done:
  REPLY_MACRO (VL_API_SFW_POLICY_ADD_DEL_REPLY);
}

/* --- sfw_policy_rule_add_del --- */

static void
vl_api_sfw_policy_rule_add_del_t_handler (
  vl_api_sfw_policy_rule_add_del_t *mp)
{
  sfw_main_t *sm = &sfw_main;
  vl_api_sfw_policy_rule_add_del_reply_t *rmp;
  int rv = 0;
  vlib_main_t *vm = vlib_get_main ();

  sfw_feature_init (sm);

  char policy_name[65];
  sfw_api_copy_fixed_string (policy_name, sizeof (policy_name),
			     mp->policy_name, sizeof (mp->policy_name));

  sfw_policy_t *p = sfw_policy_find (sm, policy_name);
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto done;
    }

  u32 rule_index = ntohl (mp->rule_index);
  u8 need_barrier =
    (vlib_num_workers () > 0 && vlib_get_main ()->main_loop_count > 0);
  if (need_barrier)
    vlib_worker_thread_barrier_sync (vm);

  if (mp->is_add)
    {
      sfw_rule_t rule;
      clib_memset (&rule, 0, sizeof (rule));
      rule.action = mp->action;
      rule.af = mp->address_family;
      rule.protocol = mp->protocol;
      rule.src_port_lo = ntohs (mp->src_port_lo);
      rule.src_port_hi = ntohs (mp->src_port_hi);
      rule.dst_port_lo = ntohs (mp->dst_port_lo);
      rule.dst_port_hi = ntohs (mp->dst_port_hi);
      rule.icmp_type = mp->icmp_type;
      rule.icmp_code = mp->icmp_code;

      /* Decode both prefixes into fib_prefix_t, then fan out to
       * ip46_address_t + plen so they fit the sfw_rule_t shape. */
      fib_prefix_t src_fp, dst_fp;
      ip_prefix_decode (&mp->src_prefix, &src_fp);
      ip_prefix_decode (&mp->dst_prefix, &dst_fp);

      if (rule.af == SFW_AF_IP4)
	{
	  rule.src_prefix.ip4 = src_fp.fp_addr.ip4;
	  rule.dst_prefix.ip4 = dst_fp.fp_addr.ip4;
	}
      else if (rule.af == SFW_AF_IP6)
	{
	  rule.src_prefix.ip6 = src_fp.fp_addr.ip6;
	  rule.dst_prefix.ip6 = dst_fp.fp_addr.ip6;
	}
      /* SFW_AF_ANY leaves the prefixes as zero */
      rule.src_plen = src_fp.fp_len;
      rule.dst_plen = dst_fp.fp_len;

      /* Insert at rule_index or append if past current length */
      if (rule_index >= vec_len (p->rules))
	vec_add1 (p->rules, rule);
      else
	{
	  vec_insert (p->rules, 1, rule_index);
	  p->rules[rule_index] = rule;
	}
    }
  else
    {
      if (rule_index < vec_len (p->rules))
	vec_delete (p->rules, 1, rule_index);
      else
	rv = VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  if (need_barrier)
    vlib_worker_thread_barrier_release (vm);

done:
  REPLY_MACRO (VL_API_SFW_POLICY_RULE_ADD_DEL_REPLY);
}

/* --- sfw_nat_pool_add_del --- */

/* Helpers that tear down the per-thread port bookkeeping allocated
 * by dynamic-mode pools. Mirror of the vec_validate layout in the
 * add path. Safe to call on a deterministic-mode pool (vecs are
 * empty). */
static void
sfw_nat_pool_free_internals (sfw_nat_pool_t *pool)
{
  u32 t;
  for (t = 0; t < vec_len (pool->port_bitmaps); t++)
    vec_free (pool->port_bitmaps[t]);
  vec_free (pool->port_bitmaps);
  for (t = 0; t < vec_len (pool->next_port); t++)
    vec_free (pool->next_port[t]);
  vec_free (pool->next_port);
  vec_free (pool->thread_port_start);
  vec_free (pool->thread_port_count);
}

static void
vl_api_sfw_nat_pool_add_del_t_handler (vl_api_sfw_nat_pool_add_del_t *mp)
{
  sfw_main_t *sm = &sfw_main;
  vl_api_sfw_nat_pool_add_del_reply_t *rmp;
  int rv = 0;

  fib_prefix_t ext_fp, int_fp;
  ip_prefix_decode (&mp->external_prefix, &ext_fp);
  ip_prefix_decode (&mp->internal_prefix, &int_fp);

  /* IPv4-only today. */
  if (ext_fp.fp_proto != FIB_PROTOCOL_IP4 || int_fp.fp_proto != FIB_PROTOCOL_IP4)
    {
      rv = VNET_API_ERROR_INVALID_ADDRESS_FAMILY;
      goto done;
    }
  if (ext_fp.fp_len > 32 || int_fp.fp_len > 32)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  ip4_address_t ext_addr = ext_fp.fp_addr.ip4;
  u8 ext_plen = ext_fp.fp_len;
  ip4_address_t int_addr = int_fp.fp_addr.ip4;
  u8 int_plen = int_fp.fp_len;

  if (mp->is_add)
    {
      sfw_nat_pool_t pool;
      clib_memset (&pool, 0, sizeof (pool));
      pool.kind = SFW_POOL_KIND_NAT44;
      pool.external_addr = ext_addr;
      pool.external_plen = ext_plen;
      pool.internal_addr = int_addr;
      pool.internal_plen = int_plen;
      pool.mode = mp->mode;
      pool.port_range_start = 1024;
      pool.port_range_end = 65535;
      pool.n_external_addrs =
	(ext_plen < 32) ? (1u << (32 - ext_plen)) : 1;
      pool.n_internal_addrs =
	(int_plen < 32) ? (1u << (32 - int_plen)) : 1;

      u32 hosts_per_external = pool.n_internal_addrs / pool.n_external_addrs;
      if (hosts_per_external == 0)
	hosts_per_external = 1;
      u32 port_range = pool.port_range_end - pool.port_range_start + 1;
      pool.ports_per_host = (u16) (port_range / hosts_per_external);
      if (pool.ports_per_host == 0)
	pool.ports_per_host = 1;

      if (mp->mode == SFW_NAT_MODE_DYNAMIC)
	{
	  sfw_feature_init (sm);
	  u32 nworkers = vlib_num_workers ();
	  u32 nthreads = nworkers + 1;
	  u32 slice = port_range / nthreads;
	  if (slice == 0)
	    slice = 1;

	  vec_validate (pool.port_bitmaps, nworkers);
	  vec_validate (pool.next_port, nworkers);
	  vec_validate (pool.thread_port_start, nworkers);
	  vec_validate (pool.thread_port_count, nworkers);

	  u32 t;
	  for (t = 0; t < nthreads; t++)
	    {
	      pool.thread_port_start[t] = pool.port_range_start + (t * slice);
	      pool.thread_port_count[t] =
		(t == nthreads - 1) ? (port_range - t * slice) : slice;

	      vec_validate (pool.port_bitmaps[t], pool.n_external_addrs - 1);
	      vec_validate_init_empty (pool.next_port[t],
				       pool.n_external_addrs - 1, 0);
	      u32 a;
	      for (a = 0; a < pool.n_external_addrs; a++)
		pool.port_bitmaps[t][a] = 0;
	    }
	}

      vec_add1 (sm->nat_pools, pool);
    }
  else
    {
      /* Find the pool whose (external_addr/plen, internal_addr/plen)
       * matches exactly and remove it. Delete by walking and
       * splicing rather than by index — callers don't know the
       * internal pool index. */
      u32 i;
      int matched = 0;
      for (i = 0; i < vec_len (sm->nat_pools); i++)
	{
	  sfw_nat_pool_t *p = &sm->nat_pools[i];
	  if (p->external_addr.as_u32 == ext_addr.as_u32 &&
	      p->external_plen == ext_plen &&
	      p->internal_addr.as_u32 == int_addr.as_u32 &&
	      p->internal_plen == int_plen)
	    {
	      sfw_nat_pool_free_internals (p);
	      vec_delete (sm->nat_pools, 1, i);
	      matched = 1;
	      break;
	    }
	}
      if (!matched)
	rv = VNET_API_ERROR_NO_SUCH_ENTRY;
    }

done:
  REPLY_MACRO (VL_API_SFW_NAT_POOL_ADD_DEL_REPLY);
}

/* --- sfw_nat64_pool_add_del --- */

static int
sfw_nat64_api_plen_valid (u8 plen)
{
  return (plen == 32 || plen == 40 || plen == 48 || plen == 56 ||
	  plen == 64 || plen == 96);
}

static void
vl_api_sfw_nat64_pool_add_del_t_handler (
  vl_api_sfw_nat64_pool_add_del_t *mp)
{
  sfw_main_t *sm = &sfw_main;
  vl_api_sfw_nat64_pool_add_del_reply_t *rmp;
  int rv = 0;

  fib_prefix_t ext_fp, v6_fp;
  ip_prefix_decode (&mp->external_prefix, &ext_fp);
  ip_prefix_decode (&mp->nat64_prefix, &v6_fp);

  if (ext_fp.fp_proto != FIB_PROTOCOL_IP4 ||
      v6_fp.fp_proto != FIB_PROTOCOL_IP6)
    {
      rv = VNET_API_ERROR_INVALID_ADDRESS_FAMILY;
      goto done;
    }
  if (ext_fp.fp_len > 32 ||
      !sfw_nat64_api_plen_valid ((u8) v6_fp.fp_len))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  ip4_address_t ext_addr = ext_fp.fp_addr.ip4;
  u8 ext_plen = ext_fp.fp_len;
  ip6_address_t v6_prefix = v6_fp.fp_addr.ip6;
  u8 v6_plen = v6_fp.fp_len;

  if (mp->is_add)
    {
      sfw_nat_pool_t pool;
      clib_memset (&pool, 0, sizeof (pool));
      pool.kind = SFW_POOL_KIND_NAT64;
      pool.external_addr = ext_addr;
      pool.external_plen = ext_plen;
      pool.mode = SFW_NAT_MODE_DYNAMIC;
      ip6_address_copy (&pool.nat64_prefix, &v6_prefix);
      pool.nat64_prefix_len = v6_plen;
      pool.port_range_start = 1024;
      pool.port_range_end = 65535;
      pool.n_external_addrs =
	(ext_plen < 32) ? (1u << (32 - ext_plen)) : 1;

      sfw_feature_init (sm);
      u32 nworkers = vlib_num_workers ();
      u32 nthreads = nworkers + 1;
      u32 port_range = pool.port_range_end - pool.port_range_start + 1;
      u32 slice = port_range / nthreads;
      if (slice == 0)
	slice = 1;

      vec_validate (pool.port_bitmaps, nworkers);
      vec_validate (pool.next_port, nworkers);
      vec_validate (pool.thread_port_start, nworkers);
      vec_validate (pool.thread_port_count, nworkers);

      for (u32 t = 0; t < nthreads; t++)
	{
	  pool.thread_port_start[t] = pool.port_range_start + (t * slice);
	  pool.thread_port_count[t] =
	    (t == nthreads - 1) ? (port_range - t * slice) : slice;
	  vec_validate (pool.port_bitmaps[t], pool.n_external_addrs - 1);
	  vec_validate_init_empty (pool.next_port[t],
				   pool.n_external_addrs - 1, 0);
	  for (u32 a = 0; a < pool.n_external_addrs; a++)
	    pool.port_bitmaps[t][a] = 0;
	}

      vec_add1 (sm->nat_pools, pool);
    }
  else
    {
      u32 i;
      int matched = 0;
      for (i = 0; i < vec_len (sm->nat_pools); i++)
	{
	  sfw_nat_pool_t *p = &sm->nat_pools[i];
	  if (p->kind != SFW_POOL_KIND_NAT64)
	    continue;
	  if (p->external_addr.as_u32 == ext_addr.as_u32 &&
	      p->external_plen == ext_plen && p->nat64_prefix_len == v6_plen &&
	      clib_memcmp (&p->nat64_prefix, &v6_prefix,
			   sizeof (ip6_address_t)) == 0)
	    {
	      sfw_nat_pool_free_internals (p);
	      vec_delete (sm->nat_pools, 1, i);
	      matched = 1;
	      break;
	    }
	}
      if (!matched)
	rv = VNET_API_ERROR_NO_SUCH_ENTRY;
    }

done:
  REPLY_MACRO (VL_API_SFW_NAT64_POOL_ADD_DEL_REPLY);
}

/* --- sfw_nat_static_add_del --- */

static void
vl_api_sfw_nat_static_add_del_t_handler (
  vl_api_sfw_nat_static_add_del_t *mp)
{
  sfw_main_t *sm = &sfw_main;
  vl_api_sfw_nat_static_add_del_reply_t *rmp;
  int rv = 0;

  ip46_address_t ext46, int46;
  ip46_type_t ext_type = ip_address_decode (&mp->external_address, &ext46);
  ip46_type_t int_type = ip_address_decode (&mp->internal_address, &int46);

  if (ext_type != IP46_TYPE_IP4 || int_type != IP46_TYPE_IP4)
    {
      rv = VNET_API_ERROR_INVALID_ADDRESS_FAMILY;
      goto done;
    }

  ip4_address_t ext_addr = ext46.ip4;
  ip4_address_t int_addr = int46.ip4;
  u16 ext_port = ntohs (mp->external_port);
  u16 int_port = ntohs (mp->internal_port);

  if (mp->is_add)
    {
      sfw_nat_static_t mapping;
      clib_memset (&mapping, 0, sizeof (mapping));
      mapping.external_addr = ext_addr;
      mapping.external_port = ext_port;
      mapping.internal_addr = int_addr;
      mapping.internal_port = int_port;
      mapping.protocol = mp->protocol;
      vec_add1 (sm->nat_statics, mapping);
    }
  else
    {
      u32 i;
      int matched = 0;
      for (i = 0; i < vec_len (sm->nat_statics); i++)
	{
	  sfw_nat_static_t *s = &sm->nat_statics[i];
	  if (s->external_addr.as_u32 == ext_addr.as_u32 &&
	      s->protocol == mp->protocol &&
	      s->external_port == ext_port)
	    {
	      vec_delete (sm->nat_statics, 1, i);
	      matched = 1;
	      break;
	    }
	}
      if (!matched)
	rv = VNET_API_ERROR_NO_SUCH_ENTRY;
    }

done:
  REPLY_MACRO (VL_API_SFW_NAT_STATIC_ADD_DEL_REPLY);
}

/* Pull in the generated setup_message_id_table + handler array. */
#include <sfw/sfw.api.c>

clib_error_t *
sfw_plugin_api_hookup (vlib_main_t *vm)
{
  sfw_main_t *sm = &sfw_main;
  sm->msg_id_base = setup_message_id_table ();
  return 0;
}
