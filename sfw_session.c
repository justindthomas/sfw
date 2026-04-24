/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 */

/* sfw_session.c - session create/delete/lookup/timeout helpers */

#include <sfw/sfw.h>
#include <vlib/vlib.h>
#include <vlib/threads.h>

sfw_session_t *
sfw_session_create (sfw_main_t *sm, u32 thread_index, f64 now)
{
  sfw_session_t *s;

  /* If at capacity, evict the LRU tail.  Use deferred free so other
   * threads holding a stale reference don't hit a freed slot. */
  if (pool_elts (sm->sessions[thread_index]) >= sm->max_sessions_per_worker)
    {
      u32 tail = sm->lru_tail[thread_index];
      if (tail == ~0)
	return 0;

      sfw_session_t *victim =
	pool_elt_at_index (sm->sessions[thread_index], tail);
      sfw_session_unhash (sm, victim);
      sfw_lru_remove (sm, victim);
      vec_add1 (sm->pending_free[thread_index], tail);
    }

  pool_get (sm->sessions[thread_index], s);
  clib_memset (s, 0, sizeof (*s));
  s->thread_index = thread_index;
  s->lru_next = ~0;
  s->lru_prev = ~0;
  sfw_lru_add_head (sm, s, now);
  return s;
}

/* Insert a session's hash entries (primary + secondary).  Returns 0
 * on success.  On failure, any partially inserted key is removed and
 * the session is freed back to the pool. */
int
sfw_session_insert_hash (sfw_main_t *sm, sfw_session_t *s, u64 enc,
			 clib_bihash_kv_48_8_t *kv1,
			 clib_bihash_kv_48_8_t *kv2)
{
  if (clib_bihash_add_del_48_8 (&sm->session_hash, kv1, 1) != 0)
    {
      sfw_lru_remove (sm, s);
      pool_put (sm->sessions[s->thread_index], s);
      return -1;
    }

  if (clib_bihash_add_del_48_8 (&sm->session_hash, kv2, 1) != 0)
    {
      /* Roll back the first insertion */
      clib_bihash_add_del_48_8 (&sm->session_hash, kv1, 0);
      sfw_lru_remove (sm, s);
      pool_put (sm->sessions[s->thread_index], s);
      return -1;
    }

  return 0;
}

/* Remove a session from the bihash (both entries) but do NOT touch
 * the LRU or free the pool slot.  The caller is responsible for
 * LRU removal and deferring pool_put. */
void
sfw_session_unhash (sfw_main_t *sm, sfw_session_t *s)
{
  /* Remove primary hash entry (stored key) */
  clib_bihash_kv_48_8_t kv;
  int rv;
  clib_memset (&kv, 0, sizeof (kv));
  if (s->is_ip6)
    clib_memcpy_fast (&kv.key, &s->k6, sizeof (sfw_key6_t));
  else
    clib_memcpy_fast (&kv.key, &s->k4, sizeof (sfw_key4_t));
  rv = clib_bihash_add_del_48_8 (&sm->session_hash, &kv, 0 /* is_add */);
  if (PREDICT_FALSE (rv != 0))
    clib_warning ("sfw: primary hash delete failed (rv=%d)", rv);

  /* Remove secondary hash entry if present */
  if (s->has_nat_key && s->nat_type == SFW_NAT_NONE)
    {
      clib_memset (&kv, 0, sizeof (kv));
      if (s->is_ip6)
	{
	  sfw_key6_t *dk = (sfw_key6_t *) &kv.key;
	  ip6_address_copy (&dk->src, &s->k6.dst);
	  ip6_address_copy (&dk->dst, &s->k6.src);
	  dk->src_port = s->k6.dst_port;
	  dk->dst_port = s->k6.src_port;
	  dk->protocol = s->k6.protocol;
	}
      else
	{
	  sfw_key4_t *dk = (sfw_key4_t *) &kv.key;
	  dk->src = s->k4.dst;
	  dk->dst = s->k4.src;
	  dk->src_port = s->k4.dst_port;
	  dk->dst_port = s->k4.src_port;
	  dk->protocol = s->k4.protocol;
	}
      rv = clib_bihash_add_del_48_8 (&sm->session_hash, &kv, 0 /* is_add */);
      if (PREDICT_FALSE (rv != 0))
	clib_warning ("sfw: secondary hash delete failed (rv=%d)", rv);
    }
  else if (s->has_nat_key && s->nat_type == SFW_NAT_SNAT)
    {
      clib_memset (&kv, 0, sizeof (kv));
      sfw_key4_t *nk = (sfw_key4_t *) &kv.key;
      nk->src = s->k4.src;
      nk->dst = s->xlate.v4.nat_addr;
      nk->src_port = s->k4.src_port;
      nk->dst_port = s->xlate.v4.nat_port;
      nk->protocol = s->k4.protocol;
      rv = clib_bihash_add_del_48_8 (&sm->session_hash, &kv, 0 /* is_add */);
      if (PREDICT_FALSE (rv != 0))
	clib_warning ("sfw: NAT hash delete failed (rv=%d)", rv);
    }
  else if (s->has_nat_key && s->nat_type == SFW_NAT_DNAT)
    {
      clib_memset (&kv, 0, sizeof (kv));
      sfw_key4_t *nk = (sfw_key4_t *) &kv.key;
      nk->src = s->xlate.v4.nat_addr;
      nk->dst = s->k4.dst;
      nk->src_port = s->xlate.v4.nat_port;
      nk->dst_port = s->k4.dst_port;
      nk->protocol = s->k4.protocol;
      rv = clib_bihash_add_del_48_8 (&sm->session_hash, &kv, 0 /* is_add */);
      if (PREDICT_FALSE (rv != 0))
	clib_warning ("sfw: DNAT hash delete failed (rv=%d)", rv);
    }
  else if (s->has_nat_key && s->nat_type == SFW_NAT_NAT64)
    {
      /* v4 return key. Return direction: src = v4_server,
       * dst = v4_pool. For TCP/UDP, src_port is the v4 dport
       * (= k6.src_port after the ingress reversal) and dst_port
       * is the allocated v4 pool port. For ICMP the on-wire id
       * equals v4_pool_port in both directions (we rewrote it in
       * the forward translation; remote echoes it back), so both
       * key port fields are v4_pool_port to match sfw_extract_l4
       * on return. */
      clib_memset (&kv, 0, sizeof (kv));
      sfw_key4_t *nk = (sfw_key4_t *) &kv.key;
      nk->src = s->xlate.n64.v4_server;
      nk->dst = s->xlate.n64.v4_pool;
      if (s->k6.protocol == IP_PROTOCOL_ICMP6)
	{
	  nk->src_port = s->xlate.n64.v4_pool_port;
	  nk->dst_port = s->xlate.n64.v4_pool_port;
	  nk->protocol = IP_PROTOCOL_ICMP;
	}
      else
	{
	  nk->src_port = s->k6.src_port;
	  nk->dst_port = s->xlate.n64.v4_pool_port;
	  nk->protocol = s->k6.protocol;
	}
      rv = clib_bihash_add_del_48_8 (&sm->session_hash, &kv, 0 /* is_add */);
      if (PREDICT_FALSE (rv != 0))
	clib_warning ("sfw: NAT64 v4-return hash delete failed (rv=%d)", rv);
    }

  /* Free the allocated port back to the bitmap for dynamic SNAT sessions */
  if (s->nat_type == SFW_NAT_SNAT)
    {
      u16 port_h = clib_net_to_host_u16 (s->xlate.v4.nat_port);
      u32 i;
      for (i = 0; i < vec_len (sm->nat_pools); i++)
	{
	  sfw_nat_pool_t *pool = &sm->nat_pools[i];
	  if (pool->kind != SFW_POOL_KIND_NAT44)
	    continue;
	  if (pool->mode != SFW_NAT_MODE_DYNAMIC || !pool->port_bitmaps)
	    continue;
	  /* Check if the NAT address belongs to this pool */
	  if (pool->n_external_addrs == 1 &&
	      pool->external_addr.as_u32 == s->xlate.v4.nat_addr.as_u32)
	    {
	      sfw_nat_free_port (pool, s->thread_index, 0, port_h);
	      break;
	    }
	  else if (pool->n_external_addrs > 1)
	    {
	      u32 ext_idx = sfw_ip4_addr_index (&s->xlate.v4.nat_addr,
						 &pool->external_addr,
						 pool->external_plen);
	      if (ext_idx < pool->n_external_addrs)
		{
		  sfw_nat_free_port (pool, s->thread_index, ext_idx, port_h);
		  break;
		}
	    }
	}
    }
  /* Free the allocated v4 pool port for NAT64 sessions. pool_idx is
   * stored directly on the session, so no scan needed. */
  else if (s->nat_type == SFW_NAT_NAT64)
    {
      if (s->xlate.n64.pool_idx < vec_len (sm->nat_pools))
	{
	  sfw_nat_pool_t *pool = &sm->nat_pools[s->xlate.n64.pool_idx];
	  if (pool->kind == SFW_POOL_KIND_NAT64 && pool->port_bitmaps)
	    {
	      u32 ext_idx = sfw_ip4_addr_index (&s->xlate.n64.v4_pool,
						 &pool->external_addr,
						 pool->external_plen);
	      if (ext_idx < pool->n_external_addrs)
		{
		  u16 port_h =
		    clib_net_to_host_u16 (s->xlate.n64.v4_pool_port);
		  sfw_nat_free_port (pool, s->thread_index, ext_idx, port_h);
		}
	    }
	}
    }
}

/* Remove a session completely: unhash, unlink from LRU, free pool slot.
 * Only safe when no other thread can be referencing the session
 * (e.g., from the CLI "clear sfw sessions" command). */
void
sfw_session_remove (sfw_main_t *sm, sfw_session_t *s)
{
  sfw_session_unhash (sm, s);
  sfw_lru_remove (sm, s);
  pool_put (sm->sessions[s->thread_index], s);
}

u8 *
format_sfw_session (u8 *s, va_list *args)
{
  sfw_session_t *sess = va_arg (*args, sfw_session_t *);
  f64 now = va_arg (*args, f64);
  int verbose = va_arg (*args, int);

  /* Display in original connection direction (reverse the stored key) */
  if (sess->is_ip6)
    {
      s = format (s, "  [ip6] %U:%u -> %U:%u proto %u", format_ip6_address,
		  &sess->k6.dst, clib_net_to_host_u16 (sess->k6.dst_port),
		  format_ip6_address, &sess->k6.src,
		  clib_net_to_host_u16 (sess->k6.src_port), sess->k6.protocol);
    }
  else
    {
      s = format (s, "  [ip4] %U:%u -> %U:%u proto %u", format_ip4_address,
		  &sess->k4.dst, clib_net_to_host_u16 (sess->k4.dst_port),
		  format_ip4_address, &sess->k4.src,
		  clib_net_to_host_u16 (sess->k4.src_port), sess->k4.protocol);
    }

  /* NAT translation info */
  if (sess->nat_type == SFW_NAT_SNAT)
    {
      s = format (s, " SNAT->%U:%u", format_ip4_address, &sess->xlate.v4.nat_addr,
		  clib_net_to_host_u16 (sess->xlate.v4.nat_port));
    }
  else if (sess->nat_type == SFW_NAT_DNAT)
    {
      s = format (s, " DNAT %U:%u->%U:%u", format_ip4_address,
		  &sess->xlate.v4.nat_addr, clib_net_to_host_u16 (sess->xlate.v4.nat_port),
		  format_ip4_address, &sess->xlate.v4.orig_addr,
		  clib_net_to_host_u16 (sess->xlate.v4.orig_port));
    }
  else if (sess->nat_type == SFW_NAT_NAT64)
    {
      /* Show the v4 side of the mapping: our SNAT'd pool src -> v4 server
       * at the v4 dport (stored on the reversed k6 as src_port). Makes
       * the v6<->v4 correspondence obvious at a glance. */
      s = format (s, " NAT64 v4 %U:%u->%U:%u (pool %u)", format_ip4_address,
		  &sess->xlate.n64.v4_pool,
		  clib_net_to_host_u16 (sess->xlate.n64.v4_pool_port),
		  format_ip4_address, &sess->xlate.n64.v4_server,
		  clib_net_to_host_u16 (sess->k6.src_port),
		  sess->xlate.n64.pool_idx);
    }

  if (verbose)
    {
      sfw_main_t *sm = &sfw_main;
      f64 remaining = sess->expires - now;
      s = format (s, " ttl %.1fs thread %u", remaining, sess->thread_index);

      /* Verify session is findable in bihash */
      clib_bihash_kv_48_8_t kv;
      clib_memset (&kv, 0, sizeof (kv));
      if (sess->is_ip6)
	clib_memcpy_fast (&kv.key, &sess->k6, sizeof (sfw_key6_t));
      else
	clib_memcpy_fast (&kv.key, &sess->k4, sizeof (sfw_key4_t));
      if (clib_bihash_search_48_8 (&sm->session_hash, &kv, &kv) == 0)
	s = format (s, " hash:OK");
      else
	s = format (s, " hash:FAIL");
    }

  s = format (s, "\n");
  return s;
}

/* --- Periodic session expiry process ---
 *
 * sfw_expire_inline is called per-frame from each worker's sfw_ip4/ip6
 * nodes and walks the LRU from tail until it hits a non-expired
 * session. That is fast and correct for same-thread flows — every
 * packet match on the owner thread calls sfw_lru_touch, which moves
 * the session to LRU head, so LRU-tail is truly the oldest.
 *
 * It is *wrong* for cross-thread refresh: when a reverse-direction
 * packet hashes to a different worker, sfw_node.c bumps
 * session->expires but cannot call sfw_lru_touch (the LRU is
 * per-thread and touching another thread's LRU isn't safe). The
 * session stays at its old LRU position with a fresh expires, and
 * the owner's per-frame LRU walk breaks on it — stranding every
 * genuinely-expired session behind it. Observed on Mellanox AF_XDP
 * where reverse-path RSS routinely lands return traffic on a
 * different worker than the session's owner.
 *
 * The backstop: wake every SFW_EXPIRE_INTERVAL seconds on the main
 * thread, take the worker barrier, and scan each per-worker pool in
 * full (pool_foreach, not LRU-follow) so cross-thread-refreshed
 * sessions that eventually expire don't strand everything behind
 * them. The per-frame LRU walk remains the hot-path optimization;
 * this is the correctness backstop.
 *
 * Barrier hold time is O(sessions across all workers). Home-router
 * volumes (hundreds of sessions) are microseconds; larger deployments
 * can raise SFW_EXPIRE_INTERVAL to amortize.
 */

#define SFW_EXPIRE_INTERVAL 5.0

/* Full-pool expiry sweep for one thread's session pool. Same two-phase
 * defer pattern as sfw_expire_inline so it interleaves cleanly with the
 * per-frame path: phase 1 pool_put's whatever was queued last cycle,
 * phase 2 unhashes every session whose expires is in the past and
 * queues it for next cycle. Must run under the worker barrier.
 */
static void
sfw_expire_full_sweep (sfw_main_t *sm, u32 thread_index, f64 now)
{
  /* Phase 1: drain previous cycle's pending_free. Either this sweep
   * or the per-frame path could have populated it — both share the
   * same vector. */
  u32 *pf = sm->pending_free[thread_index];
  for (u32 j = 0; j < vec_len (pf); j++)
    pool_put_index (sm->sessions[thread_index], pf[j]);
  vec_reset_length (pf);

  /* Phase 1a: honour a pending `clear sfw session` request. Mirrors
   * the inline path; owner-thread-only writers to these per-thread
   * structures are still the only writers here because the barrier
   * is held. */
  if (PREDICT_FALSE (sm->clear_requested[thread_index]))
    {
      sm->clear_requested[thread_index] = 0;
      sfw_session_t *s;
      u32 *indices = 0;
      pool_foreach (s, sm->sessions[thread_index])
	{
	  vec_add1 (indices, s - sm->sessions[thread_index]);
	}
      for (u32 j = 0; j < vec_len (indices); j++)
	{
	  s = pool_elt_at_index (sm->sessions[thread_index], indices[j]);
	  sfw_session_unhash (sm, s);
	  sfw_lru_remove (sm, s);
	  pool_put (sm->sessions[thread_index], s);
	}
      vec_free (indices);
      sm->pending_free[thread_index] = pf;
      return;
    }

  /* Phase 2: walk the pool, not the LRU. Catch every expired session
   * regardless of LRU position. */
  sfw_session_t *s;
  pool_foreach (s, sm->sessions[thread_index])
    {
      if (s->expires < now)
	{
	  u32 si = s - sm->sessions[thread_index];
	  sfw_session_unhash (sm, s);
	  sfw_lru_remove (sm, s);
	  vec_add1 (pf, si);
	}
    }
  sm->pending_free[thread_index] = pf;
}

static uword
sfw_expire_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
		    vlib_frame_t *f)
{
  sfw_main_t *sm = &sfw_main;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, SFW_EXPIRE_INTERVAL);
      /* Drain any posted events — we don't use them today, we only
       * care about the periodic wake-up. */
      vlib_process_get_events (vm, 0);

      if (!sm->initialized)
	continue;

      f64 now = vlib_time_now (vm);
      u32 n_slots = vec_len (sm->sessions);
      if (n_slots == 0)
	continue;

      vlib_worker_thread_barrier_sync (vm);
      /* sm->sessions is vec_validate'd to `nworkers` in sfw_feature_init,
       * giving slots [0 .. nworkers] (main + each worker). Iterate all
       * slots so we cover workers whose packet path has gone idle. */
      for (u32 ti = 0; ti < n_slots; ti++)
	sfw_expire_full_sweep (sm, ti, now);
      vlib_worker_thread_barrier_release (vm);
    }
  return 0;
}

VLIB_REGISTER_NODE (sfw_expire_process_node) = {
  .function = sfw_expire_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "sfw-expire-process",
};
