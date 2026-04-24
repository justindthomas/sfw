/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 */

/* sfw_node.c - sfw-ip4 and sfw-ip6 packet processing nodes */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vppinfra/error.h>
#include <sfw/sfw.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/adj/adj.h>
#include <vnet/dpo/receive_dpo.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u8 action;
  u8 session_found;
  u8 protocol;
  u8 nat_applied;
  u8 nat64_dir; /* 0=none, 1=v6->v4, 2=v4->v6 */
} sfw_trace_t;

#ifndef CLIB_MARCH_VARIANT

static u8 *
format_sfw_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sfw_trace_t *t = va_arg (*args, sfw_trace_t *);

  s = format (
    s,
    "SFW: sw_if %u next %u action %u sess %u proto %u nat %u nat64 %u\n",
    t->sw_if_index, t->next_index, t->action, t->session_found, t->protocol,
    t->nat_applied, t->nat64_dir);
  return s;
}

vlib_node_registration_t sfw_ip4_node;
vlib_node_registration_t sfw_ip6_node;
vlib_node_registration_t sfw_ip4_output_node;
vlib_node_registration_t sfw_ip6_output_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_sfw_error                                                     \
  _ (PROCESSED, "sfw packets processed")                                      \
  _ (SESSIONS_CREATED, "sfw sessions created")                                \
  _ (SESSION_HITS, "sfw session hits")                                        \
  _ (DENIED, "sfw packets denied")                                            \
  _ (PERMITTED, "sfw packets permitted (stateless)")                          \
  _ (NAT_TRANSLATED, "sfw NAT translations")                                 \
  _ (NAT_EXHAUSTED, "sfw NAT port exhaustion drops")                          \
  _ (LOCAL_ORIGINATED, "sfw locally-originated flows (ip*-output)")           \
  _ (NAT64_V6_TO_V4, "sfw NAT64 v6->v4 translations")                         \
  _ (NAT64_V4_TO_V6, "sfw NAT64 v4->v6 translations")                         \
  _ (NAT64_UNKNOWN_PREFIX, "sfw NAT64 dst not in any configured prefix")      \
  _ (NAT64_HEADROOM, "sfw NAT64 buffer headroom exhausted (v4->v6)")          \
  _ (NAT64_ICMP_UNSUPPORTED, "sfw NAT64 untranslatable ICMP drop")

typedef enum
{
#define _(sym, str) SFW_ERROR_##sym,
  foreach_sfw_error
#undef _
    SFW_N_ERROR,
} sfw_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *sfw_error_strings[] = {
#define _(sym, string) string,
  foreach_sfw_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  SFW_NEXT_DROP,
  SFW_NEXT_LOOKUP_V4, /* for NAT64 v4->v6 return hand-off (sfw-ip4) and
			v6->v4 ingress hand-off (sfw-ip6 after translate) */
  SFW_NEXT_LOOKUP_V6, /* symmetric */
  SFW_N_NEXT,
} sfw_next_t;

/* Check implicit ICMPv6 types */
static inline int
sfw_is_implicit_icmpv6 (u8 type)
{
  switch (type)
    {
    case 1:   /* destination unreachable */
    case 2:   /* packet too big (PMTUD) */
    case 3:   /* time exceeded */
    case 128: /* echo request */
    case 129: /* echo reply */
    case 133: /* router solicitation */
    case 134: /* router advertisement */
    case 135: /* neighbor solicitation */
    case 136: /* neighbor advertisement */
      return 1;
    default:
      return 0;
    }
}

/* Extract L4 key fields. Ports are in network byte order. */
static inline void
sfw_extract_l4 (u8 protocol, void *l4_hdr, u16 *src_port, u16 *dst_port,
		u8 *icmp_type, u8 *icmp_code)
{
  *src_port = 0;
  *dst_port = 0;
  *icmp_type = 0;
  *icmp_code = 0;

  switch (protocol)
    {
    case IP_PROTOCOL_TCP:
    case IP_PROTOCOL_UDP:
      {
	udp_header_t *udp = (udp_header_t *) l4_hdr;
	*src_port = udp->src_port;
	*dst_port = udp->dst_port;
      }
      break;

    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMP6:
      {
	u8 *icmp = (u8 *) l4_hdr;
	*icmp_type = icmp[0];
	*icmp_code = icmp[1];
	u8 t = icmp[0];
	if (t == 0 || t == 8 || t == 128 || t == 129)
	  {
	    u16 id;
	    clib_memcpy_fast (&id, icmp + 4, sizeof (id));
	    *src_port = id;
	    *dst_port = id;
	  }
      }
      break;

    case IP_PROTOCOL_IPSEC_ESP:
      {
	/* ESP has a 32-bit SPI instead of ports.  Split across both
	 * port fields to preserve the full value in the session key. */
	u32 spi;
	clib_memcpy_fast (&spi, l4_hdr, sizeof (spi));
	spi = clib_net_to_host_u32 (spi);
	*src_port = clib_host_to_net_u16 ((u16) (spi >> 16));
	*dst_port = clib_host_to_net_u16 ((u16) (spi & 0xFFFF));
      }
      break;

    default:
      break;
    }
}

/* Resolve the destination zone via FIB lookup (IPv4).
 * Returns the zone_id of the TX interface, or SFW_ZONE_NONE. */
static inline u32
sfw_resolve_dst_zone4 (sfw_main_t *sm, u32 sw_if_index,
		       ip4_address_t *dst_addr)
{
  u32 fib_index =
    vec_elt (ip4_main.fib_index_by_sw_if_index, sw_if_index);
  index_t lbi = ip4_fib_forwarding_lookup (fib_index, dst_addr);
  const load_balance_t *lb = load_balance_get (lbi);
  const dpo_id_t *dpo = load_balance_get_bucket_i (lb, 0);

  if (dpo->dpoi_type == DPO_ADJACENCY ||
      dpo->dpoi_type == DPO_ADJACENCY_INCOMPLETE ||
      dpo->dpoi_type == DPO_ADJACENCY_MIDCHAIN)
    {
      u32 tx_sw = adj_get_sw_if_index (dpo->dpoi_index);
      if (tx_sw < vec_len (sm->if_config))
	return sm->if_config[tx_sw].zone_id;
    }
  else if (dpo->dpoi_type == DPO_RECEIVE)
    {
      /* Traffic destined for one of the router's own addresses.
       * Map to the built-in "local" zone so operators can write
       * cross-zone policies (e.g., external->local) that gate
       * traffic terminated on the router itself. */
      return SFW_ZONE_LOCAL;
    }

  return SFW_ZONE_NONE;
}

/* Resolve the destination zone via FIB lookup (IPv6).
 * Returns the zone_id of the TX interface, or SFW_ZONE_NONE. */
static inline u32
sfw_resolve_dst_zone6 (sfw_main_t *sm, u32 sw_if_index,
		       ip6_address_t *dst_addr)
{
  u32 fib_index =
    vec_elt (ip6_main.fib_index_by_sw_if_index, sw_if_index);
  index_t lbi = ip6_fib_table_fwding_lookup (fib_index, dst_addr);
  const load_balance_t *lb = load_balance_get (lbi);
  const dpo_id_t *dpo = load_balance_get_bucket_i (lb, 0);

  if (dpo->dpoi_type == DPO_ADJACENCY ||
      dpo->dpoi_type == DPO_ADJACENCY_INCOMPLETE ||
      dpo->dpoi_type == DPO_ADJACENCY_MIDCHAIN)
    {
      u32 tx_sw = adj_get_sw_if_index (dpo->dpoi_index);
      if (tx_sw < vec_len (sm->if_config))
	return sm->if_config[tx_sw].zone_id;
    }
  else if (dpo->dpoi_type == DPO_RECEIVE)
    {
      /* Traffic destined for one of the router's own addresses — map
       * to the built-in "local" zone.  See sfw_resolve_dst_zone4. */
      return SFW_ZONE_LOCAL;
    }

  return SFW_ZONE_NONE;
}

/* Look up the zone-pair policy. Returns NULL if no policy. */
static inline sfw_policy_t *
sfw_zone_pair_policy (sfw_main_t *sm, u32 src_zone, u32 dst_zone)
{
  u32 idx = src_zone * SFW_MAX_ZONES + dst_zone;
  return sm->zone_pairs[idx].policy;
}

/* True if the given src address is configured on this router — used on
 * the ip4-output feature arc to detect locally-originated traffic (VPP
 * self-generated ICMP, VCL apps, host-stack daemons). */
static inline int
sfw_is_local_src4 (u32 sw_if_index, ip4_address_t *src_addr)
{
  if (sw_if_index >= vec_len (ip4_main.fib_index_by_sw_if_index))
    return 0;
  u32 fib_index = vec_elt (ip4_main.fib_index_by_sw_if_index, sw_if_index);
  index_t lbi = ip4_fib_forwarding_lookup (fib_index, src_addr);
  const load_balance_t *lb = load_balance_get (lbi);
  const dpo_id_t *dpo = load_balance_get_bucket_i (lb, 0);
  return dpo->dpoi_type == DPO_RECEIVE;
}

static inline int
sfw_is_local_src6 (u32 sw_if_index, ip6_address_t *src_addr)
{
  if (sw_if_index >= vec_len (ip6_main.fib_index_by_sw_if_index))
    return 0;
  u32 fib_index = vec_elt (ip6_main.fib_index_by_sw_if_index, sw_if_index);
  index_t lbi = ip6_fib_table_fwding_lookup (fib_index, src_addr);
  const load_balance_t *lb = load_balance_get (lbi);
  const dpo_id_t *dpo = load_balance_get_bucket_i (lb, 0);
  return dpo->dpoi_type == DPO_RECEIVE;
}

/* --- IPv4 node (two-pass design) ---
 *
 * Pass 1 (search + classify): Extract fields, do FIB lookup for destination
 *   zone, find zone-pair policy, search bihash, evaluate rules.
 *   No bihash adds — avoids interleaving adds and searches.
 *
 * Pass 2 (session creation): Create sessions and add to bihash for packets
 *   that need new sessions. Apply NAT translations.
 */

/* Per-packet metadata bridging pass 1 and pass 2 */
typedef struct
{
  sfw_session_t *session;  /* found session, or NULL */
  sfw_policy_t *policy;	   /* zone-pair policy */
  ip4_address_t nat_addr;  /* computed NAT address */
  u16 nat_port;		   /* computed NAT port */
  u16 src_port;		   /* extracted L4 source port */
  u16 dst_port;		   /* extracted L4 destination port */
  u8 action;		   /* resolved action */
  u8 protocol;		   /* IP protocol */
  u8 is_from_zone;	   /* 1 if RX is from_zone (outbound), 0 if to_zone
			      (inbound) */
  u8 icmp_type;
  u8 icmp_code;
  u8 nat_computed; /* 0=none, 1=SNAT, 2=DNAT */
  u8 nat_mode;	   /* sfw_nat_mode_t — set during pass 1 NAT translation */
  u32 nat_alloc_idx; /* sm->v4_port_allocs index selected for SNAT;
			  stamped on the session so sfw_session_unhash
			  can free the allocated port. */
  u8 nat64_return; /* 1 if matched session has nat_type == SFW_NAT_NAT64
		      and needs v4->v6 rewrite in pass 2 */
} sfw_pkt_meta_t;

always_inline uword
sfw_ip4_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_frame_t *frame, int is_trace)
{
  u32 *from, n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];
  sfw_main_t *sm = &sfw_main;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  u32 created = 0, hits = 0, denied = 0, permitted = 0, nat_translated = 0,
      nat_exhausted = 0;
  sfw_pkt_meta_t meta[VLIB_FRAME_SIZE];
  u32 i;

  from = vlib_frame_vector_args (frame);
  n_vectors = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_vectors);

  /* Initialize nexts to feature-next for all packets */
  for (i = 0; i < n_vectors; i++)
    {
      u32 next0;
      vnet_feature_next (&next0, bufs[i]);
      nexts[i] = next0;
    }

  /* ================================================================
   * PASS 1: Search bihash + classify. NO bihash adds in this pass.
   * ================================================================ */
  for (i = 0; i < n_vectors; i++)
    {
      sfw_pkt_meta_t *m = &meta[i];
      clib_memset (m, 0, sizeof (*m));
      m->action = SFW_ACTION_PERMIT;

      ip4_header_t *ip0 = vlib_buffer_get_current (bufs[i]);
      u32 sw_if_index0 = vnet_buffer (bufs[i])->sw_if_index[VLIB_RX];

      /* Skip broadcast/multicast/unspecified */
      u32 dst_h = clib_net_to_host_u32 (ip0->dst_address.as_u32);
      u32 src_h = clib_net_to_host_u32 (ip0->src_address.as_u32);
      if (PREDICT_FALSE (dst_h == 0xFFFFFFFF || src_h == 0 ||
			 (dst_h >> 28) == 0xE))
	{
	  permitted++;
	  continue;
	}

      m->protocol = ip0->protocol;

      /* Validate both IP length and buffer coverage before L4 access.
       * Use actual IHL (not fixed 20) to account for IP options.
       * Check that the vlib_buffer actually contains the claimed bytes. */
      u16 ip_len = clib_net_to_host_u16 (ip0->length);
      u16 ihl = (ip0->ip_version_and_header_length & 0x0F) << 2;
      u16 buf_len = vlib_buffer_length_in_chain (vm, bufs[i]);
      if (PREDICT_FALSE (ihl < sizeof (ip4_header_t) ||
			 ip_len < ihl + 4 || buf_len < ihl + 4))
	{
	  permitted++;
	  continue;
	}

      void *l4_hdr = ip4_next_header (ip0);
      sfw_extract_l4 (m->protocol, l4_hdr, &m->src_port, &m->dst_port,
		      &m->icmp_type, &m->icmp_code);

      /* --- Session lookup (before zone/policy resolution) ---
       *
       * Search bihash with both key directions. If an existing session
       * is found, permit and apply NAT — no zone or policy work needed.
       * This handles return traffic uniformly, including traffic to the
       * router's own NATted addresses (same-zone, no policy). */
      clib_bihash_kv_48_8_t kv = { 0 }, result = { 0 };
      sfw_key4_t *key;
      u8 found_session = 0;
      u8 is_from_zone = 1;

      /* Try reverse-key (outbound direction) */
      key = (sfw_key4_t *) &kv.key;
      key->src = ip0->dst_address;
      key->dst = ip0->src_address;
      key->src_port = m->dst_port;
      key->dst_port = m->src_port;
      key->protocol = m->protocol;

      if (clib_bihash_search_48_8 (&sm->session_hash, &kv, &result) == 0)
	{
	  found_session = 1;
	  is_from_zone = 1;
	}
      else
	{
	  /* Try direct-key (inbound/return direction) */
	  clib_memset (&kv, 0, sizeof (kv));
	  key = (sfw_key4_t *) &kv.key;
	  key->src = ip0->src_address;
	  key->dst = ip0->dst_address;
	  key->src_port = m->src_port;
	  key->dst_port = m->dst_port;
	  key->protocol = m->protocol;

	  if (clib_bihash_search_48_8 (&sm->session_hash, &kv, &result) == 0)
	    {
	      found_session = 1;
	      is_from_zone = 0;
	    }
	}

      if (found_session)
	{
	  u32 st = sfw_session_thread (result.value);
	  u32 si = sfw_session_index (result.value);
	  m->session = pool_elt_at_index (sm->sessions[st], si);

	  /* Don't reset timeout for sessions in TCP close/reset state */
	  if (PREDICT_TRUE (!m->session->tcp_rst &&
			    !(m->session->tcp_fin_fwd &&
			      m->session->tcp_fin_rev)))
	    {
	      if (st == thread_index)
		sfw_lru_touch (sm, m->session, now);
	      else
		m->session->expires = now + sm->session_timeout;
	    }

	  hits++;
	  m->action = SFW_ACTION_PERMIT;
	  m->is_from_zone = is_from_zone;

	  /* Apply NAT for existing sessions. xlate.v4 fields hold the
	   * v4 NAT addresses/ports for SNAT/DNAT sessions.
	   * from_zone traffic: rewrite source (SNAT direction).
	   * to_zone traffic:   rewrite destination (reverse-DNAT).
	   * NAT64 sessions are a special case: the matched session is
	   * a v4 return direction hit; we defer the v4->v6 rewrite to
	   * Pass 2 so both passes stay free of bihash / buffer-header
	   * interleaving. */
	  if (m->session->nat_type == SFW_NAT_SNAT ||
	      m->session->nat_type == SFW_NAT_DNAT)
	    {
	      if (is_from_zone)
		sfw_nat_apply_snat (ip0, l4_hdr, m->protocol,
				    &m->session->xlate.v4.nat_addr,
				    m->session->xlate.v4.nat_port);
	      else
		sfw_nat_apply_dnat (ip0, l4_hdr, m->protocol,
				    &m->session->xlate.v4.orig_addr,
				    m->session->xlate.v4.orig_port);
	      nat_translated++;
	    }
	  else if (m->session->nat_type == SFW_NAT_NAT64)
	    {
	      m->nat64_return = 1;
	    }

	  /* TCP state tracking: shorten timeout on RST or bidirectional FIN.
	   * Only the owning thread updates the state bits and LRU. */
	  if (m->protocol == IP_PROTOCOL_TCP)
	    {
	      tcp_header_t *tcp = (tcp_header_t *) l4_hdr;
	      u8 flags = tcp->flags;
	      if (PREDICT_FALSE (flags & TCP_FLAG_RST))
		{
		  m->session->tcp_rst = 1;
		  m->session->expires = now + SFW_TCP_CLOSE_TIMEOUT;
		}
	      else if (PREDICT_FALSE (flags & TCP_FLAG_FIN))
		{
		  if (is_from_zone)
		    m->session->tcp_fin_fwd = 1;
		  else
		    m->session->tcp_fin_rev = 1;
		  if (m->session->tcp_fin_fwd && m->session->tcp_fin_rev)
		    m->session->expires = now + SFW_TCP_CLOSE_TIMEOUT;
		}
	    }

	  continue; /* session handled, skip policy evaluation */
	}

      /* --- No session found — resolve zones and evaluate policy --- */

      u32 src_zone = SFW_ZONE_NONE;
      if (sw_if_index0 < vec_len (sm->if_config))
	src_zone = sm->if_config[sw_if_index0].zone_id;

      if (PREDICT_FALSE (src_zone == SFW_ZONE_NONE))
	continue; /* no zone assigned, pass through */

      /* Check DNAT statics first. If matched, resolve the destination
       * zone from the DNAT target (internal address) instead of the
       * original destination. This gives us the correct zone-pair
       * policy (e.g., external→internal) for rule evaluation. */
      sfw_nat_static_t *dnat = sfw_nat_find_dnat (
	sm, &ip0->dst_address, m->dst_port, m->protocol);

      u32 dst_zone;
      if (dnat)
	{
	  /* DNAT matched — resolve zone from the translation target */
	  dst_zone =
	    sfw_resolve_dst_zone4 (sm, sw_if_index0, &dnat->internal_addr);
	  m->nat_addr = dnat->internal_addr;
	  m->nat_port = dnat->internal_port ?
			  clib_host_to_net_u16 (dnat->internal_port) :
			  m->dst_port;
	  m->nat_computed = 2; /* DNAT */
	}
      else
	{
	  dst_zone =
	    sfw_resolve_dst_zone4 (sm, sw_if_index0, &ip0->dst_address);
	}

      /* Look up zone-pair policy (try both directions) */
      sfw_policy_t *policy = sfw_zone_pair_policy (sm, src_zone, dst_zone);
      is_from_zone = 1;
      if (!policy)
	{
	  policy = sfw_zone_pair_policy (sm, dst_zone, src_zone);
	  if (policy)
	    is_from_zone = 0;
	}

      if (PREDICT_FALSE (!policy))
	continue; /* no zone-pair policy, pass through */

      m->policy = policy;
      m->is_from_zone = is_from_zone;

      /* Evaluate rules. For DNAT traffic, match against the post-
       * translation destination so rules describe what the server sees
       * (e.g., dport 8080 instead of the pre-NAT dport 80). */
      ip46_address_t src46 = { 0 }, dst46 = { 0 };
      src46.ip4 = ip0->src_address;
      dst46.ip4 = dnat ? m->nat_addr : ip0->dst_address;
      u16 match_dport = dnat ? clib_net_to_host_u16 (m->nat_port) :
			       clib_net_to_host_u16 (m->dst_port);
      m->action = sfw_match_rules (
	policy->rules, vec_len (policy->rules), policy->default_action, 0,
	&src46, &dst46, m->protocol, clib_net_to_host_u16 (m->src_port),
	match_dport, m->icmp_type, m->icmp_code);

      /* If rules deny, clear the DNAT — don't translate denied traffic */
      if (m->action == SFW_ACTION_DENY)
	m->nat_computed = 0;

      /* If rules permit-stateful (or stronger) and DNAT matched,
       * upgrade to permit-stateful-nat to trigger DNAT session creation */
      if (dnat && (m->action == SFW_ACTION_PERMIT_STATEFUL ||
		   m->action == SFW_ACTION_PERMIT_STATEFUL_NAT))
	m->action = SFW_ACTION_PERMIT_STATEFUL_NAT;

      /* Pre-compute NAT translation for SNAT actions (non-DNAT) */
      if (!dnat && m->action == SFW_ACTION_PERMIT_STATEFUL_NAT)
	{
	  if (sfw_nat_translate_source (
		sm, thread_index, &ip0->src_address, m->src_port,
		m->protocol, &ip0->dst_address, &m->nat_addr,
		&m->nat_port, &m->nat_mode, &m->nat_alloc_idx) == 0)
	    {
	      if (m->protocol == IP_PROTOCOL_ICMP)
		m->nat_port = m->src_port;
	      m->nat_computed = 1; /* SNAT */
	    }
	  else
	    {
	      m->action = SFW_ACTION_DENY; /* NAT port exhaustion */
	      nat_exhausted++;
	    }
	}
    }

  /* ================================================================
   * PASS 2: Create sessions + add to bihash. NO searches in this pass.
   * ================================================================ */
  u32 nat64_v4_to_v6 = 0;
  u32 nat64_icmp_unsupp = 0;
  for (i = 0; i < n_vectors; i++)
    {
      sfw_pkt_meta_t *m = &meta[i];
      ip4_header_t *ip0 = vlib_buffer_get_current (bufs[i]);

      /* NAT64 v4->v6 return path: the v4 packet just matched a NAT64
       * session and needs to be rewritten back to IPv6 before being
       * handed off to ip6-lookup. No session state changes here. */
      if (PREDICT_FALSE (m->nat64_return))
	{
	  int rv = sfw_nat64_translate_v4_to_v6 (vm, bufs[i], m->session);
	  if (rv == 0)
	    {
	      nat64_v4_to_v6++;
	      nexts[i] = SFW_NEXT_LOOKUP_V6;
	    }
	  else
	    {
	      nexts[i] = SFW_NEXT_DROP;
	      bufs[i]->error = node->errors[SFW_ERROR_NAT64_ICMP_UNSUPPORTED];
	      nat64_icmp_unsupp++;
	    }

	  if (is_trace && (bufs[i]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sfw_trace_t *t =
		vlib_add_trace (vm, node, bufs[i], sizeof (*t));
	      t->sw_if_index = vnet_buffer (bufs[i])->sw_if_index[VLIB_RX];
	      t->next_index = nexts[i];
	      t->action = SFW_ACTION_PERMIT;
	      t->session_found = 1;
	      t->protocol = m->protocol;
	      t->nat_applied = 0;
	      t->nat64_dir = 2; /* v4 -> v6 */
	    }
	  (void) ip0;
	  continue;
	}

      if (m->action == SFW_ACTION_DENY)
	{
	  nexts[i] = SFW_NEXT_DROP;
	  bufs[i]->error = node->errors[SFW_ERROR_DENIED];
	  denied++;
	}
      else if (m->action == SFW_ACTION_PERMIT)
	{
	  if (!m->session)
	    permitted++;
	}
      else if (m->action == SFW_ACTION_PERMIT_STATEFUL && !m->session)
	{
	  sfw_session_t *s = sfw_session_create (sm, thread_index, now);
	  if (PREDICT_TRUE (s != 0))
	    {
	      s->is_ip6 = 0;
	      s->nat_type = SFW_NAT_NONE;
	      s->has_nat_key = 1;
	      s->k4.src = ip0->dst_address;
	      s->k4.dst = ip0->src_address;
	      s->k4.src_port = m->dst_port;
	      s->k4.dst_port = m->src_port;
	      s->k4.protocol = m->protocol;

	      u64 enc = sfw_session_encode (
		thread_index, s - sm->sessions[thread_index]);

	      clib_bihash_kv_48_8_t kv1, kv2;
	      clib_memset (&kv1, 0, sizeof (kv1));
	      clib_memcpy_fast (&kv1.key, &s->k4, sizeof (sfw_key4_t));
	      kv1.value = enc;

	      clib_memset (&kv2, 0, sizeof (kv2));
	      sfw_key4_t *dk = (sfw_key4_t *) &kv2.key;
	      dk->src = ip0->src_address;
	      dk->dst = ip0->dst_address;
	      dk->src_port = m->src_port;
	      dk->dst_port = m->dst_port;
	      dk->protocol = m->protocol;
	      kv2.value = enc;

	      if (sfw_session_insert_hash (sm, s, enc, &kv1, &kv2) == 0)
		created++;
	    }
	}
      else if (m->action == SFW_ACTION_PERMIT_STATEFUL_NAT && !m->session &&
	       m->nat_computed)
	{
	  void *l4_hdr = ip4_next_header (ip0);

	  if (m->nat_computed == 1) /* SNAT */
	    {
	      /* Guard: re-check bihash before creating. Cross-frame
	       * bihash searches intermittently miss existing entries. */
	      clib_bihash_kv_48_8_t gk = { 0 }, gr = { 0 };
	      sfw_key4_t *gkey = (sfw_key4_t *) &gk.key;
	      gkey->src = ip0->dst_address;
	      gkey->dst = ip0->src_address;
	      gkey->src_port = m->dst_port;
	      gkey->dst_port = m->src_port;
	      gkey->protocol = m->protocol;
	      if (clib_bihash_search_48_8 (&sm->session_hash, &gk, &gr) == 0)
		{
		  u32 gt = sfw_session_thread (gr.value);
		  u32 gi = sfw_session_index (gr.value);
		  sfw_session_t *gs =
		    pool_elt_at_index (sm->sessions[gt], gi);
		  if (gs->nat_type == SFW_NAT_SNAT)
		    sfw_nat_apply_snat (ip0, l4_hdr, m->protocol,
					&gs->xlate.v4.nat_addr, gs->xlate.v4.nat_port);
		  if (gt == thread_index)
		    sfw_lru_touch (sm, gs, now);
		  else
		    gs->expires = now + sm->session_timeout;
		  nat_translated++;
		  hits++;
		  continue;
		}

	      /* Deterministic NAT collision check.  Deterministic NAT maps
	       * source ports via modulo, so different source ports can
	       * compute the same external port.  Scan the host's port range
	       * for a free slot.  Dynamic NAT uses per-thread bitmap
	       * allocation which prevents collisions by design. */
	      if (m->nat_mode == SFW_NAT_MODE_DETERMINISTIC)
		{
		  u8 found_free = 0;
		  u16 nat_port_h = clib_net_to_host_u16 (m->nat_port);

		  /* Find the deterministic pool that produced this
		   * translation */
		  for (u32 pi = 0; pi < vec_len (sm->nat_pools); pi++)
		    {
		      sfw_nat_pool_t *pool = &sm->nat_pools[pi];
		      if (pool->mode != SFW_NAT_MODE_DETERMINISTIC)
			continue;

		      u32 mask =
			pool->external_plen ?
			  clib_host_to_net_u32 (
			    ~0u << (32 - pool->external_plen)) :
			  0;
		      if ((m->nat_addr.as_u32 & mask) !=
			  (pool->external_addr.as_u32 & mask))
			continue;

		      u32 int_idx = sfw_ip4_addr_index (
			&ip0->src_address, &pool->internal_addr,
			pool->internal_plen);
		      if (int_idx >= pool->n_internal_addrs)
			continue;

		      u32 hpe =
			pool->n_internal_addrs / pool->n_external_addrs;
		      if (hpe == 0)
			hpe = 1;
		      u32 host_off = int_idx % hpe;
		      u16 port_base = pool->port_range_start +
				      (host_off * pool->ports_per_host);

		      for (u16 p = 0; p < pool->ports_per_host; p++)
			{
			  u16 try_port =
			    port_base + ((nat_port_h - port_base + p) %
					 pool->ports_per_host);
			  clib_bihash_kv_48_8_t ck = { 0 }, cr = { 0 };
			  sfw_key4_t *ckey = (sfw_key4_t *) &ck.key;
			  ckey->src = ip0->dst_address;
			  ckey->dst = m->nat_addr;
			  ckey->src_port = m->dst_port;
			  ckey->dst_port = clib_host_to_net_u16 (try_port);
			  ckey->protocol = m->protocol;
			  if (clib_bihash_search_48_8 (&sm->session_hash,
						       &ck, &cr) != 0)
			    {
			      m->nat_port =
				clib_host_to_net_u16 (try_port);
			      found_free = 1;
			      break;
			    }
			}
		      break;
		    }

		  if (!found_free)
		    {
		      nexts[i] = SFW_NEXT_DROP;
		      bufs[i]->error =
			node->errors[SFW_ERROR_NAT_EXHAUSTED];
		      nat_exhausted++;
		      denied++;
		      continue;
		    }
		}

	      sfw_session_t *s = sfw_session_create (sm, thread_index, now);
	      if (PREDICT_TRUE (s != 0))
		{
		  s->is_ip6 = 0;
		  s->nat_type = SFW_NAT_SNAT;
		  s->has_nat_key = 1;
		  s->k4.src = ip0->dst_address;
		  s->k4.dst = ip0->src_address;
		  s->k4.src_port = m->dst_port;
		  s->k4.dst_port = m->src_port;
		  s->k4.protocol = m->protocol;
		  s->xlate.v4.nat_addr = m->nat_addr;
		  s->xlate.v4.nat_port = m->nat_port;
		  s->xlate.v4.orig_addr = ip0->src_address;
		  s->xlate.v4.orig_port = m->src_port;
		  s->xlate.v4.v4_alloc_idx = m->nat_alloc_idx;

		  u64 enc = sfw_session_encode (
		    thread_index, s - sm->sessions[thread_index]);

		  clib_bihash_kv_48_8_t kv1, kv2;
		  clib_memset (&kv1, 0, sizeof (kv1));
		  clib_memcpy_fast (&kv1.key, &s->k4, sizeof (sfw_key4_t));
		  kv1.value = enc;

		  clib_memset (&kv2, 0, sizeof (kv2));
		  sfw_key4_t *nk = (sfw_key4_t *) &kv2.key;
		  nk->src = ip0->dst_address;
		  nk->dst = m->nat_addr;
		  nk->src_port = m->dst_port;
		  nk->dst_port = m->nat_port;
		  nk->protocol = m->protocol;
		  kv2.value = enc;

		  if (sfw_session_insert_hash (sm, s, enc, &kv1, &kv2) == 0)
		    {
		      sfw_nat_apply_snat (ip0, l4_hdr, m->protocol,
					  &m->nat_addr, m->nat_port);
		      nat_translated++;
		      created++;
		    }
		}
	    }
	  else if (m->nat_computed == 2) /* DNAT */
	    {
	      sfw_session_t *s = sfw_session_create (sm, thread_index, now);
	      if (PREDICT_TRUE (s != 0))
		{
		  s->is_ip6 = 0;
		  s->nat_type = SFW_NAT_DNAT;
		  s->has_nat_key = 1;
		  s->k4.src = ip0->src_address;
		  s->k4.dst = m->nat_addr;
		  s->k4.src_port = m->src_port;
		  s->k4.dst_port = m->nat_port;
		  s->k4.protocol = m->protocol;
		  s->xlate.v4.nat_addr = ip0->dst_address;
		  s->xlate.v4.nat_port = m->dst_port;
		  s->xlate.v4.orig_addr = m->nat_addr;
		  s->xlate.v4.orig_port = m->nat_port;

		  u64 enc = sfw_session_encode (
		    thread_index, s - sm->sessions[thread_index]);

		  clib_bihash_kv_48_8_t kv1, kv2;
		  clib_memset (&kv1, 0, sizeof (kv1));
		  clib_memcpy_fast (&kv1.key, &s->k4, sizeof (sfw_key4_t));
		  kv1.value = enc;

		  clib_memset (&kv2, 0, sizeof (kv2));
		  sfw_key4_t *nk = (sfw_key4_t *) &kv2.key;
		  nk->src = ip0->src_address;
		  nk->dst = ip0->dst_address;
		  nk->src_port = m->src_port;
		  nk->dst_port = m->dst_port;
		  nk->protocol = m->protocol;
		  kv2.value = enc;

		  if (sfw_session_insert_hash (sm, s, enc, &kv1, &kv2) == 0)
		    {
		      sfw_nat_apply_dnat (ip0, l4_hdr, m->protocol,
					  &m->nat_addr, m->nat_port);
		      nat_translated++;
		      created++;
		    }
		}
	    }
	}

      /* Trace */
      if (is_trace && (bufs[i]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  sfw_trace_t *t = vlib_add_trace (vm, node, bufs[i], sizeof (*t));
	  t->sw_if_index = vnet_buffer (bufs[i])->sw_if_index[VLIB_RX];
	  t->next_index = nexts[i];
	  t->action = m->action;
	  t->session_found = (m->session != 0);
	  t->protocol = m->protocol;
	  t->nat_applied = m->nat_computed;
	  t->nat64_dir = 0;
	}
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_vectors);

  /* Expire stale sessions on this worker */
  sfw_expire_inline (sm, thread_index, now);

  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_PROCESSED,
			       n_vectors);
  vlib_node_increment_counter (vm, node->node_index,
			       SFW_ERROR_SESSIONS_CREATED, created);
  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_SESSION_HITS,
			       hits);
  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_DENIED,
			       denied);
  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_PERMITTED,
			       permitted);
  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_NAT_TRANSLATED,
			       nat_translated);
  if (PREDICT_FALSE (nat_exhausted))
    vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_NAT_EXHAUSTED,
				 nat_exhausted);
  if (PREDICT_FALSE (nat64_v4_to_v6))
    vlib_node_increment_counter (vm, node->node_index,
				 SFW_ERROR_NAT64_V4_TO_V6, nat64_v4_to_v6);
  if (PREDICT_FALSE (nat64_icmp_unsupp))
    vlib_node_increment_counter (vm, node->node_index,
				 SFW_ERROR_NAT64_ICMP_UNSUPPORTED,
				 nat64_icmp_unsupp);
  return n_vectors;
}

VLIB_NODE_FN (sfw_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return sfw_ip4_inline (vm, node, frame, 1);
  else
    return sfw_ip4_inline (vm, node, frame, 0);
}

/* --- IPv6 node (two-pass design) ---
 *
 * Same two-pass structure as IPv4 with FIB-based zone resolution.
 * IPv6 has no NAT — pure stateful firewall. */

/* Per-packet metadata bridging pass 1 and pass 2 */
typedef struct
{
  sfw_session_t *session; /* found session, or NULL */
  sfw_policy_t *policy;	  /* zone-pair policy */
  u16 src_port;		  /* extracted L4 source port */
  u16 dst_port;		  /* extracted L4 destination port */
  u8 action;		  /* resolved action */
  u8 protocol;		  /* IP protocol */
  u8 is_from_zone;	  /* 1 if RX is from_zone (outbound) */
  u8 icmp_type;
  u8 icmp_code;

  /* NAT64 ingress (v6->v4). nat64_pool_idx == ~0 means no NAT64. */
  u32 nat64_pool_idx;
  ip4_address_t nat64_v4_server; /* embedded v4 dst extracted from v6 */
  ip4_address_t nat64_v4_pool;   /* allocated v4 pool source */
  u16 nat64_v4_pool_port;	 /* allocated v4 src port (net order) */
  u8 nat64_forward;		 /* 1 = new v6->v4 flow, translate in pass 2 */
  u8 nat64_return;		 /* 1 = matched NAT64 session, translate
				      (rare on v6 input; kept for symmetry) */
} sfw_pkt_meta6_t;

always_inline uword
sfw_ip6_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_frame_t *frame, int is_trace)
{
  u32 *from, n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];
  sfw_main_t *sm = &sfw_main;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  u32 created = 0, hits = 0, denied = 0, permitted = 0;
  sfw_pkt_meta6_t meta[VLIB_FRAME_SIZE];
  u32 i;

  from = vlib_frame_vector_args (frame);
  n_vectors = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_vectors);

  /* Initialize nexts to feature-next for all packets */
  for (i = 0; i < n_vectors; i++)
    {
      u32 next0;
      vnet_feature_next (&next0, bufs[i]);
      nexts[i] = next0;
    }

  /* ================================================================
   * PASS 1: Search bihash + classify. NO bihash adds in this pass.
   * ================================================================ */
  for (i = 0; i < n_vectors; i++)
    {
      sfw_pkt_meta6_t *m = &meta[i];
      clib_memset (m, 0, sizeof (*m));
      m->action = SFW_ACTION_PERMIT;
      m->nat64_pool_idx = ~0;

      ip6_header_t *ip0 = vlib_buffer_get_current (bufs[i]);
      u32 sw_if_index0 = vnet_buffer (bufs[i])->sw_if_index[VLIB_RX];

      /* Pass link-local traffic without policy evaluation. */
      if (PREDICT_FALSE (ip6_address_is_link_local_unicast (&ip0->src_address)
			 || ip6_address_is_link_local_unicast (
			   &ip0->dst_address)))
	{
	  permitted++;
	  continue;
	}

      m->protocol = ip0->protocol;

      /* Validate both payload length and buffer coverage for L4 access */
      u16 ip6_plen = clib_net_to_host_u16 (ip0->payload_length);
      u16 buf_len = vlib_buffer_length_in_chain (vm, bufs[i]);
      if (PREDICT_FALSE (ip6_plen < 4 ||
			 buf_len < sizeof (ip6_header_t) + 4))
	{
	  permitted++;
	  continue;
	}

      void *l4_hdr = ip6_next_header (ip0);
      sfw_extract_l4 (m->protocol, l4_hdr, &m->src_port, &m->dst_port,
		      &m->icmp_type, &m->icmp_code);

      /* --- Session lookup (before zone/policy resolution) ---
       * Try both key directions. If found, permit immediately. */
      clib_bihash_kv_48_8_t kv = { 0 }, result = { 0 };
      sfw_key6_t *key;
      u8 found_session = 0;

      /* Try reverse-key (outbound direction) */
      u8 is_from_zone6 = 1;
      key = (sfw_key6_t *) &kv.key;
      ip6_address_copy (&key->src, &ip0->dst_address);
      ip6_address_copy (&key->dst, &ip0->src_address);
      key->src_port = m->dst_port;
      key->dst_port = m->src_port;
      key->protocol = m->protocol;

      if (clib_bihash_search_48_8 (&sm->session_hash, &kv, &result) == 0)
	found_session = 1;
      else
	{
	  /* Try direct-key (inbound/return direction) */
	  is_from_zone6 = 0;
	  clib_memset (&kv, 0, sizeof (kv));
	  key = (sfw_key6_t *) &kv.key;
	  ip6_address_copy (&key->src, &ip0->src_address);
	  ip6_address_copy (&key->dst, &ip0->dst_address);
	  key->src_port = m->src_port;
	  key->dst_port = m->dst_port;
	  key->protocol = m->protocol;

	  if (clib_bihash_search_48_8 (&sm->session_hash, &kv, &result) == 0)
	    found_session = 1;
	}

      if (found_session)
	{
	  u32 st = sfw_session_thread (result.value);
	  u32 si = sfw_session_index (result.value);
	  m->session = pool_elt_at_index (sm->sessions[st], si);

	  /* Don't reset timeout for sessions in TCP close/reset state */
	  if (PREDICT_TRUE (!m->session->tcp_rst &&
			    !(m->session->tcp_fin_fwd &&
			      m->session->tcp_fin_rev)))
	    {
	      if (st == thread_index)
		sfw_lru_touch (sm, m->session, now);
	      else
		m->session->expires = now + sm->session_timeout;
	    }

	  hits++;
	  m->action = SFW_ACTION_PERMIT;

	  /* If this is a NAT64 session, any v6 packet that matched it
	   * is a forward-direction retransmit and needs v6->v4 rewrite
	   * in Pass 2. */
	  if (m->session->nat_type == SFW_NAT_NAT64)
	    m->nat64_forward = 1;

	  /* TCP state tracking */
	  if (m->protocol == IP_PROTOCOL_TCP)
	    {
	      tcp_header_t *tcp = (tcp_header_t *) l4_hdr;
	      u8 flags = tcp->flags;
	      if (PREDICT_FALSE (flags & TCP_FLAG_RST))
		{
		  m->session->tcp_rst = 1;
		  m->session->expires = now + SFW_TCP_CLOSE_TIMEOUT;
		}
	      else if (PREDICT_FALSE (flags & TCP_FLAG_FIN))
		{
		  if (is_from_zone6)
		    m->session->tcp_fin_fwd = 1;
		  else
		    m->session->tcp_fin_rev = 1;
		  if (m->session->tcp_fin_fwd && m->session->tcp_fin_rev)
		    m->session->expires = now + SFW_TCP_CLOSE_TIMEOUT;
		}
	    }

	  continue; /* session handled, skip policy evaluation */
	}

      /* --- No session found — resolve zones and evaluate policy --- */

      u32 src_zone = SFW_ZONE_NONE;
      if (sw_if_index0 < vec_len (sm->if_config))
	src_zone = sm->if_config[sw_if_index0].zone_id;

      if (PREDICT_FALSE (src_zone == SFW_ZONE_NONE))
	continue;

      u32 dst_zone =
	sfw_resolve_dst_zone6 (sm, sw_if_index0, &ip0->dst_address);

      sfw_policy_t *policy = sfw_zone_pair_policy (sm, src_zone, dst_zone);
      u8 is_from_zone = 1;
      if (!policy)
	{
	  policy = sfw_zone_pair_policy (sm, dst_zone, src_zone);
	  if (policy)
	    is_from_zone = 0;
	}

      if (PREDICT_FALSE (!policy))
	continue;

      m->policy = policy;
      m->is_from_zone = is_from_zone;

      /* Implicit ICMPv6 permit — stateless passthrough for NDP,
       * PMTUD, and echo, so those don't need explicit rules. But
       * NOT for packets destined to a configured NAT64 prefix:
       * those need the NAT64 translation path. Without this
       * guard, ping6 64:ff9b::<v4> bypassed NAT64, got forwarded
       * as plain v6 towards a destination that isn't globally
       * routable, and produced no reply. */
      if (m->protocol == IP_PROTOCOL_ICMP6 && policy->implicit_icmpv6 &&
	  sfw_is_implicit_icmpv6 (m->icmp_type) &&
	  sfw_nat64_match_pool (sm, &ip0->dst_address) == ~0u)
	{
	  permitted++;
	  continue;
	}

      /* Evaluate rules */
      ip46_address_t src46 = { 0 }, dst46 = { 0 };
      ip6_address_copy (&src46.ip6, &ip0->src_address);
      ip6_address_copy (&dst46.ip6, &ip0->dst_address);

      m->action = sfw_match_rules (
	policy->rules, vec_len (policy->rules), policy->default_action, 1,
	&src46, &dst46, m->protocol, clib_net_to_host_u16 (m->src_port),
	clib_net_to_host_u16 (m->dst_port), m->icmp_type, m->icmp_code);

      /* NAT64 pool match for PERMIT_STATEFUL_NAT flows.
       *
       * The rule match already decided "permit" — this branch just
       * layers NAT64 on top when possible. When we can't do NAT64
       * (non-translatable protocol, or no NAT64 pool covers the v6
       * dst), fall back to PERMIT_STATEFUL rather than denying: a
       * single zone-pair policy with `default-action
       * permit-stateful-nat` naturally covers both v4 SNAT and
       * v6 pass-through-with-state, which is what operators
       * commonly want. Deny decisions come from rules, not from
       * NAT64 failure.
       *
       * The NAT64_UNKNOWN_PREFIX counter still increments so
       * operators who *do* intend NAT64 can spot v6 traffic that
       * isn't being translated because no pool matches. */
      if (m->action == SFW_ACTION_PERMIT_STATEFUL_NAT)
	{
	  if (m->protocol != IP_PROTOCOL_TCP &&
	      m->protocol != IP_PROTOCOL_UDP &&
	      m->protocol != IP_PROTOCOL_ICMP6)
	    {
	      m->action = SFW_ACTION_PERMIT_STATEFUL;
	      continue;
	    }

	  u32 pool_idx = sfw_nat64_match_pool (sm, &ip0->dst_address);
	  if (pool_idx == ~0u)
	    {
	      m->action = SFW_ACTION_PERMIT_STATEFUL;
	      vlib_node_increment_counter (vm, node->node_index,
					   SFW_ERROR_NAT64_UNKNOWN_PREFIX, 1);
	      continue;
	    }

	  sfw_nat_pool_t *pool = &sm->nat_pools[pool_idx];
	  ip4_address_t v4_dst;
	  if (sfw_nat64_extract_v4 (&pool->nat64_prefix,
				    pool->nat64_prefix_len,
				    &ip0->dst_address, &v4_dst) != 0)
	    {
	      m->action = SFW_ACTION_PERMIT_STATEFUL;
	      vlib_node_increment_counter (vm, node->node_index,
					   SFW_ERROR_NAT64_UNKNOWN_PREFIX, 1);
	      continue;
	    }

	  /* Pick a preferred pool v4 address by hashing the 5-tuple,
	   * then try subsequent addresses on exhaustion. Mirrors
	   * sfw_nat_dynamic_translate. */
	  u32 hash = ip0->src_address.as_u32[0] ^ ip0->src_address.as_u32[3] ^
		     ((u32) m->src_port << 16) ^ (u32) m->protocol;
	  u32 n = pool->n_external_addrs ? pool->n_external_addrs : 1;
	  u32 preferred = hash % n;
	  u16 port_h = 0;
	  u32 external_idx = 0;
	  for (u32 attempt = 0; attempt < n; attempt++)
	    {
	      external_idx = (preferred + attempt) % n;
	      port_h = sfw_v4_port_alloc_port (sm, pool->v4_alloc_idx,
					       thread_index, external_idx);
	      if (port_h != 0)
		break;
	    }
	  if (port_h == 0)
	    {
	      m->action = SFW_ACTION_DENY;
	      vlib_node_increment_counter (vm, node->node_index,
					   SFW_ERROR_NAT_EXHAUSTED, 1);
	      continue;
	    }

	  ip4_address_t v4_pool_addr;
	  sfw_ip4_addr_from_index (&v4_pool_addr, &pool->external_addr,
				   pool->external_plen, external_idx);
	  m->nat64_pool_idx = pool_idx;
	  m->nat64_v4_server = v4_dst;
	  m->nat64_v4_pool = v4_pool_addr;
	  m->nat64_v4_pool_port = clib_host_to_net_u16 (port_h);
	  m->nat64_forward = 1;
	}
    }

  /* ================================================================
   * PASS 2: Create sessions + add to bihash. NO searches in this pass.
   * ================================================================ */
  u32 nat64_v6_to_v4 = 0;
  u32 nat64_headroom = 0;
  u32 nat64_icmp_unsupp = 0;
  for (i = 0; i < n_vectors; i++)
    {
      sfw_pkt_meta6_t *m = &meta[i];
      ip6_header_t *ip0 = vlib_buffer_get_current (bufs[i]);

      if (m->action == SFW_ACTION_DENY)
	{
	  nexts[i] = SFW_NEXT_DROP;
	  bufs[i]->error = node->errors[SFW_ERROR_DENIED];
	  denied++;
	}
      else if (m->nat64_forward && m->session &&
	       m->session->nat_type == SFW_NAT_NAT64)
	{
	  /* Retransmit of an existing NAT64 flow — translate the packet
	   * using the existing session; no new session insertion. */
	  int rv = sfw_nat64_translate_v6_to_v4 (vm, bufs[i], m->session);
	  if (rv == 0)
	    {
	      nat64_v6_to_v4++;
	      nexts[i] = SFW_NEXT_LOOKUP_V4;
	    }
	  else
	    {
	      nexts[i] = SFW_NEXT_DROP;
	      bufs[i]->error = node->errors[SFW_ERROR_NAT64_ICMP_UNSUPPORTED];
	      nat64_icmp_unsupp++;
	    }
	}
      else if (m->nat64_forward && !m->session &&
	       m->nat64_pool_idx != ~0u)
	{
	  /* New NAT64 forward flow — create session, insert both
	   * bihash entries, then translate + hand off to ip4-lookup. */
	  sfw_session_t *s = sfw_session_create (sm, thread_index, now);
	  if (PREDICT_TRUE (s != 0))
	    {
	      s->is_ip6 = 1;
	      s->nat_type = SFW_NAT_NAT64;
	      s->has_nat_key = 1;
	      /* k6: v6 forward key stored reversed (matches return
	       * direction v6 lookup, plus serves as ingress-direction
	       * match via the reverse-key scan at Pass 1 start). */
	      ip6_address_copy (&s->k6.src, &ip0->dst_address);
	      ip6_address_copy (&s->k6.dst, &ip0->src_address);
	      s->k6.src_port = m->dst_port;
	      s->k6.dst_port = m->src_port;
	      s->k6.protocol = m->protocol;
	      /* xlate.n64: v4 side state */
	      s->xlate.n64.v4_pool = m->nat64_v4_pool;
	      s->xlate.n64.v4_server = m->nat64_v4_server;
	      s->xlate.n64.v4_pool_port = m->nat64_v4_pool_port;
	      s->xlate.n64.pool_idx = m->nat64_pool_idx;
	      s->xlate.n64.v4_alloc_idx =
		sm->nat_pools[m->nat64_pool_idx].v4_alloc_idx;

	      u64 enc = sfw_session_encode (
		thread_index, s - sm->sessions[thread_index]);

	      clib_bihash_kv_48_8_t kv1, kv2;
	      /* kv1: v6 forward key — use the stored k6 verbatim. */
	      clib_memset (&kv1, 0, sizeof (kv1));
	      clib_memcpy_fast (&kv1.key, &s->k6, sizeof (sfw_key6_t));
	      kv1.value = enc;

	      /* kv2: v4 return key (zero-padded to 48). Return
	       * direction: v4 server -> v4 pool.
	       *   TCP/UDP: src_port = v4_dport (= m->dst_port),
	       *            dst_port = allocated v4 pool port.
	       *   ICMP:    both ports carry the echo id, which we
	       *            rewrote to v4_pool_port in the forward
	       *            translation; remote echoes it back, so
	       *            both port fields match v4_pool_port. */
	      clib_memset (&kv2, 0, sizeof (kv2));
	      sfw_key4_t *nk = (sfw_key4_t *) &kv2.key;
	      nk->src = m->nat64_v4_server;
	      nk->dst = m->nat64_v4_pool;
	      if (m->protocol == IP_PROTOCOL_ICMP6)
		{
		  nk->src_port = m->nat64_v4_pool_port;
		  nk->dst_port = m->nat64_v4_pool_port;
		  nk->protocol = IP_PROTOCOL_ICMP;
		}
	      else
		{
		  nk->src_port = m->dst_port;
		  nk->dst_port = m->nat64_v4_pool_port;
		  nk->protocol = m->protocol;
		}
	      kv2.value = enc;

	      if (sfw_session_insert_hash (sm, s, enc, &kv1, &kv2) == 0)
		{
		  created++;
		  int rv = sfw_nat64_translate_v6_to_v4 (vm, bufs[i], s);
		  if (rv == 0)
		    {
		      nat64_v6_to_v4++;
		      nexts[i] = SFW_NEXT_LOOKUP_V4;
		    }
		  else if (rv == -2)
		    {
		      nexts[i] = SFW_NEXT_DROP;
		      bufs[i]->error =
			node->errors[SFW_ERROR_NAT64_HEADROOM];
		      nat64_headroom++;
		    }
		  else
		    {
		      nexts[i] = SFW_NEXT_DROP;
		      bufs[i]->error =
			node->errors[SFW_ERROR_NAT64_ICMP_UNSUPPORTED];
		      nat64_icmp_unsupp++;
		    }
		}
	      else
		{
		  /* Hash insert failed; free the allocated port. */
		  sfw_nat_pool_t *p = &sm->nat_pools[m->nat64_pool_idx];
		  u32 ext_idx = sfw_ip4_addr_index (&m->nat64_v4_pool,
						     &p->external_addr,
						     p->external_plen);
		  sfw_v4_port_alloc_free_port (
		    sm, p->v4_alloc_idx, thread_index, ext_idx,
		    clib_net_to_host_u16 (m->nat64_v4_pool_port));
		  nexts[i] = SFW_NEXT_DROP;
		}
	    }
	  else
	    {
	      /* Session allocation failed; free the port. */
	      sfw_nat_pool_t *p = &sm->nat_pools[m->nat64_pool_idx];
	      u32 ext_idx =
		sfw_ip4_addr_index (&m->nat64_v4_pool, &p->external_addr,
				    p->external_plen);
	      sfw_v4_port_alloc_free_port (
		sm, p->v4_alloc_idx, thread_index, ext_idx,
		clib_net_to_host_u16 (m->nat64_v4_pool_port));
	    }
	}
      else if (m->action == SFW_ACTION_PERMIT)
	{
	  if (!m->session)
	    permitted++;
	}
      else if ((m->action == SFW_ACTION_PERMIT_STATEFUL ||
		m->action == SFW_ACTION_PERMIT_STATEFUL_NAT) &&
	       !m->session)
	{
	  sfw_session_t *s = sfw_session_create (sm, thread_index, now);
	  if (PREDICT_TRUE (s != 0))
	    {
	      s->is_ip6 = 1;
	      s->nat_type = SFW_NAT_NONE;
	      s->has_nat_key = 1;
	      ip6_address_copy (&s->k6.src, &ip0->dst_address);
	      ip6_address_copy (&s->k6.dst, &ip0->src_address);
	      s->k6.src_port = m->dst_port;
	      s->k6.dst_port = m->src_port;
	      s->k6.protocol = m->protocol;

	      u64 enc = sfw_session_encode (
		thread_index, s - sm->sessions[thread_index]);

	      clib_bihash_kv_48_8_t kv1, kv2;
	      clib_memset (&kv1, 0, sizeof (kv1));
	      clib_memcpy_fast (&kv1.key, &s->k6, sizeof (sfw_key6_t));
	      kv1.value = enc;

	      clib_memset (&kv2, 0, sizeof (kv2));
	      sfw_key6_t *dk = (sfw_key6_t *) &kv2.key;
	      ip6_address_copy (&dk->src, &ip0->src_address);
	      ip6_address_copy (&dk->dst, &ip0->dst_address);
	      dk->src_port = m->src_port;
	      dk->dst_port = m->dst_port;
	      dk->protocol = m->protocol;
	      kv2.value = enc;

	      if (sfw_session_insert_hash (sm, s, enc, &kv1, &kv2) == 0)
		created++;
	    }
	}

      /* Trace */
      if (is_trace && (bufs[i]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  sfw_trace_t *t = vlib_add_trace (vm, node, bufs[i], sizeof (*t));
	  t->sw_if_index = vnet_buffer (bufs[i])->sw_if_index[VLIB_RX];
	  t->next_index = nexts[i];
	  t->action = m->action;
	  t->session_found = (m->session != 0);
	  t->protocol = m->protocol;
	  t->nat_applied = 0;
	  t->nat64_dir = m->nat64_forward ? 1 : 0;
	}
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_vectors);
  sfw_expire_inline (sm, thread_index, now);

  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_PROCESSED,
			       n_vectors);
  vlib_node_increment_counter (vm, node->node_index,
			       SFW_ERROR_SESSIONS_CREATED, created);
  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_SESSION_HITS,
			       hits);
  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_DENIED,
			       denied);
  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_PERMITTED,
			       permitted);
  if (PREDICT_FALSE (nat64_v6_to_v4))
    vlib_node_increment_counter (vm, node->node_index,
				 SFW_ERROR_NAT64_V6_TO_V4, nat64_v6_to_v4);
  if (PREDICT_FALSE (nat64_headroom))
    vlib_node_increment_counter (vm, node->node_index,
				 SFW_ERROR_NAT64_HEADROOM, nat64_headroom);
  if (PREDICT_FALSE (nat64_icmp_unsupp))
    vlib_node_increment_counter (vm, node->node_index,
				 SFW_ERROR_NAT64_ICMP_UNSUPPORTED,
				 nat64_icmp_unsupp);
  return n_vectors;
}

VLIB_NODE_FN (sfw_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return sfw_ip6_inline (vm, node, frame, 1);
  else
    return sfw_ip6_inline (vm, node, frame, 0);
}

/* --- IPv4 output arc (sfw-ip4-out) ---
 *
 * Catches traffic the input arc never sees: VPP self-generated replies
 * (ICMP, TCP RST-to-unknown), VCL apps, and any other locally-originated
 * packets.  Synthesizes src_zone = SFW_ZONE_LOCAL when the source address
 * is configured on this router (FIB DPO_RECEIVE), then applies the
 * (local, dst_zone) zone-pair policy and creates a session so the return
 * traffic finds a matching entry on the input arc.
 *
 * Forwarded traffic (input arc → lookup → rewrite → here) also traverses
 * this node.  A session hash lookup catches those cases and we simply
 * pass through — no second session gets created. */

typedef struct
{
  sfw_session_t *session;
  sfw_policy_t *policy;
  u16 src_port;
  u16 dst_port;
  u8 action;
  u8 protocol;
  u8 icmp_type;
  u8 icmp_code;
  u8 is_local_src;
} sfw_out_meta_t;

always_inline uword
sfw_ip4_output_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame, int is_trace)
{
  u32 *from, n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];
  sfw_main_t *sm = &sfw_main;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  u32 created = 0, hits = 0, denied = 0, permitted = 0, local_originated = 0;
  sfw_out_meta_t meta[VLIB_FRAME_SIZE];
  u32 i;

  from = vlib_frame_vector_args (frame);
  n_vectors = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_vectors);

  for (i = 0; i < n_vectors; i++)
    {
      u32 next0;
      vnet_feature_next (&next0, bufs[i]);
      nexts[i] = next0;
    }

  /* Pass 1: lookup + classify (no bihash adds) */
  for (i = 0; i < n_vectors; i++)
    {
      sfw_out_meta_t *m = &meta[i];
      clib_memset (m, 0, sizeof (*m));
      m->action = SFW_ACTION_PERMIT;

      /* On ip4-output, ip4-rewrite has already prepended the L2 rewrite
       * and advanced current_data backward by save_rewrite_length bytes.
       * The IP header lives past that offset. */
      u32 rw_len = vnet_buffer (bufs[i])->ip.save_rewrite_length;
      ip4_header_t *ip0 =
	(ip4_header_t *) ((u8 *) vlib_buffer_get_current (bufs[i]) + rw_len);
      u32 tx_sw_if_index = vnet_buffer (bufs[i])->sw_if_index[VLIB_TX];

      u32 dst_h = clib_net_to_host_u32 (ip0->dst_address.as_u32);
      u32 src_h = clib_net_to_host_u32 (ip0->src_address.as_u32);
      if (PREDICT_FALSE (dst_h == 0xFFFFFFFF || src_h == 0 ||
			 (dst_h >> 28) == 0xE))
	{
	  permitted++;
	  continue;
	}

      m->protocol = ip0->protocol;

      u16 ip_len = clib_net_to_host_u16 (ip0->length);
      u16 ihl = (ip0->ip_version_and_header_length & 0x0F) << 2;
      u16 buf_len = vlib_buffer_length_in_chain (vm, bufs[i]);
      if (PREDICT_FALSE (ihl < sizeof (ip4_header_t) ||
			 ip_len < ihl + 4 || buf_len < ihl + 4))
	{
	  permitted++;
	  continue;
	}

      void *l4_hdr = ip4_next_header (ip0);
      sfw_extract_l4 (m->protocol, l4_hdr, &m->src_port, &m->dst_port,
		      &m->icmp_type, &m->icmp_code);

      /* Session lookup — matches both forwarded traffic (session created
       * on input arc) and local-originated retransmits. */
      clib_bihash_kv_48_8_t kv = { 0 }, result = { 0 };
      sfw_key4_t *key;
      u8 found_session = 0;
      u8 is_from_zone = 1;

      key = (sfw_key4_t *) &kv.key;
      key->src = ip0->dst_address;
      key->dst = ip0->src_address;
      key->src_port = m->dst_port;
      key->dst_port = m->src_port;
      key->protocol = m->protocol;

      if (clib_bihash_search_48_8 (&sm->session_hash, &kv, &result) == 0)
	{
	  found_session = 1;
	  is_from_zone = 1;
	}
      else
	{
	  clib_memset (&kv, 0, sizeof (kv));
	  key = (sfw_key4_t *) &kv.key;
	  key->src = ip0->src_address;
	  key->dst = ip0->dst_address;
	  key->src_port = m->src_port;
	  key->dst_port = m->dst_port;
	  key->protocol = m->protocol;
	  if (clib_bihash_search_48_8 (&sm->session_hash, &kv, &result) == 0)
	    {
	      found_session = 1;
	      is_from_zone = 0;
	    }
	}

      if (found_session)
	{
	  u32 st = sfw_session_thread (result.value);
	  u32 si = sfw_session_index (result.value);
	  m->session = pool_elt_at_index (sm->sessions[st], si);

	  if (PREDICT_TRUE (!m->session->tcp_rst &&
			    !(m->session->tcp_fin_fwd &&
			      m->session->tcp_fin_rev)))
	    {
	      if (st == thread_index)
		sfw_lru_touch (sm, m->session, now);
	      else
		m->session->expires = now + sm->session_timeout;
	    }

	  hits++;
	  m->action = SFW_ACTION_PERMIT;

	  if (m->protocol == IP_PROTOCOL_TCP)
	    {
	      tcp_header_t *tcp = (tcp_header_t *) l4_hdr;
	      u8 flags = tcp->flags;
	      if (PREDICT_FALSE (flags & TCP_FLAG_RST))
		{
		  m->session->tcp_rst = 1;
		  m->session->expires = now + SFW_TCP_CLOSE_TIMEOUT;
		}
	      else if (PREDICT_FALSE (flags & TCP_FLAG_FIN))
		{
		  if (is_from_zone)
		    m->session->tcp_fin_fwd = 1;
		  else
		    m->session->tcp_fin_rev = 1;
		  if (m->session->tcp_fin_fwd && m->session->tcp_fin_rev)
		    m->session->expires = now + SFW_TCP_CLOSE_TIMEOUT;
		}
	    }
	  continue;
	}

      /* No session — is this a locally-originated new flow?
       * The FIB DPO_RECEIVE check identifies any src configured on this
       * router (on any interface, any FIB).  If it isn't local, the
       * packet was merely transiting and either hit a stateless
       * permit on the input arc or wasn't zoned — either way, pass. */
      if (!sfw_is_local_src4 (tx_sw_if_index, &ip0->src_address))
	continue;
      m->is_local_src = 1;

      if (tx_sw_if_index >= vec_len (sm->if_config))
	continue;
      u32 dst_zone = sm->if_config[tx_sw_if_index].zone_id;
      if (dst_zone == SFW_ZONE_NONE)
	continue;

      sfw_policy_t *policy =
	sfw_zone_pair_policy (sm, SFW_ZONE_LOCAL, dst_zone);
      if (PREDICT_FALSE (!policy))
	continue;

      m->policy = policy;

      ip46_address_t src46 = { 0 }, dst46 = { 0 };
      src46.ip4 = ip0->src_address;
      dst46.ip4 = ip0->dst_address;
      m->action = sfw_match_rules (
	policy->rules, vec_len (policy->rules), policy->default_action, 0,
	&src46, &dst46, m->protocol, clib_net_to_host_u16 (m->src_port),
	clib_net_to_host_u16 (m->dst_port), m->icmp_type, m->icmp_code);
    }

  /* Pass 2: create sessions for locally-originated new flows */
  for (i = 0; i < n_vectors; i++)
    {
      sfw_out_meta_t *m = &meta[i];
      u32 rw_len = vnet_buffer (bufs[i])->ip.save_rewrite_length;
      ip4_header_t *ip0 =
	(ip4_header_t *) ((u8 *) vlib_buffer_get_current (bufs[i]) + rw_len);

      if (m->action == SFW_ACTION_DENY)
	{
	  nexts[i] = SFW_NEXT_DROP;
	  bufs[i]->error = node->errors[SFW_ERROR_DENIED];
	  denied++;
	}
      else if (m->action == SFW_ACTION_PERMIT)
	{
	  if (!m->session && m->is_local_src)
	    permitted++;
	}
      else if ((m->action == SFW_ACTION_PERMIT_STATEFUL ||
		m->action == SFW_ACTION_PERMIT_STATEFUL_NAT) &&
	       !m->session && m->is_local_src)
	{
	  /* Cross-frame re-check: a prior frame on another worker may
	   * have just inserted a session for this flow. */
	  clib_bihash_kv_48_8_t gk = { 0 }, gr = { 0 };
	  sfw_key4_t *gkey = (sfw_key4_t *) &gk.key;
	  gkey->src = ip0->dst_address;
	  gkey->dst = ip0->src_address;
	  gkey->src_port = m->dst_port;
	  gkey->dst_port = m->src_port;
	  gkey->protocol = m->protocol;
	  if (clib_bihash_search_48_8 (&sm->session_hash, &gk, &gr) == 0)
	    {
	      hits++;
	      continue;
	    }

	  sfw_session_t *s = sfw_session_create (sm, thread_index, now);
	  if (PREDICT_TRUE (s != 0))
	    {
	      s->is_ip6 = 0;
	      s->nat_type = SFW_NAT_NONE;
	      s->has_nat_key = 1;
	      s->k4.src = ip0->dst_address;
	      s->k4.dst = ip0->src_address;
	      s->k4.src_port = m->dst_port;
	      s->k4.dst_port = m->src_port;
	      s->k4.protocol = m->protocol;

	      u64 enc = sfw_session_encode (
		thread_index, s - sm->sessions[thread_index]);

	      clib_bihash_kv_48_8_t kv1, kv2;
	      clib_memset (&kv1, 0, sizeof (kv1));
	      clib_memcpy_fast (&kv1.key, &s->k4, sizeof (sfw_key4_t));
	      kv1.value = enc;

	      clib_memset (&kv2, 0, sizeof (kv2));
	      sfw_key4_t *dk = (sfw_key4_t *) &kv2.key;
	      dk->src = ip0->src_address;
	      dk->dst = ip0->dst_address;
	      dk->src_port = m->src_port;
	      dk->dst_port = m->dst_port;
	      dk->protocol = m->protocol;
	      kv2.value = enc;

	      if (sfw_session_insert_hash (sm, s, enc, &kv1, &kv2) == 0)
		{
		  created++;
		  local_originated++;
		}
	    }
	}

      if (is_trace && (bufs[i]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  sfw_trace_t *t = vlib_add_trace (vm, node, bufs[i], sizeof (*t));
	  t->sw_if_index = vnet_buffer (bufs[i])->sw_if_index[VLIB_TX];
	  t->next_index = nexts[i];
	  t->action = m->action;
	  t->session_found = (m->session != 0);
	  t->protocol = m->protocol;
	  t->nat_applied = 0;
	  t->nat64_dir = 0;
	}
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_vectors);
  sfw_expire_inline (sm, thread_index, now);

  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_PROCESSED,
			       n_vectors);
  vlib_node_increment_counter (vm, node->node_index,
			       SFW_ERROR_SESSIONS_CREATED, created);
  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_SESSION_HITS,
			       hits);
  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_DENIED,
			       denied);
  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_PERMITTED,
			       permitted);
  vlib_node_increment_counter (vm, node->node_index,
			       SFW_ERROR_LOCAL_ORIGINATED, local_originated);
  return n_vectors;
}

VLIB_NODE_FN (sfw_ip4_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return sfw_ip4_output_inline (vm, node, frame, 1);
  else
    return sfw_ip4_output_inline (vm, node, frame, 0);
}

/* --- IPv6 output arc (sfw-ip6-out) --- */

always_inline uword
sfw_ip6_output_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame, int is_trace)
{
  u32 *from, n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];
  sfw_main_t *sm = &sfw_main;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  u32 created = 0, hits = 0, denied = 0, permitted = 0, local_originated = 0;
  sfw_out_meta_t meta[VLIB_FRAME_SIZE];
  u32 i;

  from = vlib_frame_vector_args (frame);
  n_vectors = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_vectors);

  for (i = 0; i < n_vectors; i++)
    {
      u32 next0;
      vnet_feature_next (&next0, bufs[i]);
      nexts[i] = next0;
    }

  /* Pass 1 */
  for (i = 0; i < n_vectors; i++)
    {
      sfw_out_meta_t *m = &meta[i];
      clib_memset (m, 0, sizeof (*m));
      m->action = SFW_ACTION_PERMIT;

      /* See IPv4 output: IP header lives past the saved rewrite length. */
      u32 rw_len = vnet_buffer (bufs[i])->ip.save_rewrite_length;
      ip6_header_t *ip0 =
	(ip6_header_t *) ((u8 *) vlib_buffer_get_current (bufs[i]) + rw_len);
      u32 tx_sw_if_index = vnet_buffer (bufs[i])->sw_if_index[VLIB_TX];

      if (PREDICT_FALSE (
	    ip6_address_is_link_local_unicast (&ip0->src_address) ||
	    ip6_address_is_link_local_unicast (&ip0->dst_address)))
	{
	  permitted++;
	  continue;
	}

      m->protocol = ip0->protocol;

      u16 ip6_plen = clib_net_to_host_u16 (ip0->payload_length);
      u16 buf_len = vlib_buffer_length_in_chain (vm, bufs[i]);
      if (PREDICT_FALSE (ip6_plen < 4 ||
			 buf_len < sizeof (ip6_header_t) + 4))
	{
	  permitted++;
	  continue;
	}

      void *l4_hdr = ip6_next_header (ip0);
      sfw_extract_l4 (m->protocol, l4_hdr, &m->src_port, &m->dst_port,
		      &m->icmp_type, &m->icmp_code);

      clib_bihash_kv_48_8_t kv = { 0 }, result = { 0 };
      sfw_key6_t *key;
      u8 found_session = 0;
      u8 is_from_zone = 1;

      key = (sfw_key6_t *) &kv.key;
      ip6_address_copy (&key->src, &ip0->dst_address);
      ip6_address_copy (&key->dst, &ip0->src_address);
      key->src_port = m->dst_port;
      key->dst_port = m->src_port;
      key->protocol = m->protocol;

      if (clib_bihash_search_48_8 (&sm->session_hash, &kv, &result) == 0)
	{
	  found_session = 1;
	  is_from_zone = 1;
	}
      else
	{
	  clib_memset (&kv, 0, sizeof (kv));
	  key = (sfw_key6_t *) &kv.key;
	  ip6_address_copy (&key->src, &ip0->src_address);
	  ip6_address_copy (&key->dst, &ip0->dst_address);
	  key->src_port = m->src_port;
	  key->dst_port = m->dst_port;
	  key->protocol = m->protocol;
	  if (clib_bihash_search_48_8 (&sm->session_hash, &kv, &result) == 0)
	    {
	      found_session = 1;
	      is_from_zone = 0;
	    }
	}

      if (found_session)
	{
	  u32 st = sfw_session_thread (result.value);
	  u32 si = sfw_session_index (result.value);
	  m->session = pool_elt_at_index (sm->sessions[st], si);

	  if (PREDICT_TRUE (!m->session->tcp_rst &&
			    !(m->session->tcp_fin_fwd &&
			      m->session->tcp_fin_rev)))
	    {
	      if (st == thread_index)
		sfw_lru_touch (sm, m->session, now);
	      else
		m->session->expires = now + sm->session_timeout;
	    }

	  hits++;
	  m->action = SFW_ACTION_PERMIT;

	  if (m->protocol == IP_PROTOCOL_TCP)
	    {
	      tcp_header_t *tcp = (tcp_header_t *) l4_hdr;
	      u8 flags = tcp->flags;
	      if (PREDICT_FALSE (flags & TCP_FLAG_RST))
		{
		  m->session->tcp_rst = 1;
		  m->session->expires = now + SFW_TCP_CLOSE_TIMEOUT;
		}
	      else if (PREDICT_FALSE (flags & TCP_FLAG_FIN))
		{
		  if (is_from_zone)
		    m->session->tcp_fin_fwd = 1;
		  else
		    m->session->tcp_fin_rev = 1;
		  if (m->session->tcp_fin_fwd && m->session->tcp_fin_rev)
		    m->session->expires = now + SFW_TCP_CLOSE_TIMEOUT;
		}
	    }
	  continue;
	}

      if (!sfw_is_local_src6 (tx_sw_if_index, &ip0->src_address))
	continue;
      m->is_local_src = 1;

      if (tx_sw_if_index >= vec_len (sm->if_config))
	continue;
      u32 dst_zone = sm->if_config[tx_sw_if_index].zone_id;
      if (dst_zone == SFW_ZONE_NONE)
	continue;

      sfw_policy_t *policy =
	sfw_zone_pair_policy (sm, SFW_ZONE_LOCAL, dst_zone);
      if (PREDICT_FALSE (!policy))
	continue;

      m->policy = policy;

      if (m->protocol == IP_PROTOCOL_ICMP6 && policy->implicit_icmpv6 &&
	  sfw_is_implicit_icmpv6 (m->icmp_type))
	{
	  permitted++;
	  continue;
	}

      ip46_address_t src46 = { 0 }, dst46 = { 0 };
      ip6_address_copy (&src46.ip6, &ip0->src_address);
      ip6_address_copy (&dst46.ip6, &ip0->dst_address);
      m->action = sfw_match_rules (
	policy->rules, vec_len (policy->rules), policy->default_action, 1,
	&src46, &dst46, m->protocol, clib_net_to_host_u16 (m->src_port),
	clib_net_to_host_u16 (m->dst_port), m->icmp_type, m->icmp_code);
    }

  /* Pass 2 */
  for (i = 0; i < n_vectors; i++)
    {
      sfw_out_meta_t *m = &meta[i];
      u32 rw_len = vnet_buffer (bufs[i])->ip.save_rewrite_length;
      ip6_header_t *ip0 =
	(ip6_header_t *) ((u8 *) vlib_buffer_get_current (bufs[i]) + rw_len);

      if (m->action == SFW_ACTION_DENY)
	{
	  nexts[i] = SFW_NEXT_DROP;
	  bufs[i]->error = node->errors[SFW_ERROR_DENIED];
	  denied++;
	}
      else if (m->action == SFW_ACTION_PERMIT)
	{
	  if (!m->session && m->is_local_src)
	    permitted++;
	}
      else if ((m->action == SFW_ACTION_PERMIT_STATEFUL ||
		m->action == SFW_ACTION_PERMIT_STATEFUL_NAT) &&
	       !m->session && m->is_local_src)
	{
	  clib_bihash_kv_48_8_t gk = { 0 }, gr = { 0 };
	  sfw_key6_t *gkey = (sfw_key6_t *) &gk.key;
	  ip6_address_copy (&gkey->src, &ip0->dst_address);
	  ip6_address_copy (&gkey->dst, &ip0->src_address);
	  gkey->src_port = m->dst_port;
	  gkey->dst_port = m->src_port;
	  gkey->protocol = m->protocol;
	  if (clib_bihash_search_48_8 (&sm->session_hash, &gk, &gr) == 0)
	    {
	      hits++;
	      continue;
	    }

	  sfw_session_t *s = sfw_session_create (sm, thread_index, now);
	  if (PREDICT_TRUE (s != 0))
	    {
	      s->is_ip6 = 1;
	      s->nat_type = SFW_NAT_NONE;
	      s->has_nat_key = 1;
	      ip6_address_copy (&s->k6.src, &ip0->dst_address);
	      ip6_address_copy (&s->k6.dst, &ip0->src_address);
	      s->k6.src_port = m->dst_port;
	      s->k6.dst_port = m->src_port;
	      s->k6.protocol = m->protocol;

	      u64 enc = sfw_session_encode (
		thread_index, s - sm->sessions[thread_index]);

	      clib_bihash_kv_48_8_t kv1, kv2;
	      clib_memset (&kv1, 0, sizeof (kv1));
	      clib_memcpy_fast (&kv1.key, &s->k6, sizeof (sfw_key6_t));
	      kv1.value = enc;

	      clib_memset (&kv2, 0, sizeof (kv2));
	      sfw_key6_t *dk = (sfw_key6_t *) &kv2.key;
	      ip6_address_copy (&dk->src, &ip0->src_address);
	      ip6_address_copy (&dk->dst, &ip0->dst_address);
	      dk->src_port = m->src_port;
	      dk->dst_port = m->dst_port;
	      dk->protocol = m->protocol;
	      kv2.value = enc;

	      if (sfw_session_insert_hash (sm, s, enc, &kv1, &kv2) == 0)
		{
		  created++;
		  local_originated++;
		}
	    }
	}

      if (is_trace && (bufs[i]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  sfw_trace_t *t = vlib_add_trace (vm, node, bufs[i], sizeof (*t));
	  t->sw_if_index = vnet_buffer (bufs[i])->sw_if_index[VLIB_TX];
	  t->next_index = nexts[i];
	  t->action = m->action;
	  t->session_found = (m->session != 0);
	  t->protocol = m->protocol;
	  t->nat_applied = 0;
	  t->nat64_dir = 0;
	}
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_vectors);
  sfw_expire_inline (sm, thread_index, now);

  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_PROCESSED,
			       n_vectors);
  vlib_node_increment_counter (vm, node->node_index,
			       SFW_ERROR_SESSIONS_CREATED, created);
  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_SESSION_HITS,
			       hits);
  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_DENIED,
			       denied);
  vlib_node_increment_counter (vm, node->node_index, SFW_ERROR_PERMITTED,
			       permitted);
  vlib_node_increment_counter (vm, node->node_index,
			       SFW_ERROR_LOCAL_ORIGINATED, local_originated);
  return n_vectors;
}

VLIB_NODE_FN (sfw_ip6_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return sfw_ip6_output_inline (vm, node, frame, 1);
  else
    return sfw_ip6_output_inline (vm, node, frame, 0);
}

/* --- Node registrations --- */

#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (sfw_ip4_node) = {
  .name = "sfw-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_sfw_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (sfw_error_strings),
  .error_strings = sfw_error_strings,
  .n_next_nodes = SFW_N_NEXT,
  .next_nodes = {
    [SFW_NEXT_DROP] = "error-drop",
    [SFW_NEXT_LOOKUP_V4] = "ip4-lookup",
    [SFW_NEXT_LOOKUP_V6] = "ip6-lookup",
  },
};

VLIB_REGISTER_NODE (sfw_ip6_node) = {
  .name = "sfw-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_sfw_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (sfw_error_strings),
  .error_strings = sfw_error_strings,
  .n_next_nodes = SFW_N_NEXT,
  .next_nodes = {
    [SFW_NEXT_DROP] = "error-drop",
    [SFW_NEXT_LOOKUP_V4] = "ip4-lookup",
    [SFW_NEXT_LOOKUP_V6] = "ip6-lookup",
  },
};

VLIB_REGISTER_NODE (sfw_ip4_output_node) = {
  .name = "sfw-ip4-out",
  .vector_size = sizeof (u32),
  .format_trace = format_sfw_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (sfw_error_strings),
  .error_strings = sfw_error_strings,
  .n_next_nodes = SFW_N_NEXT,
  .next_nodes = {
    [SFW_NEXT_DROP] = "error-drop",
    [SFW_NEXT_LOOKUP_V4] = "ip4-lookup",
    [SFW_NEXT_LOOKUP_V6] = "ip6-lookup",
  },
};

VLIB_REGISTER_NODE (sfw_ip6_output_node) = {
  .name = "sfw-ip6-out",
  .vector_size = sizeof (u32),
  .format_trace = format_sfw_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (sfw_error_strings),
  .error_strings = sfw_error_strings,
  .n_next_nodes = SFW_N_NEXT,
  .next_nodes = {
    [SFW_NEXT_DROP] = "error-drop",
    [SFW_NEXT_LOOKUP_V4] = "ip4-lookup",
    [SFW_NEXT_LOOKUP_V6] = "ip6-lookup",
  },
};
#endif /* CLIB_MARCH_VARIANT */
