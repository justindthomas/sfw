/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 */

/* sfw_nat64.c - stateful NAT64 (RFC 6146) + RFC 6052 prefix embed/extract
 * + RFC 7915 packet translation (TCP/UDP inline, ICMP via core VPP helpers).
 *
 * Deliberately does NOT depend on VPP's stock plugins/nat/nat64/ code,
 * which sfw replaces. The only VPP dependencies are the clean, plugin-
 * free translation helpers in vnet/ip/ip6_to_ip4.h and ip4_to_ip6.h. */

#include <sfw/sfw.h>
#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/ip/ip6_to_ip4.h>
#include <vnet/ip/ip4_to_ip6.h>

/* --- RFC 6052 §2.2 address embedding/extraction ---
 *
 * Concatenation layout by prefix length (byte indices into the 16-byte v6):
 *
 *   /32:   [0..3] prefix [4..7] v4 [8] u=0 [9..15] suffix=0
 *   /40:   [0..4] prefix [5..7] v4[0..2] [8] u=0 [9] v4[3] [10..15] suffix=0
 *   /48:   [0..5] prefix [6..7] v4[0..1] [8] u=0 [9..10] v4[2..3] [11..15]=0
 *   /56:   [0..6] prefix [7] v4[0] [8] u=0 [9..11] v4[1..3] [12..15]=0
 *   /64:   [0..7] prefix [8] u=0 [9..12] v4 [13..15]=0
 *   /96:   [0..11] prefix [12..15] v4
 *
 * The "u-octet" (byte 8) is RFC 6052's reserved field and MUST be zero in
 * embedded addresses. Prefix lengths other than the six above are invalid
 * per RFC 6052; sfw_nat64_pool_add_del rejects them at config time. */

void
sfw_nat64_embed_v4 (const ip6_address_t *prefix, u8 prefix_len,
		    const ip4_address_t *v4, ip6_address_t *out_v6)
{
  clib_memset (out_v6, 0, sizeof (*out_v6));
  /* Copy the prefix bits first — the u-octet and remainder will be
   * overwritten for short prefixes below. */
  u8 pfx_bytes = prefix_len / 8;
  clib_memcpy_fast (out_v6->as_u8, prefix->as_u8, pfx_bytes);

  switch (prefix_len)
    {
    case 32:
      /* [4..7] = v4 */
      clib_memcpy_fast (&out_v6->as_u8[4], &v4->as_u8[0], 4);
      break;
    case 40:
      /* [5..7] = v4[0..2], skip u-octet at [8], [9] = v4[3] */
      clib_memcpy_fast (&out_v6->as_u8[5], &v4->as_u8[0], 3);
      out_v6->as_u8[8] = 0;
      out_v6->as_u8[9] = v4->as_u8[3];
      break;
    case 48:
      /* [6..7] = v4[0..1], [8]=0, [9..10] = v4[2..3] */
      clib_memcpy_fast (&out_v6->as_u8[6], &v4->as_u8[0], 2);
      out_v6->as_u8[8] = 0;
      clib_memcpy_fast (&out_v6->as_u8[9], &v4->as_u8[2], 2);
      break;
    case 56:
      /* [7] = v4[0], [8]=0, [9..11] = v4[1..3] */
      out_v6->as_u8[7] = v4->as_u8[0];
      out_v6->as_u8[8] = 0;
      clib_memcpy_fast (&out_v6->as_u8[9], &v4->as_u8[1], 3);
      break;
    case 64:
      /* [8]=0 (already zero), [9..12] = v4 */
      out_v6->as_u8[8] = 0;
      clib_memcpy_fast (&out_v6->as_u8[9], &v4->as_u8[0], 4);
      break;
    case 96:
      /* [12..15] = v4 */
      clib_memcpy_fast (&out_v6->as_u8[12], &v4->as_u8[0], 4);
      break;
    default:
      /* Config validation should prevent us reaching here. Zero-fill
       * leaves the v4 embedded as 0.0.0.0 so any extract immediately
       * fails the prefix match — observable rather than silent. */
      break;
    }
}

int
sfw_nat64_extract_v4 (const ip6_address_t *prefix, u8 prefix_len,
		      const ip6_address_t *v6, ip4_address_t *out_v4)
{
  u8 pfx_bytes = prefix_len / 8;
  if (pfx_bytes && clib_memcmp (v6->as_u8, prefix->as_u8, pfx_bytes) != 0)
    return -1;

  switch (prefix_len)
    {
    case 32:
      clib_memcpy_fast (&out_v4->as_u8[0], &v6->as_u8[4], 4);
      break;
    case 40:
      if (v6->as_u8[8] != 0)
	return -1;
      clib_memcpy_fast (&out_v4->as_u8[0], &v6->as_u8[5], 3);
      out_v4->as_u8[3] = v6->as_u8[9];
      break;
    case 48:
      if (v6->as_u8[8] != 0)
	return -1;
      clib_memcpy_fast (&out_v4->as_u8[0], &v6->as_u8[6], 2);
      clib_memcpy_fast (&out_v4->as_u8[2], &v6->as_u8[9], 2);
      break;
    case 56:
      if (v6->as_u8[8] != 0)
	return -1;
      out_v4->as_u8[0] = v6->as_u8[7];
      clib_memcpy_fast (&out_v4->as_u8[1], &v6->as_u8[9], 3);
      break;
    case 64:
      if (v6->as_u8[8] != 0)
	return -1;
      clib_memcpy_fast (&out_v4->as_u8[0], &v6->as_u8[9], 4);
      break;
    case 96:
      clib_memcpy_fast (&out_v4->as_u8[0], &v6->as_u8[12], 4);
      break;
    default:
      return -1;
    }
  return 0;
}

u32
sfw_nat64_match_pool (sfw_main_t *sm, const ip6_address_t *v6_dst)
{
  u32 i;
  for (i = 0; i < vec_len (sm->nat_pools); i++)
    {
      sfw_nat_pool_t *p = &sm->nat_pools[i];
      if (p->kind != SFW_POOL_KIND_NAT64)
	continue;

      u8 pfx_bytes = p->nat64_prefix_len / 8;
      if (pfx_bytes == 0)
	return i; /* malformed — shouldn't happen if add_del validates */
      if (clib_memcmp (v6_dst->as_u8, p->nat64_prefix.as_u8, pfx_bytes) == 0)
	{
	  /* For lengths where byte 8 is the u-octet, also verify it's zero.
	   * An arbitrary v6 address whose leading bytes happen to match the
	   * prefix but whose u-octet is nonzero is not a NAT64 address. */
	  switch (p->nat64_prefix_len)
	    {
	    case 40:
	    case 48:
	    case 56:
	    case 64:
	      if (v6_dst->as_u8[8] != 0)
		continue;
	      break;
	    default:
	      break;
	    }
	  return i;
	}
    }
  return ~0;
}

/* --- Packet rewrite ---
 *
 * RFC 7915 §5 (v6→v4) and §4 (v4→v6). For TCP/UDP we write the
 * translation directly — simpler than repurposing VPP's generic helpers
 * that target the stock NAT64 plugin's data model. For ICMP we call
 * icmp6_to_icmp / icmp_to_icmp6 from core VPP with a small callback
 * that stamps our translated addresses into the new v4/v6 header. */

typedef struct
{
  ip4_address_t new_src; /* v4 pool address (session->xlate.n64.v4_pool) */
  ip4_address_t new_dst; /* embedded v4 dst (session->xlate.n64.v4_server) */
} sfw_nat64_v6_to_v4_ctx_t;

typedef struct
{
  ip6_address_t new_src; /* prefix::v4_server (re-embedded) */
  ip6_address_t new_dst; /* v6 client (k6.dst) */
} sfw_nat64_v4_to_v6_ctx_t;

static int
sfw_nat64_v6_to_v4_outer_cb (ip6_header_t *ip6, ip4_header_t *ip4, void *arg)
{
  sfw_nat64_v6_to_v4_ctx_t *ctx = arg;
  ip4->src_address = ctx->new_src;
  ip4->dst_address = ctx->new_dst;
  return 0;
}

/* For inner ICMP errors, the embedded packet is the v6-side copy of the
 * original outbound. From the remote's POV it was addressed to the v4
 * server; so inner src = v4_pool (our translated src) and inner dst =
 * v4_server (the remote itself). Mirrors the outer translation. */
static int
sfw_nat64_v6_to_v4_inner_cb (ip6_header_t *ip6, ip4_header_t *ip4, void *arg)
{
  sfw_nat64_v6_to_v4_ctx_t *ctx = arg;
  ip4->src_address = ctx->new_src;
  ip4->dst_address = ctx->new_dst;
  return 0;
}

static int
sfw_nat64_v4_to_v6_outer_cb (vlib_buffer_t *b, ip4_header_t *ip4,
			     ip6_header_t *ip6, void *arg)
{
  sfw_nat64_v4_to_v6_ctx_t *ctx = arg;
  ip6_address_copy (&ip6->src_address, &ctx->new_src);
  ip6_address_copy (&ip6->dst_address, &ctx->new_dst);
  return 0;
}

static int
sfw_nat64_v4_to_v6_inner_cb (vlib_buffer_t *b, ip4_header_t *ip4,
			     ip6_header_t *ip6, void *arg)
{
  sfw_nat64_v4_to_v6_ctx_t *ctx = arg;
  /* Inner direction is reversed: the embedded packet in an ICMP error
   * was an outgoing packet from the remote's POV, meaning our client's
   * traffic translated back to v6. Inner src = v6 client (from their
   * POV they sent *to* the v4 server). For the outer ICMP error, the
   * v4 layer had src = server, dst = pool; the inner embedded packet
   * had src = pool, dst = server. Translating back means inner v6
   * src = prefix::server, inner v6 dst = v6_client. */
  ip6_address_copy (&ip6->src_address, &ctx->new_dst);
  ip6_address_copy (&ip6->dst_address, &ctx->new_src);
  return 0;
}

int
sfw_nat64_translate_v6_to_v4 (vlib_main_t *vm, vlib_buffer_t *b,
			      sfw_session_t *session)
{
  ip6_header_t *ip6 = vlib_buffer_get_current (b);
  u16 payload_length = clib_net_to_host_u16 (ip6->payload_length);
  u8 hop_limit = ip6->hop_limit;
  u32 ip_version_traffic_class_and_flow_label =
    ip6->ip_version_traffic_class_and_flow_label;
  u8 next_header = ip6->protocol;

  /* Save v6 addresses for pseudo-header checksum fixup. */
  ip6_address_t old_src, old_dst;
  old_src.as_u64[0] = ip6->src_address.as_u64[0];
  old_src.as_u64[1] = ip6->src_address.as_u64[1];
  old_dst.as_u64[0] = ip6->dst_address.as_u64[0];
  old_dst.as_u64[1] = ip6->dst_address.as_u64[1];

  sfw_nat64_v6_to_v4_ctx_t ctx;
  ctx.new_src = session->xlate.n64.v4_pool;
  ctx.new_dst = session->xlate.n64.v4_server;

  if (next_header == IP_PROTOCOL_ICMP6)
    {
      /* Core VPP helper handles the entire rewrite including header
       * shrink (vlib_buffer_advance), pseudo-header fixup, inner-packet
       * recursion for error messages, echo type translation, and L4
       * checksum recomputation. */
      int rv = icmp6_to_icmp (vm, b, sfw_nat64_v6_to_v4_outer_cb, &ctx,
			      sfw_nat64_v6_to_v4_inner_cb, &ctx);
      if (rv != 0)
	return rv;
      /* After icmp6_to_icmp, buffer-current points at the new IPv4
       * header. Stamp in the translated source port (ICMP echo id). */
      ip4_header_t *ip4 = vlib_buffer_get_current (b);
      if (ip4->protocol == IP_PROTOCOL_ICMP)
	{
	  icmp46_header_t *icmp = (icmp46_header_t *) (ip4 + 1);
	  if (icmp->type == ICMP4_echo_request ||
	      icmp->type == ICMP4_echo_reply)
	    {
	      u16 old_id = ((u16 *) icmp)[2];
	      u16 new_id = session->xlate.n64.v4_pool_port;
	      ((u16 *) icmp)[2] = new_id;
	      /* Incremental ICMP checksum update for the id change. */
	      ip_csum_t csum = icmp->checksum;
	      csum = ip_csum_update (csum, old_id, new_id, icmp46_header_t,
				     checksum /* dummy */);
	      icmp->checksum = ip_csum_fold (csum);
	    }
	}
      return 0;
    }

  /* TCP / UDP: write translation in place. Net shrink: IPv6 header (40)
   * - IPv4 header (20) = 20 bytes; vlib_buffer_advance by +20. */
  if (next_header != IP_PROTOCOL_TCP && next_header != IP_PROTOCOL_UDP)
    return -1;

  vlib_buffer_advance (b, sizeof (ip6_header_t) - sizeof (ip4_header_t));
  ip4_header_t *ip4 = vlib_buffer_get_current (b);

  ip4->ip_version_and_header_length = IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
  ip4->tos = ip6_translate_tos (ip_version_traffic_class_and_flow_label);
  ip4->length =
    clib_host_to_net_u16 (payload_length + sizeof (ip4_header_t));
  ip4->fragment_id = 0;
  ip4->flags_and_fragment_offset =
    clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);
  ip4->ttl = hop_limit;
  ip4->protocol = next_header;
  ip4->src_address = session->xlate.n64.v4_pool;
  ip4->dst_address = session->xlate.n64.v4_server;
  ip4->checksum = ip4_header_checksum (ip4);

  /* L4 checksum pseudo-header swap: subtract v6 pseudo, add v4 pseudo,
   * subtract old src port, add new src port. */
  u16 old_src_port, new_src_port = session->xlate.n64.v4_pool_port;
  u16 *l4_csum_ptr;
  if (next_header == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) (ip4 + 1);
      old_src_port = tcp->src_port;
      tcp->src_port = new_src_port;
      l4_csum_ptr = &tcp->checksum;
    }
  else /* UDP */
    {
      udp_header_t *udp = (udp_header_t *) (ip4 + 1);
      old_src_port = udp->src_port;
      udp->src_port = new_src_port;
      l4_csum_ptr = &udp->checksum;
    }

  if (next_header == IP_PROTOCOL_UDP && *l4_csum_ptr == 0)
    {
      /* IPv4 UDP permits zero checksum; IPv6 required it. RFC 7915 §4.5
       * says "any" UDP packet without a checksum MUST be dropped rather
       * than translated with an elided checksum — but we got here with
       * a valid checksum from IPv6. This branch really shouldn't fire. */
    }
  else
    {
      ip_csum_t csum = *l4_csum_ptr;
      csum = ip_csum_sub_even (csum, old_src.as_u64[0]);
      csum = ip_csum_sub_even (csum, old_src.as_u64[1]);
      csum = ip_csum_sub_even (csum, old_dst.as_u64[0]);
      csum = ip_csum_sub_even (csum, old_dst.as_u64[1]);
      csum = ip_csum_add_even (csum, ip4->src_address.as_u32);
      csum = ip_csum_add_even (csum, ip4->dst_address.as_u32);
      csum = ip_csum_sub_even (csum, old_src_port);
      csum = ip_csum_add_even (csum, new_src_port);
      *l4_csum_ptr = ip_csum_fold (csum);
    }

  return 0;
}

int
sfw_nat64_translate_v4_to_v6 (vlib_main_t *vm, vlib_buffer_t *b,
			      sfw_session_t *session)
{
  /* Buffer grows by 20 bytes on a TCP/UDP v4->v6 translation. Guard
   * against insufficient headroom before calling vlib_buffer_advance
   * with a negative offset. Standard VPP buffers have 128 bytes of
   * pre-data headroom (VLIB_BUFFER_PRE_DATA_SIZE); this is almost
   * always satisfied, but we drop defensively if not. */
  ip4_header_t *ip4 = vlib_buffer_get_current (b);
  u16 ip_len = clib_net_to_host_u16 (ip4->length);
  u8 tos = ip4->tos;
  u8 ttl = ip4->ttl;
  u8 protocol = ip4->protocol;

  sfw_nat64_v4_to_v6_ctx_t ctx;
  /* v6 src = prefix::v4_server (extracted from session for stability) */
  {
    sfw_main_t *sm = &sfw_main;
    sfw_nat_pool_t *pool =
      &sm->nat_pools[session->xlate.n64.pool_idx];
    sfw_nat64_embed_v4 (&pool->nat64_prefix, pool->nat64_prefix_len,
			&session->xlate.n64.v4_server, &ctx.new_src);
  }
  /* v6 dst = original v6 client. Session k6 is stored reversed (return
   * direction), so the client's address is in k6.dst. */
  ip6_address_copy (&ctx.new_dst, &session->k6.dst);

  if (protocol == IP_PROTOCOL_ICMP)
    {
      int rv = icmp_to_icmp6 (b, sfw_nat64_v4_to_v6_outer_cb, &ctx,
			      sfw_nat64_v4_to_v6_inner_cb, &ctx);
      if (rv != 0)
	return rv;
      /* Restore original v6 client echo id (session->k6.dst_port holds
       * the original v6 sport = original echo id). */
      ip6_header_t *ip6 = vlib_buffer_get_current (b);
      if (ip6->protocol == IP_PROTOCOL_ICMP6)
	{
	  icmp46_header_t *icmp = (icmp46_header_t *) (ip6 + 1);
	  if (icmp->type == ICMP6_echo_request ||
	      icmp->type == ICMP6_echo_reply)
	    {
	      u16 old_id = ((u16 *) icmp)[2];
	      u16 new_id = session->k6.dst_port;
	      ((u16 *) icmp)[2] = new_id;
	      ip_csum_t csum = icmp->checksum;
	      csum = ip_csum_update (csum, old_id, new_id, icmp46_header_t,
				     checksum);
	      icmp->checksum = ip_csum_fold (csum);
	    }
	}
      return 0;
    }

  if (protocol != IP_PROTOCOL_TCP && protocol != IP_PROTOCOL_UDP)
    return -1;

  /* Save old v4 addresses + old dst port for pseudo-header fixup. */
  ip4_address_t old_v4_src = ip4->src_address;
  ip4_address_t old_v4_dst = ip4->dst_address;

  /* Headroom check: need 20 extra bytes of prepended space. */
  if (PREDICT_FALSE (b->current_data <
		     (i16) (sizeof (ip6_header_t) - sizeof (ip4_header_t))))
    return -2;

  vlib_buffer_advance (b, -(i32) (sizeof (ip6_header_t) - sizeof (ip4_header_t)));
  ip6_header_t *ip6 = vlib_buffer_get_current (b);

  /* Build IPv6 header. Traffic class = v4 TOS; flow label = 0. */
  ip6->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0x60000000 | ((u32) tos << 20));
  ip6->payload_length =
    clib_host_to_net_u16 (ip_len - sizeof (ip4_header_t));
  ip6->protocol = protocol;
  ip6->hop_limit = ttl;
  ip6_address_copy (&ip6->src_address, &ctx.new_src);
  ip6_address_copy (&ip6->dst_address, &ctx.new_dst);

  /* L4 checksum: swap v4 pseudo for v6 pseudo and restore the original
   * client's port in the appropriate field (dst port for return
   * traffic: v4 return packet has dst_port = v4_pool_port; v6 packet
   * gets dst_port = original v6 client sport = session->k6.dst_port). */
  u16 old_dst_port, new_dst_port = session->k6.dst_port;
  u16 *l4_csum_ptr;
  void *l4_hdr = (u8 *) ip6 + sizeof (ip6_header_t);
  if (protocol == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) l4_hdr;
      old_dst_port = tcp->dst_port;
      tcp->dst_port = new_dst_port;
      l4_csum_ptr = &tcp->checksum;
    }
  else /* UDP */
    {
      udp_header_t *udp = (udp_header_t *) l4_hdr;
      old_dst_port = udp->dst_port;
      udp->dst_port = new_dst_port;
      l4_csum_ptr = &udp->checksum;
    }

  if (protocol == IP_PROTOCOL_UDP && *l4_csum_ptr == 0)
    {
      /* Translated UDP with zero checksum over IPv6 is illegal. RFC 7915
       * says drop unless we can recompute; recompute over payload. */
      udp_header_t *udp = (udp_header_t *) l4_hdr;
      u16 l4_len = clib_net_to_host_u16 (ip6->payload_length);
      ip_csum_t csum = ip_incremental_checksum (0, udp, l4_len);
      csum = ip_csum_with_carry (csum, clib_host_to_net_u16 (l4_len));
      csum =
	ip_csum_with_carry (csum, clib_host_to_net_u16 (IP_PROTOCOL_UDP));
      csum = ip_csum_with_carry (csum, ip6->src_address.as_u64[0]);
      csum = ip_csum_with_carry (csum, ip6->src_address.as_u64[1]);
      csum = ip_csum_with_carry (csum, ip6->dst_address.as_u64[0]);
      csum = ip_csum_with_carry (csum, ip6->dst_address.as_u64[1]);
      udp->checksum = ~ip_csum_fold (csum);
      if (udp->checksum == 0)
	udp->checksum = 0xffff;
    }
  else
    {
      ip_csum_t csum = *l4_csum_ptr;
      csum = ip_csum_sub_even (csum, old_v4_src.as_u32);
      csum = ip_csum_sub_even (csum, old_v4_dst.as_u32);
      csum = ip_csum_add_even (csum, ip6->src_address.as_u64[0]);
      csum = ip_csum_add_even (csum, ip6->src_address.as_u64[1]);
      csum = ip_csum_add_even (csum, ip6->dst_address.as_u64[0]);
      csum = ip_csum_add_even (csum, ip6->dst_address.as_u64[1]);
      csum = ip_csum_sub_even (csum, old_dst_port);
      csum = ip_csum_add_even (csum, new_dst_port);
      *l4_csum_ptr = ip_csum_fold (csum);
    }

  return 0;
}
