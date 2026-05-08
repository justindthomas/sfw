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

  /* Reject prefix lengths outside RFC 6052 §2.2's set before reading
   * any prefix bytes. Both ingress paths (CLI sfw_nat64_plen_valid in
   * sfw.c, binary API sfw_nat64_api_plen_valid in sfw_api.c) already
   * filter — but a length > 128 reaching this function would compute
   * pfx_bytes > 16 in the memcpy below and read past prefix->as_u8[15]
   * into adjacent caller memory, then write those bytes into the
   * synthesized IPv6 destination on the wire (CWE-125 + CWE-200).
   * Re-validate here so the disclosure primitive can't be revived by
   * a future ingress path that forgets the check. */
  switch (prefix_len)
    {
    case 32: case 40: case 48: case 56: case 64: case 96:
      break;
    default:
      return;
    }

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
    }
}

int
sfw_nat64_extract_v4 (const ip6_address_t *prefix, u8 prefix_len,
		      const ip6_address_t *v6, ip4_address_t *out_v4)
{
  /* Same defense as sfw_nat64_embed_v4: a `prefix_len > 128` reaching
   * here would compute pfx_bytes > 16 and the memcmp below would read
   * past the 16-byte v6 / prefix buffers. The original audit (F4)
   * declared this function safe by inspection of its switch's
   * default-return arm — but the OOB is in the pre-switch memcmp,
   * not the switch itself. */
  switch (prefix_len)
    {
    case 32: case 40: case 48: case 56: case 64: case 96:
      break;
    default:
      return -1;
    }

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
sfw_nat64_match_pool (sfw_main_t *sm, u32 table_id,
		      const ip6_address_t *v6_dst)
{
  u32 i;
  for (i = 0; i < vec_len (sm->nat_pools); i++)
    {
      sfw_nat_pool_t *p = &sm->nat_pools[i];
      if (p->kind != SFW_POOL_KIND_NAT64)
	continue;
      /* VRF guard: pool serves only its configured ingress VRF. */
      if (p->table_id != table_id)
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
  sfw_session_t *session;
} sfw_nat64_v6_to_v4_ctx_t;

typedef struct
{
  ip6_address_t new_src; /* prefix::v4_server (re-embedded) */
  ip6_address_t new_dst; /* v6 client (k6.dst) */
  sfw_session_t *session;
} sfw_nat64_v4_to_v6_ctx_t;

static int
sfw_nat64_v6_to_v4_outer_cb (ip6_header_t *ip6, ip4_header_t *ip4, void *arg)
{
  sfw_nat64_v6_to_v4_ctx_t *ctx = arg;
  ip4->src_address = ctx->new_src;
  ip4->dst_address = ctx->new_dst;
  return 0;
}

/* Inner packet of an ICMP error is the *original* datagram that caused
 * the error. In almost all real-world cases (PMTUD, TTL exceeded, port
 * unreachable replies, etc.) the inner datagram travels in the reverse
 * direction of the outer error — the error reporter received the
 * datagram and is complaining back to its sender. So the inner's v6
 * src was the outer's v6 dst (the v4 server, via the NAT64 prefix)
 * and the inner's v6 dst was the outer's v6 src (the v6 client).
 * Translating that inner to v4: src = v4_server, dst = v4_pool, and the
 * inner's L4 destination port (which in v6 form was the v6 client's
 * original source port, stored as session->k6.dst_port) translates
 * to the allocated v4 pool port. We also rewrite the inner L4
 * checksum for the port change; the helper will layer its own
 * pseudo-header (address) delta on top afterwards. */
static int
sfw_nat64_v6_to_v4_inner_cb (ip6_header_t *ip6, ip4_header_t *ip4, void *arg)
{
  sfw_nat64_v6_to_v4_ctx_t *ctx = arg;
  ip4->src_address = ctx->new_dst;
  ip4->dst_address = ctx->new_src;

  /* Rewrite inner L4 port/id. Assumes no inner extension headers —
   * true for the vast majority of real traffic. L4 lives immediately
   * after the v6 header. */
  u8 inner_proto = ip6->protocol;
  void *l4 = (u8 *) ip6 + sizeof (ip6_header_t);
  u16 new_dport = ctx->session->xlate.n64.v4_pool_port;

  if (inner_proto == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) l4;
      u16 old = tcp->dst_port;
      tcp->dst_port = new_dport;
      ip_csum_t csum = tcp->checksum;
      csum =
	ip_csum_update (csum, old, new_dport, tcp_header_t, dst_port);
      tcp->checksum = ip_csum_fold (csum);
    }
  else if (inner_proto == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *) l4;
      u16 old = udp->dst_port;
      udp->dst_port = new_dport;
      if (udp->checksum != 0)
	{
	  ip_csum_t csum = udp->checksum;
	  csum =
	    ip_csum_update (csum, old, new_dport, udp_header_t, dst_port);
	  udp->checksum = ip_csum_fold (csum);
	}
    }
  else if (inner_proto == IP_PROTOCOL_ICMP6)
    {
      /* Inner ICMPv6 echo: translate the id. The helper will fully
       * recompute the inner ICMP checksum after we return. */
      icmp46_header_t *icmp = (icmp46_header_t *) l4;
      if (icmp->type == ICMP6_echo_request || icmp->type == ICMP6_echo_reply)
	((u16 *) icmp)[2] = new_dport;
    }
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
  /* Inner direction is reversed from outer: the inner packet in an
   * ICMP error is the original packet that caused the error, which
   * went in the opposite direction. For outer v4 src=v4_server,
   * dst=v4_pool (an error complaining about what we sent), the inner
   * was the original packet v4_pool -> v4_server. Translating back
   * to v6: inner src = v6_client, inner dst = prefix::v4_server.
   *
   * The outer new_src here is prefix::v4_server (built from the
   * session in translate_v4_to_v6) and new_dst is v6_client, so we
   * assign inner src = new_dst (v6_client), inner dst = new_src
   * (prefix::v4_server). */
  ip6_address_copy (&ip6->src_address, &ctx->new_dst);
  ip6_address_copy (&ip6->dst_address, &ctx->new_src);

  /* Rewrite inner L4 source port back to the original v6 client port.
   * The original v4 inner had sport = v4_pool_port (our allocated
   * translated port); in the v6 form it should be the client's
   * original source port, stored as session->k6.dst_port. */
  u8 inner_proto = ip4->protocol;
  void *l4 = (u8 *) ip4 + sizeof (ip4_header_t);
  u16 new_sport = ctx->session->k6.dst_port;

  if (inner_proto == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) l4;
      u16 old = tcp->src_port;
      tcp->src_port = new_sport;
      ip_csum_t csum = tcp->checksum;
      csum =
	ip_csum_update (csum, old, new_sport, tcp_header_t, src_port);
      tcp->checksum = ip_csum_fold (csum);
    }
  else if (inner_proto == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *) l4;
      u16 old = udp->src_port;
      udp->src_port = new_sport;
      if (udp->checksum != 0)
	{
	  ip_csum_t csum = udp->checksum;
	  csum =
	    ip_csum_update (csum, old, new_sport, udp_header_t, src_port);
	  udp->checksum = ip_csum_fold (csum);
	}
    }
  else if (inner_proto == IP_PROTOCOL_ICMP)
    {
      icmp46_header_t *icmp = (icmp46_header_t *) l4;
      if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply)
	((u16 *) icmp)[2] = new_sport;
    }
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
  ctx.session = session;

  if (next_header == IP_PROTOCOL_ICMP6)
    {
      /* F5/F6 length pre-check, symmetric to the v4→v6 path below.
       * `icmp6_to_icmp` calls our inner cb on TCP/UDP/ICMP6 inner
       * datagrams; the cb reads/writes the inner L4 checksum at byte
       * offset 16-17 (TCP), 6-7 (UDP), or 4-5 (ICMP echo id). RFC 4443
       * requires ICMPv6 errors to carry "as much of the invoking packet
       * as fits in 1280 bytes", but an attacker can craft a smaller
       * one. Reject buffers that don't span outer IPv6 + outer ICMP6 +
       * inner IPv6 + 18 bytes of inner L4 (TCP-conservative); without
       * this, the cb reads/writes past the buffer (CWE-125 + CWE-787
       * memory-corruption primitive). */
      const size_t inner_l4_min = 18;
      if (b->current_length <
	  sizeof (ip6_header_t) + sizeof (icmp46_header_t) +
	    sizeof (ip6_header_t) + inner_l4_min)
	return -1;
      /* F8: `icmp6_to_icmp` recomputes the outer ICMP checksum by
       * walking `ip6->payload_length` bytes (vnet/ip/ip6_to_ip4.h:521).
       * payload_length is u16 attacker-controlled; an inflated value
       * walks tens of KB past the buffer and folds adjacent
       * packet-pool memory into the on-wire checksum (CWE-125 +
       * CWE-200). Mirror F7's drop-on-mismatch shape per RFC 7915
       * §4.5: drop when the declared payload length exceeds what
       * actually follows the IPv6 header. */
      u16 declared_pl = clib_net_to_host_u16 (ip6->payload_length);
      if (declared_pl > b->current_length - sizeof (ip6_header_t))
	return -1;

      /* F9: same shape as F8 but on the INNER header carried in an
       * ICMP6 error's body. The helper at vnet/ip/ip6_to_ip4.h:470
       * computes inner_ip4->length from inner_ip6->payload_length and
       * walks `inner_ip4->length - sizeof(ip4_header_t)` bytes through
       * `ip_incremental_checksum`. inner_ip6->payload_length is an
       * independent attacker-controlled u16 — F8's outer bound doesn't
       * cover it. Only error-type ICMP6 packets carry an inner; gate
       * on type so legitimate echo packets aren't mis-rejected by the
       * read-as-payload-length of arbitrary echo data. */
      icmp46_header_t *outer_icmp6 = (icmp46_header_t *) (ip6 + 1);
      u8 t6 = outer_icmp6->type;
      if (t6 == ICMP6_destination_unreachable ||
	  t6 == ICMP6_packet_too_big ||
	  t6 == ICMP6_time_exceeded ||
	  t6 == ICMP6_parameter_problem)
	{
	  /* Inner IPv6 header sits 8 bytes past the outer ICMP6 header.
	   * F5/F6 already required current_length >= 106 = 40+8+40+18,
	   * so the inner ip6 header is fully readable here.
	   *
	   * F9.1: the ICMPv6 *error* outer header is 8 bytes (4-byte
	   * generic icmp46_header_t + 4 bytes error-specific data per
	   * RFC 4443 §3) — NOT sizeof(icmp46_header_t)=4. The VPP
	   * helper at vnet/ip/ip6_to_ip4.h:259-307 uses the literal +8;
	   * mirror that here so we read inner_ip6->payload_length from
	   * the right offset. The previous F9 fix was off by 4, which
	   * read part of the inner ip_version_traffic_class_and_flow_label
	   * (12 bits attacker-controlled flow label) as if it were
	   * payload_length — small misread values let real inflated
	   * lengths slip through. */
	  ip6_header_t *inner_ip6 =
	    (ip6_header_t *) ((u8 *) outer_icmp6 + 8);
	  u16 inner_pl = clib_net_to_host_u16 (inner_ip6->payload_length);
	  size_t inner_pl_offset =
	    sizeof (ip6_header_t) + 8 + sizeof (ip6_header_t);
	  if (inner_pl > b->current_length - inner_pl_offset)
	    return -1;
	}
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
  ctx.session = session;
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
      /* F8: `icmp_to_icmp6` recomputes the outer ICMP checksum by
       * walking `ip4->length` bytes — `ip_incremental_checksum (...,
       * icmp, ip6->payload_length)` at vnet/ip/ip4_to_ip6.h:482, with
       * payload_length derived from ip4->length. An inflated u16
       * length walks tens of KB past the buffer into adjacent
       * packet-pool memory and folds it into the on-wire checksum
       * (CWE-125 + CWE-200). The F5/F6 pre-check below only fires for
       * error types — echo requests bypass it and can hit the helper
       * with a 28-byte buffer claiming a 65535-byte length. Validate
       * up front, mirroring F7's drop-on-mismatch per RFC 7915 §4.5.
       *
       * F10: also require ip_len >= sizeof(ip4_header_t). Without
       * the lower bound the helper computes
       *   ip6->payload_length = htons(ntohs(ip4->length) - 20)
       * which wraps the u16 to ~65500 when ip4->length < 20, then
       * walks ~65 KB past the buffer (CWE-191 + CWE-125 + CWE-200). */
      if (ip_len < sizeof (ip4_header_t) || ip_len > b->current_length)
	return -1;

      /* VPP's icmp_to_icmp6 (vnet/ip/ip4_to_ip6.h) calls os_panic() if
       * the embedded inner header in an ICMP error reports a protocol
       * other than TCP/UDP/ICMP. An attacker on the v4 side can reach
       * that path with a crafted ICMPv4 error carrying e.g. an inner
       * ESP/GRE/SCTP header — remote DoS on the data plane. Pre-screen
       * those before handing the buffer to the helper. */
      icmp46_header_t *outer_icmp = (icmp46_header_t *) (ip4 + 1);
      u8 t = outer_icmp->type;
      if (t == ICMP4_destination_unreachable ||
	  t == ICMP4_time_exceeded ||
	  t == ICMP4_parameter_problem)
	{
	  /* Inner IPv4 header sits 8 bytes past the outer ICMP header.
	   * F5: also require 18 bytes of inner L4 — `icmp_to_icmp6` will
	   * call our inner cb, which reads/writes the inner L4 checksum
	   * at byte offset 16-17 (TCP) — without this, an RFC-792-minimum
	   * 8-byte inner L4 echo drives a 2-byte OOB read+write past the
	   * buffer (CWE-125 + CWE-787). 18 bytes is conservative for TCP;
	   * UDP (8) and ICMP (6) fit too. */
	  const size_t inner_l4_min = 18;
	  if (b->current_length <
	      sizeof (ip4_header_t) + 8 + sizeof (ip4_header_t) + inner_l4_min)
	    return -1;
	  ip4_header_t *inner = (ip4_header_t *) ((u8 *) outer_icmp + 8);
	  u8 ip = inner->protocol;
	  if (ip != IP_PROTOCOL_TCP && ip != IP_PROTOCOL_UDP &&
	      ip != IP_PROTOCOL_ICMP)
	    return -1;

	  /* F9 (v4→v6 sibling): bound inner_ip4->length the same way F8
	   * bounds the outer. The helper at vnet/ip/ip4_to_ip6.h:402
	   * walks `ntohs(inner_ip6->payload_length)` bytes for the inner
	   * ICMP recompute, where inner_ip6->payload_length =
	   * htons(ntohs(inner_ip4->length) - 20). The same lower-bound
	   * guard from F10 (length < sizeof(ip4_header_t) → wrap to ~65500)
	   * applies on the inner header too.
	   *
	   * F9.1: the ICMPv4 error outer header is 8 bytes (RFC 792 §3),
	   * not sizeof(icmp46_header_t)=4. The `inner` pointer above
	   * already uses the correct +8; the offset math here also has
	   * to use 8 so the upper bound matches the actual inner_ip4
	   * position. */
	  size_t inner_ip4_offset =
	    sizeof (ip4_header_t) + 8;
	  u16 inner_len = clib_net_to_host_u16 (inner->length);
	  if (inner_len < sizeof (ip4_header_t) ||
	      inner_len > b->current_length - inner_ip4_offset)
	    return -1;
	}

      /* F11: ICMP4 parameter_problem code 0/2 — `icmp_to_icmp6` indexes
       * a static 20-entry `icmp_to_icmp6_updater_pointer_table` at
       * vnet/ip/ip4_to_ip6.h:211 with the attacker-supplied byte at
       * offset 4 of the ICMP header (the v4 "pointer" field), with no
       * bounds check. Pointer ≥ 20 reads OOB into adjacent .rodata,
       * and the read byte is then written into the outgoing v6 packet
       * (CWE-125 + CWE-129 + CWE-200). The table has only 20 entries
       * so reject any pointer byte ≥ 20 before invoking the helper.
       * Pointer values > 19 are legitimate in IPv4 (e.g., 28 for an
       * options-field error), so this rejects some valid ICMPv4
       * traffic — but the upstream helper's table doesn't extend
       * past index 19, so those translations weren't well-formed
       * anyway. Cleaner upstream fix would be in VPP itself. */
      if (t == ICMP4_parameter_problem &&
	  (outer_icmp->code == ICMP4_parameter_problem_pointer_indicates_error
	   || outer_icmp->code == ICMP4_parameter_problem_bad_length))
	{
	  /* Need at least sizeof(ip4_header_t)+sizeof(icmp46_header_t)+1
	   * bytes to safely read the pointer byte (helper's
	   * `*((u8 *)(icmp+1))`). F5/F6 minimum (66 bytes) covers this
	   * for error types, but parameter_problem can hit the helper
	   * directly without an inner — bound-check explicitly. */
	  if (b->current_length <
	      sizeof (ip4_header_t) + sizeof (icmp46_header_t) + 1)
	    return -1;
	  u8 ptr_byte = *((u8 *) outer_icmp + sizeof (icmp46_header_t));
	  if (ptr_byte >= 20)
	    return -1;
	}

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
      /* F7: ip6->payload_length is derived from the attacker-supplied
       * v4 ip4->length and is u16 (up to 65535). VPP buffers are
       * typically 2KB, so a forged total_length walks
       * ip_incremental_checksum tens of KB past the buffer, leaking
       * adjacent packet-pool memory into the folded checksum that
       * goes out on the wire (CWE-125 + CWE-200). Drop translation
       * when the declared L4 length exceeds the buffer's L4 reality —
       * RFC 7915 §4.5 explicitly permits dropping packets whose
       * UDP checksum cannot be correctly recomputed. */
      size_t l4_avail =
	b->current_length - ((u8 *) udp - (u8 *) vlib_buffer_get_current (b));
      if (l4_len > l4_avail)
	return -1;
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
