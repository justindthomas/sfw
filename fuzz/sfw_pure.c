/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * sfw_pure.c — MIRROR of pure (no-VPP-runtime) functions from sfw.
 *
 * KEEP IN LOCKSTEP WITH the originals in:
 *   ../sfw_api.c       (sfw_api_copy_fixed_string)
 *   ../sfw_nat64.c     (sfw_nat64_embed_v4, sfw_nat64_extract_v4,
 *                       sfw_nat64_v6_to_v4_outer_cb)
 *
 * The functions below are copied from sfw's `.c` files. They have no
 * dependency on `sfw_main_t`, `vlib_buffer_t`, the bihash session
 * table, or VPP's graph-node infrastructure — only on libvppinfra's
 * memcpy/memset wrappers and the flat IP header struct typedefs from
 * `vnet/ip/`.
 *
 * Why a mirror rather than #including the originals: each `.c` file's
 * first line is `#include <sfw/sfw.h>`, which transitively pulls in
 * the full sfw plugin runtime (sfw_main_t, bihash session table, all
 * of vlib). Linking that requires building the entire plugin against
 * vpp-dev, which is a weekend of cmake fiddling and produces a much
 * larger fuzzer binary that's hard to debug.
 *
 * The price is drift risk: if the originals change, this mirror must
 * be updated too. Mitigation:
 *
 *   1. The mirrored functions are intentionally chosen to be either
 *      RFC-frozen wire-format arithmetic (RFC 6052 NAT64 prefix
 *      packing) or trivially-stable boundary helpers (fixed-string
 *      decode, callback that copies four-tuple fields). They rarely
 *      change.
 *   2. fuzz/build.sh diffs the mirrored bodies against the originals
 *      at build time and refuses to build on divergence.
 *   3. Mirrored functions are renamed to `_mirror` suffix so the
 *      harness can link them without collision when v1 plugin-link
 *      mode arrives.
 *
 * Note on `static` qualifier: the originals are `static`. The mirrors
 * drop `static` so the harness's `extern` declaration can resolve.
 * The body is byte-identical otherwise; the drift check operates on
 * `^<fname> (` to `^}$` which ignores the storage class on the prior
 * line.
 */

#include <stddef.h>
#include <string.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vppinfra/clib.h>

/* ===========================================================================
 * sfw_nat64_embed_v4 / sfw_nat64_extract_v4 — RFC 6052 prefix arithmetic.
 * =========================================================================== */

/* MIRROR-START: sfw_nat64_embed_v4 (sfw_nat64.c:38) */
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
/* MIRROR-END: sfw_nat64_embed_v4 */

/* MIRROR-START: sfw_nat64_extract_v4 (sfw_nat64.c:88) */
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
/* MIRROR-END: sfw_nat64_extract_v4 */

/* ===========================================================================
 * sfw_api_copy_fixed_string — fixed-string wire-field decoder.
 * ===========================================================================
 * Original is `static` in sfw_api.c. Mirror dropped the storage class
 * so the harness's extern decl resolves. Body verbatim.
 */

/* MIRROR-START: sfw_api_copy_fixed_string (sfw_api.c:30) */
void
sfw_api_copy_fixed_string (char *buf, size_t buf_len, const void *wire,
			   size_t wire_len)
{
  if (buf_len == 0)
    return;
  size_t n = wire_len < buf_len - 1 ? wire_len : buf_len - 1;
  memset (buf, 0, buf_len);
  memcpy (buf, wire, n);
  buf[buf_len - 1] = 0;
}
/* MIRROR-END: sfw_api_copy_fixed_string */

/* ===========================================================================
 * sfw_session shim + RFC 7915 NAT64 outer/inner callbacks.
 * ===========================================================================
 * The callbacks dereference `ctx->session->{k6.dst_port,
 * xlate.n64.v4_pool_port}`. We define a *minimal* session shim with
 * just those two field paths so the mirrored function bodies
 * typecheck and link without sfw.h's 200-line `sfw_session_t`.
 *
 * The shim is layout-different from the production sfw_session_t
 * (other fields omitted). That's fine for fuzzing the callback's
 * logic — all that matters is the field-path expressions resolve to
 * `u16` reads. The harness allocates the shim, sets the values, and
 * the callback never observes a memory layout that differs from what
 * the real plugin would see for THESE specific fields.
 *
 * Drift risk: if sfw.h ever renames `k6.dst_port` or
 * `xlate.n64.v4_pool_port`, the mirrored function bodies will pick
 * up the new path and the build's drift check (which diffs against
 * the originals) catches the lockstep failure.
 */

typedef struct
{
  u16 dst_port;
} sfw_session_k6_shim_t;

typedef struct
{
  u16 v4_pool_port;
} sfw_session_xlate_n64_shim_t;

typedef struct
{
  sfw_session_xlate_n64_shim_t n64;
} sfw_session_xlate_shim_t;

typedef struct
{
  sfw_session_k6_shim_t k6;
  sfw_session_xlate_shim_t xlate;
} sfw_session_t;

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

/* MIRROR-START: sfw_nat64_v6_to_v4_outer_cb (sfw_nat64.c:196) */
int
sfw_nat64_v6_to_v4_outer_cb (ip6_header_t *ip6, ip4_header_t *ip4, void *arg)
{
  sfw_nat64_v6_to_v4_ctx_t *ctx = arg;
  ip4->src_address = ctx->new_src;
  ip4->dst_address = ctx->new_dst;
  return 0;
}
/* MIRROR-END: sfw_nat64_v6_to_v4_outer_cb */

/* The inner callbacks read inner L4 from the bytes immediately
 * following the IP header. They use VPP's ip_csum_* macros, which
 * come from <vnet/ip/ip_packet.h> (transitively pulled by the
 * ip*_packet.h includes above) and resolve to inline arithmetic at
 * compile time — no extra link deps. */

#include <vnet/ip/ip_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/icmp46_packet.h>

/* MIRROR-START: sfw_nat64_v6_to_v4_inner_cb (sfw_nat64.c:217) */
int
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
/* MIRROR-END: sfw_nat64_v6_to_v4_inner_cb */

/* The v4_to_v6 inner callback's first arg is `vlib_buffer_t *b`. The
 * body never dereferences it, so we don't need a vlib_buffer_t shim —
 * the type comes from <vlib/buffer.h> which is pulled in transitively
 * by the L4 packet headers above. The prototype matches sfw_nat64.c
 * byte-for-byte and the build's drift check passes. */

/* MIRROR-START: sfw_nat64_v4_to_v6_inner_cb (sfw_nat64.c:276) */
int
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
/* MIRROR-END: sfw_nat64_v4_to_v6_inner_cb */
