/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * fuzz_nat64_inner_cb_v4_to_v6.c — libFuzzer harness for the v4→v6
 * inner-packet rewrite callback (sfw_nat64.c:276).
 *
 * Symmetric to v6→v4 inner: invoked by `icmp_to_icmp6` when a NAT64
 * v4→v6 ICMP error needs its inner datagram rewritten back into v6
 * form. The inner protocol byte is attacker-controlled (came from
 * the v4 wire); the dispatch covers TCP/UDP/ICMP4.
 *
 * F2 was originally found in this neighbourhood — the v4→v6 ICMP
 * error path triggered an `os_panic` in VPP's `icmp_to_icmp6` helper
 * when the inner protocol was unrecognised. F2 was fixed by pre-
 * screening the inner protocol in `sfw_nat64_translate_v4_to_v6`
 * BEFORE invoking `icmp_to_icmp6` (commit `a467542`), so
 * `icmp_to_icmp6` should never see an unhandled inner. This harness
 * now fuzzes the *inner callback* itself; if F2's pre-screen is ever
 * weakened, the callback again sees arbitrary bytes and we want
 * coverage of what it does in that case.
 *
 * Input layout (minimum 72 bytes, same structure as v6→v4 harness
 * but with addresses sized for v6/v4 swapped per the cb signature):
 *   data[0..1]    new_sport (u16, k6.dst_port the cb writes)
 *   data[2..17]   new_src (v6, prefix::v4_server)
 *   data[18..33]  new_dst (v6 client)
 *   data[34..53]  ip4 header (20 bytes)
 *   data[54..]    inner L4 bytes (TCP/UDP/ICMPv4). >= 18 bytes —
 *                 this matches the translator-level F5 fix in
 *                 sfw_nat64_translate_v4_to_v6 (sfw_nat64.c:497ff)
 *                 which now requires the buffer to extend at least
 *                 18 bytes into the inner L4 before the cb is
 *                 invoked. The harness mirrors that constraint so
 *                 it tests what the cb actually sees in production.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

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
  ip6_address_t new_src;
  ip6_address_t new_dst;
  sfw_session_t *session;
} sfw_nat64_v4_to_v6_ctx_t;

/* Mirror prototype matches sfw_nat64.c byte-for-byte; vlib_buffer_t
 * comes from <vlib/buffer.h>. The harness never derefs `b` (passes
 * NULL); we just need the type for the extern decl. */
#include <vlib/buffer.h>

extern int sfw_nat64_v4_to_v6_inner_cb (vlib_buffer_t *b, ip4_header_t *ip4,
					ip6_header_t *ip6, void *arg);

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  /* Need: 2 (sport) + 16 + 16 (v6 addrs) + 20 (ip4 hdr) + 18 (L4) = 72.
   * The 18-byte L4 minimum mirrors the translator's F5 length-check —
   * shorter buffers can't reach this cb in production. */
  if (size < 72)
    return 0;

  sfw_session_t session;
  memset (&session, 0, sizeof (session));
  session.k6.dst_port = ((u16) data[0] << 8) | data[1];

  sfw_nat64_v4_to_v6_ctx_t ctx;
  memset (&ctx, 0, sizeof (ctx));
  memcpy (&ctx.new_src.as_u8[0], data + 2, 16);
  memcpy (&ctx.new_dst.as_u8[0], data + 18, 16);
  ctx.session = &session;

  /* ip4 header + inner L4 in one heap chunk for ASan coverage. */
  size_t hdrs_avail = size - 34;
  uint8_t *hdrs = (uint8_t *) malloc (hdrs_avail);
  if (!hdrs)
    return 0;
  memcpy (hdrs, data + 34, hdrs_avail);

  ip4_header_t *ip4 = (ip4_header_t *) hdrs;
  ip6_header_t ip6;
  memset (&ip6, 0, sizeof (ip6));

  (void) sfw_nat64_v4_to_v6_inner_cb (NULL, ip4, &ip6, &ctx);

  free (hdrs);
  return 0;
}
