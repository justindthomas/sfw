/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * fuzz_nat64_inner_cb_v6_to_v4.c — libFuzzer harness for the v6→v4
 * inner-packet rewrite callback (sfw_nat64.c:217).
 *
 * The inner callback is invoked by VPP's `icmp6_to_icmp` helper when
 * translating an ICMPv6 error message — the outer ICMP gets converted
 * to ICMPv4, and the inner (the original datagram that caused the
 * error) needs its addresses + L4 ports rewritten too. Bugs in this
 * callback are reachable from any IPv6 client able to reach the
 * NAT64-enabled interface; the inner protocol byte is attacker-
 * controlled.
 *
 * Specifically interesting:
 *   - inner_proto in {TCP, UDP, ICMP6} branches dispatch on the inner
 *     protocol byte and rewrite L4 ports + checksums. Wrong-length
 *     reads here are CWE-125 candidates.
 *   - The implementation reads inner L4 at `ip6 + sizeof(ip6_header_t)`
 *     without bounds-checking the buffer. If `b` is shorter than
 *     ip6_header + tcp_header (40 + 20 = 60 bytes), we'd read past
 *     the buffer — ASan should catch.
 *   - ICMPv6 echo handling writes `((u16 *)icmp)[2] = new_dport` —
 *     similar pattern to F4 (an unbounded array index past a
 *     fixed-size struct).
 *
 * Input layout (variable, minimum 68 bytes):
 *   data[0..1]    new_dport (u16, the v4_pool_port the cb writes)
 *   data[2..5]    new_src (v4 pool addr — outer cb's ctx)
 *   data[6..9]    new_dst (embedded v4 — outer cb's ctx)
 *   data[10..49]  ip6 header (40 bytes)
 *   data[50..]    inner L4 bytes — TCP/UDP/ICMPv6 header. >= 18 bytes
 *                 to mirror the translator-level F5/F6 fix in
 *                 sfw_nat64_translate_v6_to_v4 (sfw_nat64.c:357ff)
 *                 which now drops buffers that don't extend that far
 *                 before invoking the cb. Shorter L4 isn't reachable
 *                 in production.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

/* Mirror types — see sfw_pure.c. The shim is layout-different from
 * production but path-compatible (k6.dst_port, xlate.n64.v4_pool_port). */
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
  ip4_address_t new_src;
  ip4_address_t new_dst;
  sfw_session_t *session;
} sfw_nat64_v6_to_v4_ctx_t;

extern int sfw_nat64_v6_to_v4_inner_cb (ip6_header_t *ip6,
					ip4_header_t *ip4, void *arg);

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  /* Min: 2 (dport) + 4 + 4 (addrs) + 40 (ip6 hdr) + 18 (L4) = 68.
   * History: an earlier version required +20 (L4); the v0 audit pass
   * lowered to +0 to expose F5 (truncated-L4 read at offset 16-17),
   * which it did. Now F5 is fixed at the translator layer
   * (sfw_nat64_translate_v6_to_v4 drops buffers shorter than this),
   * so the harness mirrors the production reachability constraint:
   * the cb only ever sees buffers with ≥18 bytes of inner L4. */
  if (size < 68)
    return 0;

  sfw_session_t session;
  memset (&session, 0, sizeof (session));
  session.xlate.n64.v4_pool_port = ((u16) data[0] << 8) | data[1];

  sfw_nat64_v6_to_v4_ctx_t ctx;
  memset (&ctx, 0, sizeof (ctx));
  memcpy (&ctx.new_src.as_u8[0], data + 2, 4);
  memcpy (&ctx.new_dst.as_u8[0], data + 6, 4);
  ctx.session = &session;

  /* Allocate ip6 header + inner L4 in one heap chunk so ASan can flag
   * any read past the chunk boundary. The chunk is sized to the
   * fuzzer-supplied input minus the 10 prefix bytes (dport + addrs);
   * everything after is what the callback might read. */
  size_t hdrs_avail = size - 10;
  uint8_t *hdrs = (uint8_t *) malloc (hdrs_avail);
  if (!hdrs)
    return 0;
  memcpy (hdrs, data + 10, hdrs_avail);

  ip6_header_t *ip6 = (ip6_header_t *) hdrs;
  ip4_header_t ip4;
  memset (&ip4, 0, sizeof (ip4));

  (void) sfw_nat64_v6_to_v4_inner_cb (ip6, &ip4, &ctx);

  free (hdrs);
  return 0;
}
