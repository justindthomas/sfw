/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * F9 v2 reproducer (v6→v4 inner-ICMP path, post-F9-fix): exposes an
 * off-by-4 bug in the F9 fix at sfw_nat64.c:432 / 435.
 *
 * The F9 fix computes:
 *
 *     ip6_header_t *inner_ip6 =
 *         (ip6_header_t *) ((u8 *) outer_icmp6 + sizeof (icmp46_header_t));
 *     size_t inner_pl_offset =
 *         sizeof (ip6_header_t) + sizeof (icmp46_header_t) + sizeof (ip6_header_t);
 *
 * `sizeof(icmp46_header_t) = 4` (type+code+checksum).  But ICMPv6 *error*
 * messages have an **8-byte** outer header — 4 generic bytes plus 4
 * error-specific bytes (e.g., MTU for Packet Too Big, unused for
 * Destination Unreachable, pointer for Parameter Problem).  The VPP
 * helper at vnet/ip/ip6_to_ip4.h:259-307 correctly uses `icmp + 8`:
 *
 *     case ICMP6_destination_unreachable:
 *       *inner_ip6 = (ip6_header_t *) u8_ptr_add (icmp, 8);
 *
 * So the F9 check reads `inner_ip6->payload_length` at outer offset
 * 44+4=48 (the real `inner_ip6->ip_version_traffic_class_and_flow_label`'s
 * last two bytes) instead of 52-53 (the real inner payload_length).
 * `inner_pl_offset` is also computed as 84 instead of 88.  Triggers
 * that put a small value at the misread location pass the check, but
 * the helper then reads the real inner_payload_length (which can be
 * arbitrarily large) and walks tens of KB through ip_incremental_checksum
 * exactly as F9 originally described.
 *
 * Trigger (217 bytes, captured by the post-F9-fix 10-min v1 fuzz pass):
 *   - outer ip6 with payload_length=0, protocol=ICMP6
 *   - outer ICMP6 type=packet_too_big (2)
 *   - bytes 48-51 are inner ip6 vtfl with the LOW 16 bits = 0x000a = 10
 *     → the F9 fix misreads this as inner_pl, sees 10, passes the check
 *   - real inner ip6 payload_length at offset 52-53 = 0x1140 = 4416
 *
 * Fix: change `sizeof(icmp46_header_t)` to 8 in both inner_ip6 pointer
 * arithmetic and inner_pl_offset.  Same off-by-4 bug exists on the
 * v4→v6 sibling check (sfw_nat64.c:617-625) — change `inner_ip4_offset`
 * from `sizeof(ip4_header_t) + sizeof(icmp46_header_t)` (= 24) to
 * `sizeof(ip4_header_t) + 8` (= 28).
 *
 * Build via fuzz/sfw_full/build.sh.  Run:
 *   ./out/F9_v6_to_v4_inner_icmp_v2
 * Pre-fix-correction output: ASan stack-buffer-overflow, n=4356.
 * Post-fix-correction output: clean exit (SFW dropped).
 */

#include <stdio.h>
#include <string.h>

#include <vlib/vlib.h>
#include <vnet/ip/ip6_packet.h>
#include <sfw/sfw.h>

#include "../harness_buffer.h"

extern int sfw_nat64_translate_v6_to_v4 (vlib_main_t *vm, vlib_buffer_t *b,
					 sfw_session_t *session);

static const uint8_t f9v2_trigger[] = {
  /* 0..15: outer ip6 (vtfl=02bfbfbf, paylen=0, proto=58, hop=191) */
  0x02, 0xbf, 0xbf, 0xbf, 0x00, 0x00, 0x3a, 0xbf, 0xbf, 0x21, 0x21, 0x21,
  0x21, 0x21, 0x21, 0xff,
  /* 16..31: outer src tail / dst */
  0xff, 0xff, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21,
  0x21, 0xff, 0xff, 0xff,
  /* 32..39: outer dst tail */
  0xff, 0xff, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21,
  /* 40..47: outer ICMP6 (type=2 packet_too_big, code=1, csum=0xbfbf,
   *                      body=0xbf000031 — 4 error-specific bytes) */
  0x02, 0x01, 0xbf, 0xbf, 0xbf, 0x00, 0x00, 0x31,
  /* 48..51: real inner ip6 vtfl. Low 16 bits (offset 48-49) = 0x000a — the
   *         F9 fix misreads these as inner_pl=10, passes check. */
  0x00, 0x0a, 0x0a, 0x40,
  /* 52..53: real inner ip6 payload_length = 0x1140 = 4416 */
  0x11, 0x40,
  /* 54..55: real inner ip6 protocol=0x11(UDP), hop_limit=0x11 */
  0x11, 0x11,
  /* 56..87: inner src/dst */
  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  /* 88..: filler past the F5/F6 minimum (>=106 bytes total) */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00
};

int
main (void)
{
  fuzz_buffer_t fb;
  fuzz_buffer_init (&fb, /*headroom=*/0, f9v2_trigger, sizeof (f9v2_trigger));

  sfw_session_t s;
  memset (&s, 0, sizeof (s));
  s.xlate.n64.v4_pool.as_u32 = 0x0a000001;
  s.xlate.n64.v4_server.as_u32 = 0xc0000201;
  s.xlate.n64.v4_pool_port = 0x1234;
  s.k6.dst_port = 0x5678;

  fprintf (stderr,
	   "F9 v2: outer ICMP6 packet_too_big, F9 fix off-by-4 lets a "
	   "misread inner_pl=10 pass the check while real inner_paylen=4416\n");
  int rv = sfw_nat64_translate_v6_to_v4 (NULL, &fb.b, &s);
  fprintf (stderr, "rv=%d (clean exit means F9 fix has been corrected)\n",
	   rv);
  return 0;
}
