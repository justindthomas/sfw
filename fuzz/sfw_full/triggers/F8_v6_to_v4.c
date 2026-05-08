/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * F8 reproducer (v6→v4): ICMPv6 echo-request with payload_length=0xFFFF.
 *
 * VPP's `icmp6_to_icmp` (vnet/ip/ip6_to_ip4.h:521) recomputes the
 * outer ICMP checksum using `clib_net_to_host_u16(ip4->length) -
 * sizeof(ip4_header_t)` bytes from the icmp pointer.  Earlier in the
 * same helper, `ip4->length` is set as `u16_net_add(ip6->payload_length,
 * sizeof(ip4_header_t))`, so the read length tracks the attacker-
 * supplied payload_length up to ~64 KB.
 *
 * SFW's translator passes the F5/F6 length pre-check (>=106 bytes for
 * the ICMP6 path), then hands the buffer to the helper.  The helper
 * walks past the 2 KB buffer end into adjacent packet-pool memory and
 * folds those bytes into the wire-side ICMP checksum — memory
 * disclosure (CWE-125 + CWE-200) reachable from any v6 NAT64 client.
 *
 * Symmetric to F8_v4_to_v6.c; both fixes go in the SFW translator
 * before invoking the helper, mirroring F7's clamp-and-drop pattern.
 *
 * Build via fuzz/sfw_full/build.sh — produces `out/F8_v6_to_v4` next
 * to the harnesses.  Run it standalone to confirm a fix:
 *   ./out/F8_v6_to_v4
 * Pre-fix output: ASan stack-buffer-overflow.
 * Post-fix output: clean exit with rv=-1 (SFW dropped the packet).
 */

#include <stdio.h>
#include <string.h>

#include <vlib/vlib.h>
#include <vnet/ip/ip6_packet.h>
#include <sfw/sfw.h>

#include "../harness_buffer.h"

extern int sfw_nat64_translate_v6_to_v4 (vlib_main_t *vm, vlib_buffer_t *b,
					 sfw_session_t *session);

int
main (void)
{
  fuzz_buffer_t fb;
  /* Build a minimal ICMPv6 echo-request that passes SFW's F5 length
   * check (current_length >= 106) but advertises payload_length=
   * 0xFFFF in the IPv6 header.  Junk bytes after the ICMP header are
   * fine — they're just there to satisfy the F5 size floor. */
  uint8_t pkt[106];
  memset (pkt, 0, sizeof (pkt));

  /* IPv6 header */
  uint32_t v_tc_fl = clib_host_to_net_u32 (0x60000000);
  memcpy (pkt + 0, &v_tc_fl, 4);
  uint16_t pl = clib_host_to_net_u16 (0xFFFF);	/* attacker-controlled */
  memcpy (pkt + 4, &pl, 2);
  pkt[6] = IP_PROTOCOL_ICMP6;
  pkt[7] = 64;
  /* src/dst zero */

  /* ICMPv6 echo-request header */
  pkt[40] = ICMP6_echo_request;	/* type 128 */
  /* code 0, csum 0, id+seq arbitrary */
  pkt[44] = 0x12;
  pkt[45] = 0x34;
  pkt[46] = 0x56;
  pkt[47] = 0x78;

  fuzz_buffer_init (&fb, /*headroom=*/0, pkt, sizeof (pkt));

  sfw_session_t s;
  memset (&s, 0, sizeof (s));
  s.xlate.n64.v4_pool.as_u32 = 0x0a000001;
  s.xlate.n64.v4_server.as_u32 = 0xc0000201;
  s.xlate.n64.v4_pool_port = 0x1234;
  s.k6.dst_port = 0x5678;

  fprintf (stderr, "F8 v6->v4: payload_length=0xFFFF, current_length=106\n");
  int rv = sfw_nat64_translate_v6_to_v4 (NULL, &fb.b, &s);
  fprintf (stderr, "rv=%d (clean exit means F8 has been fixed)\n", rv);
  return 0;
}
