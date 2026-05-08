/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * F8 reproducer (v4→v6): ICMPv4 echo-request with ip4->length=0xFFFF.
 *
 * Symmetric to F8_v6_to_v4.c.  VPP's `icmp_to_icmp6` (vnet/ip/
 * ip4_to_ip6.h:482) recomputes the outer ICMP checksum using
 * `clib_net_to_host_u16(ip6->payload_length)` bytes from the icmp
 * pointer.  Earlier in the same helper, `ip6->payload_length` is set
 * from `ip4->length`, which is attacker-controlled.
 *
 * **Crucially, the v4→v6 translator's F5/F6 length pre-check fires
 * only for ICMP4 destination_unreachable / time_exceeded /
 * parameter_problem (the error types).  ICMP4 echo-request has no
 * inner packet and bypasses the check entirely** — making this
 * direction reachable with a 28-byte buffer (vs. v6→v4's 106-byte
 * floor).  Trivial trigger.
 *
 * Build via fuzz/sfw_full/build.sh.  Run:
 *   ./out/F8_v4_to_v6
 * Pre-fix output: ASan stack-buffer-overflow.
 * Post-fix output: clean exit with rv=-1 (SFW dropped the packet).
 */

#include <stdio.h>
#include <string.h>

#include <vlib/vlib.h>
#include <vnet/ip/ip4_packet.h>
#include <sfw/sfw.h>

#include "../harness_buffer.h"

extern int sfw_nat64_translate_v4_to_v6 (vlib_main_t *vm, vlib_buffer_t *b,
					 sfw_session_t *session);

int
main (void)
{
  fuzz_buffer_t fb;
  uint8_t pkt[28];	      /* IPv4 (20) + ICMP4 echo (8) */
  memset (pkt, 0, sizeof (pkt));

  /* IPv4 header */
  pkt[0] = 0x45;	      /* version 4, IHL 5 (20-byte header) */
  pkt[1] = 0x00;	      /* TOS */
  uint16_t total_len = clib_host_to_net_u16 (0xFFFF);	/* attacker */
  memcpy (pkt + 2, &total_len, 2);
  pkt[8] = 64;		      /* TTL */
  pkt[9] = IP_PROTOCOL_ICMP;
  /* checksum (10-11), src/dst (12-19) zero */

  /* ICMP4 echo-request header at offset 20 */
  pkt[20] = ICMP4_echo_request;	/* type 8 */
  /* code, csum, id, seq */
  pkt[24] = 0x12;
  pkt[25] = 0x34;
  pkt[26] = 0x56;
  pkt[27] = 0x78;

  /* Headroom of 128 leaves room for the 20-byte v4→v6 header
   * expansion.  Matches VPP's VLIB_BUFFER_PRE_DATA_SIZE. */
  fuzz_buffer_init (&fb, /*headroom=*/128, pkt, sizeof (pkt));

  /* Populate sfw_main.nat_pools[0] with 64:ff9b::/96 — the
   * translator dereferences this to compute the v6 src embed. */
  static sfw_nat_pool_t fake_pool;
  memset (&fake_pool, 0, sizeof (fake_pool));
  fake_pool.nat64_prefix.as_u8[0] = 0x00;
  fake_pool.nat64_prefix.as_u8[1] = 0x64;
  fake_pool.nat64_prefix.as_u8[2] = 0xff;
  fake_pool.nat64_prefix.as_u8[3] = 0x9b;
  fake_pool.nat64_prefix_len = 96;
  sfw_main.nat_pools = &fake_pool;

  sfw_session_t s;
  memset (&s, 0, sizeof (s));
  s.xlate.n64.pool_idx = 0;
  s.xlate.n64.v4_server.as_u32 = 0xc0000201;
  s.k6.dst.as_u8[0] = 0x20;
  s.k6.dst.as_u8[1] = 0x01;
  s.k6.dst.as_u8[2] = 0x0d;
  s.k6.dst.as_u8[3] = 0xb8;
  s.k6.dst.as_u8[15] = 0x01;
  s.k6.dst_port = 0x1234;

  fprintf (stderr, "F8 v4->v6: ip4->length=0xFFFF, current_length=28\n");
  int rv = sfw_nat64_translate_v4_to_v6 (NULL, &fb.b, &s);
  fprintf (stderr, "rv=%d (clean exit means F8 has been fixed)\n", rv);
  return 0;
}
