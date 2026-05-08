/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * F10 reproducer (v4→v6 length-wrap): ICMPv4 echo-reply with
 * `ip4->length = 0`.
 *
 * F8's v4→v6 fix added an upper-bound check (`ip4->length >
 * b->current_length → drop`).  But VPP's `icmp_to_icmp6` helper
 * (ip4_to_ip6.h:440) sets `ip6->payload_length = htons(ntohs(ip4->length)
 * - sizeof(ip4_header_t))` unconditionally — with `ip4->length < 20`,
 * the unsigned subtraction wraps the u16 to ~65500.  The OUTER ICMP
 * recompute at line 482 then walks `ntohs(ip6->payload_length)` ≈
 * 65516 bytes from the icmp pointer — far past any realistic buffer.
 *
 * Same wire-side memory-disclosure primitive as F8/F9 (CWE-125 +
 * CWE-200), reachable from any IPv4 client able to send a
 * total_length=0 (or <20) ICMP packet to the NAT64 dataplane.
 *
 * 23-byte trigger captured organically by fuzz_translate_v4_to_v6
 * within seconds of post-F8-fix fuzzing.
 *
 * Build via fuzz/sfw_full/build.sh.  Run:
 *   ./out/F10_v4_to_v6_length_wrap
 * Pre-fix output: ASan stack-buffer-overflow (n=65516 byte read).
 * Post-fix output: clean exit (SFW dropped the packet).
 *
 * Fix sketch (mirrors F8 but adds a lower bound):
 *   if (ip_len > b->current_length || ip_len < sizeof (ip4_header_t))
 *     return -1;
 */

#include <stdio.h>
#include <string.h>

#include <vlib/vlib.h>
#include <vnet/ip/ip4_packet.h>
#include <sfw/sfw.h>

#include "../harness_buffer.h"

extern int sfw_nat64_translate_v4_to_v6 (vlib_main_t *vm, vlib_buffer_t *b,
					 sfw_session_t *session);

static const uint8_t f10_trigger[] = {
  /* IPv4 header (20 bytes), length=0, protocol=ICMP, rest junk */
  0x0a, 0x0a, 0x00, 0x00, 0x47, 0x47, 0x47, 0x47, 0x47, 0x01, 0x00, 0x47,
  0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47,
  /* ICMP4 header (3 of 8 bytes — type=0=echo_reply) */
  0x00, 0x0a, 0x0a
};

int
main (void)
{
  fuzz_buffer_t fb;
  fuzz_buffer_init (&fb, /*headroom=*/128, f10_trigger, sizeof (f10_trigger));

  /* Populate sfw_main.nat_pools[0] with 64:ff9b::/96 — translator
   * dereferences it to compute the v6 src embed. */
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
  s.k6.dst_port = 0x1234;

  fprintf (stderr,
	   "F10 v4->v6: ICMP4 echo-reply, ip4->length=0 → wraps to ~65516\n");
  int rv = sfw_nat64_translate_v4_to_v6 (NULL, &fb.b, &s);
  fprintf (stderr, "rv=%d (clean exit means F10 has been fixed)\n", rv);
  return 0;
}
