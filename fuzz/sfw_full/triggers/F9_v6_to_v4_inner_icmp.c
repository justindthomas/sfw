/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * F9 reproducer (v6→v4 inner-ICMP path): ICMPv6 destination_unreachable
 * carrying inner IPv6+fragment-header+ICMPv6 with attacker-controlled
 * inner payload_length.
 *
 * After F8 fixed the OUTER ICMP recompute, the v1 post-fix fuzz pass
 * surfaced this sibling path: the helper recomputes the *inner* ICMP
 * checksum (ip6_to_ip4.h:470) using `ntohs(inner_ip4->length)-20`,
 * where `inner_ip4->length` is set just above as
 * `u16_net_add(inner_ip6->payload_length, sizeof(ip4)+sizeof(ip6)-inner_l4_offset)`.
 * `inner_ip6->payload_length` is u16 attacker-controlled (sits inside
 * the outer ICMP error's body, independent of the outer's payload_length
 * F8 already bounds).
 *
 * Reachability: outer ICMPv6 must be a recognised error type (so
 * inner_ip6 is set), inner ip6 protocol must be FRAGMENTATION (or any
 * extension header that walks to ICMP6), the walk must terminate at
 * ICMP6 (so the helper translates inner_protocol = ICMP6 → ICMP and
 * recomputes inner ICMP checksum). All attacker-controlled.
 *
 * 229-byte trigger captured organically by fuzz_translate_v6_to_v4
 * within seconds of post-F8-fix fuzzing.  The exact bytes of the
 * fuzzer trigger are reproduced inline below to keep this seed
 * self-contained and bytewise reproducible.
 *
 * Build via fuzz/sfw_full/build.sh.  Run:
 *   ./out/F9_v6_to_v4_inner_icmp
 * Pre-fix output: ASan stack-buffer-overflow (n=11300 byte read
 *   from inner ICMP recompute).
 * Post-fix output: clean exit (SFW dropped the packet).
 */

#include <stdio.h>
#include <string.h>

#include <vlib/vlib.h>
#include <vnet/ip/ip6_packet.h>
#include <sfw/sfw.h>

#include "../harness_buffer.h"

extern int sfw_nat64_translate_v6_to_v4 (vlib_main_t *vm, vlib_buffer_t *b,
					 sfw_session_t *session);

/* The exact 229-byte trigger captured by libFuzzer. The high-level
 * structure is:
 *   bytes 0..39   outer IPv6 header (payload_length=49, protocol=ICMP6)
 *   bytes 40..47  outer ICMPv6 (type=destination_unreachable, code=0)
 *   bytes 48..87  inner IPv6 header (protocol=FRAGMENTATION,
 *                 payload_length=0x2c2c=11308 — attacker)
 *   bytes 88..95  inner fragment header (next_hdr=ICMP6=0x3a)
 *   bytes 96..   inner ICMP6 + filler */
static const uint8_t f9_trigger[] = {
  /* 0..15 */
  0x31, 0x00, 0x01, 0x00, 0x00, 0x31, 0x3a, 0x31, 0x31, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xfe,
  /* 16..31 */
  0xff, 0xff, 0x31, 0x31, 0x06, 0x04, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
  0x06, 0x06, 0x35, 0x30,
  /* 32..47 */
  0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x01, 0x00, 0x00, 0x00,
  0x06, 0x06, 0x06, 0x06,
  /* 48..63 — inner ip6 vtfl/payload_length/protocol/hop_limit */
  0x06, 0x06, 0x2c, 0x2c, 0x2c, 0x2c, 0x2c, 0x2c, 0x2c, 0x2c, 0x2c, 0x2c,
  0x2c, 0x2c, 0x2c, 0x2c,
  /* 64..79 — inner src/dst */
  0x2c, 0x2c, 0x2c, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7,
  0xc7, 0xc7, 0xc7, 0xc7,
  /* 80..95 — inner dst tail + frag header start */
  0xc7, 0xc7, 0xc7, 0x00, 0x00, 0x31, 0x3a, 0x31, 0x3a, 0x31, 0x31, 0xff,
  0xff, 0xff, 0xff, 0xff,
  /* 96.. — inner ICMP6 region + filler */
  0xff, 0xff, 0x31, 0x31, 0x06, 0x04, 0x06, 0x06, 0x2c, 0x2c, 0x2c, 0x6f,
  0x6f, 0x6f, 0x6f, 0x6f,
  0x6f, 0x6f, 0x6f, 0x6f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
  0x6f, 0x6f, 0x6f, 0x6f,
  0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f,
  0x6f, 0x6f, 0x6f, 0x6f,
  0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f,
  0x6f, 0x6f, 0x6f, 0x6f,
  0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f,
  0x6f, 0x6f, 0x6f, 0x6f,
  0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f,
  0x6f, 0x6f, 0x6f, 0x6f,
  0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x2c, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0xf7, 0xff, 0xff, 0x00, 0xff
};

int
main (void)
{
  fuzz_buffer_t fb;
  fuzz_buffer_init (&fb, /*headroom=*/0, f9_trigger, sizeof (f9_trigger));

  sfw_session_t s;
  memset (&s, 0, sizeof (s));
  s.xlate.n64.v4_pool.as_u32 = 0x0a000001;
  s.xlate.n64.v4_server.as_u32 = 0xc0000201;
  s.xlate.n64.v4_pool_port = 0x1234;
  s.k6.dst_port = 0x5678;

  fprintf (stderr,
	   "F9 v6->v4: outer ICMP6 dest_unreachable, inner ip6 protocol="
	   "FRAGMENTATION, frag.next_hdr=ICMP6, inner payload_length=11308\n");
  int rv = sfw_nat64_translate_v6_to_v4 (NULL, &fb.b, &s);
  fprintf (stderr, "rv=%d (clean exit means F9 has been fixed)\n", rv);
  return 0;
}
