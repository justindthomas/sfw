/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * F11 reproducer (v4→v6 parameter_problem table OOB): ICMPv4
 * parameter_problem with a "pointer" byte > 19 reads out-of-bounds
 * from a 20-entry global lookup table.
 *
 * VPP helper at vnet/ip/ip4_to_ip6.h:200-216 handles ICMP4 parameter
 * problem by translating the v4 "pointer" byte (which indicates which
 * v4 header field had the error) into a v6 equivalent via a static
 * lookup table:
 *
 *     case ICMP4_parameter_problem_pointer_indicates_error:
 *     case ICMP4_parameter_problem_bad_length:
 *       icmp->type = ICMP6_parameter_problem;
 *       icmp->code = ICMP6_parameter_problem_erroneous_header_field;
 *       u8 ptr =
 *         icmp_to_icmp6_updater_pointer_table[*((u8 *) (icmp + 1))];
 *       if (ptr == 0xff)
 *         return -1;
 *
 * `*((u8 *) (icmp + 1))` reads the FIRST byte after the 4-byte ICMP
 * header (i.e., the v4 pointer field). It's used as an index into a
 * static 20-entry table at vnet/ip/ip4_to_ip6.h:31-36. **No bounds
 * check.** An attacker-supplied pointer byte ≥ 20 reads past the
 * table and the value is then written into the outgoing v6 packet
 * via the subsequent `*((u32 *)(icmp+1)) = htonl(ptr)` — small leak
 * of adjacent .data/.rodata bytes, plus the OOB read itself is a
 * classic CWE-125.
 *
 * Reachability: standard ICMPv4 parameter_problem packet with code
 * 0 (pointer_indicates_error) or 2 (bad_length).  Pointer byte > 19
 * is normal in v4 (for example, v4 pointer 28 indicates an option
 * byte), so this is reachable from any IPv4 NAT64 client without
 * any malformation.  Unauthenticated.
 *
 * 70-byte trigger captured organically by fuzz_translate_v4_to_v6
 * within the post-F9-fix 10-min fuzz pass.
 *
 * Build via fuzz/sfw_full/build.sh.  Run:
 *   ./out/F11_v4_to_v6_param_problem_table
 * Pre-fix output: ASan global-buffer-overflow (read 38 bytes past
 *   the 20-byte global table).
 * Post-fix output: clean exit (SFW dropped or VPP helper bounded).
 *
 * Fix sketch — gate icmp_to_icmp6 invocation on the parameter_problem
 * pointer being in-range. Best fix lives in the SFW translator since
 * VPP is shared across plugins:
 *
 *   if (t == ICMP4_parameter_problem)
 *     {
 *       icmp46_header_t *outer_icmp = (icmp46_header_t *) (ip4 + 1);
 *       if (outer_icmp->code == ICMP4_parameter_problem_pointer_indicates_error
 *           || outer_icmp->code == ICMP4_parameter_problem_bad_length)
 *         {
 *           u8 ptr_byte = *((u8 *) (outer_icmp + 1));
 *           if (ptr_byte >= 20)
 *             return -1;
 *         }
 *     }
 *
 * The 20 here is the size of icmp_to_icmp6_updater_pointer_table[].
 * Probably worth defining a constant in sfw or upstreaming the bound
 * check into VPP.
 */

#include <stdio.h>
#include <string.h>

#include <vlib/vlib.h>
#include <vnet/ip/ip4_packet.h>
#include <sfw/sfw.h>

#include "../harness_buffer.h"

extern int sfw_nat64_translate_v4_to_v6 (vlib_main_t *vm, vlib_buffer_t *b,
					 sfw_session_t *session);

/* Verbatim 70-byte trigger from libFuzzer.  Inner ip4 length at
 * offsets 30-31 = 0x001e = 30, which passes F9's [20, current_length-24]
 * range; pointer byte at offset 24 = 0x3a = 58, indexes the 20-entry
 * table OOB. */
static const uint8_t f11_trigger[] = {
  0x1e, 0x00, 0x00, 0x15, 0x00, 0x00, 0x62, 0x00, 0x00, 0x01, 0x30, 0x08,
  0x1e, 0x0a, 0x00, 0x00, 0x1e, 0x2f, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
  0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x1e, 0x00, 0x00, 0x00,
  0x00, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
  0x1e, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
  0x00, 0x94, 0x00, 0x00, 0x08, 0x00, 0xf7, 0x00, 0x00, 0x00
};

int
main (void)
{
  fuzz_buffer_t fb;
  fuzz_buffer_init (&fb, /*headroom=*/128, f11_trigger, sizeof (f11_trigger));

  /* Populate sfw_main.nat_pools[0]. */
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
	   "F11 v4->v6: ICMP4 parameter_problem code=0, pointer byte=58 → "
	   "OOB index into 20-entry icmp_to_icmp6_updater_pointer_table[]\n");
  int rv = sfw_nat64_translate_v4_to_v6 (NULL, &fb.b, &s);
  fprintf (stderr, "rv=%d (clean exit means F11 has been fixed)\n", rv);
  return 0;
}
