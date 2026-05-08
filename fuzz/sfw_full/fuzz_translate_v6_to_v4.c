/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * fuzz_translate_v6_to_v4.c — drives the full v6→v4 NAT64 translator
 * `sfw_nat64_translate_v6_to_v4` (sfw_nat64.c:362) with a synthesised
 * vlib_buffer_t.
 *
 * Reachable from any IPv6 client able to send through the NAT64
 * dataplane.  The translator's two attacker-controlled u16s are
 * `ip6->payload_length` and `b->current_length` (set by VPP's
 * device input — corresponds to bytes-on-wire); both are exercised
 * by the harness.
 *
 * What v0 covered separately is now reached through this single
 * entrypoint:
 *   - sfw_nat64_v6_to_v4_outer_cb     — invoked by icmp6_to_icmp
 *   - sfw_nat64_v6_to_v4_inner_cb     — same, for inner-packet rewrite
 *
 * Inputs are interpreted as the *contents* of the IPv6 packet
 * starting at offset 0; the harness stamps the session translation
 * fields (v4_pool, v4_server, v4_pool_port) deterministically.
 *
 * Findings already surfaced by this harness (during initial spike):
 *   F8: ICMP6→ICMP4 outer-checksum recompute walks attacker-controlled
 *       payload_length past buffer (CWE-125 + CWE-200).
 *       Trigger seed: triggers/F8_v6_to_v4.c.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <vlib/vlib.h>
#include <sfw/sfw.h>

#include "harness_buffer.h"

extern int sfw_nat64_translate_v6_to_v4 (vlib_main_t *vm, vlib_buffer_t *b,
					 sfw_session_t *session);

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  /* Need at least an outer IPv6 header to attempt a translation; the
   * F5/F6 length pre-check inside the translator will reject sub-106
   * byte ICMP6 errors but TCP/UDP go through with shorter inputs. */
  if (size < sizeof (ip6_header_t))
    return 0;

  fuzz_buffer_t fb;
  fuzz_buffer_init (&fb, 0, data, size);

  sfw_session_t s;
  memset (&s, 0, sizeof (s));
  /* Deterministic translation targets — keep these stable so corpus
   * minimisation works (no crash dependence on session contents). */
  s.xlate.n64.v4_pool.as_u32 = 0x0a000001;	/* 10.0.0.1   */
  s.xlate.n64.v4_server.as_u32 = 0xc0000201;	/* 192.0.2.1  */
  s.xlate.n64.v4_pool_port = 0x1234;
  s.k6.dst_port = 0x5678;

  /* vm = NULL is safe: the v6→v4 translator only plumbs vm into
   * ip6_parse → ip6_ext_header_walk, both of which deref `b` only.
   * The ICMP-error path (icmp6_to_icmp) is the only caller of
   * ip6_parse, and only for inner packets. */
  (void) sfw_nat64_translate_v6_to_v4 (NULL, &fb.b, &s);
  return 0;
}
