/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * fuzz_translate_v4_to_v6.c — drives the full v4→v6 NAT64 translator
 * `sfw_nat64_translate_v4_to_v6` (sfw_nat64.c:496) with a synthesised
 * vlib_buffer_t.
 *
 * Reachable from any IPv4 client whose packet hits the NAT64
 * dataplane.  The translator's two attacker-controlled u16s here are
 * `ip4->length` and `b->current_length`.  In the ICMP echo-request
 * branch (no inner), there is no F5/F6 length pre-check, so the
 * helper is reached with very small buffers — making this direction
 * easier to trigger than v6→v4.
 *
 * The harness places the IPv4 header at headroom=128 to give the
 * translator room to prepend 20 bytes for the v6 expansion (RFC 7915
 * §4: v4(20) → v6(40)).  This matches VPP's default
 * VLIB_BUFFER_PRE_DATA_SIZE.
 *
 * Unlike v6→v4, this translator dereferences sfw_main.nat_pools to
 * pull the NAT64 prefix for the v6 src embed.  The harness populates
 * a single fake pool with 64:ff9b::/96 (well-known NAT64 prefix from
 * RFC 6052).
 *
 * Findings already surfaced by this harness (during initial spike):
 *   F8: ICMP4→ICMP6 outer-checksum recompute walks attacker-controlled
 *       ip4->length / payload_length past buffer (CWE-125 + CWE-200).
 *       Trigger seed: triggers/F8_v4_to_v6.c.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <vlib/vlib.h>
#include <sfw/sfw.h>

#include "harness_buffer.h"

extern int sfw_nat64_translate_v4_to_v6 (vlib_main_t *vm, vlib_buffer_t *b,
					 sfw_session_t *session);

/* Single fake NAT64 pool — 64:ff9b::/96 from RFC 6052 §2.1.  Hot-
 * loaded on the first call; subsequent calls reuse. */
static sfw_nat_pool_t fake_pool;
static int pools_inited;

static void
ensure_pool (void)
{
  if (pools_inited)
    return;
  memset (&fake_pool, 0, sizeof (fake_pool));
  fake_pool.nat64_prefix.as_u8[0] = 0x00;
  fake_pool.nat64_prefix.as_u8[1] = 0x64;
  fake_pool.nat64_prefix.as_u8[2] = 0xff;
  fake_pool.nat64_prefix.as_u8[3] = 0x9b;
  fake_pool.nat64_prefix_len = 96;
  /* sfw_main.nat_pools is declared as a vec.  VPP's vec_t accessors
   * are pointer-array-equivalent (`v[i]` walks from the pointed
   * element); so a plain array address works at runtime even though
   * the vec header would be missing.  Translator only does `[idx]`. */
  sfw_main.nat_pools = &fake_pool;
  pools_inited = 1;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  /* Need at least an outer IPv4 header (20 bytes) to even attempt.
   * The harness's headroom (128) leaves 1920 bytes for the packet —
   * easily enough for any realistic NAT64 input. */
  if (size < 20)
    return 0;

  ensure_pool ();

  fuzz_buffer_t fb;
  fuzz_buffer_init (&fb, /*headroom=*/128, data, size);

  sfw_session_t s;
  memset (&s, 0, sizeof (s));
  s.xlate.n64.pool_idx = 0;
  s.xlate.n64.v4_pool.as_u32 = 0x0a000001;
  s.xlate.n64.v4_server.as_u32 = 0xc0000201;
  s.xlate.n64.v4_pool_port = 0x1234;
  /* k6.dst is the v6 client.  Deterministic 2001:db8::1 keeps
   * minimisation stable. */
  s.k6.dst.as_u8[0] = 0x20;
  s.k6.dst.as_u8[1] = 0x01;
  s.k6.dst.as_u8[2] = 0x0d;
  s.k6.dst.as_u8[3] = 0xb8;
  s.k6.dst.as_u8[15] = 0x01;
  s.k6.dst_port = 0x5678;

  (void) sfw_nat64_translate_v4_to_v6 (NULL, &fb.b, &s);
  return 0;
}
