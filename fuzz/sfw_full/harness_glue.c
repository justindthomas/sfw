/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * harness_glue.c — symbols sfw_nat64.c reaches for that aren't
 * resolved by libvppinfra.  Two of them:
 *
 *   - `sfw_main`   the global state.  sfw.h declares it `extern`;
 *                  sfw_nat64_translate_v4_to_v6 dereferences it to
 *                  pull the NAT64 prefix out of nat_pools[idx] for
 *                  the v6 src embed.  The v6→v4 translator never
 *                  reads it.
 *
 *   - `vnet_incremental_checksum_fp`   VPP normally swaps in a
 *                  CPU-feature-detected SIMD impl at vlib_init time
 *                  (see vnet/ip/ip_packet.c::ip_packet_init).  We
 *                  don't run vlib_init, so we provide a portable
 *                  RFC-1071 ones-complement implementation.
 *                  Correctness > speed for a fuzzer.
 *
 * Everything else the translators reach (icmp6_to_icmp,
 * icmp_to_icmp6, ip6_parse, ip6_ext_header_walk, vlib_buffer_advance,
 * vlib_buffer_get_current, ip4_header_checksum, ip_csum_*) is
 * `static_always_inline` in VPP headers and emits per-TU.
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip_packet.h>
#include <sfw/sfw.h>

/* Zero-initialised; harnesses that need nat_pools populate it
 * themselves before invoking the v4->v6 translator. */
sfw_main_t sfw_main;

static ip_csum_t
fuzz_incremental_checksum_portable (ip_csum_t csum, void *data_arg,
				    uword n_bytes)
{
  u8 *p = data_arg;
  while (n_bytes >= sizeof (u32))
    {
      u32 w;
      __builtin_memcpy (&w, p, sizeof (w));
      csum = ip_csum_with_carry (csum, w);
      p += sizeof (u32);
      n_bytes -= sizeof (u32);
    }
  if (n_bytes > 0)
    {
      u32 tmp = 0;
      __builtin_memcpy (&tmp, p, n_bytes);
      csum = ip_csum_with_carry (csum, tmp);
    }
  return csum;
}

ip_csum_t (*vnet_incremental_checksum_fp) (ip_csum_t, void *, uword) =
  fuzz_incremental_checksum_portable;
