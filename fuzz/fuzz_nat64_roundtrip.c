/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * fuzz_nat64_roundtrip.c — libFuzzer harness for RFC 6052 prefix
 * embed/extract roundtrip property.
 *
 * The oracle is simple: for any (prefix, prefix_len, v4) triple where
 * prefix_len is one of {32, 40, 48, 56, 64, 96}, the round trip
 *   v4 → embed → v6 → extract → v4'
 * must satisfy v4 == v4'. For invalid prefix lengths, embed produces
 * a degraded v6 and extract returns -1; we accept that as long as
 * neither function corrupts memory or crashes.
 *
 * ASan + UBSan + libFuzzer catch:
 *   - Out-of-bounds writes during embed.
 *   - Out-of-bounds reads during extract.
 *   - Roundtrip violations (caught explicitly via __builtin_trap).
 *   - Sign / overflow bugs in the prefix-len arithmetic.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

extern void sfw_nat64_embed_v4 (const ip6_address_t *prefix, u8 prefix_len,
				const ip4_address_t *v4,
				ip6_address_t *out_v6);
extern int sfw_nat64_extract_v4 (const ip6_address_t *prefix, u8 prefix_len,
				 const ip6_address_t *v6,
				 ip4_address_t *out_v4);

/* Input layout (21 bytes minimum):
 *   data[0..15]  prefix (16 bytes)
 *   data[16]     prefix_len (1 byte; uses full u8 space so the fuzzer
 *                explores invalid lengths too)
 *   data[17..20] v4 (4 bytes) */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 21)
    return 0;

  ip6_address_t prefix;
  memcpy (&prefix.as_u8[0], data, 16);
  u8 prefix_len = data[16];
  ip4_address_t v4;
  memcpy (&v4.as_u8[0], data + 17, 4);

  ip6_address_t out_v6;
  sfw_nat64_embed_v4 (&prefix, prefix_len, &v4, &out_v6);

  /* For valid prefix lengths, the roundtrip must be identity (after
   * normalising the prefix bits to what extract verifies — embed
   * writes the same prefix bytes it just copied from `prefix`, so
   * extract's prefix-match always succeeds for the just-embedded
   * v6). */
  ip4_address_t roundtrip;
  int rv = sfw_nat64_extract_v4 (&prefix, prefix_len, &out_v6, &roundtrip);

  switch (prefix_len)
    {
    case 32:
    case 40:
    case 48:
    case 56:
    case 64:
    case 96:
      /* Valid lengths: extract must succeed and roundtrip must hold. */
      if (rv != 0)
	__builtin_trap (); /* extract failed on a value we just embedded */
      if (memcmp (v4.as_u8, roundtrip.as_u8, 4) != 0)
	__builtin_trap (); /* roundtrip violated */
      break;
    default:
      /* Invalid lengths: extract should reject. The implementation
       * may also accept if pfx_bytes happens to be 0; either is
       * fine as long as nothing corrupts memory. */
      (void) rv;
      break;
    }

  return 0;
}
