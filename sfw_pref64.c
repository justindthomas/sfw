/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 */

/* sfw_pref64.c - RFC 8781 PREF64 Router Advertisement option.
 *
 * Registers a callback with VPP's ip6_ra via ip6_ra_extra_option_register
 * (a small core-side hook patched in by vpp-patches/). When a NAT64
 * prefix has been associated with an interface by CLI/API, every RA
 * emitted on that interface — whether solicited or periodic — carries
 * a PREF64 option pointing at that prefix. Clients that understand the
 * option (e.g. recent Linux with 464XLAT/CLAT, iOS/macOS) pick up the
 * prefix automatically and route DNS-synthesized A-over-AAAA traffic
 * through NAT64 without needing DNS64 on the host. */

#include <sfw/sfw.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip6-nd/ip6_ra.h>

/* RFC 8781 §4.1 PREF64 option layout (16 bytes, length=2 in 8-byte units):
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Type = 38    |    Length = 2 |     Scaled Lifetime     | PLC |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                   Highest 96 bits of NAT64 prefix             |
 *  |                     (zero-padded if prefix shorter)           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Scaled Lifetime = ceil(seconds / 8), upper 13 bits of the 16-bit
 * combined field. PLC (Prefix Length Code) is the lower 3 bits:
 *   0 = /96, 1 = /64, 2 = /56, 3 = /48, 4 = /40, 5 = /32.
 */

#define SFW_ND_OPTION_PREF64 38

static int
sfw_pref64_plc_from_len (u8 prefix_len, u8 *out_plc)
{
  switch (prefix_len)
    {
    case 96:
      *out_plc = 0;
      return 0;
    case 64:
      *out_plc = 1;
      return 0;
    case 56:
      *out_plc = 2;
      return 0;
    case 48:
      *out_plc = 3;
      return 0;
    case 40:
      *out_plc = 4;
      return 0;
    case 32:
      *out_plc = 5;
      return 0;
    default:
      return -1;
    }
}

static void
sfw_pref64_build_option (u8 *out, const ip6_address_t *prefix,
			 u8 prefix_len, u16 lifetime_sec)
{
  u8 plc = 0;
  sfw_pref64_plc_from_len (prefix_len, &plc);

  /* RFC 8781 §4.1: scaled_lifetime = seconds / 8, clamped to the
   * representable range (13 bits * 8 = 65528 seconds). Ceiling
   * division so non-multiples of 8 don't round to zero. */
  u32 scaled = (lifetime_sec + 7) / 8;
  if (scaled > 0x1FFF)
    scaled = 0x1FFF;
  u16 combined = (u16) ((scaled << 3) | (plc & 0x7));

  out[0] = SFW_ND_OPTION_PREF64;
  out[1] = 2; /* length in units of 8 bytes => 16 bytes total */
  out[2] = (combined >> 8) & 0xff;
  out[3] = combined & 0xff;
  /* Highest 96 bits of the NAT64 prefix. Zero bits beyond prefix_len
   * so we never leak whatever was in the source ip6_address_t. */
  clib_memset (&out[4], 0, 12);
  u8 pfx_bytes = prefix_len / 8;
  if (pfx_bytes > 12)
    pfx_bytes = 12;
  clib_memcpy_fast (&out[4], prefix->as_u8, pfx_bytes);
}

/* The callback invoked by VPP's RA builder for every RA it sends.
 * Runs for both periodic and solicited RAs (they share the builder).
 * Writes exactly 16 bytes of PREF64 option on interfaces that have
 * pref64_advertise set, or nothing otherwise. */
static void
sfw_pref64_ra_option_cb (vlib_main_t *vm, u32 *bi, u32 sw_if_index,
			 u16 *payload_length)
{
  sfw_main_t *sm = &sfw_main;
  if (sw_if_index >= vec_len (sm->if_config))
    return;
  sfw_if_config_t *ic = &sm->if_config[sw_if_index];
  if (!ic->pref64_advertise)
    return;

  if (vlib_buffer_add_data (vm, bi, ic->pref64_option_bytes, 16))
    return; /* buffer alloc failure; silently skip this RA */
  *payload_length += 16;
}

void
sfw_pref64_init (void)
{
  ip6_ra_extra_option_register (sfw_pref64_ra_option_cb);
}

int
sfw_pref64_enable (sfw_main_t *sm, u32 sw_if_index,
		   const ip6_address_t *prefix, u8 prefix_len,
		   u16 lifetime_sec)
{
  /* Prefix must correspond to an existing NAT64 pool; advertising a
   * PREF64 we don't actually translate is worse than not advertising
   * at all (clients would send traffic into a black hole). */
  u32 pool_idx = sfw_nat64_match_pool (sm, prefix);
  if (pool_idx == ~0u)
    return -1;

  /* Defensive: re-validate the exact prefix_len against the pool's,
   * since sfw_nat64_match_pool only requires containment. */
  sfw_nat_pool_t *pool = &sm->nat_pools[pool_idx];
  if (pool->nat64_prefix_len != prefix_len)
    return -1;

  u8 plc_unused;
  if (sfw_pref64_plc_from_len (prefix_len, &plc_unused) != 0)
    return -1;

  vec_validate (sm->if_config, sw_if_index);
  sfw_if_config_t *ic = &sm->if_config[sw_if_index];

  /* Lifetime default: 3 × typical max RA interval (~200s) per
   * RFC 8781 §4.1 recommendation, clamped to max representable
   * value. Users can override via CLI/API lifetime parameter. */
  u16 eff_lifetime = lifetime_sec ? lifetime_sec : 1800;
  if (eff_lifetime > 65528)
    eff_lifetime = 65528;

  sfw_pref64_build_option (ic->pref64_option_bytes, prefix, prefix_len,
			   eff_lifetime);
  ic->pref64_advertise = 1;
  return 0;
}

int
sfw_pref64_disable (sfw_main_t *sm, u32 sw_if_index)
{
  if (sw_if_index >= vec_len (sm->if_config))
    return -1;
  sm->if_config[sw_if_index].pref64_advertise = 0;
  return 0;
}
