/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 */

/* sfw_rdnss.c - RFC 8106 RDNSS Router Advertisement option.
 *
 * Same shape as sfw_pref64.c: registers a callback with VPP's
 * ip6_ra_extra_option_register hook so every RA emitted on an
 * interface where sfw_rdnss_enable has been called carries an
 * RDNSS option listing the configured IPv6 nameservers. Clients
 * that understand the option (recent Linux/Android, iOS/macOS,
 * Windows) pick up the resolver address(es) without DHCPv6.
 *
 * VPP itself only declares the RDNSS option type code in an enum
 * (icmp46_packet.h:222) — no builder, no API, no CLI. We own the
 * full path. */

#include <sfw/sfw.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip6-nd/ip6_ra.h>

/* RFC 8106 §5.1 RDNSS option layout (8 + 16*N bytes total):
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Type = 25    |  Length=1+2N  |           Reserved            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                           Lifetime                            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  :                       Server N (16 bytes)                     :
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Length is in 8-byte units. Lifetime is seconds the resolver may
 * be used; per RFC 8106 §5.1 a client SHOULD NOT use a value > 2 ×
 * MaxRtrAdvInterval. 0 means stop using; 0xFFFFFFFF means infinite.
 */

#define SFW_ND_OPTION_RDNSS 25

static void
sfw_rdnss_build_option (u8 *out, const ip6_address_t *servers, u8 n,
			u32 lifetime_sec)
{
  out[0] = SFW_ND_OPTION_RDNSS;
  out[1] = 1 + 2 * n; /* length in 8-byte units */
  out[2] = 0;
  out[3] = 0;
  u32 lt = clib_host_to_net_u32 (lifetime_sec);
  clib_memcpy_fast (&out[4], &lt, 4);
  for (u8 i = 0; i < n; i++)
    clib_memcpy_fast (&out[8 + 16 * i], servers[i].as_u8, 16);
}

/* The callback invoked by VPP's RA builder for every RA it sends.
 * Runs for both periodic and solicited RAs (they share the builder).
 * Writes 8 + 16*N bytes on interfaces with rdnss_count > 0. */
static void
sfw_rdnss_ra_option_cb (vlib_main_t *vm, u32 *bi, u32 sw_if_index,
			u16 *payload_length)
{
  sfw_main_t *sm = &sfw_main;
  if (sw_if_index >= vec_len (sm->if_config))
    return;
  sfw_if_config_t *ic = &sm->if_config[sw_if_index];
  if (ic->rdnss_count == 0)
    return;

  if (vlib_buffer_add_data (vm, bi, ic->rdnss_option_bytes,
			    ic->rdnss_option_len))
    return; /* buffer alloc failure; silently skip this RA */
  *payload_length += ic->rdnss_option_len;
}

void
sfw_rdnss_init (void)
{
  ip6_ra_extra_option_register (sfw_rdnss_ra_option_cb);
}

int
sfw_rdnss_enable (sfw_main_t *sm, u32 sw_if_index,
		  const ip6_address_t *servers, u8 n, u32 lifetime_sec)
{
  if (n == 0 || n > SFW_RDNSS_MAX)
    return -1;

  vec_validate (sm->if_config, sw_if_index);
  sfw_if_config_t *ic = &sm->if_config[sw_if_index];

  /* Lifetime default: 600s. RFC 8106 §5.1 recommends RDNSS Lifetime
   * be in [MaxRtrAdvInterval, 2 × MaxRtrAdvInterval]; 600s is a safe
   * pick for the typical 200–600s MaxRtrAdvInterval range and stays
   * well above the 180s floor that Android 15+ enforces via
   * net.ipv6.conf.<if>.accept_ra_min_lft (RA sections under that
   * value are silently dropped by the kernel — RDNSS at 90s
   * triggered the v6-only-mostly + Android failure tracked at
   * issuetracker #396995424). Caller may pass 0xFFFFFFFF for
   * "infinite" or any explicit value. */
  u32 lt = lifetime_sec ? lifetime_sec : 600;

  sfw_rdnss_build_option (ic->rdnss_option_bytes, servers, n, lt);
  ic->rdnss_option_len = 8 + 16 * n;
  ic->rdnss_count = n;
  return 0;
}

int
sfw_rdnss_disable (sfw_main_t *sm, u32 sw_if_index)
{
  if (sw_if_index >= vec_len (sm->if_config))
    return -1;
  sfw_if_config_t *ic = &sm->if_config[sw_if_index];
  ic->rdnss_count = 0;
  ic->rdnss_option_len = 0;
  return 0;
}
