/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 */

/* sfw_dnr.c - RFC 9463 DNR (Discovery of Network-designated
 * Resolvers) Router Advertisement option.
 *
 * Same shape as sfw_rdnss.c / sfw_pref64.c: registers a callback
 * with VPP's ip6_ra_extra_option_register hook so every RA emitted
 * on an interface where sfw_dnr_enable has been called carries a
 * type-144 DNR option. Where RDNSS (RFC 8106) advertises a plaintext
 * Do53 resolver, DNR advertises an *encrypted* one: an Authentication
 * Domain Name the client validates against the resolver's TLS
 * certificate, the resolver's IPv6 address(es), and SvcParams naming
 * the transport. This build advertises DNS-over-TLS (ALPN "dot",
 * RFC 9461) — the port is omitted, so clients use the DoT default of
 * 853.
 *
 * VPP has no native DNR support — no option-type enum, no builder,
 * no API. sfw owns the entire path via the ip6_ra extra-option
 * hook. */

#include <sfw/sfw.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip6-nd/ip6_ra.h>

/* RFC 9463 §6.1 DNR option for Router Advertisements (variable
 * length, padded to an 8-octet boundary):
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Type = 144  |    Length     |       Service Priority        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                          Lifetime                             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          ADN Length           |   ADN (DNS wire format)      ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               ~
 *  |          Addr Length          |  IPv6 Address(es), 16 ea.    ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               ~
 *  |        SvcParams Length       |  SvcParams (RFC 9460 §2.2)   ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               ~
 *  |                 (zero pad to 8-octet boundary)               ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Length is in 8-octet units (the standard ND option unit) and
 * counts the padding. The explicit SvcParams Length field is what
 * lets a parser separate the SvcParams from the trailing pad — the
 * pad is otherwise indistinguishable from more SvcParam bytes.
 */

#define SFW_ND_OPTION_DNR 144

/* Fixed SvcParams for DoT, RFC 9460 §2.2 wire format: a single
 * SvcParamKey "alpn" (key 1). Its value is a length-prefixed list of
 * ALPN protocol ids; the one id is "dot" (RFC 9461 §3). The "port"
 * SvcParam is omitted — RFC 9461 defines 853 as the DoT default. 8
 * octets total:
 *   00 01      SvcParamKey  = 1 (alpn)
 *   00 04      SvcParamValue length = 4
 *   03         alpn-id length = 3
 *   64 6f 74   "dot"                                                */
static const u8 sfw_dnr_svcparams_dot[8] = {
  0x00, 0x01, 0x00, 0x04, 0x03, 'd', 'o', 't',
};

/* Encode a textual domain name into uncompressed DNS wire format
 * (RFC 1035 §3.1): each label prefixed by its length octet, the
 * whole name terminated by a zero (root) octet. A single trailing
 * '.' is tolerated. Returns the wire length, or 0 if the name is
 * empty / just ".", has an empty or oversized label, or the
 * encoding would exceed SFW_DNR_ADN_MAX. */
static u16
sfw_dnr_encode_adn (const char *adn, u8 *out)
{
  if (adn == 0 || adn[0] == 0)
    return 0;

  u16 w = 0;
  const char *p = adn;
  while (*p && *p != '.')
    {
      const char *dot = p;
      while (*dot && *dot != '.')
	dot++;
      uword label_len = dot - p;
      if (label_len == 0 || label_len > 63)
	return 0; /* empty label ("a..b") or label too long */
      if ((uword) w + 1 + label_len + 1 > SFW_DNR_ADN_MAX)
	return 0; /* would overflow the max name length */
      out[w++] = (u8) label_len;
      clib_memcpy_fast (&out[w], p, label_len);
      w += label_len;
      p = dot;
      if (*p == '.')
	p++;
    }

  if (w == 0)
    return 0; /* name was empty or just "." */
  out[w++] = 0; /* terminating root label */
  return w;
}

/* Build the full DNR option (including the trailing pad) into out,
 * which must be at least SFW_DNR_OPTION_MAX bytes. Returns 0 on
 * success with *out_len set, or -1 on bad arguments. */
static int
sfw_dnr_build_option (u8 *out, u16 *out_len, const char *adn,
		      u16 service_priority, u32 lifetime_sec,
		      const ip6_address_t *addrs, u8 n_addr)
{
  if (n_addr == 0 || n_addr > SFW_DNR_MAX)
    return -1;

  u8 adn_wire[SFW_DNR_ADN_MAX];
  u16 adn_len = sfw_dnr_encode_adn (adn, adn_wire);
  if (adn_len == 0)
    return -1;

  u16 addr_len = (u16) n_addr * 16;
  u16 svc_len = (u16) sizeof (sfw_dnr_svcparams_dot);

  /* Option length before the 8-octet pad: type+len(2) + svcprio(2) +
   * lifetime(4) + adnlen(2) + ADN + addrlen(2) + addresses +
   * svcparamslen(2) + SvcParams. */
  u32 body = 2 + 2 + 4 + 2 + adn_len + 2 + addr_len + 2 + svc_len;
  u32 padded = (body + 7) & ~((u32) 7);
  if (padded > SFW_DNR_OPTION_MAX || padded / 8 > 255)
    return -1;

  /* RFC 9460 §2.4.1: SvcPriority 0 selects AliasMode; DNR is always
   * ServiceMode, so promote a 0 to 1. */
  if (service_priority == 0)
    service_priority = 1;

  u16 o = 0;
  out[o++] = SFW_ND_OPTION_DNR;
  out[o++] = (u8) (padded / 8);

  u16 sp = clib_host_to_net_u16 (service_priority);
  clib_memcpy_fast (&out[o], &sp, 2);
  o += 2;

  u32 lt = clib_host_to_net_u32 (lifetime_sec);
  clib_memcpy_fast (&out[o], &lt, 4);
  o += 4;

  u16 al = clib_host_to_net_u16 (adn_len);
  clib_memcpy_fast (&out[o], &al, 2);
  o += 2;
  clib_memcpy_fast (&out[o], adn_wire, adn_len);
  o += adn_len;

  u16 dl = clib_host_to_net_u16 (addr_len);
  clib_memcpy_fast (&out[o], &dl, 2);
  o += 2;
  for (u8 i = 0; i < n_addr; i++)
    {
      clib_memcpy_fast (&out[o], addrs[i].as_u8, 16);
      o += 16;
    }

  u16 sl = clib_host_to_net_u16 (svc_len);
  clib_memcpy_fast (&out[o], &sl, 2);
  o += 2;
  clib_memcpy_fast (&out[o], sfw_dnr_svcparams_dot, svc_len);
  o += svc_len;

  while (o < padded) /* zero-pad to the 8-octet boundary */
    out[o++] = 0;

  *out_len = o;
  return 0;
}

/* The callback invoked by VPP's RA builder for every RA it sends.
 * Runs for both periodic and solicited RAs (they share the builder).
 * Appends the precomputed DNR option on interfaces that opted in. */
static void
sfw_dnr_ra_option_cb (vlib_main_t *vm, u32 *bi, u32 sw_if_index,
		      u16 *payload_length)
{
  sfw_main_t *sm = &sfw_main;
  if (sw_if_index >= vec_len (sm->if_config))
    return;
  sfw_if_config_t *ic = &sm->if_config[sw_if_index];
  if (!ic->dnr_enabled)
    return;

  if (vlib_buffer_add_data (vm, bi, ic->dnr_option_bytes,
			    ic->dnr_option_len))
    return; /* buffer alloc failure; silently skip this RA */
  *payload_length += ic->dnr_option_len;
}

void
sfw_dnr_init (void)
{
  ip6_ra_extra_option_register (sfw_dnr_ra_option_cb);
}

int
sfw_dnr_enable (sfw_main_t *sm, u32 sw_if_index, const char *adn,
		const ip6_address_t *addrs, u8 n_addr,
		u16 service_priority, u32 lifetime_sec)
{
  /* Lifetime default 600s — same reasoning as sfw_rdnss.c: well
   * inside RFC 9463 §6.1's ">= 3 x MaxRtrAdvInterval" guidance for
   * the typical 200s interval, and above the 180s accept_ra_min_lft
   * floor Android 15+ enforces. 0xFFFFFFFF means infinite. */
  u32 lt = lifetime_sec ? lifetime_sec : 600;

  /* Build into a scratch buffer first so a malformed ADN or
   * oversized option leaves any existing config untouched. */
  u8 buf[SFW_DNR_OPTION_MAX];
  u16 len = 0;
  if (sfw_dnr_build_option (buf, &len, adn, service_priority, lt, addrs,
			    n_addr) != 0)
    return -1;

  vec_validate (sm->if_config, sw_if_index);
  sfw_if_config_t *ic = &sm->if_config[sw_if_index];
  clib_memcpy_fast (ic->dnr_option_bytes, buf, len);
  ic->dnr_option_len = len;
  ic->dnr_enabled = 1;
  return 0;
}

int
sfw_dnr_disable (sfw_main_t *sm, u32 sw_if_index)
{
  if (sw_if_index >= vec_len (sm->if_config))
    return -1;
  sfw_if_config_t *ic = &sm->if_config[sw_if_index];
  ic->dnr_enabled = 0;
  ic->dnr_option_len = 0;
  return 0;
}
