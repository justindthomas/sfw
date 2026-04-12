/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 */

/* sfw_rules.c - rule matching and policy management */

#include <sfw/sfw.h>

static inline int
sfw_prefix_match (ip46_address_t *addr, ip46_address_t *prefix, u8 plen,
		  u8 is_ip6)
{
  if (plen == 0)
    return 1; /* match any */

  if (is_ip6)
    {
      /* Compare plen bits of IPv6 address */
      u32 full_words = plen / 32;
      u32 remaining_bits = plen % 32;
      u32 i;

      for (i = 0; i < full_words; i++)
	{
	  if (addr->ip6.as_u32[i] != prefix->ip6.as_u32[i])
	    return 0;
	}
      if (remaining_bits)
	{
	  u32 mask = clib_host_to_net_u32 (~0u << (32 - remaining_bits));
	  if ((addr->ip6.as_u32[i] & mask) != (prefix->ip6.as_u32[i] & mask))
	    return 0;
	}
      return 1;
    }
  else
    {
      u32 mask = clib_host_to_net_u32 (~0u << (32 - plen));
      return (addr->ip4.as_u32 & mask) == (prefix->ip4.as_u32 & mask);
    }
}

static inline int
sfw_port_match (u16 port, u16 lo, u16 hi)
{
  /* lo == 0 && hi == 0 means "any port" */
  if (lo == 0 && hi == 0)
    return 1;
  return (port >= lo && port <= hi);
}

sfw_action_t
sfw_match_rules (sfw_rule_t *rules, u32 n_rules, u8 default_action,
		 u8 is_ip6, ip46_address_t *src, ip46_address_t *dst,
		 u8 protocol, u16 src_port, u16 dst_port, u8 icmp_type,
		 u8 icmp_code)
{
  u32 i;

  for (i = 0; i < n_rules; i++)
    {
      sfw_rule_t *r = &rules[i];

      /* Address family check: AF_ANY matches both, otherwise must match */
      if (r->af == SFW_AF_IP4 && is_ip6)
	continue;
      if (r->af == SFW_AF_IP6 && !is_ip6)
	continue;

      /* Protocol check (0 = any) */
      if (r->protocol != 0 && r->protocol != protocol)
	continue;

      /* Source prefix */
      if (r->src_plen > 0 && !sfw_prefix_match (src, &r->src_prefix,
						 r->src_plen, is_ip6))
	continue;

      /* Destination prefix */
      if (r->dst_plen > 0 && !sfw_prefix_match (dst, &r->dst_prefix,
						 r->dst_plen, is_ip6))
	continue;

      /* Port ranges (only meaningful for TCP/UDP) */
      if (protocol == IP_PROTOCOL_TCP || protocol == IP_PROTOCOL_UDP)
	{
	  if (!sfw_port_match (src_port, r->src_port_lo, r->src_port_hi))
	    continue;
	  if (!sfw_port_match (dst_port, r->dst_port_lo, r->dst_port_hi))
	    continue;
	}

      /* ICMP type/code (only meaningful for ICMP/ICMPv6) */
      if (protocol == IP_PROTOCOL_ICMP || protocol == IP_PROTOCOL_ICMP6)
	{
	  if (r->icmp_type != 255 && r->icmp_type != icmp_type)
	    continue;
	  if (r->icmp_code != 255 && r->icmp_code != icmp_code)
	    continue;
	}

      /* Match found */
      return (sfw_action_t) r->action;
    }

  return (sfw_action_t) default_action;
}
