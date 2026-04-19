/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 */

/* sfw_nat.c - NAT pool management, translation, port allocation */

#include <sfw/sfw.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/ip/ip_types.h>

/* --- Address helpers --- */

u32
sfw_ip4_addr_index (ip4_address_t *addr, ip4_address_t *base, u8 plen)
{
  u32 mask = plen ? (~0u << (32 - plen)) : 0;
  u32 a = clib_net_to_host_u32 (addr->as_u32);
  u32 b = clib_net_to_host_u32 (base->as_u32);
  return (a & ~mask) - (b & ~mask);
}

void
sfw_ip4_addr_from_index (ip4_address_t *out, ip4_address_t *base, u8 plen,
			 u32 index)
{
  u32 b = clib_net_to_host_u32 (base->as_u32);
  out->as_u32 = clib_host_to_net_u32 (b + index);
}

/* --- Deterministic NAT port mapping --- */

/* For deterministic mode, each internal host gets a fixed range of ports
 * on a specific external address:
 *   external_index = internal_index / hosts_per_external
 *   port_offset = (internal_index % hosts_per_external) * ports_per_host
 *   allocated_port = port_range_start + port_offset + (flow_hash %
 * ports_per_host) */

static int
sfw_nat_det_translate (sfw_nat_pool_t *pool, ip4_address_t *internal_addr,
		       u16 internal_port, u8 protocol,
		       ip4_address_t *out_external, u16 *out_port)
{
  u32 internal_idx =
    sfw_ip4_addr_index (internal_addr, &pool->internal_addr, pool->internal_plen);

  if (internal_idx >= pool->n_internal_addrs)
    return -1;

  u32 hosts_per_external =
    pool->n_internal_addrs / pool->n_external_addrs;
  if (hosts_per_external == 0)
    hosts_per_external = 1;

  u32 external_idx = internal_idx / hosts_per_external;
  if (external_idx >= pool->n_external_addrs)
    external_idx = pool->n_external_addrs - 1;

  u32 host_offset = internal_idx % hosts_per_external;
  u16 port_base = pool->port_range_start +
		  (host_offset * pool->ports_per_host);

  /* Use source port as offset within the host's range */
  u16 sport_h = clib_net_to_host_u16 (internal_port);
  u16 port_offset = sport_h % pool->ports_per_host;
  u16 mapped_port = port_base + port_offset;

  if (mapped_port > pool->port_range_end)
    mapped_port = port_base; /* wrap */

  sfw_ip4_addr_from_index (out_external, &pool->external_addr,
			   pool->external_plen, external_idx);
  *out_port = clib_host_to_net_u16 (mapped_port);
  return 0;
}

/* --- Dynamic NAT port mapping --- */

/* Allocate a port from this thread's exclusive slice of the port range.
 * Returns the allocated port in host byte order, or 0 on exhaustion. */
static u16
sfw_nat_alloc_port (sfw_nat_pool_t *pool, u32 thread_index,
		    u32 external_idx)
{
  u16 count = pool->thread_port_count[thread_index];
  if (count == 0)
    return 0;

  clib_bitmap_t **bm = &pool->port_bitmaps[thread_index][external_idx];
  u32 hint = pool->next_port[thread_index][external_idx];

  /* Search for a free bit starting from the hint */
  uword bit = clib_bitmap_next_clear (*bm, hint);
  if (bit >= count)
    {
      bit = clib_bitmap_next_clear (*bm, 0);
      if (bit >= count)
	return 0; /* exhausted */
    }

  *bm = clib_bitmap_set (*bm, bit, 1);
  pool->next_port[thread_index][external_idx] = (bit + 1) % count;
  return pool->thread_port_start[thread_index] + (u16) bit;
}

/* Free a previously allocated port back to the bitmap. */
void
sfw_nat_free_port (sfw_nat_pool_t *pool, u32 thread_index,
		   u32 external_idx, u16 port_h)
{
  u16 start = pool->thread_port_start[thread_index];
  u32 bit = port_h - start;
  pool->port_bitmaps[thread_index][external_idx] =
    clib_bitmap_set (pool->port_bitmaps[thread_index][external_idx], bit, 0);
}

static int
sfw_nat_dynamic_translate (sfw_nat_pool_t *pool, u32 thread_index,
			   ip4_address_t *internal_addr, u16 internal_port,
			   u8 protocol, ip4_address_t *out_external,
			   u16 *out_port)
{
  /* Hash the source tuple to select a preferred external address */
  u32 hash = internal_addr->as_u32 ^ ((u32) internal_port << 16) ^
	     ((u32) protocol << 8);

  u32 preferred_idx = hash % pool->n_external_addrs;
  u32 n = pool->n_external_addrs;
  u32 attempt;

  /* Try the preferred address first, then fall back to others */
  for (attempt = 0; attempt < n; attempt++)
    {
      u32 external_idx = (preferred_idx + attempt) % n;
      u16 port = sfw_nat_alloc_port (pool, thread_index, external_idx);
      if (port != 0)
	{
	  sfw_ip4_addr_from_index (out_external, &pool->external_addr,
				   pool->external_plen, external_idx);
	  *out_port = clib_host_to_net_u16 (port);
	  return 0;
	}
    }

  return -1; /* all external addresses exhausted */
}

/* --- Public NAT API --- */

int
sfw_nat_translate_source (sfw_main_t *sm, u32 thread_index,
			  ip4_address_t *src_addr, u16 src_port, u8 protocol,
			  ip4_address_t *dst_addr, ip4_address_t *out_addr,
			  u16 *out_port, u8 *out_mode)
{
  u32 i;

  for (i = 0; i < vec_len (sm->nat_pools); i++)
    {
      sfw_nat_pool_t *pool = &sm->nat_pools[i];

      /* Check if source address falls within this pool's internal range */
      u32 mask = pool->internal_plen ?
		   clib_host_to_net_u32 (~0u << (32 - pool->internal_plen)) :
		   0;
      if ((src_addr->as_u32 & mask) !=
	  (pool->internal_addr.as_u32 & mask))
	continue;

      /* Skip NAT if destination is also in the internal range.
       * This prevents NATting traffic to the router itself and
       * LAN-to-LAN traffic — only transit traffic gets NATted. */
      if ((dst_addr->as_u32 & mask) ==
	  (pool->internal_addr.as_u32 & mask))
	return -1;

      /* Skip NAT for subnet broadcast and network addresses of the
       * internal prefix (except /31 where both addresses are usable). */
      if (pool->internal_plen < 31)
	{
	  u32 dst_h = clib_net_to_host_u32 (dst_addr->as_u32);
	  u32 host_mask = ~(~0u << (32 - pool->internal_plen));
	  u32 host_part = dst_h & host_mask;
	  if (host_part == 0 || host_part == host_mask)
	    return -1; /* network or broadcast address */
	}

      /* Skip NAT for multicast destinations */
      if ((clib_net_to_host_u32 (dst_addr->as_u32) >> 28) == 0xE)
	return -1;

      *out_mode = pool->mode;
      switch (pool->mode)
	{
	case SFW_NAT_MODE_DETERMINISTIC:
	  return sfw_nat_det_translate (pool, src_addr, src_port, protocol,
					out_addr, out_port);
	case SFW_NAT_MODE_DYNAMIC:
	  return sfw_nat_dynamic_translate (pool, thread_index, src_addr,
					    src_port, protocol, out_addr,
					    out_port);
	}
    }

  return -1; /* no matching pool */
}

sfw_nat_static_t *
sfw_nat_find_dnat (sfw_main_t *sm, ip4_address_t *dst_addr, u16 dst_port,
		   u8 protocol)
{
  u32 i;
  u16 dst_port_h = clib_net_to_host_u16 (dst_port);
  sfw_nat_static_t *wildcard = 0;

  for (i = 0; i < vec_len (sm->nat_statics); i++)
    {
      sfw_nat_static_t *s = &sm->nat_statics[i];
      if (s->external_addr.as_u32 != dst_addr->as_u32)
	continue;

      /* Exact match (port + protocol) takes priority */
      if (s->external_port == dst_port_h && s->protocol == protocol)
	return s;

      /* 1:1 match (port=0, protocol=0 = match any) */
      if (s->external_port == 0 && s->protocol == 0)
	wildcard = s;
    }

  return wildcard;
}

/* --- Packet rewrite --- */

/* Incrementally update IP and L4 checksums after address/port change */
static inline void
sfw_nat_update_checksums (ip4_header_t *ip0, void *l4_hdr, u8 protocol,
			  ip4_address_t *old_addr, ip4_address_t *new_addr,
			  u16 old_port, u16 new_port)
{
  ip_csum_t csum;

  /* IP header checksum */
  csum = ip0->checksum;
  csum = ip_csum_update (csum, old_addr->as_u32, new_addr->as_u32,
			 ip4_header_t, src_address);
  ip0->checksum = ip_csum_fold (csum);

  /* L4 checksum */
  if (protocol == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) l4_hdr;
      csum = tcp->checksum;
      csum = ip_csum_update (csum, old_addr->as_u32, new_addr->as_u32,
			     ip4_header_t, src_address);
      csum = ip_csum_update (csum, old_port, new_port, ip4_header_t,
			     length /* dummy */);
      tcp->checksum = ip_csum_fold (csum);
    }
  else if (protocol == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *) l4_hdr;
      if (udp->checksum != 0)
	{
	  csum = udp->checksum;
	  csum = ip_csum_update (csum, old_addr->as_u32, new_addr->as_u32,
				 ip4_header_t, src_address);
	  csum = ip_csum_update (csum, old_port, new_port, ip4_header_t,
				 length);
	  udp->checksum = ip_csum_fold (csum);
	}
    }
}

void
sfw_nat_apply_snat (ip4_header_t *ip0, void *l4_hdr, u8 protocol,
		    ip4_address_t *new_addr, u16 new_port)
{
  ip4_address_t old_addr = ip0->src_address;
  u16 old_port = 0;

  ip0->src_address = *new_addr;

  /* Only translate ports for TCP/UDP. ICMP identifiers must be preserved
   * because the remote end echoes them back unchanged in the reply. */
  if (protocol == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) l4_hdr;
      old_port = tcp->src_port;
      tcp->src_port = new_port;
    }
  else if (protocol == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *) l4_hdr;
      old_port = udp->src_port;
      udp->src_port = new_port;
    }

  sfw_nat_update_checksums (ip0, l4_hdr, protocol, &old_addr, new_addr,
			    old_port, new_port);
}

void
sfw_nat_apply_dnat (ip4_header_t *ip0, void *l4_hdr, u8 protocol,
		    ip4_address_t *new_addr, u16 new_port)
{
  ip4_address_t old_addr = ip0->dst_address;
  u16 old_port = 0;

  ip0->dst_address = *new_addr;

  if (protocol == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) l4_hdr;
      old_port = tcp->dst_port;
      tcp->dst_port = new_port;
    }
  else if (protocol == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *) l4_hdr;
      old_port = udp->dst_port;
      udp->dst_port = new_port;
    }

  sfw_nat_update_checksums (ip0, l4_hdr, protocol, &old_addr, new_addr,
			    old_port, new_port);
}
