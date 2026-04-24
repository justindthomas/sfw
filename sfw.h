/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 */

/* sfw.h - stateful firewall + NAT plugin for VPP */

#ifndef __included_sfw_h__
#define __included_sfw_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_packet.h>
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>

/* --- Session keys --- */

/* IPv4 session key — zero-padded to 48 bytes for unified bihash_48_8.
 * Occupies first 16 bytes; remaining 32 bytes must be zero. */
typedef struct
{
  ip4_address_t src;
  ip4_address_t dst;
  u16 src_port;
  u16 dst_port;
  u8 protocol;
  u8 pad[3];
} sfw_key4_t;

STATIC_ASSERT_SIZEOF (sfw_key4_t, 16);

/* IPv6 session key — full 48 bytes */
typedef CLIB_PACKED (struct {
  ip6_address_t src;
  ip6_address_t dst;
  u16 src_port;
  u16 dst_port;
  u8 protocol;
  u8 pad[11];
}) sfw_key6_t;

STATIC_ASSERT_SIZEOF (sfw_key6_t, 48);

/* --- NAT types --- */

typedef enum
{
  SFW_NAT_NONE = 0,
  SFW_NAT_SNAT,  /* source translation (outbound) */
  SFW_NAT_DNAT,  /* destination translation (inbound port forward) */
  SFW_NAT_NAT64, /* stateful IPv6->IPv4 translation (RFC 6146) */
} sfw_nat_type_t;

typedef enum
{
  SFW_NAT_MODE_DETERMINISTIC = 0,
  SFW_NAT_MODE_DYNAMIC,
} sfw_nat_mode_t;

/* Pool kind distinguishes NAT44 pools (internal v4 -> external v4)
 * from NAT64 pools (NAT64 v6 prefix -> external v4). */
typedef enum
{
  SFW_POOL_KIND_NAT44 = 0,
  SFW_POOL_KIND_NAT64 = 1,
} sfw_pool_kind_t;

/* NAT pool: maps internal prefix to external prefix.
 * For NAT44 (kind == NAT44) the internal_addr/plen describes the v4 source
 * range to translate and external_addr/plen the v4 pool to translate into.
 * For NAT64 (kind == NAT64) the external_addr/plen is still the v4 pool,
 * but internal_addr/plen is unused; nat64_prefix / nat64_prefix_len
 * describe the RFC 6052 prefix used to embed the v4 destination in v6.
 *
 * The per-thread port allocation machinery is shared verbatim: the
 * bitmap indexes v4 pool addresses by external_idx and port slots by
 * (port - thread_port_start[t]).  NAT64 ICMP echo identifiers consume
 * entries from the same bitmap as TCP/UDP ports (both are u16). */
typedef struct
{
  u8 kind; /* sfw_pool_kind_t: NAT44 or NAT64 */

  ip4_address_t external_addr; /* first address in external v4 range */
  u8 external_plen;
  ip4_address_t internal_addr; /* first address in internal range (NAT44 only) */
  u8 internal_plen;
  u8 mode; /* sfw_nat_mode_t — NAT64 pools are always dynamic */

  /* NAT64 only: RFC 6052 prefix for address embedding (valid when
   * kind == SFW_POOL_KIND_NAT64). nat64_prefix_len must be one of
   * {32, 40, 48, 56, 64, 96}. */
  ip6_address_t nat64_prefix;
  u8 nat64_prefix_len;

  /* Deterministic mode parameters (NAT44 only) */
  u16 ports_per_host;

  /* Dynamic mode: per-thread port ranges.
   * The allocatable port range (1024-65535) is divided equally among
   * workers so each thread allocates from an exclusive slice with no
   * locking and no cross-thread collisions.
   *   thread 0: ports 1024 .. 1024+slice-1
   *   thread 1: ports 1024+slice .. 1024+2*slice-1
   *   ...
   * port_bitmaps[thread][ext_addr] tracks which ports within the
   * thread's slice are in use. */
  clib_bitmap_t ***port_bitmaps; /* vec[nworkers] of vec[n_ext_addrs] */
  u32 **next_port;		  /* vec[nworkers] of vec[n_ext_addrs] */
  u16 *thread_port_start;	  /* vec[nworkers] — first port for this thread */
  u16 *thread_port_count;	  /* vec[nworkers] — number of ports for this thread */

  /* Computed at add time */
  u32 n_external_addrs;
  u32 n_internal_addrs;
  u16 port_range_start; /* first allocatable port (default 1024) */
  u16 port_range_end;   /* last allocatable port (default 65535) */
} sfw_nat_pool_t;

/* DNAT static mapping */
typedef struct
{
  ip4_address_t external_addr;
  u16 external_port;
  ip4_address_t internal_addr;
  u16 internal_port;
  u8 protocol; /* TCP/UDP */
} sfw_nat_static_t;

/* --- Sessions --- */

typedef struct
{
  u8 is_ip6; /* ingress family; set once at session create */
  union
  {
    sfw_key4_t k4;
    sfw_key6_t k6;
  };
  u32 thread_index;
  f64 expires;
  u32 lru_next;
  u32 lru_prev;

  u8 nat_type;	  /* sfw_nat_type_t */
  u8 has_nat_key; /* 1 if a second bihash entry exists for the NATted key */

  /* Translation state — tag discriminated by nat_type.
   *   SFW_NAT_NONE                      → neither branch used
   *   SFW_NAT_SNAT / SFW_NAT_DNAT      → xlate.v4 holds v4 NAT info
   *   SFW_NAT_NAT64                     → xlate.n64 holds cross-family info
   *
   * NAT44 call sites read xlate.v4.*; NAT64 paths use xlate.n64.*
   * The v4 return key for a NAT64 session is reconstructable from
   * (n64.v4_server, n64.v4_pool, k6.src_port, n64.v4_pool_port, proto)
   * — k6 stores the ingress v6 key reversed for return-lookup matching,
   * so k6.src_port already equals the v4 dport and k6.dst_port already
   * equals the original v6 client sport. */
  union
  {
    struct
    {
      ip4_address_t nat_addr;  /* translated address */
      u16 nat_port;		/* translated port (network byte order) */
      ip4_address_t orig_addr; /* original pre-translation address */
      u16 orig_port;		/* original pre-translation port */
    } v4;
    struct
    {
      ip4_address_t v4_pool;	/* SNAT'd v4 source (from the pool) */
      ip4_address_t v4_server; /* embedded v4 destination (extracted from v6) */
      u16 v4_pool_port;	/* allocated v4 source port / ICMP id (net order) */
      u8 pool_idx;		/* index into sm->nat_pools for port free */
    } n64;
  } xlate;

  /* TCP connection state for early session expiry.
   * RST from either direction → short timeout.
   * FIN from both directions → short timeout. */
  u8 tcp_fin_fwd : 1; /* FIN seen from from_zone (initiator) */
  u8 tcp_fin_rev : 1; /* FIN seen from to_zone (responder) */
  u8 tcp_rst : 1;     /* RST seen from either direction */
} sfw_session_t;

/* Short timeout for sessions in TCP close/reset state (seconds) */
#define SFW_TCP_CLOSE_TIMEOUT 5.0

/* --- Rules and policies --- */

typedef enum
{
  SFW_ACTION_DENY = 0,
  SFW_ACTION_PERMIT,
  SFW_ACTION_PERMIT_STATEFUL,
  SFW_ACTION_PERMIT_STATEFUL_NAT, /* create session + apply SNAT */
} sfw_action_t;

/* Address family filter for rules */
typedef enum
{
  SFW_AF_ANY = 0, /* match both IPv4 and IPv6 */
  SFW_AF_IP4,	   /* match IPv4 only */
  SFW_AF_IP6,	   /* match IPv6 only */
} sfw_af_t;

typedef struct
{
  ip46_address_t src_prefix;
  ip46_address_t dst_prefix;
  u8 src_plen;
  u8 dst_plen;
  u8 protocol; /* 0 = any */
  u8 action;   /* sfw_action_t */
  u8 af;       /* sfw_af_t: ANY, IP4, or IP6 */
  u16 src_port_lo; /* 0 = any */
  u16 src_port_hi;
  u16 dst_port_lo;
  u16 dst_port_hi;
  u8 icmp_type; /* 255 = any */
  u8 icmp_code; /* 255 = any */
} sfw_rule_t;

typedef struct
{
  sfw_rule_t *rules;	/* vec of rules, evaluated in order */
  u8 default_action;	/* sfw_action_t */
  u8 implicit_icmpv6;	/* 1 = auto-permit NDP/PMTUD/echo (default) */
  char name[64];
  u32 from_zone_id; /* zone where traffic originates */
  u32 to_zone_id;   /* zone where traffic is destined */
} sfw_policy_t;

/* --- Zones --- */

#define SFW_ZONE_NONE	    0	/* unassigned / unknown zone */
#define SFW_ZONE_LOCAL	    1	/* built-in: traffic to/from the router itself */
#define SFW_MAX_ZONES	    16	/* max zones (zone_id 2..15, 0=none, 1=local) */

/* Zone definition */
typedef struct
{
  char name[32];
  u32 zone_id; /* compact numeric ID (1-based, 0 = none) */
} sfw_zone_t;

/* Zone-pair policy lookup entry */
typedef struct
{
  sfw_policy_t *policy; /* policy for this zone-pair, or NULL */
} sfw_zone_pair_t;

/* Per-interface config, indexed by sw_if_index */
typedef struct
{
  u32 zone_id;	  /* which zone this interface belongs to (0 = none) */
  u8 feature_on; /* 1 if sfw feature arcs are enabled on this interface */

  /* RFC 8781 PREF64 option advertisement. When pref64_advertise is
   * set, sfw's callback appends a 16-byte PREF64 option to every RA
   * emitted on this interface. pref64_option_bytes is the exact wire
   * format, precomputed from the pool prefix and lifetime at config
   * time so the hot path is a straight 16-byte buffer append. */
  u8 pref64_advertise;
  u8 pref64_option_bytes[16];
} sfw_if_config_t;

/* --- Plugin main --- */

typedef struct
{
  /* Unified session hash table (48-byte key for both IPv4 and IPv6).
   * IPv4 keys are zero-padded to 48 bytes. NATted sessions have TWO
   * entries: one with original key, one with translated key. */
  clib_bihash_48_8_t session_hash;

  /* Per-worker session pools and LRU lists */
  sfw_session_t **sessions; /* vec[nworkers] of per-thread pools */
  u32 *lru_head;	    /* vec[nworkers] - most recently used */
  u32 *lru_tail;	    /* vec[nworkers] - least recently used */

  /* Per-worker deferred free lists.  Sessions are unhashed and removed
   * from the LRU immediately, but pool_put is deferred by one expiry
   * cycle so that other threads holding a stale pool reference from a
   * concurrent bihash lookup don't hit a freed slot. */
  u32 **pending_free; /* vec[nworkers] of vec of session indices */

  /* Per-interface config (vec indexed by sw_if_index) */
  sfw_if_config_t *if_config;

  /* Zone definitions (pool indexed by zone_id) */
  sfw_zone_t zones[SFW_MAX_ZONES];
  u32 n_zones; /* number of defined zones (next zone_id to assign) */

  /* Zone-pair policy table: [from_zone_id * SFW_MAX_ZONES + to_zone_id] */
  sfw_zone_pair_t zone_pairs[SFW_MAX_ZONES * SFW_MAX_ZONES];

  /* Policy pool */
  sfw_policy_t **policies; /* vec of policy pointers */

  /* NAT pools and static mappings */
  sfw_nat_pool_t *nat_pools;     /* vec of NAT pool configs */
  sfw_nat_static_t *nat_statics; /* vec of DNAT static mappings */

  /* Config parameters */
  f64 session_timeout;		/* default 120.0 seconds */
  u32 max_sessions_per_worker;	/* default 100000 */
  u32 hash_buckets;		/* default 65536 */
  uword hash_memory;		/* default 256 MB */

  /* Convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  u16 msg_id_base;

  /* State */
  u8 initialized;

  /* Per-worker flag: set by CLI to request session clearing.
   * Each worker checks this in sfw_expire_inline and clears its
   * own sessions, avoiding cross-thread pool mutation. */
  volatile u8 *clear_requested; /* vec[nworkers] */

  /* Debug: per-thread flag to log first failed destination lookup */
  u8 *debug_logged; /* vec[nworkers], set to 1 after first log */
} sfw_main_t;

extern sfw_main_t sfw_main;

/* --- Multi-worker session encoding --- */

static inline u64
sfw_session_encode (u32 thread_index, u32 session_index)
{
  return ((u64) thread_index << 32) | (u64) session_index;
}

#define sfw_session_thread(v) ((u32) ((v) >> 32))
#define sfw_session_index(v)  ((u32) ((v) &0xFFFFFFFF))

/* --- LRU list management --- */

static inline void
sfw_lru_remove (sfw_main_t *sm, sfw_session_t *s)
{
  u32 ti = s->thread_index;
  u32 si = s - sm->sessions[ti];

  if (si == sm->lru_head[ti])
    sm->lru_head[ti] = s->lru_next;
  if (si == sm->lru_tail[ti])
    sm->lru_tail[ti] = s->lru_prev;

  if (s->lru_next != ~0)
    {
      sfw_session_t *next = pool_elt_at_index (sm->sessions[ti], s->lru_next);
      next->lru_prev = s->lru_prev;
    }
  if (s->lru_prev != ~0)
    {
      sfw_session_t *prev = pool_elt_at_index (sm->sessions[ti], s->lru_prev);
      prev->lru_next = s->lru_next;
    }
}

static inline void
sfw_lru_add_head (sfw_main_t *sm, sfw_session_t *s, f64 now)
{
  u32 ti = s->thread_index;
  u32 si = s - sm->sessions[ti];

  s->expires = now + sm->session_timeout;

  if (sm->lru_head[ti] != ~0)
    {
      sfw_session_t *old_head =
	pool_elt_at_index (sm->sessions[ti], sm->lru_head[ti]);
      old_head->lru_prev = si;
    }

  s->lru_prev = ~0;
  s->lru_next = sm->lru_head[ti];
  sm->lru_head[ti] = si;

  if (sm->lru_tail[ti] == ~0)
    sm->lru_tail[ti] = si;
}

static inline void
sfw_lru_touch (sfw_main_t *sm, sfw_session_t *s, f64 now)
{
  sfw_lru_remove (sm, s);
  sfw_lru_add_head (sm, s, now);
}

/* Remove a session from bihash and LRU but keep the pool slot.
 * Used by sfw_expire_inline to defer pool_put. */
void sfw_session_unhash (sfw_main_t *sm, sfw_session_t *s);

/* Remove a session completely (unhash + LRU + pool_put).
 * Only safe when no other thread can be referencing the session. */
void sfw_session_remove (sfw_main_t *sm, sfw_session_t *s);

/* --- Inline session expiry ---
 * Called once per frame on the current worker thread.
 * Each worker only expires its own sessions (thread-safe).
 *
 * Two-phase deferred free: first pool_put sessions that were unhashed
 * in the *previous* cycle (giving other threads time to finish any
 * in-progress access), then unhash newly expired sessions. */
static inline void
sfw_expire_inline (sfw_main_t *sm, u32 thread_index, f64 now)
{
  /* Phase 1: free sessions deferred from the previous cycle */
  u32 *pf = sm->pending_free[thread_index];
  u32 j;
  for (j = 0; j < vec_len (pf); j++)
    pool_put_index (sm->sessions[thread_index], pf[j]);
  vec_reset_length (pf);

  /* Check for CLI-requested clear (worker-safe: we own this pool) */
  if (PREDICT_FALSE (sm->clear_requested[thread_index]))
    {
      sm->clear_requested[thread_index] = 0;
      sfw_session_t *s;
      u32 *indices = 0;
      pool_foreach (s, sm->sessions[thread_index])
	{
	  vec_add1 (indices, s - sm->sessions[thread_index]);
	}
      for (j = 0; j < vec_len (indices); j++)
	{
	  s = pool_elt_at_index (sm->sessions[thread_index], indices[j]);
	  sfw_session_unhash (sm, s);
	  sfw_lru_remove (sm, s);
	  pool_put (sm->sessions[thread_index], s);
	}
      vec_free (indices);
      sm->pending_free[thread_index] = pf;
      return;
    }

  /* Phase 2: unhash expired sessions, defer pool_put to next cycle */
  u32 tail = sm->lru_tail[thread_index];
  while (tail != ~0)
    {
      sfw_session_t *s = pool_elt_at_index (sm->sessions[thread_index], tail);
      if (s->expires >= now)
	break; /* LRU-ordered: remaining sessions are newer */

      u32 prev = s->lru_prev;
      u32 si = s - sm->sessions[thread_index];
      sfw_session_unhash (sm, s);
      sfw_lru_remove (sm, s);
      vec_add1 (pf, si);
      tail = prev;
    }

  sm->pending_free[thread_index] = pf;
}

/* --- Forward declarations --- */

extern vlib_node_registration_t sfw_ip4_node;
extern vlib_node_registration_t sfw_ip6_node;
extern vlib_node_registration_t sfw_ip4_output_node;
extern vlib_node_registration_t sfw_ip6_output_node;

void sfw_feature_init (sfw_main_t *sm);

/* Enable or disable the sfw feature arc on a single interface. */
int sfw_enable_disable_interface (sfw_main_t *sm, u32 sw_if_index, int enable);

/* Zone helpers. Zone 0 is SFW_ZONE_NONE; zone 1 is the built-in
 * "local". find_or_create returns an existing zone id if the name
 * is already known, or a freshly allocated one. Returns
 * SFW_ZONE_NONE when the table is full. */
u32 sfw_zone_find_by_name (sfw_main_t *sm, const char *name);
u32 sfw_zone_find_or_create (sfw_main_t *sm, const char *name);

/* Policy helpers. sfw_policy_create wires the new policy into the
 * zone-pair table and enables the feature arc on every interface
 * that falls in from_zone or to_zone. sfw_policy_delete is the
 * inverse: detach from zone-pair, free rules + the policy struct. */
sfw_policy_t *sfw_policy_find (sfw_main_t *sm, const char *name);
sfw_policy_t *sfw_policy_create (sfw_main_t *sm, const char *name,
				 u32 from_zone_id, u32 to_zone_id);
void sfw_policy_delete (sfw_main_t *sm, sfw_policy_t *p);

/* API message handlers hookup (see sfw_api.c). */
clib_error_t *sfw_plugin_api_hookup (vlib_main_t *vm);

/* Rule matching */
sfw_action_t sfw_match_rules (sfw_rule_t *rules, u32 n_rules,
			      u8 default_action, u8 is_ip6,
			      ip46_address_t *src, ip46_address_t *dst,
			      u8 protocol, u16 src_port, u16 dst_port,
			      u8 icmp_type, u8 icmp_code);

/* Session management */
sfw_session_t *sfw_session_create (sfw_main_t *sm, u32 thread_index, f64 now);
int sfw_session_insert_hash (sfw_main_t *sm, sfw_session_t *s, u64 enc,
			     clib_bihash_kv_48_8_t *kv1,
			     clib_bihash_kv_48_8_t *kv2);

/* NAT */
int sfw_nat_translate_source (sfw_main_t *sm, u32 thread_index,
			      ip4_address_t *src_addr, u16 src_port,
			      u8 protocol, ip4_address_t *dst_addr,
			      ip4_address_t *out_addr, u16 *out_port,
			      u8 *out_mode);
sfw_nat_static_t *sfw_nat_find_dnat (sfw_main_t *sm,
				      ip4_address_t *dst_addr, u16 dst_port,
				      u8 protocol);
u32 sfw_ip4_addr_index (ip4_address_t *addr, ip4_address_t *base, u8 plen);
void sfw_ip4_addr_from_index (ip4_address_t *out, ip4_address_t *base,
			      u8 plen, u32 index);
u16 sfw_nat_pool_alloc_port (sfw_nat_pool_t *pool, u32 thread_index,
			     u32 external_idx);
void sfw_nat_free_port (sfw_nat_pool_t *pool, u32 thread_index,
			u32 external_idx, u16 port_h);
void sfw_nat_apply_snat (ip4_header_t *ip0, void *l4_hdr, u8 protocol,
			 ip4_address_t *new_addr, u16 new_port);
void sfw_nat_apply_dnat (ip4_header_t *ip0, void *l4_hdr, u8 protocol,
			 ip4_address_t *new_addr, u16 new_port);

/* NAT64 (RFC 6146 stateful, RFC 6052 prefix embed/extract, RFC 7915
 * packet translation). All live in sfw_nat64.c. */

/* RFC 6052 §2.2 embed: write <prefix> :: <v4> into out_v6 using the
 * prefix length's u-octet rules. prefix_len must be one of
 * {32,40,48,56,64,96}. */
void sfw_nat64_embed_v4 (const ip6_address_t *prefix, u8 prefix_len,
			 const ip4_address_t *v4, ip6_address_t *out_v6);

/* RFC 6052 §2.2 extract: if v6 lies within <prefix>, write the
 * embedded v4 into out_v4 and return 0; otherwise return -1. */
int sfw_nat64_extract_v4 (const ip6_address_t *prefix, u8 prefix_len,
			  const ip6_address_t *v6, ip4_address_t *out_v4);

/* Find a NAT64 pool whose prefix covers v6_dst. Returns pool index into
 * sm->nat_pools, or ~0 if no pool matches. */
u32 sfw_nat64_match_pool (sfw_main_t *sm, const ip6_address_t *v6_dst);

/* In-place translate the IPv6 packet at vlib_buffer_get_current(b) to
 * IPv4, using session->xlate.n64 fields for the translated addresses
 * and port/id. Shrinks the buffer by 20 bytes. Returns 0 on success,
 * negative value on failure (unsupported protocol, headroom issue). */
int sfw_nat64_translate_v6_to_v4 (vlib_main_t *vm, vlib_buffer_t *b,
				  sfw_session_t *session);

/* In-place translate the IPv4 packet at vlib_buffer_get_current(b) to
 * IPv6, using session fields for the restored v6 client addresses and
 * ports. Grows the buffer by 20 bytes (requires buffer headroom). */
int sfw_nat64_translate_v4_to_v6 (vlib_main_t *vm, vlib_buffer_t *b,
				  sfw_session_t *session);

/* --- PREF64 Router Advertisement option (RFC 8781) ---
 *
 * Registered at plugin init via VPP's ip6_ra_extra_option_register (a
 * small core-side hook shipped alongside sfw in vpp-patches/). Emits
 * the 16-byte PREF64 option on every RA sent on interfaces where
 * sfw_pref64_enable has been called. */

/* Plugin-init registration; called once from sfw_feature_init. */
void sfw_pref64_init (void);

/* Enable / disable PREF64 advertisement on an interface. prefix and
 * prefix_len must match an existing SFW_POOL_KIND_NAT64 pool (so the
 * advertised prefix is one the router actually translates). lifetime_sec
 * == 0 means "auto" (derive from RA default lifetime, clamped to
 * RFC 8781 max 65528s). Returns 0 on success, -1 if pool not found or
 * prefix length not one of {32,40,48,56,64,96}. */
int sfw_pref64_enable (sfw_main_t *sm, u32 sw_if_index,
		       const ip6_address_t *prefix, u8 prefix_len,
		       u16 lifetime_sec);
int sfw_pref64_disable (sfw_main_t *sm, u32 sw_if_index);

format_function_t format_sfw_session;

#endif /* __included_sfw_h__ */
