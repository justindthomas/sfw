/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * TEST-ONLY shim standing in for <sfw/sfw.h> (and, transitively, the
 * vlib/vnet headers) so the three RFC RA-option encoders — sfw_pref64.c,
 * sfw_rdnss.c, sfw_dnr.c — can be compiled *verbatim* into a standalone,
 * VPP-free test translation unit with plain cc.
 *
 * This shim deliberately does NOT reproduce any encoder logic. It only
 * provides the handful of scalar types, the ip6_address_t union, the
 * clib byte-order / mem helpers, the SFW_* sizing constants, and the two
 * config structs whose *field layout* the encoders touch. A field/type
 * mismatch here surfaces as a compile error, never as a silently wrong
 * byte — so the shim cannot mask a wire-format bug. The bytes under test
 * are produced entirely by the real encoder bodies.
 *
 * Struct field definitions are copied to match sfw.h exactly (checked
 * against the canonical header at review time); only the fields the
 * encoders read/write are included.
 */
#ifndef __included_sfw_ra_test_shim_h__
#define __included_sfw_ra_test_shim_h__

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h> /* htons / htonl — endian-correct on any host */

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t i32;
typedef uintptr_t uword;

/* VPP ip6_address_t (vnet/ip/ip6_packet.h) */
typedef union
{
  u8 as_u8[16];
  u16 as_u16[8];
  u32 as_u32[4];
  u64 as_u64[2];
} ip6_address_t;

typedef union
{
  u8 as_u8[4];
  u32 as_u32;
} ip4_address_t;

/* clib helpers the encoders use. htons/htonl are endian-correct, so the
 * expected big-endian wire bytes are asserted on any build host. */
#define clib_memset	  memset
#define clib_memcpy_fast  memcpy
#define clib_host_to_net_u16(x) htons ((u16) (x))
#define clib_host_to_net_u32(x) htonl ((u32) (x))

/* --- SFW sizing constants (copied from sfw.h) --- */
#define SFW_DNR_MAX	   4
#define SFW_DNR_ADN_MAX	   255
#define SFW_DNR_OPTION_MAX 360
#define SFW_DNR_BUF_MAX	   (2 * SFW_DNR_OPTION_MAX)
#define SFW_RDNSS_MAX	   4

/* --- Per-interface config (only the encoder-touched fields) --- */
typedef struct
{
  u32 zone_id;
  u8 feature_on;

  u8 pref64_advertise;
  u8 pref64_option_bytes[16];

  u8 rdnss_count;
  u8 rdnss_option_len;
  u8 rdnss_option_bytes[8 + 16 * 4];

  u8 dnr_enabled;
  u16 dnr_option_len;
  u8 dnr_option_bytes[SFW_DNR_BUF_MAX];
} sfw_if_config_t;

/* NAT pool — only the field sfw_pref64_enable reads. */
typedef struct
{
  u8 nat64_prefix_len;
} sfw_nat_pool_t;

/* Plugin main — only the vecs the encoders' enable/cb touch. */
typedef struct
{
  sfw_if_config_t *if_config;
  sfw_nat_pool_t *nat_pools;
} sfw_main_t;

extern sfw_main_t sfw_main;

/* vec_* stand-ins. These appear only inside the enable/disable/cb
 * functions, which the test compiles and links but never calls, so the
 * macros need only compile — never behave. The wire-format tests call
 * the pure encoder statics directly. */
#define vec_len(v)	   (0u)
#define vec_elt(v, i)	   ((v)[i])
#define vec_validate(v, i) do { (void) (i); } while (0)

/* ip6_main_t (vnet/ip/ip6.h) — only the field sfw_pref64_enable reads. */
typedef struct
{
  u32 *fib_index_by_sw_if_index;
} ip6_main_t;
extern ip6_main_t ip6_main;

/* Opaque vlib_main_t for the callback signatures. */
typedef struct vlib_main vlib_main_t;

/* Runtime externs referenced only by the uncalled enable/cb functions;
 * satisfied by stub definitions in the test .c so the TU links. */
int vlib_buffer_add_data (vlib_main_t *vm, u32 *buffer_index, void *data,
			  u32 n_data_bytes);
u32 sfw_nat64_match_pool (sfw_main_t *sm, u32 table_id,
			  const ip6_address_t *v6_dst);

/* Public prototypes the encoder .c files define (kept in sync w/ sfw.h). */
void sfw_pref64_init (void);
int sfw_pref64_enable (sfw_main_t *sm, u32 sw_if_index,
		       const ip6_address_t *prefix, u8 prefix_len,
		       u16 lifetime_sec);
int sfw_pref64_disable (sfw_main_t *sm, u32 sw_if_index);
void sfw_rdnss_init (void);
int sfw_rdnss_enable (sfw_main_t *sm, u32 sw_if_index,
		      const ip6_address_t *servers, u8 n, u32 lifetime_sec);
int sfw_rdnss_disable (sfw_main_t *sm, u32 sw_if_index);
void sfw_dnr_init (void);
int sfw_dnr_enable (sfw_main_t *sm, u32 sw_if_index, const char *adn,
		    const ip6_address_t *addrs, u8 n_addr,
		    u16 service_priority, u32 lifetime_sec);
int sfw_dnr_disable (sfw_main_t *sm, u32 sw_if_index);

#endif /* __included_sfw_ra_test_shim_h__ */
