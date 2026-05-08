/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * fuzz_nat64_outer_cb.c — libFuzzer harness for the v6→v4 outer-header
 * rewrite callback (sfw_nat64.c:196).
 *
 * The callback is small: it copies new_src/new_dst from a context
 * struct into a freshly-allocated ip4 header. The interesting fuzz
 * surface is the pointer arithmetic and any aliasing the caller might
 * trigger — the inputs that drive the callback in production
 * (translated address pair) are operator-supplied via the NAT64 pool
 * config, and bugs analogous to F4 might exist in how the caller
 * constructs the context.
 *
 * Today's harness exercises the callback with arbitrary new_src/new_dst
 * combinations, including invalid IPv4 addresses, network-byte-order
 * confusion, and aliasing scenarios where ip6 and ip4 share memory.
 * ASan + UBSan catch any out-of-bounds write or undefined behaviour.
 *
 * Input layout (47 bytes minimum):
 *   data[0..3]    new_src (v4 pool addr)
 *   data[4..7]    new_dst (embedded v4 server)
 *   data[8..47]   ip6 header (40 bytes, mostly ignored — we only test
 *                 the pointer arg shape; full ip6 parsing is the
 *                 caller's job, not the callback's)
 *
 * The output ip4 header is a stack buffer the harness owns. ASan
 * red-zones it on all sides.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

/* Mirror of the context struct from sfw_nat64.c; sfw_session is
 * forward-declared in sfw_pure.c since the callback never derefs it. */
struct sfw_session;
typedef struct sfw_session sfw_session_t;

typedef struct
{
  ip4_address_t new_src;
  ip4_address_t new_dst;
  sfw_session_t *session;
} sfw_nat64_v6_to_v4_ctx_t;

extern int sfw_nat64_v6_to_v4_outer_cb (ip6_header_t *ip6,
					ip4_header_t *ip4, void *arg);

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 48)
    return 0;

  sfw_nat64_v6_to_v4_ctx_t ctx;
  memset (&ctx, 0, sizeof (ctx));
  memcpy (&ctx.new_src.as_u8[0], data, 4);
  memcpy (&ctx.new_dst.as_u8[0], data + 4, 4);
  ctx.session = NULL; /* callback never derefs */

  /* The ip6 input is parsed for context only — the callback today
   * doesn't read from it, but we pass a real pointer so any future
   * change that starts reading ip6 fields gets fuzzed automatically. */
  ip6_header_t ip6;
  memcpy (&ip6, data + 8, sizeof (ip6_header_t));

  ip4_header_t ip4;
  memset (&ip4, 0, sizeof (ip4));

  int rv = sfw_nat64_v6_to_v4_outer_cb (&ip6, &ip4, &ctx);
  (void) rv;

  /* Post-condition: the callback must have copied new_src/new_dst
   * verbatim into ip4. ASan catches any out-of-bounds write; this
   * assert catches any silent corruption. */
  if (memcmp (&ip4.src_address, &ctx.new_src, 4) != 0)
    __builtin_trap ();
  if (memcmp (&ip4.dst_address, &ctx.new_dst, 4) != 0)
    __builtin_trap ();

  return 0;
}
