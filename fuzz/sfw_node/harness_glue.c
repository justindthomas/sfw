/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * harness_glue.c — extern symbols sfw_node.c (and its sibling sfw .c
 * files) reach for that aren't present in libvppinfra.  Two
 * categories:
 *
 *   1. **VPP runtime data** — `vlib_global_main`, `vlib_thread_main`,
 *      `ip4_main`, `ip6_main`, `feature_main`, the FIB pools, etc.
 *      VPP normally allocates and populates these at vlib_init time;
 *      we provide zero-initialised storage so the linker resolves
 *      them.  Anything reaching into these at runtime needs explicit
 *      setup in `harness_init` (see harness_init.h) before invoking
 *      the sfw node.
 *
 *   2. **VPP runtime functions** — `vlib_*` / `vnet_*` / `format_*` /
 *      `unformat_*` / sfw plugin glue that we don't need at runtime.
 *      Stubs return harmless defaults; calls during fuzzing fall
 *      through cleanly so we can iterate towards real coverage.
 *
 * v2.0 scope: linker-clean only.  v2.1 will populate vm->buffer_main,
 * the FIB indices, and `feature_main` so the sfw node's per-packet
 * loop runs against a real fixture.  The plumbing for that is the
 * point of the chassis — see README.md.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/feature/feature.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip_packet.h>
#include <sfw/sfw.h>

/* ============================================================ */
/*  Category 1: VPP runtime globals                              */
/* ============================================================ */

vlib_global_main_t vlib_global_main;
vlib_thread_main_t vlib_thread_main;
vlib_buffer_func_main_t vlib_buffer_func_main;
u8 **vlib_thread_stacks;

vnet_feature_main_t feature_main;

ip4_main_t ip4_main;
ip6_main_t ip6_main;
ip4_fib_16_t *ip4_fib_16s;
ip4_mtrie_8_ply_t *ip4_ply_pool;
ip6_fib_fwding_table_instance_t ip6_fib_fwding_table;
load_balance_t *load_balance_pool;

/* sfw_main is defined in sfw.c (which we compile in here, unlike the
 * v1 sfw_full chassis that only compiled sfw_nat64.c).  No second
 * definition needed. */

/* The CPU-feature-detected SIMD checksum that VPP swaps in at
 * vlib_init time.  Reuse the v1 portable RFC-1071 implementation. */
static ip_csum_t
fuzz_incremental_checksum_portable (ip_csum_t csum, void *data_arg,
				    uword n_bytes)
{
  uint8_t *p = data_arg;
  while (n_bytes >= sizeof (uint32_t))
    {
      uint32_t w;
      __builtin_memcpy (&w, p, sizeof (w));
      csum = ip_csum_with_carry (csum, w);
      p += sizeof (uint32_t);
      n_bytes -= sizeof (uint32_t);
    }
  if (n_bytes > 0)
    {
      uint32_t tmp = 0;
      __builtin_memcpy (&tmp, p, n_bytes);
      csum = ip_csum_with_carry (csum, tmp);
    }
  return csum;
}

ip_csum_t (*vnet_incremental_checksum_fp) (ip_csum_t, void *, uword) =
  fuzz_incremental_checksum_portable;

/* ============================================================ */
/*  Category 2: VPP runtime function stubs                       */
/* ============================================================ */

/* Single zero-initialised vnet_main_t the stub vnet_get_main()
 * returns.  Callers use it primarily for `interface_main.sw_interfaces`
 * lookups; harness_init can populate one entry's worth of pool storage
 * if the harness needs to drive sw_if_index validation. */
static vnet_main_t fuzz_vnet_main;

vnet_main_t *
vnet_get_main (void)
{
  return &fuzz_vnet_main;
}

/* Feature-arc enable/disable is a no-op in fuzz: every interface is
 * "enabled" by virtue of the harness invoking the node directly. */
int
vnet_feature_enable_disable (const char *arc_name, const char *node_name,
			     u32 sw_if_index, int enable_disable,
			     void *feature_config,
			     u32 n_feature_config_bytes)
{
  (void) arc_name;
  (void) node_name;
  (void) sw_if_index;
  (void) enable_disable;
  (void) feature_config;
  (void) n_feature_config_bytes;
  return 0;
}

/* sfw plugin glue we don't compile in.  Stubs satisfy the linker; if
 * anything actually calls these in the harness, the abort makes it
 * obvious so we can wire it through. */
__attribute__((noreturn)) static void
fuzz_unimplemented (const char *name)
{
  fprintf (stderr, "harness: unimplemented stub %s called — wire it through\n",
	   name);
  abort ();
}

void
sfw_pref64_init (void)
{
}

int
sfw_pref64_enable (sfw_main_t *sm, u32 sw_if_index,
		   const ip6_address_t *prefix, u8 prefix_len,
		   u16 lifetime_sec)
{
  (void) sm;
  (void) sw_if_index;
  (void) prefix;
  (void) prefix_len;
  (void) lifetime_sec;
  return 0;
}

int
sfw_pref64_disable (sfw_main_t *sm, u32 sw_if_index)
{
  (void) sm;
  (void) sw_if_index;
  return 0;
}

void
sfw_rdnss_init (void)
{
}

int
sfw_rdnss_enable (sfw_main_t *sm, u32 sw_if_index,
		  const ip6_address_t *servers, u8 n_servers,
		  u32 lifetime_sec)
{
  (void) sm;
  (void) sw_if_index;
  (void) servers;
  (void) n_servers;
  (void) lifetime_sec;
  return 0;
}

int
sfw_rdnss_disable (sfw_main_t *sm, u32 sw_if_index)
{
  (void) sm;
  (void) sw_if_index;
  return 0;
}

clib_error_t *
sfw_plugin_api_hookup (vlib_main_t *vm)
{
  (void) vm;
  return NULL;
}

/* vlib runtime stubs.  None of these get reached by sfw_ip{4,6}_inline
 * unless the harness explicitly arranges for it (e.g., trace mode). */
uword
vlib_buffer_length_in_chain_slow_path (vlib_main_t *vm, vlib_buffer_t *b)
{
  (void) vm;
  return b ? b->current_length : 0;
}

void
vlib_cli_output (vlib_main_t *vm, char *fmt, ...)
{
  (void) vm;
  (void) fmt;
}

void *
vlib_add_trace (vlib_main_t *vm, vlib_node_runtime_t *r, vlib_buffer_t *b,
		u32 n_data_bytes)
{
  (void) vm;
  (void) r;
  (void) b;
  (void) n_data_bytes;
  /* Returning NULL here is fine for the non-trace path; the harness
   * runs with `node->flags = 0`, so VLIB_NODE_FLAG_TRACE is clear and
   * sfw_ip{4,6}_inline never invokes vlib_add_trace anyway. */
  return NULL;
}

void
vlib_worker_thread_barrier_sync_int (vlib_main_t *vm, const char *func_name)
{
  (void) vm;
  (void) func_name;
}

void
vlib_worker_thread_barrier_release (vlib_main_t *vm)
{
  (void) vm;
}

/* adj layer / formatting / unformatting — used in CLI paths from
 * sfw.c, not the node body.  Stubs panic to flag accidental reach. */
u32
adj_get_sw_if_index (u32 ai)
{
  (void) ai;
  fuzz_unimplemented ("adj_get_sw_if_index");
}

u8 *
format_vnet_sw_if_index_name (u8 *s, va_list *args)
{
  (void) args;
  return s;
}

uword
unformat_vnet_sw_interface (unformat_input_t *input, va_list *args)
{
  (void) input;
  (void) args;
  return 0;
}
