/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * fuzz_sfw_ip4_node.c — v2 chassis harness for the sfw IPv4 node.
 *
 * v2.0 scope (linker-clean): the harness body returns 0 unconditionally,
 * confirming that all sfw .c files compile + link against the chassis
 * glue and libvppinfra.  This is the foundation v2.1 builds on.
 *
 * v2.1 will:
 *   - allocate a 1-element vlib_buffer_t pool indexed via vm->buffer_main
 *   - synthesise a vlib_frame_t carrying that buffer's index
 *   - populate ip4_main.fib_index_by_sw_if_index[0] = 0 so the per-
 *     packet zone resolution doesn't OOB-read
 *   - wire feature_main.feature_config_main_by_arc_index so the
 *     vnet_feature_next() lookup returns a sane next-node index
 *   - call sfw_ip4_inline(vm, node_runtime, frame, 0) with is_trace=0
 *   - then drain the per-pass counters + reset state for the next
 *     iteration
 *
 * The node body's parse / classify / bihash search / policy match
 * paths are what v1's sfw_full doesn't cover - once v2.1 is up the
 * coverage gap PLAN.md item #4 named is closed.
 */

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void) data;
  (void) size;
  /* v2.0 placeholder — see header comment.  Returning 0 keeps libfuzzer
   * happy while we validate the chassis builds end-to-end on the
   * build host.  Replace with sfw_ip4_inline-driving body in v2.1. */
  return 0;
}
