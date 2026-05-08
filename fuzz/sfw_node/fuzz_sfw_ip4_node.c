/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * fuzz_sfw_ip4_node.c — v2.1 driver for sfw_ip4_inline.
 *
 * The fuzzer's bytes are loaded into the synthesised vlib_buffer at
 * index 0 by harness_load_packet().  The IPv4 node body parses
 * b->data as an ip4_header_t, validates IHL/length, extracts L4 ports
 * (sfw_extract_l4), then searches the bihash session table.  With the
 * default v2.1 fixture (sm->if_config empty), src_zone resolution
 * returns SFW_ZONE_NONE for sw_if_index=0, so the policy/FIB path is
 * skipped and the per-packet loop falls through PERMIT — counters
 * stamp, frame drains via the no-op enqueue stub, next iteration.
 *
 * Coverage closed by v2.1: parse + L4-extract + bihash search.  v2.2+
 * will populate if_config so policy + FIB-lookup land too.
 */

#include <stdint.h>
#include <stddef.h>

#include <vlib/vlib.h>
#include <sfw/sfw.h>
#include "harness_init.h"

/* sfw_ip4_inline is `always_inline static` in sfw_node.c, so we can't
 * call it directly across TUs.  But the canonical entrypoint is
 * VLIB_NODE_FN(sfw_ip4_node), an `extern` function the macro emits.
 * We don't have its declaration in any header — pull it in via a
 * forward decl matching the vlib_node_function_t signature. */
extern uword sfw_ip4_node_fn (vlib_main_t *, vlib_node_runtime_t *,
			      vlib_frame_t *);

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  harness_init_once ();
  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  /* Cheap guard against truly empty input — IPv4 header alone is 20
   * bytes; libfuzzer will discover this corpus boundary on its own
   * but skipping the call costs nothing and avoids one assert per
   * iteration.  Note: we still let small-but-nonzero inputs through
   * because the IHL/length validation in sfw_ip4_inline is exactly
   * what we want to fuzz. */
  if (size == 0)
    return 0;

  harness_load_packet (data, size);
  sfw_ip4_node_fn (fuzz_get_main (), fuzz_get_node_runtime (),
		   fuzz_get_frame ());
  return 0;
}
