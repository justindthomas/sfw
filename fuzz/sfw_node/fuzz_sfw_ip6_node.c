/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * fuzz_sfw_ip6_node.c — v2.1 driver for sfw_ip6_inline.
 * Mirror of fuzz_sfw_ip4_node.c against the IPv6 node entrypoint.
 * See that file's header for the v2.1 fixture / coverage notes.
 */

#include <stdint.h>
#include <stddef.h>

#include <vlib/vlib.h>
#include <sfw/sfw.h>
#include "harness_init.h"

extern uword sfw_ip6_node_fn (vlib_main_t *, vlib_node_runtime_t *,
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
  if (size == 0)
    return 0;

  harness_load_packet (data, size);
  sfw_ip6_node_fn (fuzz_get_main (), fuzz_get_node_runtime (),
		   fuzz_get_frame ());
  return 0;
}
