/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * fuzz_sfw_ip6_node.c — v2 chassis harness for the sfw IPv6 node.
 * Same v2.0 placeholder shape as fuzz_sfw_ip4_node.c; see that file
 * and ../sfw_node/README.md for the v2.1 plan.
 */

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void) data;
  (void) size;
  return 0;
}
