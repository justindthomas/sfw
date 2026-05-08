/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * fuzz_sfw_api.c — single libFuzzer harness driving all 9 sfw_api
 * binary-API handlers.  The first byte of the fuzzer input selects
 * which handler is invoked (op_id % 9); the remaining bytes are
 * memcpy'd into the message struct (capped at struct size).
 *
 * Coverage targets:
 *   - sfw_api_copy_fixed_string (audit F3 was a buf_len=0 underflow
 *     here — fixed; this harness is the regression watch).
 *   - The wire-format decode in each handler (ntohl on table_id,
 *     bool flag interpretation, etc.).
 *   - Mutator dispatch into sfw_main_t state — vec_validate of
 *     per-VRF zone-pair slabs, sfw_policy_create with overlapping
 *     names, sfw_nat_pool_add cycle (which references the shared
 *     v4_port_allocator pool), DNAT static add/del.
 *
 * Out of scope: the wire-format VPP API decoder (which translates
 * on-the-wire bytes into the packed `vl_api_sfw_*_t` struct).  The
 * harness presents fuzzer bytes as already-decoded structs, so the
 * raw-wire decode path is not exercised here.  That decode is a
 * thin layer on top of the same `sfw_api_copy_fixed_string` helper
 * we do hit.
 */

#include <stdint.h>
#include <stddef.h>
#include "harness_init.h"

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
  if (size < 1)
    return 0;

  uint8_t op = data[0];
  harness_dispatch (op, data + 1, size - 1);
  return 0;
}
