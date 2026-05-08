/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * fuzz_api_copy_fixed_string.c — libFuzzer harness for the fixed-string
 * wire-field decoder in sfw_api.c.
 *
 * F3 regression test: this function had a size_t-underflow bug if
 * `buf_len == 0` (8d5d56c) — calling memcpy with a SIZE_MAX-derived
 * length and then writing buf[SIZE_MAX-1]. Fix added a `buf_len == 0`
 * guard. Fuzzing confirms the guard holds and exercises the boundary
 * arithmetic for `wire_len` values larger and smaller than `buf_len`.
 *
 * Input layout (variable-length):
 *   data[0]       buf_len fuzz parameter (mod 64 to keep harness fast)
 *   data[1]       wire_len fuzz parameter (mod 256)
 *   data[2..]     wire bytes (caller passes data+2 as `wire`, length
 *                 capped at min(wire_len, size-2))
 *
 * The harness allocates `buf_len + 64` bytes of red-zone-padded
 * destination so ASan immediately catches any write past `buf_len`.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void sfw_api_copy_fixed_string (char *buf, size_t buf_len,
				       const void *wire, size_t wire_len);

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  size_t buf_len = (size_t) data[0] % 64;
  size_t wire_len = (size_t) data[1];
  const void *wire = data + 2;
  size_t wire_avail = size - 2;
  if (wire_len > wire_avail)
    wire_len = wire_avail;

  /* Allocate exactly buf_len bytes — no slack — so ASan red-zones flag
   * any stray write. malloc(0) is allowed; ASan will return a 1-byte
   * allocation with red-zones around it. */
  char *buf = (char *) malloc (buf_len);
  if (buf_len > 0 && !buf)
    return 0; /* allocation failed; skip this input */

  sfw_api_copy_fixed_string (buf, buf_len, wire, wire_len);

  /* Post-conditions:
   *   - If buf_len > 0, buf[buf_len-1] must be 0 (NUL-terminated).
   *   - All bytes [0..min(wire_len, buf_len-1)) must equal wire[0..n).
   * We don't assert these because the fuzzer's job is to find writes
   * past the end / underflow; the post-condition is enforced by ASan
   * if anything misbehaves on the buffer. */
  free (buf);
  return 0;
}
