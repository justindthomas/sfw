/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * harness_buffer.h — vlib_buffer_t fixture for fuzz harnesses.
 *
 * vlib_buffer_t ends with `pre_data[VLIB_BUFFER_PRE_DATA_SIZE]` (a
 * fixed array) immediately followed by `data[]` (a flexible array).
 * sizeof(vlib_buffer_t) covers the header fields + pre_data; the
 * data area lives past it.  We back the harness's buffer with a
 * union large enough to give 2KB of data area, matching VPP's
 * VLIB_BUFFER_DEFAULT_DATA_SIZE — anything written past
 * b->data[FUZZ_BUFFER_DATA_SIZE] will land in ASan's red-zone after
 * the union and trip a stack-buffer-overflow.
 *
 * vlib_buffer_get_current() returns b->data + b->current_data, where
 * current_data is signed and may be negative (pointer goes back into
 * pre_data for headroom).  Harnesses that want headroom set
 * current_data to a positive offset and use it.  current_length is
 * the byte count from the current pointer that callers may walk
 * forwards.
 */

#ifndef FUZZ_HARNESS_BUFFER_H
#define FUZZ_HARNESS_BUFFER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <vlib/vlib.h>

#define FUZZ_BUFFER_DATA_SIZE 2048

typedef union
{
  vlib_buffer_t b;
  uint8_t bytes[sizeof (vlib_buffer_t) + FUZZ_BUFFER_DATA_SIZE];
} fuzz_buffer_t;

/* Fill `b` from fuzzer input.  current_data starts at `headroom`
 * (callers needing v4→v6 expansion want >= 20).  current_length is
 * clamped to fit. */
static inline void
fuzz_buffer_init (fuzz_buffer_t *fb, uint16_t headroom, const uint8_t *data,
		  size_t size)
{
  memset (fb, 0, sizeof (*fb));
  vlib_buffer_t *b = &fb->b;
  if (headroom > FUZZ_BUFFER_DATA_SIZE - 64)
    headroom = FUZZ_BUFFER_DATA_SIZE - 64;
  size_t cap = FUZZ_BUFFER_DATA_SIZE - headroom;
  if (size > cap)
    size = cap;
  if (size > 0xffff)
    size = 0xffff;
  memcpy (b->data + headroom, data, size);
  b->current_data = (int16_t) headroom;
  b->current_length = (uint16_t) size;
}

#endif /* FUZZ_HARNESS_BUFFER_H */
