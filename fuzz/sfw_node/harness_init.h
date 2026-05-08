/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * harness_init.h — public surface of the v2.1 chassis fixture.
 *
 * harness_init_once() runs the one-time setup of the synthesised vlib
 * runtime: vm->buffer_main + buffer arena, vm->node_main, error_main
 * counters, vlib_buffer_func_main stub, feature_main config arc 0,
 * ip4_main / ip6_main FIB index vec, and sfw_main via sfw_feature_init.
 * Idempotent.
 *
 * harness_load_packet(data, size) installs the fuzzer-provided bytes
 * into the buffer at index 0 — sets current_data=0, current_length=N,
 * flags=0, ref_count=1, sw_if_index[VLIB_RX]=0, current_config_index=0,
 * vnet_buffer(b)->feature_arc_index=0.  Resets frame->n_vectors=1 so the
 * harness can re-drive sfw_ip{4,6}_inline each iteration.
 *
 * fuzz_get_main / fuzz_get_node_runtime / fuzz_get_frame are thin
 * accessors so the harness body stays free of file-scoped statics.
 */

#ifndef HARNESS_INIT_H
#define HARNESS_INIT_H

#include <stdint.h>
#include <stddef.h>
#include <vlib/vlib.h>

void harness_init_once (void);
void harness_load_packet (const uint8_t *data, size_t size);

vlib_main_t *fuzz_get_main (void);
vlib_node_runtime_t *fuzz_get_node_runtime (void);
vlib_frame_t *fuzz_get_frame (void);

#endif /* HARNESS_INIT_H */
