/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * harness_init.h — public surface of the sfw_api fuzz chassis.
 * Lighter than sfw_node v2 — control-plane handlers don't need a
 * vlib runtime, so no buffer arena / vlib_frame fixture.  We just
 * need an initialised sfw_main_t (bihash, per-thread vecs, NAT pool
 * + DNAT static + zone-pair so add/del paths exercise both create
 * and remove flows).
 *
 * harness_init_once() runs the one-time setup: vppinfra heap,
 * vlib_thread_main.n_vlib_mains=1, sfw_feature_init, then a
 * canonical-state v4 NAT pool + DNAT static + zone-pair (2->1).
 * Idempotent.
 *
 * harness_dispatch(op_id, data, size) routes the fuzzer's bytes to
 * one of the 9 vl_api_sfw_*_t_handler functions, after copying up
 * to sizeof(struct) bytes into a freshly-zeroed message buffer with
 * client_index=0 (so REPLY_MACRO sees no registration and early-
 * returns instead of trying to alloc/send a reply).
 */

#ifndef HARNESS_INIT_H
#define HARNESS_INIT_H

#include <stdint.h>
#include <stddef.h>

void harness_init_once (void);
void harness_dispatch (uint8_t op_id, const uint8_t *data, size_t size);

#endif /* HARNESS_INIT_H */
