/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * Stub for `<sfw/sfw.api.c>` — sfw_api.c includes this at the
 * bottom to pull in the generated message-id setup
 * (setup_message_id_table) plus the endian/format/tojson/fromjson/
 * calc_size symbols that the production VPP runtime registers via
 * vl_msg_api_config.  None of that surface is reached when the
 * fuzz harness calls vl_api_sfw_*_t_handler functions directly,
 * and pulling it in tries to link several hundred undefined
 * symbols from libvlibmemory.
 *
 * Clang's include search picks this up before the generated file
 * because $HERE precedes $OUT/include in the build's -I order.
 *
 * We still need a setup_message_id_table symbol because
 * sfw_plugin_api_hookup (also in sfw_api.c, exposed by the
 * `static` redefinition) calls it.  Make it return 0 — the harness
 * never reads sm->msg_id_base downstream so the value is opaque. */

static u16
setup_message_id_table (void)
{
  return 0;
}
