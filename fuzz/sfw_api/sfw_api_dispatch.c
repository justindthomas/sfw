/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * sfw_api_dispatch.c — compile sfw_api.c with `static` neutralised
 * so the harness can call vl_api_sfw_*_t_handler functions across
 * TUs.  The handlers are file-scope static in production — that's
 * the right choice for the real plugin (one TU owns its API
 * surface) but blocks cross-TU dispatch in the fuzz harness.
 *
 * `#define static` before the #include is the minimal-blast-radius
 * way to expose them: only this TU sees the redefinition, the rest
 * of the build sees normal `static`.  STATIC_ASSERT inside
 * REPLY_MACRO uses the C11 _Static_assert keyword (single token,
 * not a separate `static`), so it isn't affected.
 *
 * sfw_api.c has no file-scope static *variables* — only static
 * functions — so neutralising static doesn't accidentally export
 * any non-handler state.
 */

#define static
#include "../../sfw_api.c"
#undef static
