/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * bihash_inst.c — instantiate the clib_bihash_48_8 template into a
 * standalone object so sfw_node / sfw_session / sfw can link against
 * the real bihash implementation without pulling libvlib.
 *
 * In a normal VPP build, this instantiation lives in libvlib (or a
 * plugin's own object that includes <vppinfra/bihash_template.c>
 * exactly once). Our v2 chassis links against libvppinfra only, so
 * we own the instantiation here. Two-line file by design — the
 * macros in <vppinfra/bihash_48_8.h> set up KVP-per-page / instantiate
 * lazily / etc., and bihash_template.c emits the real symbols. */

#include <vppinfra/bihash_48_8.h>
#include <vppinfra/bihash_template.c>
