/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * bihash_inst_24_8.c — instantiation of the clib_bihash_24_8 template.
 *
 * The v2.2 fixture sets up an IPv6 FIB forwarding table whose lookup
 * (ip6_fib_table_fwding_lookup) walks ip6_fib_fwding_table.ip6_hash —
 * a clib_bihash_24_8.  libvppinfra ships the template macros but not
 * the 24/8 instantiation; without this file the harness fails to link
 * with `undefined reference to clib_bihash_init_24_8`.  Same shape as
 * bihash_inst.c (which does the 48/8 instantiation for the sfw
 * session table); separate TU because the two header sets can't
 * coexist in one TU. */

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_template.c>
