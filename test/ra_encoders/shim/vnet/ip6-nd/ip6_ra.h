/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * TEST-ONLY shim for <vnet/ip6-nd/ip6_ra.h>. The real header lives only
 * in patched VPP source (vpp-patches/0001-ip6-ra-extra-option-hook.patch)
 * and is absent from the vpp-dev package, which is exactly why the three
 * RA encoders are dark to every other harness. The signature below is
 * copied verbatim from that patch so the encoders' init() functions
 * compile identically to the production build.
 */
#ifndef __included_sfw_ra_test_ip6_ra_shim_h__
#define __included_sfw_ra_test_ip6_ra_shim_h__

typedef void (*ip6_ra_extra_option_fn_t) (vlib_main_t *vm, u32 *bi,
					  u32 sw_if_index, u16 *payload_length);
extern void ip6_ra_extra_option_register (ip6_ra_extra_option_fn_t fn);
extern void ip6_ra_extra_option_unregister (ip6_ra_extra_option_fn_t fn);

#endif
