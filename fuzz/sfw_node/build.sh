#!/usr/bin/env bash
# build.sh — compile sfw_node (v2) chassis libFuzzer harnesses inside
# the audit-tools:vpp-fuzz container.
#
# v2 vs. v1 (../sfw_full):
#   v1 reaches sfw_nat64.c's translator entrypoints with a synthesised
#   single buffer + zero-init sfw_main.  Enough to fuzz the NAT64
#   translator dispatch end-to-end but doesn't exercise the node-level
#   classifier path (zone lookup, bihash session search/insert, policy
#   match, action dispatch).
#   v2 (here) compiles the full sfw plugin minus the IPv6-RA glue
#   (sfw_pref64.c, sfw_rdnss.c — header dep `vnet/ip6-nd/ip6_ra.h`
#   isn't in vpp-dev), instantiates the bihash_48_8 template, links
#   against libvppinfra plus a chassis_glue.o that fakes the VPP
#   runtime data + functions sfw .c files reach for outside
#   libvppinfra.
#
# v2.4 scope (this script): v2.3 fixture + one wildcard DNAT static
# (203.0.113.99 -> 10.0.0.5:80) and frame->n_vectors bumped from 1
# to 4 (per-frame meta[]/nexts[] interactions, sliced via a 1-byte
# length prefix per buffer).  Coverage uplift v2.3->v2.4:
# ip4 cov 495->569 / ft 496->1467, ip6 cov 485->499 / ft 486->1245.
#
# Usage:  build.sh [output-dir]
#         (default output-dir: /src/fuzz/sfw_node/out)
set -euo pipefail

OUT="${1:-/src/fuzz/sfw_node/out}"
SRC=/src
HERE="$SRC/fuzz/sfw_node"
mkdir -p "$OUT"

SAN_LINK_FLAGS="-fsanitize=address,undefined,fuzzer"
SAN_OBJ_FLAGS="-fsanitize=address,undefined,fuzzer-no-link"
COMMON_CFLAGS="-O1 -g -Wall -fno-omit-frame-pointer"

# sfw .c files use `#include <sfw/sfw.h>`; mirror that layout.
mkdir -p "$OUT/include/sfw"
ln -sf "$SRC/sfw.h" "$OUT/include/sfw/sfw.h"

INCLUDES="-I/usr/include -I$OUT/include -I$HERE -I$SRC"

##############################################################################
# Step 1: compile every sfw .c file we can (sfw_pref64 / sfw_rdnss
# pull <vnet/ip6-nd/ip6_ra.h> which isn't in vpp-dev — we stub their
# entrypoints in harness_glue.c instead).
##############################################################################
echo "--- compile sfw .c files ---"
for f in sfw.c sfw_node.c sfw_session.c sfw_rules.c sfw_nat.c sfw_nat64.c; do
    echo "    $f"
    clang $COMMON_CFLAGS $SAN_OBJ_FLAGS $INCLUDES \
        -c "$SRC/$f" -o "$OUT/${f%.c}.o"
done

##############################################################################
# Step 2: instantiate the bihash_48_8 template into its own object so
# the bihash funcs sfw.c / sfw_session.c reach for resolve at link
# time.  Two-line file by design (see bihash_inst.c).
##############################################################################
echo "--- compile bihash_inst.o ---"
clang $COMMON_CFLAGS $SAN_OBJ_FLAGS $INCLUDES \
    -c "$HERE/bihash_inst.c" -o "$OUT/bihash_inst.o"

# v2.2: ip6_fib_fwding_table.ip6_hash uses bihash_24_8; same template
# pattern, separate TU because the {48,24}_8 header macro sets clash.
echo "--- compile bihash_inst_24_8.o ---"
clang $COMMON_CFLAGS $SAN_OBJ_FLAGS $INCLUDES \
    -c "$HERE/bihash_inst_24_8.c" -o "$OUT/bihash_inst_24_8.o"

##############################################################################
# Step 3: compile the chassis glue (VPP runtime globals + function
# stubs).  Same flags so coverage instrumentation lines up across all
# fuzzer-traced TUs.
##############################################################################
echo "--- compile harness_glue.o ---"
clang $COMMON_CFLAGS $SAN_OBJ_FLAGS $INCLUDES \
    -c "$HERE/harness_glue.c" -o "$OUT/harness_glue.o"

##############################################################################
# Step 4: build each harness — link with sanitiser + libfuzzer entry,
# every sfw .o, bihash_inst.o, harness_glue.o, and libvppinfra.
##############################################################################
build_harness() {
    local target=$1
    echo "--- $target ---"
    clang $COMMON_CFLAGS $SAN_LINK_FLAGS $INCLUDES \
        "$HERE/$target.c" \
        "$OUT/sfw.o" \
        "$OUT/sfw_node.o" \
        "$OUT/sfw_session.o" \
        "$OUT/sfw_rules.o" \
        "$OUT/sfw_nat.o" \
        "$OUT/sfw_nat64.o" \
        "$OUT/bihash_inst.o" \
        "$OUT/bihash_inst_24_8.o" \
        "$OUT/harness_glue.o" \
        -lvppinfra \
        -o "$OUT/$target"
    echo "  -> $OUT/$target"
}

build_harness fuzz_sfw_ip4_node
build_harness fuzz_sfw_ip6_node

echo
echo "=== artefacts in $OUT ==="
ls -la "$OUT"
