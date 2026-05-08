#!/usr/bin/env bash
# build.sh — compile sfw_full (v1) libFuzzer harnesses inside the
# audit-tools:vpp-fuzz container.
#
# v1 vs. v0 (../build.sh):
#   v0 mirrors a curated set of pure functions into sfw_pure.c and
#   builds harnesses against libvppinfra only — no vlib/vnet
#   dependencies, no plugin link.
#   v1 (here) compiles sfw_nat64.c itself with sanitisers and links
#   the harnesses against the resulting object file plus a tiny glue
#   layer that provides `sfw_main` and a portable
#   `vnet_incremental_checksum_fp`.  Reaches the full v6→v4 / v4→v6
#   translator dispatch including the icmp6_to_icmp / icmp_to_icmp6
#   helpers.
#
# Usage:  build.sh [output-dir]
#         (default output-dir: /src/fuzz/sfw_full/out)
set -euo pipefail

OUT="${1:-/src/fuzz/sfw_full/out}"
SRC=/src
HERE="$SRC/fuzz/sfw_full"
mkdir -p "$OUT"

SAN_LINK_FLAGS="-fsanitize=address,undefined,fuzzer"
SAN_OBJ_FLAGS="-fsanitize=address,undefined,fuzzer-no-link"
COMMON_CFLAGS="-O1 -g -Wall -fno-omit-frame-pointer"

# sfw_nat64.c does `#include <sfw/sfw.h>` because in the VPP plugin
# build tree it lives at src/plugins/sfw/.  Replicate that layout via
# a symlink under the build dir so the angle-include resolves.
mkdir -p "$OUT/include/sfw"
ln -sf "$SRC/sfw.h" "$OUT/include/sfw/sfw.h"

INCLUDES="-I/usr/include -I$OUT/include -I$HERE"

##############################################################################
# Step 1: compile sfw_nat64.c with sanitisers.  The build flags match
# what VPP would normally compile it with except for the sanitisers and
# the omission of -Werror (we want warnings — packed-member alignment
# etc — to surface but not fail the build during fuzzing).
##############################################################################
echo "--- compile sfw_nat64.o (sanitised) ---"
clang $COMMON_CFLAGS $SAN_OBJ_FLAGS $INCLUDES \
    -c "$SRC/sfw_nat64.c" -o "$OUT/sfw_nat64.o"

##############################################################################
# Step 2: compile harness glue (sfw_main + portable checksum).  Same
# flags so coverage instrumentation lines up.
##############################################################################
echo "--- compile harness_glue.o ---"
clang $COMMON_CFLAGS $SAN_OBJ_FLAGS $INCLUDES \
    -c "$HERE/harness_glue.c" -o "$OUT/harness_glue.o"

##############################################################################
# Step 3: build each harness — link with sanitiser + libfuzzer
# entrypoint, against sfw_nat64.o + harness_glue.o + libvppinfra.
##############################################################################
build_harness() {
    local target=$1
    echo "--- $target ---"
    clang $COMMON_CFLAGS $SAN_LINK_FLAGS $INCLUDES \
        "$HERE/$target.c" \
        "$OUT/sfw_nat64.o" \
        "$OUT/harness_glue.o" \
        -lvppinfra \
        -o "$OUT/$target"
    echo "  -> $OUT/$target"
}

build_harness fuzz_translate_v6_to_v4
build_harness fuzz_translate_v4_to_v6

##############################################################################
# Step 4: compile each known-trigger seed as a standalone reproducer.
# Useful for rerunning a specific finding without spinning up the full
# fuzzer.  Each trigger has its own main() (no libfuzzer entry).
##############################################################################
if [ -d "$HERE/triggers" ]; then
    echo "--- triggers ---"
    for trig in "$HERE/triggers"/*.c; do
        [ -e "$trig" ] || continue
        name=$(basename "$trig" .c)
        clang $COMMON_CFLAGS -fsanitize=address,undefined $INCLUDES \
            "$trig" \
            "$OUT/sfw_nat64.o" \
            "$OUT/harness_glue.o" \
            -lvppinfra \
            -o "$OUT/$name"
        echo "  -> $OUT/$name"
    done
fi

echo
echo "=== artefacts in $OUT ==="
ls -la "$OUT"
