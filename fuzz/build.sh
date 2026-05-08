#!/usr/bin/env bash
# build.sh — compile sfw libFuzzer harnesses inside the
# audit-tools:vpp-fuzz container.
#
# Usage:  build.sh [output-dir]
#         (default output-dir: ./out)
#
# Pre-build sanity check: refuse to build if the mirrored function
# bodies in sfw_pure.c have diverged from the originals in
# ../sfw_nat64.c. This is a coarse line-by-line check on the
# MIRROR-START / MIRROR-END regions.

set -euo pipefail

OUT="${1:-/src/fuzz/out}"
SRC=/src
mkdir -p "$OUT"

##############################################################################
# Mirror drift check.
##############################################################################
echo "--- mirror-drift check ---"
check_mirror() {
    local fname=$1
    local origin_file=$2
    # Extract function body from each file. Both have the return type on
    # one line and the function name starting at column 1 of the next.
    # Body runs from the name-line to the first column-1 closing brace.
    local mirror_body
    mirror_body=$(awk "/^$fname \(/,/^}\$/" "$SRC/fuzz/sfw_pure.c")
    local origin_body
    origin_body=$(awk "/^$fname \(/,/^}\$/" "$SRC/$origin_file")
    if [ -z "$mirror_body" ]; then
        echo "[!] Could not extract '$fname' from fuzz/sfw_pure.c"
        exit 1
    fi
    if [ -z "$origin_body" ]; then
        echo "[!] Could not extract '$fname' from $origin_file"
        exit 1
    fi
    if ! diff <(echo "$mirror_body") <(echo "$origin_body") >/dev/null; then
        echo "[!] DRIFT DETECTED: $fname mirror in fuzz/sfw_pure.c"
        echo "    differs from original in $origin_file."
        echo "    Diff (mirror < origin >):"
        diff <(echo "$mirror_body") <(echo "$origin_body") | sed 's/^/      /'
        echo
        echo "    Update fuzz/sfw_pure.c to match (or update both"
        echo "    intentionally and re-fuzz)."
        exit 1
    fi
    echo "  $fname: ok"
}
check_mirror sfw_nat64_embed_v4 sfw_nat64.c
check_mirror sfw_nat64_extract_v4 sfw_nat64.c
check_mirror sfw_nat64_v6_to_v4_outer_cb sfw_nat64.c
check_mirror sfw_nat64_v6_to_v4_inner_cb sfw_nat64.c
check_mirror sfw_nat64_v4_to_v6_inner_cb sfw_nat64.c
check_mirror sfw_api_copy_fixed_string sfw_api.c

##############################################################################
# Compile harnesses.
##############################################################################
SAN_FLAGS="-fsanitize=address,undefined,fuzzer"
COMMON_CFLAGS="-O1 -g -Wall -fno-omit-frame-pointer"

# vpp-dev installs headers under /usr/include.
INCLUDES="-I/usr/include"

build_harness() {
    local target=$1
    echo "--- $target ---"
    clang $SAN_FLAGS $COMMON_CFLAGS $INCLUDES \
        "$SRC/fuzz/sfw_pure.c" \
        "$SRC/fuzz/$target.c" \
        -lvppinfra \
        -o "$OUT/$target"
    echo "  -> $OUT/$target"
}

build_harness fuzz_nat64_roundtrip
build_harness fuzz_api_copy_fixed_string
build_harness fuzz_nat64_outer_cb
build_harness fuzz_nat64_inner_cb_v6_to_v4
build_harness fuzz_nat64_inner_cb_v4_to_v6

echo
echo "=== artefacts in $OUT ==="
ls -la "$OUT"
