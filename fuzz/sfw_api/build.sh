#!/usr/bin/env bash
# build.sh — compile the sfw_api fuzz harness inside audit-tools:
# vpp-fuzz.  Builds:
#   1. Generate sfw.api*.h via vppapigen (not in repo — produced
#      from sfw.api at plugin build time normally).
#   2. Compile sfw.c, sfw_session.c, sfw_rules.c, sfw_nat.c,
#      sfw_nat64.c (the sfw_api handlers reach for sfw_main mutators
#      in these TUs).
#   3. Compile sfw_api_dispatch.c — wrapper TU that #defines static
#      to nothing then #includes sfw_api.c, exposing the
#      vl_api_sfw_*_t_handler functions cross-TU.
#   4. Compile bihash_inst.c (48_8 instantiation for session_hash).
#   5. Compile harness_glue.c.
#   6. Link the harness against sanitisers + libfuzzer + libvppinfra.
#
# v1.0 scope: every TU compiles, every symbol resolves, the harness
# dispatches to all 9 vl_api_sfw_*_t_handler functions selected by
# op_id = data[0] % 9.
set -euo pipefail

OUT="${1:-/src/fuzz/sfw_api/out}"
SRC=/src
HERE="$SRC/fuzz/sfw_api"
mkdir -p "$OUT"

SAN_LINK_FLAGS="-fsanitize=address,undefined,fuzzer"
SAN_OBJ_FLAGS="-fsanitize=address,undefined,fuzzer-no-link"
COMMON_CFLAGS="-O1 -g -Wall -fno-omit-frame-pointer"

# sfw .c files use `#include <sfw/sfw.h>` and sfw_api.c also uses
# `#include <sfw/sfw.api_enum.h>` etc.  Mirror the layout: symlink
# sfw.h and the generated api headers into out/include/sfw/.
mkdir -p "$OUT/include/sfw"
ln -sf "$SRC/sfw.h" "$OUT/include/sfw/sfw.h"

##############################################################################
# Step 1: generate sfw.api*.h via vppapigen.
##############################################################################
echo "--- generate sfw.api headers ---"
vppapigen --includedir /usr/include \
    --outputdir "$OUT/include/sfw" \
    --input "$SRC/sfw.api" \
    --output "$OUT/include/sfw/sfw.api.h"

# vppapigen produces sfw.api_{enum,types,fromjson,tojson}.h plus
# sfw.api.c, but does *not* produce sfw.api_json.h (the in-tree
# json blob the production plugin generates separately).  sfw.api.c
# references json_api_repr_sfw and the production code path
# (setup_message_id_table) needs it.  Our harness never calls
# setup_message_id_table — sfw_api.c #includes sfw.api.c at the
# bottom anyway, so we satisfy the include with a one-liner stub.
echo "--- generate sfw.api_json.h stub ---"
cat > "$OUT/include/sfw/sfw.api_json.h" <<'EOF'
/* Stub for fuzz: real production sfw.api_json.h holds the json blob
 * for setup_message_id_table.  Harness never reaches that path —
 * dispatch invokes vl_api_sfw_*_t_handler directly — so an empty
 * string-literal satisfies the linker. */
static const char *json_api_repr_sfw = "{}";
EOF

ls "$OUT/include/sfw"

# Include order: $HERE *before* $OUT/include so our
# fuzz/sfw_api/sfw/sfw.api.c stub shadows the generated full file
# (which would pull setup_message_id_table + the message-id
# registration apparatus we don't link).
INCLUDES="-I$HERE -I/usr/include -I$OUT/include -I$SRC"

##############################################################################
# Step 2: compile sfw .c files (skip sfw_node.c — packet-path only,
# the api harness doesn't drive it; skip sfw_pref64.c / sfw_rdnss.c
# because of the same vnet/ip6-nd/ip6_ra.h dependency that excluded
# them from sfw_node v2's build).
##############################################################################
echo "--- compile sfw .c files ---"
for f in sfw.c sfw_session.c sfw_rules.c sfw_nat.c sfw_nat64.c; do
    echo "    $f"
    clang $COMMON_CFLAGS $SAN_OBJ_FLAGS $INCLUDES \
        -c "$SRC/$f" -o "$OUT/${f%.c}.o"
done

##############################################################################
# Step 3: compile the dispatch wrapper which #include's sfw_api.c
# with `static` defined to nothing.  Compiled as if it were any
# other sfw .c file — cross-TU calls into the now-extern handlers
# resolve at link time.
##############################################################################
echo "--- compile sfw_api_dispatch.o (wraps sfw_api.c) ---"
clang $COMMON_CFLAGS $SAN_OBJ_FLAGS $INCLUDES \
    -c "$HERE/sfw_api_dispatch.c" -o "$OUT/sfw_api_dispatch.o"

##############################################################################
# Step 4: bihash_48_8 instantiation (sfw uses it for session_hash).
##############################################################################
echo "--- compile bihash_inst.o ---"
clang $COMMON_CFLAGS $SAN_OBJ_FLAGS $INCLUDES \
    -c "$HERE/bihash_inst.c" -o "$OUT/bihash_inst.o"

##############################################################################
# Step 5: chassis glue (VPP runtime stubs + harness_init_once +
# per-call dispatch table).
##############################################################################
echo "--- compile harness_glue.o ---"
clang $COMMON_CFLAGS $SAN_OBJ_FLAGS $INCLUDES \
    -c "$HERE/harness_glue.c" -o "$OUT/harness_glue.o"

##############################################################################
# Step 6: link the harness.
##############################################################################
echo "--- link fuzz_sfw_api ---"
clang $COMMON_CFLAGS $SAN_LINK_FLAGS $INCLUDES \
    "$HERE/fuzz_sfw_api.c" \
    "$OUT/sfw.o" \
    "$OUT/sfw_session.o" \
    "$OUT/sfw_rules.o" \
    "$OUT/sfw_nat.o" \
    "$OUT/sfw_nat64.o" \
    "$OUT/sfw_api_dispatch.o" \
    "$OUT/bihash_inst.o" \
    "$OUT/harness_glue.o" \
    -lvppinfra \
    -o "$OUT/fuzz_sfw_api"
echo "  -> $OUT/fuzz_sfw_api"

echo
echo "=== artefacts in $OUT ==="
ls -la "$OUT"
