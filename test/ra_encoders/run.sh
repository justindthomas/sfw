#!/usr/bin/env bash
# run.sh — build + run the standalone RA-option encoder wire-format tests.
#
# No VPP, no container, no build host: the three real encoder .c files are
# compiled behind the minimal test-only shim in ./shim/ with plain cc. The
# shim shadows the <sfw/...> and <vnet/...> includes; -Ishim must therefore
# come before any system include path.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-cc}"
OUT="${TMPDIR:-/tmp}/sfw_test_ra_encoders"

"$CC" -std=c11 -Wall -Wextra -Wno-unused-parameter -g \
    -I"$HERE/shim" \
    "$HERE/test_ra_encoders.c" \
    -o "$OUT"

"$OUT"
