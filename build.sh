#!/bin/bash
#
# Containerised build for the sfw VPP plugin.
#
# Builds a small Debian image with VPP 25.10 dev packages, then compiles
# the plugin against this checkout and drops sfw_plugin.so into ./output/.
#
# Podman is preferred; falls back to docker if podman is not installed.
# Override with CONTAINER_ENGINE=docker (or podman).
#
# Environment overrides:
#   CONTAINER_ENGINE  podman | docker     (default: auto-detect)
#   IMAGE_TAG         image tag to build  (default: sfw-build:25.10)
#   VPP_BRANCH        VPP branch to clone (default: v25.10)
#   BUILD_TYPE        CMake build type    (default: Release)
#   JOBS              parallel make jobs  (default: container's nproc)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"

IMAGE_TAG="${IMAGE_TAG:-sfw-build:25.10}"
VPP_BRANCH="${VPP_BRANCH:-v25.10}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
JOBS="${JOBS:-}"

if [ -z "${CONTAINER_ENGINE:-}" ]; then
    if command -v podman >/dev/null 2>&1; then
        CONTAINER_ENGINE=podman
    elif command -v docker >/dev/null 2>&1; then
        CONTAINER_ENGINE=docker
    else
        echo "[-] Neither podman nor docker found in PATH" >&2
        exit 1
    fi
fi
echo "[+] Using container engine: $CONTAINER_ENGINE"

mkdir -p "$OUTPUT_DIR"

echo "[+] Building image $IMAGE_TAG..."
"$CONTAINER_ENGINE" build -t "$IMAGE_TAG" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR"

# Podman on Linux honours :Z for SELinux relabeling; harmless on docker/macOS
# rootless setups when the volume flag is parsed (podman accepts, docker does
# not) — so only add it for podman.
VOL_OPTS=""
if [ "$CONTAINER_ENGINE" = "podman" ]; then
    VOL_OPTS=":Z"
fi

echo "[+] Running build inside container..."
"$CONTAINER_ENGINE" run --rm \
    -v "$SCRIPT_DIR:/src${VOL_OPTS}" \
    -v "$OUTPUT_DIR:/out${VOL_OPTS}" \
    -e VPP_BRANCH="$VPP_BRANCH" \
    -e BUILD_TYPE="$BUILD_TYPE" \
    -e JOBS="$JOBS" \
    "$IMAGE_TAG" bash -euo pipefail -c '
        JOBS="${JOBS:-$(nproc)}"
        echo "[+] Cloning VPP $VPP_BRANCH..."
        git clone --depth 1 --branch "$VPP_BRANCH" \
            https://github.com/FDio/vpp.git /tmp/vpp-src 2>&1 | tail -3

        echo "[+] Installing sfw plugin source..."
        mkdir -p /tmp/vpp-src/src/plugins/sfw
        for f in /src/*.c /src/*.h /src/*.api /src/CMakeLists.txt; do
            [ -e "$f" ] && cp "$f" /tmp/vpp-src/src/plugins/sfw/
        done

        echo "[+] Configuring ($BUILD_TYPE)..."
        mkdir -p /tmp/vpp-src/build && cd /tmp/vpp-src/build
        cmake ../src \
            -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
            -DVPP_BUILD_TESTS=OFF \
            -DCMAKE_C_FLAGS="-Werror" \
            2>&1 | tail -5

        echo "[+] Building sfw_plugin (-j$JOBS)..."
        make -j"$JOBS" sfw_plugin 2>&1 | tail -10

        PLUGIN=$(find . -name sfw_plugin.so -type f | head -1)
        if [ -z "$PLUGIN" ]; then
            echo "[-] Build failed: sfw_plugin.so not found" >&2
            exit 1
        fi
        cp "$PLUGIN" /out/sfw_plugin.so
        echo "[+] Build successful: /out/sfw_plugin.so"
        ls -la /out/sfw_plugin.so
    '

echo "[+] Done: $OUTPUT_DIR/sfw_plugin.so"
