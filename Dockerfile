FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg build-essential python3 python3-ply \
        git cmake pkg-config \
    && curl -fsSL https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | bash \
    && apt-get install -y --no-install-recommends --force-yes \
        vpp-dev=25.10-release \
        libvppinfra=25.10-release \
        libvppinfra-dev=25.10-release \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
