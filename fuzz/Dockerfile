# Fuzz build for sfw — extends audit-tools:vpp with clang's compiler-rt
# fuzzer/sanitizer runtime. The base image already has clang, vpp-dev,
# libvppinfra-dev, and the sfw build deps; we add libclang-rt-dev for
# `-fsanitize=address,undefined,fuzzer` linkage.
FROM localhost/audit-tools:vpp

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libclang-rt-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
ENTRYPOINT ["/bin/bash"]
