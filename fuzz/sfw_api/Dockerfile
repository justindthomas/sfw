# sfw_api harness — extends audit-tools:vpp-fuzz so the layered base
# (clang + libfuzzer + ASan/UBSan + libclang-rt-dev + vpp-dev) carries
# over.  Mirrors ../sfw_node/Dockerfile.
FROM localhost/audit-tools:vpp-fuzz

WORKDIR /src
ENTRYPOINT ["/bin/bash"]
