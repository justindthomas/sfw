# sfw_node v2 chassis — extends audit-tools:vpp-fuzz so the v0/v1
# layered base (clang + libfuzzer + ASan/UBSan + libclang-rt-dev +
# vpp-dev) carries over.  No additional packages.
FROM localhost/audit-tools:vpp-fuzz

WORKDIR /src
ENTRYPOINT ["/bin/bash"]
