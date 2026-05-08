# sfw_full fuzz build — extends audit-tools:vpp-fuzz so the layered
# v0 base (clang + libfuzzer + ASan/UBSan + libclang-rt-dev + vpp-dev)
# carries over.  No additional packages needed: VPP headers ship with
# the apt vpp-dev pull from the audit-tools:vpp base; sfw's own .c/.h
# are mounted from the host at build time.
FROM localhost/audit-tools:vpp-fuzz

WORKDIR /src
ENTRYPOINT ["/bin/bash"]
