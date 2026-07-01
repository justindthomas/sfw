# sfw RA-option encoder wire-format tests

Standalone, VPP-free unit tests for the three IPv6 Router Advertisement
*option encoders* that sfw broadcasts onto the LAN in every RA:

| File           | RFC      | Option                                   |
|----------------|----------|------------------------------------------|
| `sfw_pref64.c` | RFC 8781 | PREF64 (type 38) — NAT64 prefix + PLC    |
| `sfw_rdnss.c`  | RFC 8106 | RDNSS  (type 25) — IPv6 resolver list    |
| `sfw_dnr.c`    | RFC 9463 | DNR    (type 144, §6.1) — encrypted DNS  |

These encoders were dark to every other harness: the fuzz tiers stub the
whole IPv6-RA module out because it needs the patched
`<vnet/ip6-nd/ip6_ra.h>` (absent from `vpp-dev`), and nothing asserted the
emitted bytes. A byteswap, wrong option type, wrong length-in-8-octet-units,
or a bad PREF64 length-code would ship silently and mis-advertise to every
host on the segment.

## How it isolates the encoders

`test_ra_encoders.c` `#include`s the **real** `sfw_pref64.c` / `sfw_rdnss.c`
/ `sfw_dnr.c` translation units — so the bytes under test come from the
exact production code, not a copy — behind the minimal shim in `shim/`:

- `shim/sfw/sfw.h` provides only the scalar types, the `ip6_address_t`
  union, the `clib_*` byte-order/mem helpers, the `SFW_*` sizing
  constants, and the config-struct field layouts the encoders touch. It
  reproduces **no** encoder logic; any mismatch is a compile error, never
  a silently wrong byte.
- `shim/vnet/ip6-nd/ip6_ra.h` carries the `ip6_ra_extra_option_fn_t`
  typedef verbatim from `vpp-patches/0001-ip6-ra-extra-option-hook.patch`.
- The other `shim/**.h` are empty include-satisfiers.

The enable/disable/callback functions in each encoder compile but are never
called; their runtime externs are satisfied by stub definitions in the test
`.c`. Each expected buffer is hand-built straight from the RFC.

## Run

```bash
./run.sh          # plain cc; no VPP, no container, no build host
```

Exits non-zero on any wire-format mismatch.
