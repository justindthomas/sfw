# SFW: Stateful Firewall + NAT Plugin for VPP

SFW is a unified stateful firewall and NAT engine for VPP. It replaces four
separate plugins (acl-plugin interface filters, ct6, det44, nat44-ed) with a
single plugin sharing one session table across both address families and NAT.

## Why a Custom Plugin

VPP's built-in firewall and NAT plugins each maintain independent session
tables and run at different positions on the feature arc. A stateful firewall
cannot track sessions across a NAT boundary because the addresses change
between the firewall and NAT evaluation points. VPP's NAT plugins also use
worker handoff, which makes it impossible to position a firewall node after
translation. SFW solves this by performing firewall evaluation and NAT
translation in the same node, with a single shared session table.

## Architecture

### Zone-Based Policy Model

Interfaces are assigned to named security zones. Policies are defined as
zone pairs (from-zone, to-zone). The sfw node determines the source zone
from the RX interface and the destination zone via FIB lookup, then selects
the matching zone-pair policy.

```
sfw zone internal interface lan
sfw zone external interface wan
sfw policy outbound from-zone internal to-zone external
sfw policy outbound default-action permit-stateful-nat
sfw policy inbound from-zone external to-zone internal
sfw policy inbound default-action deny
```

### Feature Arc Position

SFW runs on both the input (unicast) and output arcs for each address
family:

```
ip4-unicast: ... → acl-plugin → ip4-sv-reassembly → sfw-ip4 → ip4-lookup
ip4-output:  ip4-rewrite → ... → sfw-ip4-out → interface-output
ip6-unicast: ... → acl-plugin → ip6-sv-reassembly → sfw-ip6 → ip6-lookup
ip6-output:  ip6-rewrite → ... → sfw-ip6-out → interface-output
```

NAT translation happens in the pre-lookup node — same position as firewall
evaluation — which avoids the worker handoff problem entirely. The
output-arc nodes exist to catch locally-originated traffic that never
transits the input arc (see *Locally-Originated Traffic* below).

### Session Table

All sessions (IPv4, IPv6, NATted, non-NATted) share a single
`bihash_48_8` hash table. IPv4 keys are 16 bytes zero-padded to 48. IPv6
keys use the full 48 bytes. The value encodes `(thread_index << 32 | session_index)`.

Each session has two hash entries:

- **Reverse key**: `(server:port → client:port)` for outbound session matching
- **Direct key**: `(client:port → server:port)` for return traffic matching

NATted sessions additionally store the translated address/port in the session
struct. The direct key for a NATted session uses the translated address (the
public address for SNAT, the private destination for DNAT), so return traffic
arriving at the translated address finds the session directly. See
[Dual Hash Entries for NAT](#dual-hash-entries-for-nat) for the per-mode
key layout.

## Design Decisions and VPP Accommodations

### Two-Pass Node Design

**Problem**: VPP's bihash documentation warns that interleaving add and
search operations on the same bihash within a single node dispatch can cause
intermittent search failures. In practice, we observed that adding a session
entry and then searching for it in the same frame would sometimes miss,
leading to duplicate sessions.

**Solution**: The node processes each frame in two passes:
- **Pass 1** (read-only): Extract packet fields, search bihash for existing
  sessions, evaluate rules for new flows, pre-compute NAT translations. No
  bihash modifications.
- **Pass 2** (write-only): Create sessions and add bihash entries for packets
  that need new sessions. Apply NAT packet rewrites. No bihash searches.

This separation eliminates within-frame search/add interference. A retry
guard in pass 2 catches the remaining cross-frame case: before creating an
SNAT session, re-search the bihash to verify the session wasn't created by
another frame between pass 1 and pass 2.

### Session Lookup Before Zone Resolution

**Problem**: The destination zone is determined by FIB lookup, which returns
`DPO_RECEIVE` for the router's own addresses (including NATted public IPs).
When return traffic arrives at the NATted address, both source and destination
resolve to the same zone. No zone-pair policy exists for same-zone traffic,
so policy-dependent session matching would miss.

**Solution**: Session lookup runs first, before any zone or policy resolution.
The node searches the bihash with both key directions (reverse, then direct).
If an existing session is found, the packet is permitted and NAT is applied
immediately — no FIB lookup, zone resolution, or policy evaluation needed.
This makes the fast path (existing sessions) cheaper and eliminates the
same-zone edge case entirely. Zone and policy resolution only run for the
first packet of a new flow.

### FIB Lookup for Destination Zone

**Problem**: SFW runs before `ip4-lookup` on the feature arc, so VPP has not
yet determined the outgoing interface. The node needs the destination zone to
select the correct zone-pair policy for new connections.

**Solution**: The node calls `ip4_fib_forwarding_lookup()` (or the IPv6
equivalent) to resolve the destination address to a load-balance DPO, then
extracts the TX interface from the adjacency. The TX interface's zone
assignment gives the destination zone.

Three DPO types yield a usable TX interface:
- `DPO_ADJACENCY`, `DPO_ADJACENCY_INCOMPLETE`, `DPO_ADJACENCY_MIDCHAIN`:
  standard forwarded traffic — extract via `adj_get_sw_if_index()`.
- `DPO_RECEIVE`: traffic to the router's own addresses — extract via
  `receive_dpo_get()->rd_sw_if_index`.
- `DPO_DROP` and others: no resolvable zone, packet passes through without
  policy evaluation.

### Cross-Thread Session Access

**Problem**: Sessions are created by whichever worker thread processes the
first packet of a flow (determined by RSS queue assignment). Return traffic
may arrive on a different worker thread via a different RX queue. Session
pools are per-worker, but the bihash is shared.

**Solution**: The bihash value encodes both thread index and session index.
Any worker can look up any session via `pool_elt_at_index(sessions[thread], index)`.
The critical constraint is LRU list management: LRU lists are per-worker
linked lists with no synchronization. Only the owning thread may modify the
LRU pointers. When a non-owning thread touches a session, it updates only
the `expires` timestamp (a single atomic-width write), not the LRU list.

### Session Expiry

**Problem**: A background process for session expiry would need to access
other threads' session pools and LRU lists, which is unsafe without locking.

**Solution**: Session expiry runs inline at the end of each node dispatch,
after `vlib_buffer_enqueue_to_next()`. Each worker only expires sessions
from its own pool, walking the LRU tail until it finds a non-expired entry.
There is no budget limit — all expired sessions are cleaned in one pass.
This is safe because each worker's LRU list and session pool are only
modified by that worker.

### Dual Hash Entries for NAT

**Problem**: A NATted session changes an address/port on one side of the
flow. Return traffic arrives with a translated address that doesn't match
the original session key.

**Solution**: Every session inserts two bihash entries. The first entry is
always the reverse key (server → client) used to match repeat packets from
the initiator. The second entry depends on NAT mode:

| Mode     | First entry (reverse)             | Second entry                                   |
|----------|-----------------------------------|------------------------------------------------|
| No NAT   | `server → client:sport`           | `client:sport → server:dport` (direct)         |
| SNAT     | `server → private_client:sport`   | `server → public_ip:mapped_port`               |
| DNAT     | `private_server → client:sport`   | `public_ip:ext_port → client:sport`            |

Both entries point to the same session (same encoded value). `has_nat_key`
on the session tracks that the second entry was inserted so
`sfw_session_unhash` can remove the correct secondary key at teardown
time.

### Dynamic vs Deterministic NAT Pools

SNAT pools support two allocation modes, selected per pool at creation time:

- **Deterministic** (`sfw nat pool ... deterministic`): Each internal
  address is statically mapped to a fixed slice of ports on one external
  address, derived from its offset within the internal prefix. No
  allocation state is needed — the translation is computable from the
  private address alone. Good for logging/auditing (one private host →
  one predictable public tuple) and for very large internal ranges where
  dynamic allocation would thrash.
- **Dynamic** (`sfw nat pool ... dynamic`): External ports are allocated
  from a per-worker bitmap. The allocatable port range (default
  1024–65535) is sliced equally across workers, so each thread allocates
  from an exclusive range with no cross-thread coordination or locking.
  Sessions free their port back to the owning thread's bitmap on
  teardown. Good for bursty traffic where deterministic slicing would
  leave ports idle.

### Static NAT (1:1 and DNAT Port Forwards)

Beyond the pool-based SNAT modes, sfw supports static mappings created
with `sfw nat static`:

- **1:1 NAT**: `sfw nat static <ext-ip> to <int-ip>` maps an external
  address to an internal address with wildcard port/protocol matching.
  Used for servers that need a stable public IP.
- **DNAT port forward**: `sfw nat static <ext-ip>:<ext-port> proto
  tcp|udp to <int-ip>:<int-port>` forwards a single port.

DNAT is evaluated before zone-pair policy: static mappings are checked
first so the destination address is rewritten before the policy decision.
Policy rules then see the post-translation destination, which means
firewall rules can be written against the real internal address rather
than the public-facing one. Return traffic finds the session via the
DNAT secondary key (see the table above).

### TCP State-Aware Session Expiry

**Problem**: Idle TCP sessions should hold the default timeout
(~120 s), but closed connections waste session slots if they sit there
until the idle timer fires.

**Solution**: The session struct carries three TCP state bits:
`tcp_fin_fwd`, `tcp_fin_rev`, and `tcp_rst`. On each TCP packet the
node sets the appropriate bit based on the flags and direction. Once
either a RST has been seen from either side, or a FIN has been seen in
both directions, the session's `expires` is clamped to
`now + SFW_TCP_CLOSE_TIMEOUT` (5 s). The normal inline LRU walk then
collects it on the next dispatch after that deadline.

### Deferred Session Free

**Problem**: A non-owning worker may be midway through a bihash lookup
that returned a stale encoded value pointing at a session the owning
worker has just torn down. If the owning worker calls `pool_put`
immediately after unhashing, the non-owner's subsequent
`pool_elt_at_index` can land on freed memory, producing a cross-thread
use-after-free.

**Solution**: Teardown is two-phase. `sfw_session_unhash` removes both
bihash entries and unlinks the session from the owning thread's LRU,
then pushes the session index onto a per-worker `pending_free` vector.
The actual `pool_put` does not happen until the *next* inline expiry
pass, giving any concurrent lookup one full dispatch cycle to finish.
Because `pending_free` is per-worker and only touched by the owning
thread, no locking is needed.

### ESP SPI in the Session Key

**Problem**: ESP has no port numbers — flows are identified by a 32-bit
Security Parameter Index (SPI). Dropping the SPI would collapse all ESP
flows between the same address pair into a single session, which breaks
multi-SA traffic (including rekey).

**Solution**: For ESP packets the 32-bit SPI is split across the two
16-bit port fields of the session key (`src_port` = high 16 bits,
`dst_port` = low 16 bits). The unified 48-byte key layout has room for
this without any protocol-specific sidecar, and bihash lookups hash the
full SPI exactly like a `(src_port, dst_port)` pair.

### ICMP NAT Handling

ICMP echo request/reply uses an identifier field instead of ports. The remote
end echoes the identifier unchanged in the reply. SFW preserves the ICMP
identifier during SNAT (does not translate it) so that reply matching works
naturally. The identifier is stored in the port fields of the session key for
lookup purposes.

### Feature Arc Double-Enable Guard

**Problem**: Both the zone assignment CLI (`sfw zone ... interface ...`) and
the policy creation code enable the sfw feature arc on affected interfaces.
VPP's `vnet_feature_enable_disable()` is reference-counted — calling enable
twice inserts the node twice on the arc, causing every packet to be processed
by sfw twice. The second pass has no session context and denies return traffic.

**Solution**: Track `feature_on` per interface in `sfw_if_config_t`. Skip
the enable call if the feature is already active. This is checked in
`sfw_enable_disable_interface()` before calling `vnet_feature_enable_disable()`.

### Link-Local and Broadcast Bypass

IPv6 link-local traffic (`fe80::/10` source or destination) bypasses all
policy evaluation. This ensures DHCPv6, NDP, and router advertisements are
never blocked by zone-pair policies. IPv4 broadcast (`255.255.255.255`),
multicast (`224.0.0.0/4`), and unspecified source (`0.0.0.0`) are similarly
bypassed.

### Locally-Originated Traffic

**Problem**: Packets VPP itself generates — ICMP echo replies, TCP RSTs
to unknown flows, DHCP-client, IKEv2, BFD, IPFIX export, `vppctl ping`,
and any VCL-based app (including vcl-rs BGP daemons) — do not traverse
the `ip4-unicast` / `ip6-unicast` input feature arcs. Without a matching
session, the peer's reply hits the inbound deny policy and gets dropped.

**Solution**: Twin nodes `sfw-ip4-out` / `sfw-ip6-out` run on the
`ip4-output` / `ip6-output` feature arcs. They:

1. Look up the session hash — forwarded traffic (input → lookup →
   rewrite → output) matches an existing session here and passes
   through without creating a duplicate.
2. On a miss, do a FIB lookup on the packet's **source** address. If
   it resolves to `DPO_RECEIVE` the packet is locally-originated;
   otherwise the packet is just transiting and we let it pass.
3. For locally-originated packets, synthesize `src_zone = SFW_ZONE_LOCAL`
   and take `dst_zone` from the TX interface's zone assignment. The
   (local, dst_zone) zone-pair policy decides permit/deny and whether
   to create a session.
4. When a session is created here, the `kv1`/`kv2` hash entries use
   the same layout as the input arc, so return traffic finds the
   session via the existing input-side lookup logic without any
   special handling.

Output-arc features are enabled on the same interfaces as the input-arc
feature (driven by zone assignment), so no additional configuration is
required. Policies for locally-originated traffic are written against
the built-in `local` zone:

```
sfw policy egress-local from-zone local to-zone external
sfw policy egress-local default-action permit-stateful
```

Host-stack daemons that talk to VPP via a tap interface (FRR, BIRD,
etc.) **do** traverse the input arc on the tap RX and are handled by
the existing input-side logic — the output-arc hook is strictly for
traffic VPP's own data plane generates.

Buffer access on the output arc requires skipping `ip.save_rewrite_length`
bytes because `ip4-rewrite` has already prepended the L2 rewrite to
`current_data` before the output feature arc runs.

### IPv6 permit-stateful-nat

When a v6 flow's `permit-stateful-nat` policy applies and the
destination falls within a configured NAT64 prefix (see below), the
action triggers NAT64 translation. When no NAT64 prefix matches, the
action is treated identically to `permit-stateful` — a session is
created with `nat_type = SFW_NAT_NONE`. This lets a single zone-pair
policy cover both IPv4 SNAT and IPv6-to-IPv4 NAT64 without needing
separate per-family policies.

### NAT64 (RFC 6146 stateful, RFC 7915 packet translation)

sfw implements stateful NAT64 as a replacement for VPP's stock
`plugins/nat/nat64/`, which hooks into VPP in ways that interfere with
other plugins. sfw's NAT64 uses the same session table, zone-pair
policy model, and per-thread v4 port allocation already in use for
NAT44.

**Configuration**

A NAT64 pool advertises an IPv6 prefix (the RFC 6052 prefix IPv6
clients use to address IPv4 destinations) and a pool of IPv4 source
addresses for the translated packets:

```
sfw nat64 pool add 203.0.113.0/29 prefix 64:ff9b::/96
```

Supported prefix lengths are `{32, 40, 48, 56, 64, 96}` per RFC 6052.
The well-known prefix `64:ff9b::/96` is the most common choice and
works with DNS64 resolvers out of the box.

A zone-pair policy with `permit-stateful-nat` as the action triggers
NAT64 when the v6 destination matches a configured NAT64 prefix:

```
sfw zone internal-v6 interface tap0
sfw zone external interface eth0
sfw policy v6-outbound from-zone internal-v6 to-zone external
sfw policy v6-outbound default-action permit-stateful-nat
sfw nat64 pool add 203.0.113.0/29 prefix 64:ff9b::/96
```

**Packet flow**

1. A v6 packet arrives at `sfw-ip6` (input arc) destined for a prefix
   address like `64:ff9b::192.0.2.1`.
2. Session lookup misses; policy returns `permit-stateful-nat`.
3. `sfw_nat64_match_pool` finds the pool; `sfw_nat64_extract_v4`
   recovers the embedded IPv4 destination.
4. A v4 pool address + port are allocated from the per-thread bitmap.
5. A session is created with `nat_type = SFW_NAT_NAT64`. Two bihash
   entries are inserted: the v6 forward key and a v4 return key.
6. `sfw_nat64_translate_v6_to_v4` rewrites the packet (v6 header → v4
   header, 20-byte shrink) using core VPP's `ip6_to_ip4.h` helpers
   for TCP/UDP/ICMP. The packet is handed off to `ip4-lookup`.
7. The return v4 packet arrives at `sfw-ip4`, hits the session via
   the v4 return key, is recognized as NAT64 by `nat_type`, and is
   translated back to v6 (20-byte grow) via the mirror helpers.
   Handed off to `ip6-lookup`.

**ICMP translation**

ICMP is translated per RFC 7915 using core VPP's `icmp6_to_icmp` and
`icmp_to_icmp6` header-only helpers (which are not part of the stock
NAT64 plugin and have no dependencies on it):

- Echo request/reply (types 128/8 and 129/0): type translated, echo
  identifier rewritten using session state, checksum recomputed.
- Error messages (destination unreachable, time exceeded, packet too
  big, parameter problem): outer ICMP type/code translated by the
  helper; inner packet headers recursively rewritten. Inner
  addresses are translated assuming the inner datagram travels in
  the *reverse* direction of the outer error (the PMTUD case: the
  error reporter received a packet and is complaining back), and
  inner L4 ports/IDs are rewritten against session state.
- ICMPv6 redirect (type 137) is intentionally not translated
  (link-local scope per RFC 7915 §4.2).

**Observability**

```
vppctl show sfw nat64 pools
vppctl show sfw sessions verbose
vppctl show errors | grep -i nat64
```

`show sfw sessions` prints NAT64 sessions with both the v6 tuple (in
the session key) and the v4 side (`xlate.n64.v4_pool:port ->
xlate.n64.v4_server`). Error counters cover successful translations
(`NAT64_V6_TO_V4`, `NAT64_V4_TO_V6`), v6 flows hitting
`permit-stateful-nat` that fell through to plain `permit-stateful`
because no NAT64 pool matched the destination (`NAT64_UNKNOWN_PREFIX`
— informational; operators who *do* expect translation should
configure a matching pool), buffer headroom shortage on v4→v6 growth
(`NAT64_HEADROOM`), and untranslatable ICMP (`NAT64_ICMP_UNSUPPORTED`).

**Known limitations**

- **Hairpinning** — a v6 client addressing `<prefix>::<v4-of-another-v6-client>`
  is not currently translated twice (RFC-legal to punt).
- **Fragment reassembly** — the core VPP translation helpers handle
  single-fragment packets correctly; full pre-translation reassembly
  is out of scope.
- **ICMP errors from intermediate routers** — an ICMP error generated
  by an intermediate v4 router (not the v4 server itself) may carry
  an inner L4 header whose rewritten port disagrees with the
  intermediate's actual view. Outer ICMP signaling (type/code/MTU)
  still translates correctly, so PMTUD black-hole recovery works.
- **Egress policy on v4 side** — NAT64 policy decisions are made
  entirely on v6 ingress. The translated v4 packet still traverses
  `sfw-ip4-out` if enabled, so per-interface egress filtering works,
  but the v4 zone-pair policy is not re-evaluated.

### PREF64 Router Advertisements (RFC 8781)

Once a NAT64 prefix is configured, IPv6 hosts on directly-attached
segments need to discover it. The cleanest client-side mechanism is
the **PREF64 RA option** (RFC 8781): a small option the router
embeds in every Router Advertisement that tells hosts "packets
destined to this /96 (or /64, /56, /48, /40, /32) will be NAT64'd
to IPv4 by me." Recent Linux (5.3+), iOS, macOS, and Android pick
this up automatically, enabling 464XLAT / CLAT without requiring
DNS64 on every client.

VPP's stock `ip6-nd` has no PREF64 support. sfw adds it by way of a
small core-side hook to `src/vnet/ip6-nd/ip6_ra.c` that lets
plugins register additional RA-option callbacks. The hook lives in
`vpp-patches/0001-ip6-ra-extra-option-hook.patch`, applied by
`build.sh` inside the build container before the VPP tree is
compiled. It is scheduled for upstream submission; once merged, the
patch file can be dropped.

**Why augment VPP's RAs instead of emitting our own** — VPP's
existing RA builder handles prefix-info, MTU, source-link-layer
address, timers, rate-limiting, and the Router Solicitation reply
path. Running a parallel sfw-side RA engine would duplicate all of
that and drift as VPP evolves. The hook approach adds ~15 lines to
VPP and lets hosts see one coherent RA with our PREF64 option
alongside everything VPP already puts in.

**Configuration**

```
sfw nat64 pool add 203.0.113.0/29 prefix 64:ff9b::/96
sfw pref64 advertise GigabitEthernet0/0/0 prefix 64:ff9b::/96 lifetime 1800
show sfw pref64
```

The `prefix` argument must match an existing NAT64 pool — the CLI
refuses to advertise a prefix sfw doesn't actually translate, which
would black-hole client traffic. `lifetime` is in seconds; omitting
it selects a sane default (1800s). Per RFC 8781 the lifetime is
encoded in 8-second units with 13 bits of precision, capped at
65528s.

**Verification**

On the client segment: `tcpdump -vv -n 'icmp6 and ip6[40]=134' -i
<iface>` — each RA (periodic or solicited) should include option
type 38 with length 2, the correct scaled lifetime and PLC, and the
prefix bytes matching the configured NAT64 prefix. `rdisc6 <iface>`
from a Linux host triggers a solicited RA so you don't have to wait
for the periodic tick.

**Callback flow** — at sfw plugin init, `sfw_pref64_init()` calls
`ip6_ra_extra_option_register(sfw_pref64_ra_option_cb)`. Every time
VPP's RA builder reaches the "add additional options" point it
invokes all registered callbacks. The sfw callback checks
`sfw_if_config_t.pref64_advertise` for the TX interface; if set, it
appends the 16-byte precomputed option via `vlib_buffer_add_data`
and bumps the RA's payload length. Zero allocation on the hot path.

## File Structure

| File | Purpose |
|------|---------|
| `sfw.h` | All data structures: session keys, sessions, rules, policies, zones, plugin main |
| `sfw.c` | Plugin init, CLI commands (zone, policy, nat pool/static, show/clear), feature arc registration |
| `sfw_node.c` | Packet processing: sfw-ip4 / sfw-ip6 input nodes and sfw-ip4-out / sfw-ip6-out output nodes (two-pass design) |
| `sfw_rules.c` | Rule matching: first-match evaluation with prefix/port/protocol/ICMP filtering |
| `sfw_session.c` | Session lifecycle: create, remove (with dual hash cleanup), format for display |
| `sfw_nat.c` | NAT44 pool management (deterministic and dynamic modes), static 1:1 / DNAT mappings, per-thread port bitmaps, address/port translation, incremental checksum updates |
| `sfw_nat64.c` | NAT64 (RFC 6146): RFC 6052 prefix embed/extract, v6↔v4 packet translation (TCP/UDP inline, ICMP via core VPP `ip6_to_ip4.h` / `ip4_to_ip6.h` helpers), pool matching |
| `sfw_pref64.c` | RFC 8781 PREF64 RA option: per-interface config, precomputed option bytes, callback registered via VPP's `ip6_ra_extra_option_register` (see `vpp-patches/`) |
| `vpp-patches/` | Small patches against core VPP required by sfw, applied at container-build time. Currently: `0001-ip6-ra-extra-option-hook.patch` — adds the RA extra-option callback API. Upstream-bound |
| `sfw.api` | Binary API definitions (policy/rule, NAT pool, NAT static, NAT64 pool, PREF64 advertise, zone and interface ops) |
| `sfw_test.c` | VAT test client for the binary API |
