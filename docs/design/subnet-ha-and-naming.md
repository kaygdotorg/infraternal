# Subnet router failover and named routes

Proposal for [#580](https://git.kayg.org/kayg/infraternal/issues/580), J1324.
The owner needs to approve the change to D197 M3 before implementation.

Two routers on one office LAN should be able to serve the same approved
subnet. An office LAN and a home LAN that both use `192.168.1.0/24` should
also be able to appear in the same mesh. A laptop can use Office LAN while
an iPhone uses Home LAN. If both office routers go down, the laptop still
has Office LAN selected and reports it unavailable. Sending that traffic
to Home LAN could reach a different machine at the same address.

## What exists today

An approval has a stable route ID, one router, one prefix and a masquerade
setting. Approval checks for intersections with every approved network.
An arrow can target that route ID, and the compiled grant is delivered
through its router. Linux and macOS put the prefix in that peer's
WireGuard AllowedIPs for outbound selection and inbound source checking.
The OS installs a route towards the tunnel if the prefix passes local
checks. The current client route path handles IPv4. Linux can forward
approved subnets, and macOS consumes them. See the
[approval model](../../crates/infraternal-mesh/src/networks.rs),
[coordinator](../../crates/infraternal-mesh/src/coordinator.rs),
[Linux peer setup](../../crates/plugins/mesh/src/gotatun_node.rs) and
[Mac route planner](../../crates/plugins/mesh/src/macos_subnet_routes.rs).

## Approve a named subnet and its routers

Keep the existing route ID as the identity of an approved subnet. Give it
an owner-editable display name, one canonical prefix and one forwarding
mode. Every approved subnet starts with one router and becomes an HA
group when the administrator approves another member. Names can change
without changing IDs, access rules or device choices.

Each router advertises its prefix as it does today. During approval, the
administrator chooses **Create named subnet** or **Add to a subnet**.
The second action requires an exact prefix match, uses the existing
forwarding mode, and records the administrator's assertion that the
routers reach the same LAN and services. The UI shows the prefix, the
current routers and the forwarding mode before approval. A router's
advertisement and the router name alone cannot establish this. Sibling
groups with overlapping prefixes may coexist. Each router and prefix
advertisement can belong to one group, and an overlapping advertisement
on the same router must be refused in the first version to keep inbound
forwarding unambiguous. Existing checks against the mesh range and
reserved space still apply.

For example, approve `office-a` as Office LAN (route 12), add
`office-b` to route 12, and approve `home-a` as Home LAN (route 27).
All three advertise `192.168.1.0/24`. Routes 12 and 27 have independent
arrows. A withdrawn advertisement or removed member immediately loses
eligibility once applied. Removing a member preserves the group's ID
and arrows. With zero eligible routers the approved subnet stays visible
as unavailable. Revoking the group removes its arrows and device choices.
Moving a member between groups requires removal and fresh approval.

## Pick a router within the selected subnet

Use one active member per client and subnet. On initial selection, try
the first eligible member in approval order. Keep using a healthy
member through RTT changes and through recovery of a preferred member.
If the current member fails, choose the next healthy member of the same
group. Different clients may end up on different members. A change from
direct to relay through the same router is a mesh path change and can
preserve its forwarding state.

Keep one destination prefix on one peer at a time. Learn candidate health
over each peer's mesh host address. During failover, fence the prefix in
the packet path, remove the old peer's subnet binding, install the new
peer's binding and enforce the grant for that peer before lifting the
fence. Invalidate flow state tied to the old binding and reject its late
replies. The OS included route can stay in place during this change.
When every member is unhealthy, keep the enabled prefix pointed at the
mesh with a drop in the packet path while the route can safely remain
installed. This prevents fallback through a wider route or the default
gateway. Local route conflicts remain visible as a separate state.
[WireGuard cryptokey routing](https://www.wireguard.com/papers/wireguard.pdf)
and [overlapping route failover behavior](https://tailscale.com/docs/reference/troubleshooting/network-configuration/overlapping-subnet-route-failover).

Per-flow balancing would pin each connection to a router so packets in
one connection use the same forwarding and NAT state. It would need
explicit flow dispatch, reply validation by router, handling for fragments
and related ICMP, and bounded state with expiry. Putting the same prefix
in every member's AllowedIPs is insufficient. Per-client distribution
could spread load at lower cost by picking a stable member from a
client-ID hash on initial selection. Primary/standby is the first
recommendation because it fits the existing peer lookup and is easy to
diagnose. [NetBird routing peer behavior](https://docs.netbird.io/manage/networks/how-routing-peers-work).

### Health and failover time

Reuse the [direct probe](../../crates/plugins/mesh/src/direct_probe.rs)
RTT and loss observations as path hints. The current probe is a 12-byte
UDP ping or pong with a 2-second loss timeout. It runs on demand and
its token matches a reply without authenticating the router. A lost
direct probe can mean the direct leg failed while relay still works.
Use authenticated mesh traffic or a small authenticated request and
reply over the peer's usable mesh path to confirm router reachability.
Bind the result to the member and current route grant. The router should
report whether the approved prefix is still advertised and its LAN
interface, forwarding and required NAT rules are ready. An optional
administrator-supplied LAN canary could later detect failures beyond the
router. A successful readiness check covers the router and its forwarding
setup. Individual services may still be unreachable.

Arm checks on subnet enable, first send after idle, traffic with stale
receive evidence, and network or endpoint change. During real use,
authenticated traffic can refresh reachability and diagnostic probes can
cover silence or a one-way flow. Share and rate-limit probes by peer.
Try the standby in parallel when testing a suspect primary. A first test
budget is two missed confirmations started 500 ms apart, each with a
2-second deadline. This leaves 500 ms to switch and deliver the first
successful packet for a **3-second p99 target** from failure on an active
route with a ready, reachable standby. Count from the injected failure,
including time to detect suspect traffic. Measure cold start and resume
separately. An idle iPhone should wake for traffic or a relevant path or
policy event (D81). Detecting a failure while idle within a fixed time
would require periodic traffic.

With default masquerading, a replacement router generally has a
different LAN IP and no copy of the address and port mappings. Expect
TCP and NAT-dependent UDP connections to reconnect. Keep-source may
preserve a connection if return routing also converges and firewall
state allows it. Test both directions before promising continuity.
Retries go through the new router in the same LAN. Router state
replication and a shared LAN address would be separate work.
[TCP connection identity](https://www.rfc-editor.org/rfc/rfc9293.html).

## Let each device choose which subnet to use

Store choices on the server under the enrolled mesh node ID and stable
route ID. Owners can manage their own enrolled devices. A device
credential can read its own view and update its own choices. Existing
administrator approval and access rules still control eligibility.
New choices start off. On upgrade, seed enabled choices for the
previously delivered approved routes per existing node. A new enrollment
gets its own choices. Keep desired state across temporary unavailability.
A withdrawn grant takes effect independently of the preference, and
restoring a grant may restore an existing enabled choice for that same
route ID.

Two enabled groups on one device must have disjoint prefixes. Exact
matches and containment both conflict, such as `192.168.1.0/24` and
`192.168.0.0/16`. Check pairwise intersections with the currently enabled
set. A third subnet outside the selected ranges can remain enabled. If
enabling Home LAN would displace Office LAN, show **Use Home LAN instead
of Office LAN?** and list all displaced groups when there is more than
one. Commit the change and the full set of disables together. Check the
device preference revision and conflict list in the write transaction.
A concurrent change returns the current choices for a fresh decision.

Send the device its desired choices and authorized candidates as a
versioned config update. Keep standby peer identities and path data
available to the local routing owner. Expose catalog metadata for
authorized groups even when off. The OS gets routes only for enabled,
authorized groups that pass local route and underlay loop checks. The
packet path gives each usable prefix to one chosen router and enforces
the same choice on replies. The server records desired state and the
device reports the applied revision and status. A disconnected device
uses its last accepted configuration within existing mesh policy
freshness and revocation rules. Preference writes require server
confirmation. Show **Waiting for device** after commit and until the
selected device applies it. Save changed preferences and config deltas
without persisting each health sample.

Switch sites in one local reconcile. Fence the affected destination
ranges, retire the old binding and its flow state, then publish the new
binding with its access policy. Failed or stale applications must not
report the new site as active. Never send packets queued for the old
site to the new one. Clear tracked state and require a new TCP handshake
for the switched range, including after a tunnel restart. An old TCP
connection's retransmitted data then cannot enter the new site.
Cached addresses, fresh UDP sends and new
connections to a raw IP carry no site identity, so after the switch they
address the newly selected site. Warn about this consequence in the
switch confirmation. Applications that need both identities at once
need distinct destination addresses.

Keep the existing local and underlay checks on Linux and macOS, including
reconcile when the peer endpoint changes. On iOS apply the same decision
before handing prefixes to NetworkExtension. If the device already
reaches `192.168.1.0/24` over Wi-Fi, show **Blocked by local network**
when it cannot safely install Office LAN. Leaving a subnet off returns
the address to ordinary OS routing. Device selection does not change the
behavior of local LAN traffic outside the tunnel.

Negotiate a route-selection capability before delivering candidate groups
and the preference revision. Old clients can keep their original
single-router, unambiguous config. Require a client upgrade before
enabling HA or site switching on that device, and never reuse an old
client's route ID or remap a prefix to a different site in its config.
A new client that sees inconsistent choices should suppress conflicting
prefixes and ask for fresh config. Verify old router forwarding is
revoked on membership or grant removal using the existing policy
delivery and revocation path.

## API and CLI

Extend the existing [route actions](../../apps/tracer/src/canvas/mesh/protocol.ts).
These are proposed contracts. Writes use the existing authentication and
audit path. Retain `--json` and the existing approve command for a
single-router subnet. A legacy approval without a name or group keeps
the overlap refusal. Approving a different site with an overlapping
prefix requires the explicit named approval flow.

| Action | Proposed change |
|---|---|
| `mesh.route.list` | Administrator view of names, prefixes, approved members and pending advertisements. |
| `mesh.route.approve` | Existing `node_id`, `network`, `masquerade` plus an optional `name` for a new group, or `join_route_id` for an existing one. Inherit forwarding mode on join. |
| `mesh.route.rename`, `mesh.route.remove-member` | Change the name by route ID, or remove one router by node ID. `mesh.route.revoke` still removes the entire route. |
| `mesh.route.selection.list` | Authorized groups for one device with `route_id`, `name`, `network`, `routers`, `desired_enabled`, `applied_revision`, `state`, `active_router_id`, `reason` and the device preference revision. Effective status is the device's last report. |
| `mesh.route.selection.set` | `route_id`, `enabled`, `expected_revision` and optional `replace_route_ids`. Return the new desired state and revision, or the conflicting IDs and current revision. A device session infers its node ID. An account session must identify a device it can manage. |

```text
infraternal server mesh routes approve office-a 192.168.1.0/24 --name "Office LAN"
infraternal server mesh routes approve office-b 192.168.1.0/24 --join 12
infraternal server mesh routes approve home-a 192.168.1.0/24 --name "Home LAN"
infraternal mesh routes --json
infraternal mesh routes enable 12
infraternal mesh routes enable 27 --replace 12
infraternal mesh routes disable 27
```

The node CLI applies choices for the current node through the server
and surfaces apply status. Bare enable names exactly one route by ID.
For a conflict it reports the name, prefix and route ID, then prints the
explicit replacement command. The CLI reads the current revision and
sends it with the request. Scripts can supply their own expected revision.

## Access arrows, mesh DNS and iOS

Keep arrows on the approved subnet ID. An arrow to Office LAN grants the
same access through either approved office router. It grants no access
to Home LAN or to the routers' own services. Apply the existing mesh
default and explicit grants before offering candidates to a device.
Compile the same group policy for each eligible router, enforce it at
both ends, and verify that a route switch cannot reuse state from
another group with the same CIDR. A toggle can narrow use on a device.
It cannot grant access or change the mesh default.

Treat the display name as a label. Existing mesh host DNS stays on the
mesh resolver and works independently of a subnet choice. If private
DNS is needed, allow explicitly configured aliases scoped to a stable
route ID in a later slice. For example, `printer.office.internal` can
return `192.168.1.20` only when the requester has access to Office LAN
and its device has applied that choice. Return a local negative answer
for an inactive managed alias instead of forwarding it upstream.
Rebuild the local resolver view on route apply and use short TTLs.
DNS caches and open sockets can outlive a route switch, so aliases
alone cannot make equal addresses safe to use for both sites at once.

On iOS, use **Settings → Mesh → Subnet Routes**. Show one row per
authorized named subnet with its CIDR, active router or router list, and
a switch for **This iPhone**. Office LAN can show `192.168.1.0/24 · via
office-b` and a row detail for the standby. Other rows show an actionable
reason when enabled but unavailable. Use the switch confirmation for
overlaps and show a pending or failed apply inline. Keep approval in
the administrator's Mesh view. Use native controls with accessible
labels and 44-point touch targets. The SwiftUI app shows desired and
applied state from the shared Rust core and packet tunnel extension.
The extension updates included routes with
`setTunnelNetworkSettings`, and a pure router failover keeps the same
included prefix. Verify apply and actual traffic on an iPhone, since
local routes and interface-scoped connections can take precedence.
[Native client design](ios-client-grill.md) and
[Apple NetworkExtension routing](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic).

## Later option for simultaneous access

A stand-in range gives each subnet a separate destination. A 4via6-style
design assigns a mesh-unique IPv6 prefix per route ID and embeds the
original IPv4 address, so an office and a home printer at
`192.168.1.20` each have a stable IPv6 alias. Every member in the same
HA group shares its mapping. An IPv4 alternative allocates a
mesh-unique IPv4 prefix per route and translates its destination to the
real LAN address. It supports IPv4-only software but consumes address
space and can introduce another overlap. Both approaches need stable
allocation, router translation in both directions, DNS, and access
checks against route identity and translated destinations. Test
protocols that carry IP addresses in their payload and check what
source addresses and ICMP errors applications see. Start with per-device
selection and measure demand for simultaneous access before choosing
a translation design. [4via6 subnet routers](https://tailscale.com/docs/features/subnet-routers/4via6-subnets).

## What to verify before shipping

- In isolated fixtures, put two routers on Office LAN and one on Home
  LAN. Give both LANs the same CIDR and a service at the same IP with
  distinct responses. Track packet destinations during enable, disable,
  concurrent writes, restart, revoke and failover, including a
  wider conflicting CIDR. Exercise stale config, mixed capabilities,
  endpoint changes and DNS caches.
- Measure failure to first successful new connection and packet loss at
  p50, p95 and p99. Cover router process loss, router LAN loss, direct
  path loss with relay intact, a cold standby and all routers down.
  Test existing TCP and UDP with both forwarding modes. Measure probe
  wakes, radio use and extension memory on a phone at idle and during
  steady use.
- Verify Linux and both macOS route modes, then repeat select, switch,
  reconnect and Wi-Fi conflict on a real iPhone. The next mockup should
  cover an ordinary route, a group with two members, a same-prefix
  replacement, a local conflict and an enabled group with no ready router.

## Questions for the owner

| Decision | Recommendation | Other option |
|---|---|---|
| What makes two routers one subnet? | Approve explicit membership under the existing route ID. A name is editable and the same CIDR may describe two sites. | Infer membership from equal CIDR and name. This saves an approval choice but can join different sites by mistake. |
| How should HA distribute traffic? | Use ordered primary and standby, sticky until failure. Measure recovery with an active client and warm standby against the 3-second p99 target. | Spread devices across healthy members at initial selection, or fund per-flow dispatch if one client's throughput warrants it. |
| How should health work on a quiet device? | Check on demand and on relevant events. Confirm authenticated router readiness and let the first traffic after idle trigger recovery. | Keep warm probes running or require a LAN canary. Either can improve a specific failure case at the cost of extra wakeups or setup. |
| What should a new selection or conflict do? | Start new choices off, preserve existing deliveries on upgrade, and confirm an explicit replacement on each device. | Apply a server default per device. This needs a rule for which site wins and can change where existing traffic goes. |
| What should a subnet name do in DNS? | Ship it as a display name and keep existing host DNS. Add scoped aliases when there is a concrete need. | Ship configured scoped aliases in the first slice and take on cache and switch behavior with it. |
| When should both sites be reachable at once? | Defer stand-in addresses. Investigate a mesh-unique IPv6 representation first if simultaneous access becomes a requirement. | Build translation in the first release or prioritize an IPv4 stand-in pool for IPv4-only clients. |
