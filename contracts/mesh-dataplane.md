<!-- Additive direct-path node configuration and enforcement contract [163–169,198,215,216], #129. -->
# Mesh data plane, direct-path slice

The Mesh node component lives in `crates/plugins/mesh` behind its `agent`
feature. It consumes bounded configuration chunks through the existing
infraternal agent action registry and authenticated channel. No separate network listener
or authentication mechanism is introduced. A generic private same-uid Unix
control socket exposes the same public action registry to local CLI callers,
including during server outages. Node components never create a
server. Private WireGuard keys are generated locally and never serialized,
logged, passed in argv, or sent to the coordinator.

Configuration contains stable node identity, version, local IPv4/ULA host
addresses, public peer keys, discovered UDP endpoints, /32 and /128 allowed
IPs and directional new-connection policies. Snapshots and diffs are staged
until the final chunk, with contiguous version checking. A missing or failed
chunk leaves the applied view unchanged. Reconnecting requests a snapshot.
Control chunks fit the existing 8 KiB action-body resource bound.

Full coordinator snapshots may include `local_key`, the public key bound to
their local inventory identity. It must match the enabled kernel key and stay
identical across every staged chunk. An accepted local node identity may change
only in a full snapshot at a newer revision carrying this binding, after an
authorized re-enrollment. Legacy unbound snapshots and deltas cannot rotate it.
The `mesh.configure` control action is available only on the authenticated
coordinator channel, never through the public local CLI registry. Authorized
replacement reconciles the owned local host addresses, including on restart;
ordinary same-identity address changes still require the D199 overlap barrier.

Host revocation retires its Mesh membership key, direct node grants and tag
membership in the same SQLite transaction as the durable authority tombstone.
A historical tombstone is reconciled during migration. After commit the host
notifies enabled plugins through the generic lifecycle; Mesh wakes its existing
coordinator workers and withdraws that member from every peer snapshot. Retired
WireGuard keys cannot authenticate even an established flow. This differs from
ordinary grant narrowing, which retains established-flow state as specified below.

The Linux component uses typed route/generic netlink for kernel WireGuard.
Peer updates are chunked to the netlink datagram bound. It owns only its
interface and firewall table; disabling removes them and leaves no poller,
socket or timer running. Last installed configuration survives server loss.
Endpoints are server-observed addresses combined with the node's advertised
WireGuard UDP port. An endpoint is discovery, never proof of reachability.
Handshake counters distinguish a direct path from an unproven endpoint.

The server's mesh default setting defaults to allow in the open-source
edition and deny with the enterprise build feature. Explicit Access rules
replace the default for the directed pair they touch, preserving port
narrowing under allow and grant union under deny. Replies to established
connections pass in both directions. Nodes may always initiate to the server.
A preview identifies directed member pairs that lose any new-connection reach
before a default change applies; established connections retain their state.

The packet filter is one owned nftables inet table, atomically replaced from
stdin. Where nft is absent, the iptables nf_tables backend is required; legacy
iptables is rejected. No shell evaluates policy text. Interface identifiers
and addresses are typed before formatting. Route/netlink parser tests and a
fuzz target cover malformed lengths, padding and kernel error replies.

The remote transport continues to take its enrolled endpoint in this slice.
The public `ServerPath` coordinate type separates a future Mesh destination
from the enrolled fallback. TLS authority remains in the existing remote
identity, and plugin delivery uses the transport-independent `NodeChannel`
capability. D215 can select a destination without changing enrolled identity.
