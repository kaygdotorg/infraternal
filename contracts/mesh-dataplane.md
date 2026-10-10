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
