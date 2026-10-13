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
IPs and directional network access rules. Snapshots and diffs are staged
until the final chunk, with contiguous version checking. A missing or invalid
staged chunk leaves the applied view unchanged. Application failures before
public intent commits restore the old rules and preserve connection state.
Once final rules and public intent commit, exact retirement is irreversible:
cleanup failures retain the new restrictive rules and retry forward before
acknowledgment, including on replay or restart. They never restore old access. Reconnecting requests a snapshot.
Control chunks fit the existing 8 KiB action-body resource bound.

An enabled identity may advertise `compact_access: true`. Only after this
negotiation, an access-only delta may carry `access_updates`: ordered, disjoint
inclusive node-ID ranges with replacement inbound and outbound rules. Every
ID in a range must already exist in the acknowledged base; identity, addresses,
keys and endpoints remain unchanged. Ranges cannot overlap peer upserts,
removals or port continuations. Snapshot chunks cannot contain range updates.
The same exact base revision, local-key binding and final atomic installation
and retirement apply. Legacy identities receive the original peer deltas.
This keeps a uniform change at 1,000 peers within one bounded action/round trip
without increasing the action budget [242,252,256].

Full coordinator snapshots may include `local_key`, the public key bound to
their local inventory identity. It must match the enabled kernel key and stay
identical across every staged chunk. An accepted local node identity may change
only in a full snapshot at a newer revision carrying this binding, after an
authorized re-enrollment. Legacy unbound snapshots and deltas cannot rotate it.
The `mesh.configure` control action is available only on the authenticated
coordinator channel, never through the public local CLI registry. Authorized
replacement reconciles the owned local host addresses, including on restart;
ordinary same-identity address changes still require the D199 overlap barrier.

Host revocation retires its Mesh membership key, direct network access rules and tag
membership in the same SQLite transaction as the durable authority tombstone.
A historical tombstone is reconciled during migration. After commit the host
notifies enabled plugins through the generic lifecycle; Mesh wakes its existing
coordinator workers and withdraws that member from every peer snapshot. Retired
WireGuard keys cannot authenticate even an established flow. Removing a network access rule or tightening the default also retires precisely
the connection state no longer permitted [242]; permitted flows stay untouched.

The Linux component uses typed route/generic netlink for kernel WireGuard.
Peer updates are chunked to the netlink datagram bound. It owns only its
interface and firewall table; disabling removes them and leaves no poller,
socket or timer running. Last installed configuration survives server loss.
Endpoints are server-observed addresses combined with the node's advertised
WireGuard UDP port. An endpoint is discovery, never proof of reachability.
Handshake counters distinguish a direct path from an unproven endpoint.

The server's mesh default setting defaults to allow in the open-source
edition and deny with the enterprise build feature. Explicit network access rules
replace the default for the directed pair they touch, preserving port
narrowing under allow and rule union under deny. Replies pass only while their initiating tuple remains permitted by the current
network access rules. Nodes may always initiate to the server.
A preview identifies directed member pairs that lose any new-connection reach
before a default change applies. After installing the new rules, each node
removes exactly the connection state no longer permitted, including TCP and UDP
in both address families. It never flushes unrelated state or resets permitted
flows. A temporary update fence validates initiating tuples against accepted
access, or saved intent during recovery, while refusing new initiation; it never
performs cleanup. Recovery cannot reopen entries refused by committed intent. Retirement selects the complete kernel connection object by tuple, ID and zone,
removing both its original and reply indexes. Fresh TCP acceptance requires an
initiating SYN: reverse continuation on a retired socket cannot create new
connection state through still-permitted reverse access. Coordinator change to the last
node refusing the flow is measured at 10 and 1,000 peers on local and 150 ms
RTT links [242].

The packet filter is one owned nftables inet table, atomically replaced from
stdin. Where nft is absent, the iptables nf_tables backend is required; legacy
iptables is rejected. No shell evaluates network access text. Interface identifiers
and addresses are typed before formatting. Route/netlink parser tests and a
fuzz target cover malformed lengths, padding and kernel error replies.

An unchanged complete legacy snapshot may gain its previously absent `local_key`
binding at the accepted revision when it matches the enabled kernel key and
every prior field is identical. This persists public metadata only. A changed
identity, network access, address, peer, version or previously present binding cannot
use this compatibility case; normal accepted-version refusal remains in force.

## Infraternal agent server path [215,227,228]

The coordinator identifies the server in each bounded configuration. Only an
applied configuration publishes its server destination through a generic node
transport capability. The enrolled fallback port and TLS server name remain
unchanged. A replacement must prove the enrolled server identity through mutual
TLS before the live path is retired. Terminal shims, writer identity and retained
input/output offsets remain authoritative across replacement and fallback.

The server also binds its authenticated QUIC/TLS listener to its assigned mesh
address. The Mesh coordinator worker owns this listener lease; disabling Mesh
retires it. Mesh status reports the observed infraternal agent server path and
the reason for fallback, rather than inferring the transport from a handshake.

Nodes ask the kernel for a free UDP port and refuse 51820. Only the actual bound
port is advertised. Every configured peer enables persistent keepalive, so both
ends send through stateful firewall mappings. Endpoint discovery remains public
coordination, never authentication or proof of a working path.
