<!-- Peer-socket observation invariants for NAT discovery and relay integration [163,196,197,228], #220. -->
# Mesh endpoint observations

An endpoint candidate belongs to one peer-traffic socket and one network
generation. An address observed on a different socket, including the enrolled
control connection, does not establish that socket's mapping. The coordinator
authenticates each observer and binds its response to an outstanding probe,
the actual probe destination and the current generation before recording it.
Public addresses never authenticate a mesh member or widen network access.

`infraternal_mesh::discovery::Discovery` holds at most 16 live observations per
socket across both address families. Each observation identifies the observer,
the actual destination (address and UDP port) and its observed source tuple.
Refreshing the same observer/destination replaces that observation; a full book
refuses an additional observation instead of evicting an unrelated live one.
Only public coordinates are retained. The model creates no sockets or timers.

The runtime supplies monotonic elapsed time and a finite, nonzero lifetime.
Expiry occurs at the exact deadline. Backwards time is refused. A socket
replacement or network change advances the generation and clears all prior
coordinates; responses to prior generations cannot repopulate the book. A
mapping change without a local network notification must trigger revalidation
and generation retirement before a previously proven path is reused.

Candidates must be transferable unicast addresses with nonzero ports.
Unspecified, loopback, multicast, broadcast and link-local addresses are
refused. IPv6 interface scopes cannot be transferred to another node; scoped
addresses are refused. IPv4-mapped IPv6 is canonicalized to IPv4. IPv6 flow
labels are not part of candidate identity. Private IPv4 and ULA addresses may
be candidates for peers on the same network.

Mapping evidence is independent for IPv4 and IPv6. Distinct observers at the
same destination do not provide independent mapping evidence. Distinct probe
destinations seeing the same tuple establish **observed stable mapping**;
distinct destinations seeing different tuples establish **destination-dependent
mapping**. A destination-port difference counts. These observations do not
classify inbound NAT filtering or prove a full-cone NAT, direct reachability,
or failure of all possible direct paths. Hard NAT pairs use the relay in
stage 1; port prediction is outside this contract [196].

The Linux WireGuard counter representation additionally exposes the optional
current kernel peer `endpoint`. Its sockaddr decoder checks the exact family
and size (16 bytes for IPv4, 28 for IPv6), network-order port and IPv6 flow
information, and native-order family and scope. Multipart peer dumps retain a
prior endpoint when later parts omit it. Private kernel fields remain in
zeroized buffers and have no reporting representation.

A kernel endpoint may still be the configured address until authenticated
traffic updates it. Its presence, or a historical handshake, is insufficient
to label it a fresh reflexive observation. Runtime integration must correlate
new authenticated traffic with the known destination and generation before
using it as discovery evidence. An old handshake cannot validate a changed
configured endpoint.

Discovery supplies candidates and mapping evidence only. Path selection,
sustained-win hysteresis and connection continuity remain with the existing
transport controller [128,197,215]. The `PathKind` representation and #201's
observer/route leases are not replaced. Relay integration must transport only
end-to-end encrypted WireGuard packets, authenticate relay membership through
the existing admitted node identity, and enforce revocation on both direct
and relayed paths. TCP/TLS 443 remains the required fallback for UDP-blocked
networks [196]. These runtime obligations are not established by model tests.
