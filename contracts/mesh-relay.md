# Mesh relay contract

This contract records the first QUIC DATAGRAM relay slice for Linux kernel
WireGuard peers. The relay carries opaque WireGuard packets; it has no mesh
keys and does not inspect tunnel traffic. The slice follows D163, D176, D185,
D196, D197, D201, D313 and D316. It does not select a new transport, crypto
engine or path selector.

The relay runtime is opt-in at build time: `infraternal-plugin-relay/runtime`
contains the service and client, `infraternal-mesh/relay` contains the bounded
peer-socket discovery book, and `infraternal-plugin-mesh/relay` contains the
seam C shim. None of these features is enabled by the default `infraternal`
shipping feature set. The relay CLI declarations can be compiled without the
runtime. The D243 release check records this slice's static shipping-image
delta.

## Relay identity and connection

Nodes connect to a relay over QUIC using ALPN `infraternal-relay/2` (version 2
names links by opaque pair tokens, D401 Q8; version 1 named hosts). Both
directions authenticate certificates issued by the deployment CA. A node
authenticates the relay's configured DNS name, server purpose and its relay
URI: a relay leaf carries exactly one `urn:infraternal:relay:<uuid>` SAN, and a
leaf without it (such as the server's leg-B leaf) is refused. Leg B refuses any
server leaf whose DER contains that prefix, before the leaf can raise the
server-leaf floor, so a relay's key never answers a dial meant for the server
(D401 Q3). The relay
accepts a node only when its verified host certificate contains exactly one
`urn:infraternal:host:<uuid>` URI SAN and its admission callback permits that
host. A client supplied name never establishes identity. Certificate name or
purpose checks are not relaxed.

After connecting, the node opens one bidirectional QUIC stream and writes the
four-byte hello `IFR2`. This stream carries link requests and notices. Mesh
packets use QUIC DATAGRAM frames on the same connection. A reconnect replaces
the previous connection for that host and ends its links; both peers must
request their links again. Queued DATAGRAM reservations from an older
connection continue to count against that host if it reconnects before Quinn
drops them.

Before that authenticated control hello completes, the relay admits at most
256 in-flight handshakes globally and eight per source IP by default. IPv4
mapped IPv6 addresses count as their IPv4 source. New incoming connections are
refused at either limit before a serving task is spawned. Each TLS handshake
and control-hello wait has a five-second deadline; the source and global slots
are released when the host is admitted or the attempt ends.

## Relay list and the relay role (D401 Q2–Q4)

The coordinator sends each node the control action `mesh.relays` on the same
authenticated channel as its mesh configuration, after a configuration was
delivered and whenever the list changes. It is a separate action, not new
`Config` fields, because `Config` and `Chunk` refuse unknown fields and the
previous release parses the saved `mesh-public.json` strictly. A node that
refuses the action is not asked again until the coordinator reads its identity
again. The body is one object:

- `relays`: at most 8 entries of `name` (the relay leaf's DNS name, lowercase
  host name), `port` (UDP, nonzero) and optional `addresses` (at most 4; empty
  means the node resolves `name`). The node saves this part in
  `mesh-relays.json` beside its mesh state and starts from it after a restart,
  so it keeps its relays while the server is down (D285).
- `serve`, only for the node that runs the relay role (the server's own node in
  slice 1): `name`, `port`, `leaf` (relay leaf certificate PEM then PKCS#8 key
  PEM, at most 3 KiB), `roots` (one or two CA certificates) and `revoked` (at
  most 128 host UUIDs whose leaves still verify, from the coordinator's removal
  tombstones). The role's key is held in memory only and never written by the
  node. The node answers `{"accepted":true,"serving":<port>}` with the UDP port
  it bound, and the coordinator then lists that relay for every other node. A
  role whose port cannot be bound answers without `serving` and lists nothing.

The relay role admits a host whose verified leaf chains to `roots` and is not
in `revoked`. Every new list updates `revoked` and re-checks live connections,
closing refused ones and their links; each connection also ends when its
leaf's `notAfter` passes (one timer per connection, armed once). A renewed
relay leaf is installed for new handshakes without a restart; open connections
keep the leaf they were made with. The server keeps the relay leaf in its CA's
`active/relay-leaf.pem` (mode 0600, written durably before it is served), 7
days from `notBefore`, renewed at half-life while the CA is unlocked, so a
locked cold start still serves the retained leaf. The relay role is opt-in in
slice 1: the server runs with `--relay-port <udp-port>` (which also opens that
port in its host firewall policy).

A message with the maximum revoked list stays inside one 8 KiB action frame.
A revoked host beyond the first 128 still reaches nobody, because its peers
dropped its mesh key (D166) and so its pair tokens match nothing; it can hold a
connection slot until its leaf expires.

## Wire formats

Control messages have no separate length prefix. The first byte selects one
fixed body length. Readers consume exactly that body before reading the next
message. Unknown kinds, incomplete bodies and invalid decoded values end the
control stream. The largest message is 21 bytes.

| Direction | Kind | Body | Total |
| --- | --- | --- | ---: |
| Node → relay | `0x01` Link | 16-byte pair token | 17 bytes |
| Node → relay | `0x02` Unlink | 16-byte pair token | 17 bytes |
| Relay → node | `0x81` Linked | 16-byte pair token, nonzero 32-bit big-endian link ID | 21 bytes |
| Relay → node | `0x82` Unlinked | 16-byte pair token | 17 bytes |

Requests never name the other host (D401 Q8). Both ends of a pair compute the
same token: the first 16 bytes of HMAC-SHA256 keyed with the pair's X25519
static-static secret (one end's mesh private key with the other's mesh public
key) over the label `infraternal relay pair token v1\0` followed by the relay's
certificate DNS name. Only the two ends know the secret, the token is one-way,
and it differs per relay, so two relays carrying one pair see unrelated values.
A peer key whose shared secret is all zero is refused. The relay still learns
which two of its connections it joins; that is accepted (D401 Q8).

A relay creates a link only after two different authenticated hosts request
the same token. A token has at most two requesters; a further request for it
is ignored without closing the connection, so nobody joins a pair that is
waiting or linked. It assigns the same nonzero ID at both ends. A sender may forward only on a
link whose ID belongs to its connection; unknown IDs and IDs belonging to
another host are dropped. An Unlinked notice means the peer withdrew or left;
the surviving request remains pending. A node can withdraw its own request
with Unlink. Relays keep counters only, never a per-pair log.

Each QUIC DATAGRAM begins with a four-byte big-endian nonzero link ID. The
remainder is forwarded unchanged as opaque WireGuard ciphertext. The relay
does not decrypt, re-encode or copy it. The receiver removes the four-byte
link ID and sends the ciphertext to its local kernel WireGuard socket. The
frame parser rejects a zero link ID and a header-only DATAGRAM; WireGuard
validates the non-empty packet.
QUIC DATAGRAM delivery is unreliable and unordered, matching the inner
WireGuard datagram semantics. The relay-side receive queue is bounded to 8
KiB per connection and its Quinn send queue to 128 KiB per connection. A
separate forwarding budget bounds accepted DATAGRAM storage to 256 KiB per
linked pair, 4 MiB per source host across all its pairs, and 64 MiB across the
relay. Each frame is charged in 1 KiB units after adding 128 bytes for
per-DATAGRAM queue metadata, so small frames also consume budget. The relay
forwards the existing shared `Bytes` storage; its global, host and pair
reservations stay with that storage until Quinn drops the last reference after
sending or discarding it. If any reservation is unavailable or Quinn's send
queue is full, the relay drops the DATAGRAM and increments its dropped
counter. This drop policy uses DATAGRAM's existing unreliable semantics and
does not block the control stream. A single source host can therefore use at
most one sixteenth of the global forwarding budget, leaving the remaining
quota available to other hosts.

At the 4,096-host limit, the configured relay receive queues total at most 32
MiB and the global forwarding budget accounts for at most another 64 MiB of
queued DATAGRAM storage. The 128 KiB per-connection send setting is a local
ceiling; the shared global, per-host and per-pair reservations bound aggregate
queued payloads. These figures bound DATAGRAM buffering, not fixed connection,
control or link-table overhead.

### Address observation probes

Probes share the relay's UDP port and are removed before QUIC packet parsing.
Every request and response is exactly 84 bytes. Bytes 0–3 are `2a 49 46 31`
(`0x2a` followed by `IF1`); byte 4 is request kind `1` or response kind `2`;
bytes 5–7 are zero; bytes 8–15 are the connection session number; bytes 16–23
are the big-endian Unix-millisecond issue time and bytes 24–31 are a random
transaction nonce. The request reserves bytes 32–51 as zero. The
response uses byte 32 for address family (`4` or `6`), byte 33 as zero, bytes
34–35 for the observed UDP port, and bytes 36–51 for the observed IP address
(IPv4 is followed by twelve zero bytes). Bytes 52–83 are HMAC-SHA256 over the
first 52 bytes.

The session number and HMAC key come from the authenticated QUIC TLS exporter
using the label `infraternal relay probe v1`. The relay answers only a valid
request for a live connection session, and the node accepts only a valid
response with an outstanding transaction. The relay binds each transaction to
its first observed source in a 64-entry per-session rolling window and rejects
transactions older than 30 seconds. When an entry is evicted, its issue time
advances a retired-time floor, so an older transaction cannot rebind to another
source. A retry from its original source is answered; reuse from a different
source is refused. Request and response sizes match, so probes do not amplify.
A mapping reported by a relay is an
observation, not proof of inbound reachability or NAT filtering behaviour. The
discovery book keeps observations bounded, address-family-specific, expiring
and tied to a network generation (`contracts/mesh-discovery.md`).

## Seam C socket ownership

The kernel WireGuard device owns the peer-traffic UDP port. Direct peers stay
on that kernel path. The seam observes the same port without taking over
ordinary WireGuard traffic:

- One send-only IPv4 `IPPROTO_RAW` socket per seam sends probes with the
  WireGuard listen port as UDP source port. Route selection supplies the
  source address. The socket never receives data packets.
- One `AF_PACKET` `SOCK_DGRAM` tap per seam has a classic BPF filter. It
  passes only incoming, unfragmented IPv4 UDP packets addressed to the
  WireGuard port with the probe magic. Filtering occurs in the kernel before
  packet data is copied to the process. The WireGuard socket also sees a
  probe addressed to its port and drops it as an invalid WireGuard header
  before changing peer state.
- For a relayed peer only, the mesh component binds one ephemeral loopback
  UDP socket and connects it to the local WireGuard port. It changes that
  peer's kernel endpoint to the shim address. The kernel sends that peer's
  ciphertext to the shim; the shim prefixes the link ID and sends one QUIC
  DATAGRAM. Inbound ciphertext is sent from the same shim socket to the
  kernel, which authenticates it. Direct peers never use these sockets.

The raw sender and packet tap need the root privileges already required by
the Linux mesh component (D163). This slice's seam and relay observation path
are IPv4-only; IPv6 relay observation, port mapping and lower-MTU handling are
later work. On the perf VM, seam B (kernel data path with probes) measured
within roughly 3–10% of the kernel baseline, while seam A (all userspace)
used about twice the CPU per Gbit/s and added 300–600 microseconds of one-way
p50 latency. The shim measured about 270 bytes per relayed pair at 1,000
pairs. These measurements support seam C; they are not general latency
budgets (#220, D313 Q1).

## Slice-1 path and failover rules

The node's relay manager starts one set of relay paths for the listed relays
with its enrolled host leaf. After each accepted complete configuration, every
peer this node may exchange packets with, new or changed, gets one deadline
5.5 s later (one WireGuard handshake attempt plus a margin). A pair with no
handshake since its configuration was installed is relayed and records the
reason ("no direct handshake within 5 seconds"); `mesh status` shows it as
"via <relay>, because <reason>". No timer repeats for a pair. When the relay
list changes, the paths are replaced and pairs that were relayed move to the
new paths at once.

The caller requests relay service for a peer after its direct WireGuard
handshake grace period. In this slice, `direct_failed` compares the kernel's
last handshake time (seconds and nanoseconds) with the endpoint-install time
captured after the endpoint update. A handshake equal to or earlier than that
instant is stale and allows relay fallback; a later handshake in the same
second still proves the direct path. This preserves ordering without
mistaking a fresh same-second handshake for a failed path. Hole punching, ICE
checks and a relay-to-direct upgrade are not implemented here. Relay against relay is chosen by measured round trip (below); a direct
path has no round-trip sample source yet, so direct against relay is still the
failure rule above.

Each node receives the same ordered relay list and opens one connection to
each configured relay. A relayed peer requests a link from every live relay
and keeps every link it gets; nothing is withdrawn while the peer is relayed.
The first link that comes up carries the pair at once. The others are ready
alternatives, for a failover and for a measured move (#201).

### Relay choice by measured round trip (#201, D185, D313 Q5)

While a pair has two or more links, each end measures every link end to end
with a link probe: a QUIC DATAGRAM on that link whose payload, after the
four-byte link ID, is exactly 12 bytes: kind `0xf0` (probe) or `0xf1`
(answer), three zero bytes, and a big-endian 64-bit token. WireGuard message
types are 1 to 4, so a probe is never mistaken for ciphertext; the shim
removes probes before the kernel sees anything. A node answers a probe on the
same link with the same token, so one round trip covers both legs and the
relay's queueing. The relay forwards probes like any other DATAGRAM and needs
no change.

- Probe rounds start only from the send path, after one of the pair's own
  packets, at most once per second, and only while the pair has two links or
  more. No timer runs for them, so an idle pair, or a pair with one relay,
  sends nothing extra.
- A probe unanswered for 2 s counts as a 2 s sample.
- A link's samples are cleared whenever that link changes.
- The pair moves to another link only under the shared rule in
  `infraternal_mesh::path_choice`: each of the challenger's last five samples,
  spanning at least 3 s and none older than 30 s, is faster than the current
  link's median by at least max(5 ms, 15 %). At most one such move happens per
  10 s. A failover restarts that dwell; setup moves between unmeasured links
  do not.
- Until anything is measured, the lowest-indexed link carries the pair, so
  both ends agree during setup. When every link has its first sample, a link
  that beats that default by the margin takes over at once (the first measured
  choice); equal links keep the default.
- Both ends measure the same quantity and so normally choose the same relay.
  While they differ, delivery still works, because a node accepts its peer's
  packets on every link.
- A relay sees the token and could answer for the peer. It cannot look faster
  than its own leg, which the node's QUIC connection to it measures, and relays
  hold the deployment's server-purpose certificate. Authenticated probes are a
  later hardening step.

A measured move changes only which link carries the pair; the shim address,
the WireGuard endpoint and the session stay as they are. The route budget uses
the smaller of the two links' DATAGRAM limits during the move, as a failover
does.

If the active relay connection ends, the node removes that link and switches
at once to the remaining live link with the lowest measured median, or the
lowest index when none is measured. If no link remains, the active relay
becomes `None`, packets without a link are counted and dropped, and the node
requests links again when a relay becomes live. A relay reconnect uses a
five-second connect deadline. After an established connection drops, the node
retries immediately. For 60 seconds after a healthy connection ends, reconnect
attempts use a 750 ms deadline and failed attempts are separated by at most
250 ms. After that window, the connect deadline returns to five seconds and
retry backoff can grow to five seconds. A successful connection resets the
backoff. QUIC keep-alive is one second and the idle timeout is three seconds.
A recovering relay does not take the pair back by itself: it becomes a link
again and wins only under the measured rule above. The next
relay's readiness does not guarantee packet-level continuity: UDP datagrams
may be lost during a failure, while reliable applications recover through
their own retransmission or resume mechanisms. A failover is therefore
not make-before-break. A measured move is: the old link stays up and keeps
delivering whatever is already in flight on it.

The QUIC path advertises a maximum UDP payload of 1,472 bytes, the IPv4
payload limit for a 1,500-byte underlay. A 1,500-byte IPv6 underlay permits
1,452 bytes, which is two bytes short for the largest full WireGuard packet
plus link ID; route MTU reduction and Packet Too Big handling remain a later
acceptance item.

## Port 443 fallback status (D313 Q6)

D313 Q6 requires both TLS on port 443 with ALPN demultiplexing beside HTTPS
and a WebSocket upgrade for networks that pass only web-looking traffic in
the first release. Neither path is implemented in slice 1: the current relay
accepts QUIC DATAGRAMs over UDP only. Therefore this slice does not claim mesh
connectivity on UDP-blocked networks and is not the completed D313 Q6 release
surface. HTTP CONNECT remains excluded because it would add proxy credential
handling.

## Acceptance evidence

Unit tests cover fixed-size control codecs, link-ID framing, authenticated
probe parsing and captured-request source binding, forwarding-memory
reservations including one host across 256 backpressured pairs, the real QUIC
relay on loopback and relay RSS under a many-pair DATAGRAM flood. The rootless
namespace proof exercises the kernel WireGuard device, direct and relayed
peers, two relays, link failover, recovery after relay restart, NAT rebinding
and observation-generation retirement. It verifies a numbered TCP stream by
SHA-256 and checks that host links, namespaces, modules and `net.*` sysctls
are unchanged after the run. This functional proof is not performance
evidence; performance claims come only from the locked perf-VM results on
#220.
