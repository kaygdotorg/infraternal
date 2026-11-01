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

Nodes connect to a relay over QUIC using ALPN `infraternal-relay/1`. Both
directions authenticate certificates issued by the deployment CA. A node
authenticates the relay's configured DNS name and server purpose. The relay
accepts a node only when its verified host certificate contains exactly one
`urn:infraternal:host:<uuid>` URI SAN and its admission callback permits that
host. A client supplied name never establishes identity. Certificate name or
purpose checks are not relaxed.

After connecting, the node opens one bidirectional QUIC stream and writes the
four-byte hello `IFR1`. This stream carries link requests and notices. Mesh
packets use QUIC DATAGRAM frames on the same connection. A reconnect replaces
the previous connection for that host and ends its links; both peers must
request their links again.

Before that authenticated control hello completes, the relay admits at most
256 in-flight handshakes globally and eight per source IP by default. IPv4
mapped IPv6 addresses count as their IPv4 source. New incoming connections are
refused at either limit before a serving task is spawned. Each TLS handshake
and control-hello wait has a five-second deadline; the source and global slots
are released when the host is admitted or the attempt ends.

## Wire formats

Control messages have no separate length prefix. The first byte selects one
fixed body length. Readers consume exactly that body before reading the next
message. Unknown kinds, incomplete bodies and invalid decoded values end the
control stream. The largest message is 21 bytes.

| Direction | Kind | Body | Total |
| --- | --- | --- | ---: |
| Node → relay | `0x01` Link | 16-byte host UUID | 17 bytes |
| Node → relay | `0x02` Unlink | 16-byte host UUID | 17 bytes |
| Relay → node | `0x81` Linked | 16-byte peer UUID, nonzero 32-bit big-endian link ID | 21 bytes |
| Relay → node | `0x82` Unlinked | 16-byte peer UUID | 17 bytes |

A relay creates a link only after both authenticated hosts request each other.
It assigns the same nonzero ID at both ends. A sender may forward only on a
link whose ID belongs to its connection; unknown IDs and IDs belonging to
another host are dropped. An Unlinked notice means the peer withdrew or left;
the surviving request remains pending. A node can withdraw its own request
with Unlink.

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
linked pair and 64 MiB across the relay. Each frame is charged in 1 KiB units
after adding 128 bytes for per-DATAGRAM queue metadata, so small frames also
consume budget. The relay forwards the existing shared `Bytes` storage; its
budget reservations stay with that storage until Quinn drops the last
reference after sending or discarding it. If either reservation is unavailable
or Quinn's send queue is full, the relay drops the DATAGRAM and increments its
dropped counter. This drop policy uses DATAGRAM's existing unreliable
semantics and does not block the control stream.

At the 4,096-host limit, the configured relay receive queues total at most 32
MiB and the global forwarding budget accounts for at most another 64 MiB of
queued DATAGRAM storage. The 128 KiB per-connection send setting is a local
ceiling; the shared global and per-pair reservations bound aggregate queued
payloads. These figures bound DATAGRAM buffering, not fixed connection,
control or link-table overhead.

### Address observation probes

Probes share the relay's UDP port and are removed before QUIC packet parsing.
Every request and response is exactly 84 bytes. Bytes 0–3 are `2a 49 46 31`
(`0x2a` followed by `IF1`); byte 4 is request kind `1` or response kind `2`;
bytes 5–7 are zero; bytes 8–15 are the connection session number; bytes 16–31
are a random transaction ID. The request reserves bytes 32–51 as zero. The
response uses byte 32 for address family (`4` or `6`), byte 33 as zero, bytes
34–35 for the observed UDP port, and bytes 36–51 for the observed IP address
(IPv4 is followed by twelve zero bytes). Bytes 52–83 are HMAC-SHA256 over the
first 52 bytes.

The session number and HMAC key come from the authenticated QUIC TLS exporter
using the label `infraternal relay probe v1`. The relay answers only a valid
request for a live connection session, and the node accepts only a valid
response with an outstanding transaction. Request and response sizes match,
so probes do not amplify. A mapping reported by a relay is an observation,
not proof of inbound reachability or NAT filtering behaviour. The discovery
book keeps observations bounded, address-family-specific, expiring and tied
to a network generation (`contracts/mesh-discovery.md`).

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

The caller requests relay service for a peer after its direct WireGuard
handshake grace period. In this slice, `direct_failed` compares the kernel's
last handshake time (seconds and nanoseconds) with the endpoint-install time
captured after the endpoint update. A handshake equal to or earlier than that
instant is stale and allows relay fallback; a later handshake in the same
second still proves the direct path. This preserves ordering without
mistaking a fresh same-second handshake for a failed path. Hole punching, ICE
checks, the D197 selector, and a relay-to-direct upgrade are not implemented
here.

Each node receives the same ordered relay list and opens one connection to
each configured relay. While a peer has no active link, the node requests the
link from every live relay. Once links arrive, both ends retain the lowest
list index they share and withdraw higher-index links. The list order is a
temporary deterministic choice for slice 1; it is not measured RTT ranking.

If the active relay connection ends, the node removes that link and switches
to the lowest-index remaining live link. If no link remains, the active relay
becomes `None`, packets without a link are counted and dropped, and the node
requests links again when a relay becomes live. A relay reconnect uses a
five-second connect deadline and exponential backoff from 250 ms up to five
seconds. QUIC keep-alive is one second and the idle timeout is three seconds.
When another relay remains active, recovery of a previously lost lower-index
relay does not move the pair back; this slice does not fail back. The next
relay's readiness does not guarantee packet-level continuity: UDP datagrams
may be lost during a failure, while reliable applications recover through
their own retransmission or resume mechanisms. This behavior does not claim
the byte-preserving make-before-break selector required by D185/D197.

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
probe parsing, forwarding-memory reservations, the real QUIC relay on loopback
and relay RSS under a many-pair DATAGRAM flood. The rootless namespace
proof exercises the kernel WireGuard device, direct and relayed peers, two
relays, link failover, recovery after relay restart, NAT rebinding and
observation-generation retirement. It verifies a numbered TCP stream by
SHA-256 and checks that host links, namespaces, modules and `net.*` sysctls
are unchanged after the run. This functional proof is not performance
evidence; performance claims come only from the locked perf-VM results on
#220.
