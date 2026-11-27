# GotaTun side socket: small datagrams in their own `fq` flow

**Job:** J1159, J1211, J1256 · **Issue:** #260 · **Status:** on by default for infraternal nodes, per peer, only
for peers that advertise it (see "Turned on") · **Decision owner:** kayg · **Follows:** J1139, J1140 (`gotatun-send-limit.md`), J1143

## Problem

Every datagram GotaTun sends to a peer has the same 5-tuple and leaves from the same socket, so
the sending host's flow-fair qdisc (`fq` on the perf VMs' eth0) treats all of it as one flow. A
probe, a pure ACK or a keystroke then waits behind all of our own bulk to that peer. J1140
measured it on the J1137 cross-VM pairing: a separate 200 B UDP flow waited p50 0.35 ms in eth0's
`fq` under full-speed load, GotaTun's own probe 1.5–4 ms. Replies-first (J1143) already moves those
datagrams to the front of GotaTun's own queues, but not the kernel's.

## What was built (fork `kayg/gotatun-fork` `j1159-small-socket` @ `e87fef9` on J1150's `9fb980df`; benched as `7c63654` on `841ef3e`, branch `j1159-small-socket-841ef3e`)

1. **Side socket.** The device binds a second UDP socket on the same address, family set-up and
   fwmark, with an ephemeral port (`UdpSend::bind_side`, Linux only; other transports have none).
2. **Mark.** For a peer that opted in (`PeerMut::set_side_port`), data packets with a payload of
   at most 256 B on the wire get a mark in reserved header byte 1 when they are prepared. The data
   header is not covered by the AEAD, so the mark costs nothing to set and may be cleared after
   encryption. Keepalives (32 B), handshakes and cookies are never marked.
3. **When the side socket is used.** The UDP send task sends a marked datagram from the side socket
   only while the main socket sent bulk (a datagram over 256 B) to the same destination within the
   last second. Otherwise it clears the mark and uses the main socket. Without bulk, everything
   leaves exactly as with one socket: keepalive timers, NAT refresh and roaming are unchanged. The
   side socket's NAT mapping never needs inbound traffic, because nothing is ever sent to it.
4. **Receive rule.** A marked data packet that decrypts is delivered, but it moves neither the
   peer's endpoint nor its confirmed endpoint (parallel and serial receive paths), so the peer
   keeps sending to our main port. An on-path attacker who sets the mark can only stop one packet
   from moving the endpoint, which it can already do by dropping it. One who clears it makes the
   peer roam to our side port, which it can already do by rewriting the source address.
5. **Switches.** `GOTATUN_SIDE_SOCKET=1` binds the side socket and opts every peer in (bench).
   Unset, the sender is off. The receive rule is always on.

Rejected: ignoring port changes from a known IP (breaks NAT rebinding, the most common roam);
letting the peer roam freely between both ports (our endpoint flaps and the peer's own bulk splits
across two flows); always sending small packets from the side socket (the main NAT mapping would
then depend on the peer's traffic and on handshakes alone).

## Compatibility and NAT (netns test, `nat-test.sh` attached to #260)

A (gotatun-cli from the fork) → masquerading router → B (gotatun-cli or kernel WireGuard); 8 s TCP
bulk A → B plus pings every 10 ms; B's view of A's endpoint is sampled every 100 ms.

| scenario | side datagrams idle / bulk | ping loss idle / bulk / after | B's endpoint for A |
|---|---|---|---|
| side ↔ side | 0 / 607 | 0 / 0 / 0% | main mapping only (90 of 90 samples) |
| side ↔ side, NAT rebinding mid-transfer | 0 / 607 | 0 / 0 / 0% | old main → new main mapping; never a side one |
| side off ↔ side off, same rebinding | 0 / 0 | 0 / 0 / 0% | old main → new main (control) |
| side → kernel WireGuard | 0 / 478 | 0 / **71.7%** / 0% | main only |
| side off → kernel WireGuard | 0 / 0 | 0 / 0 / 0% | main only |

Stock WireGuard reads the first four bytes as one little-endian type and drops a marked packet.
An older GotaTun would accept it and roam to the side port, where nothing listens. So the sender
must be per peer, and only for peers known to run the receive rule.

## Measurements (J1137 pairing: A = calternal-perf-01, 2 cores, B = infraternal-perf-01, 6 vCPU)

Rows: **B** one socket; **S** side socket on both nodes; **SA** side socket on A only. Same binary
(infraternal dev + the fork by path), 60 s iperf3 windows, ECN, probes as in J1143.

**The probe was biased.** iputils `ping` 20240117 at `-i 0.01` busy-polls while a reply is
outstanding and the RTT is below its interval: 73% of a core at a 2 ms RTT and ≈0 at 18 ms or more
(loopback + netem). On the CPU-bound 2-core sender, ping used 0.17–0.30 cores in bloated base
windows and 0.70–0.75 once the side socket cut the RTT. That 0.5 core came out of the tunnel's
share. Holds h1 and h2 therefore showed −1.5 to −4.2% Gbit/s and +11 to +32% sender CPU per Gbit
at forward full speed, all of it ping's own CPU. Holds h5 and h6 use `-i 0.02` (no spin) for every
row. J1160 found the same busy-wait independently. Earlier J1137-kit numbers for latency-reducing
candidates (J1140's send limit among them) carry the same bias.

**Forward (A sends), non-spinning probe: mean of holds h5 and h6** (rows in the order B,SA,S
and S,SA,B; Gbit/s; latency in ms; A CPU in s/Gbit; every per-hold difference has the same sign
as the mean in the full-speed latency cells, see `pair-h56.md` on #260):

| full speed | Gbit/s B / S / SA | ping p50 B → S / SA | ping p99 B → S / SA | key p99 B → S / SA | A CPU B / S / SA |
|---|---|---|---|---|---|
| CUBIC 1 | 3.059 / 3.054 / 3.056 | 4.19 → 2.10 / 2.09 | 7.67 → 5.27 / 4.94 | 7.77 → 5.50 / 5.18 | 0.596 / 0.598 / 0.594 |
| CUBIC 8 | 3.115 / 3.120 / 3.130 | 8.33 → 2.50 / 2.48 | 13.1 → 7.61 / 7.59 | 13.5 → 7.97 / 8.02 | 0.597 / 0.577 / 0.569 |
| BBR 1 | 2.915 / 2.915 / 2.913 | 1.96 → 1.82 / 1.82 | 4.09 → 3.71 / 3.72 | 4.32 → 3.98 / 3.93 | 0.621 / 0.616 / 0.619 |
| BBR 8 | 3.058 / 3.074 / 3.076 | 6.79 → 2.46 / 2.45 | 11.4 → 6.87 / 6.84 | 11.8 → 7.12 / 7.25 | 0.590 / 0.580 / 0.580 |

B's CPU per Gbit is within ±0.03 in every cell. The page stream (64 B request, 1,200 B reply)
falls by the same 2.3–5.7 ms at p99, because its request leaves A on the side flow.

- Equal rate (fq 2.0 Gbit/s): throughput within 0.3%; ping, key and page p50/p99 within
  ±0.7 ms of B, with both signs.
- SA gains as much as S: the win is A's own small packets leaving A's bulk flow. B's ACKs on
  B's side port add nothing in this direction.
- **Reverse (B sends; h1 + h2, the probe's CPU is unchanged there because the RTT is):** within
  noise, with one consistent cell: CUBIC 1 full speed −1.5% Gbit/s (2.906 → 2.863, both holds).
  B's eth0 queue does not fill the way the 2-core A's does, so there is little to gain.
- NAT counters: side-port datagrams appear only in S/SA rows (A ≈ 58–75k per row: probes and
  requests; B ≈ 2.2M in S: its pure ACKs, because its 1,200 B page replies count as bulk to A).

## Verdict

**The receive rule ships; the sender stays off.** Pinning `e87fef9` changes nothing on the wire
(no node sends a mark unless `GOTATUN_SIDE_SOCKET=1`), but once every node runs the rule, turning
the sender on can no longer make an older node roam to a side port. On the pairing where the
sender's `fq` fills, the sender cuts loaded latency by 30–70% at full speed with throughput and CPU
within noise. It is not turned on here because that needs work outside this job:

1. a device-level switch for the embedding application (today only the bench env binds the
   socket);
2. infraternal advertising "understands the side mark" per node, and setting
   `PeerMut::set_side_port` only for such peers (stock WireGuard drops marked packets);
3. optionally, also receiving on the side socket, so a peer that roams there by mistake is still
   heard.

## Knobs

- `GOTATUN_SIDE_SOCKET=1` binds the side socket and opts every peer in; it prints
  `diag side_socket on` and `diag side_socket bound=<addr>` on stderr.
- `PeerMut::set_side_port(bool)` overrides the opt-in per peer (no effect without a side socket).
- The side socket needs replies-first's `tx` lane (on by default since J1143); with
  `GOTATUN_REPLIES_FIRST=off`, marks are cleared and everything uses the main socket.

## Turned on (J1211, owner approved 2026-11-25)

J1159 left three things open (see Verdict). All three are done, on Linux and macOS nodes.

1. **A device-level switch.** The fork (`kayg/gotatun-fork` `cd295c2`, one commit on `e87fef9`) has
   `DeviceBuilder::with_side_socket(bool)` and `Peer::with_side_port(bool)`. The node turns the
   device switch on by default. `INFRATERNAL_MESH_SIDE_SOCKET=off` (or `0`) turns it off for one
   node: no second socket, no marks, and no advertisement (`mesh/src/side_socket.rs`).
2. **Advertising.** A node answers `mesh.identity {"side_socket":true}` with `side_socket` (it
   understands the field) and `side_port` (it runs GotaTun, the receive rule, and has the second
   socket on). The kernel engine never says yes. The coordinator asks at attach, before the first
   snapshot, stores it (`mesh_nodes.side_port_supported/side_port`, one revision bump per change)
   and sets `Peer::side_port` for a peer only when that peer said yes, and only in snapshots for
   nodes that understand the field (the `ipv4_only` path, J1142).
3. **Opt-in per peer, never by default.** The engine builds every peer with an explicit
   `with_side_port(switch_on && peer.side_port)`, both rotation identities alike. A peer that did
   not advertise, an older node, a kernel-engine node: no mark is ever sent to it.
4. **Listening.** The device also receives on the second socket (`udp::side_recv::WithSide`, the
   same single receive task, main socket polled first), through the same handshake admission
   guard as the mesh port (`BoundUdpFactory::bind_side`). It is insurance: a peer that reaches
   our second port anyway (an older node's roam, a rebinding NAT) is heard, not black-holed.

Rejected: a second receive task (handshake backlog, pool and crypto order belong to one task);
asking each node for a per-peer capability (a node is capable or it is not); sending marks to every
peer and relying on the peer to ignore them (kernel WireGuard drops them, 71.7% loss).

Measured numbers are on #260 (J1211 comment) and in `research/` receipts attached there.

## On macOS (J1256, 2026-11-26)

Same product behaviour as on Linux, no macOS-specific change needed. Raw receipts are on #260
(J1256 comment); the harnesses are not in the repository.

**Mixed mesh, product nodes.** A Mac node (macOS 26.5.2 VM) and two Linux nodes (L1 side socket
on, L2 `INFRATERNAL_MESH_SIDE_SOCKET=off`) in network namespaces, in two VMs on one physical host, configured by
the production coordinator compiler. Three counterbalanced rounds of Mac on / Mac off, 48 windows of
30 s (`iperf3`, both directions, 1 and 8 flows) with the `rr.py` keystroke probe.

- Side-port datagrams appear only between two advertising nodes: Mac → L1 2,371–2,491 per upload
  window, L1 → Mac 745–885 per download window; none to or from L2, and none anywhere with the
  Mac's switch off.
- All 72,000 probes were answered.
- Throughput (0.16–0.44 Gbit/s) and probe latency show no consistent difference between on and
  off. The path is bounded by the VM host's user-mode network, so this proves interoperation, not
  a latency effect.

**Real Mac on Wi-Fi.** MacBook Air M1, macOS 27.2.1, 5 GHz. It has no root, so no utun: a harness
ran one engine per host (the product's GotaTun pin and socket options) with TCP-shaped bulk in a
fixed window and a 64 B probe every 20 ms. Medians over counterbalanced pairs of 30 s windows,
Mac uploading, off / on:

| series (peer) | load | Mbit/s | probe p50 ms |
|---|---|---|---|
| 6 pairs (Linux, behind a user-mode NAT) | 8 flows | 296 / 292 | 25.0 / 24.3 |
| 6 pairs (same) | 1 flow | 220 / 217 | 14.8 / 15.2 |
| 5 pairs (macOS, same LAN) | 8 flows | 327 / 334 | 32.0 / 31.8 |
| 5 pairs (same) | 1 flow | 234 / 221 | 14.3 / 15.1 |
| 5 pairs (same, probe skips the harness's bulk queue) | 8 flows | 303 / 320 | 32.6 / 31.6 |
| 5 pairs (same) | 1 flow | 195 / 227 | 16.7 / 14.8 |

The signs change from series to series: **no measurable gain and no measurable cost.** Idle
probes were already p50 4 ms, p99 92 ms on this Wi-Fi, so tails are the radio's. In a sample of
four saturating windows the Mac's own FQ-CoDel interface queue was empty at the median sample
(a flow was backlogged in 30–45% of samples). The likely reading, not proven, is that most of the
added delay sits where a second flow cannot pass it: below that queue (driver, radio) or ahead of
the socket. The 30–70% gain of the Linux pairing needs a sender whose flow-fair queue holds the
backlog, which this Mac rarely did.

On macOS 27 the engine's connected-send pool stays unused (J1108), and 24 of the fork's
`macos_connected` tests fail there both at the pin and at the pre-side-socket base `e87fef91`; its
13 side-socket tests pass.

