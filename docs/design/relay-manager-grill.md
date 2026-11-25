# Production relay manager: owner grill

**Job:** J1212 · **Issues:** #580, #483, #514 · **Status:** research and design only, no product code · **Decision owner:** kayg

This page prepares the owner grill for the piece that is still missing between
the relay code we have and a mesh that replaces NetBird (#580): the **relay
manager**. It is the part of every node that learns which relays exist, holds
their credentials, connects to them, decides when a pair of machines goes
through one and when it comes back, and stays inside fixed resource limits.

Every question below gives the options, what was measured or cited, and a
recommendation, which comes first. The owner makes every decision (CLAUDE.md,
"Foundational choices"). The short list is at the end.

---

## 1. The problem

Two machines can talk directly only when at least one NAT along the way lets
the other one's packets in. J536b's 18-profile matrix (#483, dev `699197421`,
rootless namespaces with real kernel NAT) shows where production stops today:

| Profile | Direct today | After D391 candidates (J536b model) | Needs |
|---|---|---|---|
| full cone, address- and port-restricted, symmetric vs full cone, CGNAT port-preserving | yes | yes | nothing |
| CGNAT port-translating, double NAT (one side / both), same NAT without hairpin | **no** | yes (127 / 88 / 132 / 54 ms) | candidates (D391), being built |
| symmetric vs port-restricted, symmetric both | **no** | **no** | a relay over UDP, or port prediction (gated by D313 Q4) |
| UDP blocked, only TCP 80/443, DPI dropping WireGuard handshakes | **no** | **no** | a relay over TCP/TLS 443 (D196, D391) |

Five profiles stay unreachable without a relay. The iPhone on cellular
(#580) is the most common real case: carrier NATs often change the port per
destination, which is the symmetric row. NetBird and Tailscale solve this the
same way: a relay that forwards the end-to-end encrypted WireGuard packets
when no direct path opens, and a move back to direct when one does.

`mesh peers` already says it plainly (802c7644c): "a firewall or NAT may
block direct UDP, and there is no relay yet".

## 2. What exists (dev `4e1927843`)

| Piece | Where | State |
|---|---|---|
| Relay service: QUIC DATAGRAM, ciphertext only, mutual TLS on the deployment CA, both-sides-request linking, bounded tables and queues, authenticated address probes on the same port | `crates/plugins/relay/src/{relay,tls,wire,probe}.rs`, `contracts/mesh-relay.md` | built, reviewed, behind the `runtime` feature |
| Relay client (one connection, link/unlink, notices) | `crates/plugins/relay/src/client.rs` | built |
| Node side: `RelayPaths` (one connection per listed relay, a loopback shim socket per relayed peer, failover, RTT-ranked choice between relays, standby links) | `crates/plugins/mesh/src/relay_path.rs` | built, **Linux only** (`cfg(all(feature = "relay", target_os = "linux"))`) |
| Shared switch rule: max(5 ms, 15 %), 5 samples over ≥ 3 s, ≥ 10 s dwell, direct wins in the band | `crates/infraternal-mesh/src/path_choice.rs` (D313 Q5) | built, used by `RelayPaths` |
| Direct-path RTT probes from the WireGuard port (Linux, macOS) | `crates/plugins/mesh/src/direct_probe.rs` (J1194, J1206) | built and shipping; nothing in production consumes them yet |
| `relay_path::direct_failed`: "no handshake after the endpoint was installed" | `relay_path.rs` | built, the only direct → relay trigger |
| Relay callbacks on the node (handshake starter/preparer, route MTU updater) | `crates/plugins/mesh/src/node.rs` | built, unused in production |
| `relay up / down / status` CLI | `crates/plugins/relay/src/cli.rs` | placeholders, "not available yet" |
| TLS on TCP 443 and WebSocket relay transports (D313 Q6, D391) | — | **not built**; J536 loopback probes only (13.9 Mbit/s TLS, 11.6 Mbit/s WebSocket, not WAN figures) |
| Relay list, relay credentials for relays other than the server, relay selection for production, `relay` feature in the shipping build | — | **not built** |

The production gap (J1206): `RelayPaths`, `direct_failed` and `Observer` are
driven only by `crates/plugins/mesh/examples/relay_fixture.rs` and
`relay_echo.rs` (features `relay` + `test-support`). `infraternal-agent`
builds the mesh plugin with `features = ["agent"]` only, so no shipped node
ever relays. The relay manager is what wires these pieces into the node.

### What is already decided (not re-asked here)

- The server always runs a relay; any node can be one; one relay role serves
  terminals and the mesh (D128, D131, D163).
- "Run a relay here" is a checkbox, never a command the user must run (D132);
  automatic relays only on datacenter machines proven reachable with spare
  capacity, with the detection rule brought back with measurements (D285).
- A pair may use any relay of its own mesh; relays forward ciphertext only;
  an admin allow-list is only an override (D313 Q3).
- The switch rule (D313 Q5, D185) and "the client picks the lowest measured
  round trip and the user can override it" (D185).
- Relay framing is QUIC DATAGRAM (D313 Q7); the first relay release is TLS on
  443 with the WebSocket upgrade, QUIC DATAGRAM after it, port 443 only for
  now (D391, amending D313's order). WireGuard inside the TLS relay is enough
  disguise for now (D391).
- Hard-NAT pairs are relayed from day one, and every relayed pair records why
  (D285). Machines already in the mesh keep their last-known addresses and
  relays while the server is down (D285, D166).
- Design scale: 1,000 peers per mesh, tested to 4,096 (D170, D393). Idle CPU
  is zero by default (D81).

## 3. How others do it (for reference only)

- **Tailscale DERP.** The coordination server hands every client a DERP map
  (regions and servers); the client keeps it across restarts, picks a *home*
  region by measured latency and reports it, and the coordination server tells
  peers, so a peer reaches you through your home region. Failover moves to
  another server in the region, then the next-closest region.
  ([DERP servers](https://tailscale.com/kb/1232/derp-servers),
  [custom DERP](https://tailscale.com/docs/reference/derp-servers/custom-derp-servers))
  **Peer relays** (GA, 2025) let any node relay over UDP on a chosen port,
  gated by an access-policy grant on which devices may use which relays
  ([peer relays](https://tailscale.com/kb/1591/peer-relays)).
- **NetBird.** The management server tells peers the relay URLs; every relay
  shares one authentication secret with the management server
  (`NB_AUTH_SECRET` / `relays.secret`), and peers present a time-limited HMAC
  token the management server issued
  ([external relays](https://docs.netbird.io/selfhosted/maintenance/scaling/set-up-external-relays),
  [env vars](https://docs.netbird.io/selfhosted/environment-variables)).
  One wrong character in that secret gives a relay that looks healthy and
  refuses every peer (same page).
- **TURN REST credentials.** A username with a timestamp and
  `password = base64(HMAC(secret, username))`, verified by the TURN server
  with a shared secret
  ([draft-uberti-behave-turn-rest](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest)).

Where we differ already: our nodes and relays both hold deployment-CA
certificates, so relay admission needs no shared secret at all (Q3).

---

## Q1. What ships first: the built QUIC relay, or D391's TLS 443 relay?

D391 says the first relay release is TLS on 443 with the WebSocket upgrade.
What is built and reviewed is the QUIC DATAGRAM relay. The manager (Q2–Q9)
is the same for both: a transport is one more way to open a relay connection.

| Option | Profiles fixed (§1) | New code | Speed |
|---|---|---|---|
| **(a) Manager + QUIC relay on the server first, TLS/WebSocket 443 next slice (recommended)** | 2 (symmetric rows) at once, 5 after slice 2 | manager only; relay transport exists | no head-of-line blocking; full mesh MTU on IPv4 (1,472-byte payload) |
| (b) Keep D391's order: manager + TLS/WebSocket 443 first | 5 at once | manager + a new stream transport (framing, back-pressure, ALPN next to HTTPS, the inner mutual TLS of #559 so a TLS-terminating proxy cannot relay) | one loss stalls every flow of the connection for ~1 RTT (D313 Q7) |
| (c) Both in one slice | 5 | both | — |

**Recommendation: (a).** It puts relaying into production one slice sooner
with code that already passed review, covers the iPhone-on-cellular case
that #580 needs, and the manager it adds is exactly what slice 2 plugs the
443 transport into. It is an order change to D391, so it is the owner's call.
If the owner keeps (b), nothing below changes.

Libraries: none new. QUIC is quinn + rustls + ring (D176). The 443 transport
can reuse what leg B's HTTPS fallback already ships (`tokio-tungstenite`,
`tokio-openssl` in `infraternal-agent`).

## Q2. Where do nodes get the relay list?

| Option | Correctness | Consistency | Cost |
|---|---|---|---|
| **(a) The server pushes it in each node's mesh configuration, persisted on the node (recommended)** | one source of truth; revisions order it with peer changes; a removed relay disappears with the next push | the same channel as peers, rules and candidates (`node_coordination.rs`, `configuration.rs`); added as an additive field behind the existing capability probe (`compact_access`, `key_rotation`, `authority_epoch`) | ~150 B per relay; 2–8 relays fit easily in one 64 KiB mesh frame |
| (b) Local config file or CLI flags | drifts from the server; no revocation | against D131/D132 (no config files, the user never runs commands) | — |
| (c) DNS (SRV records) | needs DNS the owner controls; no per-node view | a second discovery source | resolver lookups |

**Recommendation: (a)**, with `--relay` kept for tests and operators only.
One entry: the relay's host id, its certificate name, its addresses per
transport (UDP port; later the 443 URL), the region hint the server knows,
and whether the owner pinned or blocked it (D313 Q3 override). The node
writes the list next to its mesh state, so after a restart with the server
down it still knows its relays (D285).

Invariant: the relay list must never need a relayed path to arrive. The
server's own relay is reached over the underlay, and leg B keeps its TCP/TLS
443 fallback (D215, D291), so a node behind a hard NAT can always fetch it.

## Q3. Relay credentials: tokens, lifetimes, rotation, revocation

Today both directions authenticate with deployment-CA certificates: a node
presents its enrolled host leaf (`urn:infraternal:host:<uuid>`, client
purpose, 7 days, renewed at half-life; D133, D168), and the relay presents a
server-purpose leaf with a DNS name (`tls.rs`). The relay asks an
`Admission` callback whether the verified host may stay.

| Option | Secrets added | Revocation | Server down / CA locked | Built |
|---|---|---|---|---|
| **(a) Keep the CA certificates for nodes; issue a dedicated relay leaf to each relay node (recommended)** | none on nodes; one relay leaf key per relay node | at once on the server's own relay (it reads the revoked set); on node relays through the next config push (removal already reaches every peer, D166) | relays keep admitting until a node's 7-day leaf expires: at least 3.5 days after any server restart (D168) | node side yes; relay leaf issuance no |
| (b) Shared-secret HMAC tokens (NetBird / TURN style) | one secret copied to every relay; a leak on any relay forges tokens for all | by token expiry only | tokens stop renewing when the server is down | no |
| (c) Server-signed relay tickets (Ed25519, per host and per relay, hours to days) | the ticket signing key | by ticket lifetime and push | signable without the CA if a separate key signs | no |

**Recommendation: (a).** It adds no new kind of secret (the fewest-secrets
rule behind D313 Q6), reuses the leaves every node already renews, and is
what the relay already verifies. The new parts:

1. **A relay leaf that cannot pass as the server.** A node relay needs a
   server-purpose leaf, and so does the server's leg-B listener (#559). A
   relay leaf must carry `urn:infraternal:relay:<uuid>`; relay clients
   require it, and leg B refuses any leaf that carries it. Otherwise a relay
   node's leaf, issued for an IP address, could answer a leg-B dial to the
   same address.
2. **Lifetime and rotation:** 7 days renewed at half-life over the relay
   node's existing link, the same rule as host leaves (D133), so nothing new
   to tune. The server's own relay gets a relay leaf too, never its leg-B
   leaf, so one stolen key never serves both roles.
3. **Revocation on live connections.** A TLS connection outlives the check
   made at its handshake. The relay must re-run `Admission` for every
   connected host on each revocation or config change, and close a
   connection when its leaf's `notAfter` passes. This is not built.
4. **Defence in depth, already true:** a link forms only when both hosts ask
   for each other, and a healthy peer drops a removed node's key at once
   (D166), so a removed node that is still admitted somewhere reaches nobody.
   What it can still do until expiry is hold a connection slot.

Open with (a): after more than 7 days with the server down, node relays stop
admitting nodes whose leaves expired, while direct paths keep working on the
last rules (D166). **Recommendation:** accept it and say so in the docs; a
grace past `notAfter` would make a copied key usable longer.

Not answered here: iPhones join as host mode `device` with a Secure Enclave
P-256 key (#580, 2026-11-24/25 decisions). Their leaf's SAN and the relay's
admission of it are settled with the iOS enrolment slice; rustls/webpki
already verify P-256.

## Q4. Who runs relays in the first production slice?

| Option | Covers | Work |
|---|---|---|
| **(a) Slice 1: only the server's relay; slice 2: node relays (checkbox, D132) and D285's automatic datacenter relays (recommended)** | every hard-NAT pair, through the server's location | relay listener in the server process (or its embedded infraternal agent), admission from the database |
| (b) Server and node relays at once | India ↔ India pairs avoid Germany (D313 Q3: about 396 ms via Germany) | plus relay leaves (Q3), the checkbox UI (needs mockup rounds, D162), capacity and reachability checks (D285) |

**Recommendation: (a).** The server already holds a server-purpose leaf and
the revoked set, is reachable from everywhere by construction, and D163 says
it always relays. Node relays need the relay leaf, a mockup round and D285's
measured detection rule; they are worth their own slice. The owner's own
deployment today is one server in Germany, so slice 1 changes nothing for
pairs that already go direct and gives every other pair a path.

Sub-question: run the server's relay inside the server process or inside the
server machine's own infraternal agent (the machine also joins as a node,
D201)? **Recommendation:** inside the server process for slice 1, on its own
UDP port, because admission there is a direct read of the revoked set; move
it only if the D201 component split needs `relay up` on the server machine.
Port: D391 says 443 only for now; the server's TCP 443 is HTTPS (behind a
TLS-terminating reverse proxy on prod, #559), so the QUIC relay would take
UDP 443 on the server. infraternal binds nothing on UDP 443 today; whether
anything else on prod does needs a read-only check before slice 1, and the
app-owned firewall opens what the app binds (D386).

## Q5. Which relays does a node stay connected to?

Today `RelayPaths` keeps a QUIC connection to every listed relay, with a 1 s
keep-alive and a 3 s idle timeout, so a lost relay is noticed within 3 s.
The cost scales with nodes × relays:

| Quantity | Number | Source |
|---|---|---|
| Memory per idle QUIC connection | ~44 KB | D176 (leg B on quinn) |
| Relay side, every node connected | 44 MB at 1,000 nodes, 180 MB at 4,096, plus ≤ 8 KiB receive queue each (32 MiB at 4,096) and the 64 MiB forwarding budget | `contracts/mesh-relay.md` |
| Node side | ~44 KB per relay connection; ~270 B and one loopback socket per relayed peer | D176, contract |
| Idle keep-alive | 1 packet/s each way per node per relay; 1,000 nodes → 1,000 packets/s each way at each relay | `tls.rs` (`KEEP_ALIVE`) |
| Idle context switches, 2 relays | ~920 per 60 s per node, dominated by the keep-alive | J1105 (`research/relay-rtt/REPORT.md`) |

| Option | Idle cost per node | Failover | Fit for the iPhone |
|---|---|---|---|
| (a) Connect to every relay, 1 s keep-alive (today) | R wakeups/s | instant: links already exist | poor: R wakeups/s in the network extension drains the battery and breaks D81 |
| **(b) One warm home relay (lowest QUIC RTT, moved by the D313 Q5 rule) on a slow keep-alive while nothing is relayed; the others only while a pair is relayed or watched (recommended)** | 1 wakeup per keep-alive interval | home relay instant; standby relays connect in ~1 RTT when a pair needs them, as `RelayPaths` already reconnects | good |
| (c) No connection until a pair needs a relay | 0 | +1 relay handshake (~1–2 RTT) before the first relayed packet | best, but the first packet of every hard-NAT pair waits |

**Recommendation: (b).** It is how DERP's home region behaves, keeps idle
cost at one connection, and the standby rule J1194 added already avoids
links that cannot win. What needs measuring before the numbers are fixed:
whether quinn lets a connection change its keep-alive without reconnecting
(otherwise two configurations, a reconnect when a pair starts relaying), and
the battery cost of a 25 s versus 1 s keep-alive on a real iPhone (the mesh
keepalive is 25 s, D392). The home relay is also where D313 Q2 puts
rendezvous signalling, so the choice is needed anyway.

## Q6. When does a pair go through a relay?

Today: only `direct_failed` (no WireGuard handshake after the endpoint was
installed; one attempt is 5 s), so a hard-NAT pair is dark for at least 5 s
and then relayed.

| Option | First packet on a hard-NAT pair | Relay bytes spent | Consistency |
|---|---|---|---|
| (a) Direct first, relay after the 5 s grace (today) | ≥ 5 s dark | only for pairs that fail | — |
| (b) Relay and direct in parallel for every new pair, move to direct when its probes win | 1 relay RTT | the first seconds of every pair (the rule needs 5 samples over ≥ 3 s to move) | DERP-like |
| **(c) Predicted hard pairs relay at once; others direct first with the grace as a backstop (recommended)** | 1 relay RTT for predicted pairs | only for pairs that need it | D285: "pairs where both sides are behind hard NAT are relayed from day one" |

**Recommendation: (c).** The prediction is cheap with what D391 is building:
a node whose mapped port differs between two observers (the server and its
home relay, both answering authenticated address probes) has a
port-changing NAT. Two such sides, or one plus a port-restricted filter,
start relayed. Each relayed pair records the reason (D285), which also
feeds D313 Q4's two-week counter gate. The 5 s backstop stays for everything
the prediction misses.

## Q7. Failover and hysteresis with the direct probes

The rule is decided (D313 Q5) and implemented for relay ↔ relay and, since
J1194, direct ↔ relay. What production adds, each with a recommendation:

1. **Direct ↔ relay moves use the probes as built.** J1194 measured 9–13 s
   per transition, 0 wrong-choice samples after settling, 0 idle probes.
   **Keep the 5 s steady interval**; 2 s would save ~3 s per transition for
   one more 12-byte ping every 2 s per busy pair. Revisit with production
   counters.
2. **The ~1.3 s setup detour** (J1105 Q2): until measured, the lowest list
   index carries the pair, so both ends agree. With Q5's home relay, make
   the default the *lower host id's home relay*: both ends still agree, and
   it is usually near at least one of them. **Recommended**, small change.
3. **Losing the active relay** is not make-before-break (contract): datagrams
   in flight are lost, and the pair moves at once to the best remaining link.
   With (b) in Q5 a standby link may not exist yet. **Recommendation:**
   accept ~1 RTT of reconnect for that rare case rather than keep every
   relay warm.
4. **A recovering relay or direct path does not take the pair back by
   itself**; it wins only under the rule (already true). Keep.
5. **What the person sees:** the dashed arrow names the relay (D164); `mesh
   peers` and the UI show "via <relay>, because <reason>" (D285).

## Q8. Privacy: what a relay sees

A relay never holds a mesh key and forwards WireGuard ciphertext unchanged.
It does see, for every pair it carries:

- both host ids (from the verified leaves and the link requests), so it knows
  who talks to whom;
- both public addresses and ports;
- packet sizes, timing and volume.

| Option | Hides | Cost |
|---|---|---|
| **(a) Accept the metadata, limit who can be a relay, keep nothing (recommended)** | content (WireGuard) | relays keep counters only, never per-pair logs; relays are the owner's machines (D285, checkbox), and the UI lists which relays carry which pairs |
| (b) Blinded link requests (pair tokens from a coordinator-issued pair secret instead of host ids) | the host ids in requests | the relay still sees which two connections it joins, so the pairing leaks anyway; more protocol |
| (c) Pad and shape relayed traffic | sizes and timing | bandwidth and latency; out of proportion for a self-hosted mesh |

**Recommendation: (a)**, plus J1105's open item: **authenticate link probes
per pair** (an exporter-derived MAC) before relays outside the owner's direct
control exist (Enterprise deployments with many people, D313 Q3), because a
relay can see a probe token and answer for the peer to look faster than it
is. It cannot look faster than its own leg, which the node measures itself,
so this is hardening, not a hole in slice 1.

## Q9. Resource bounds

The relay service is bounded already (`contracts/mesh-relay.md`): 4,096
hosts, 1,024 requests per host, 256 handshakes (8 per source IP), 5 s
handshake deadline, forwarding budgets of 256 KiB per pair, 4 MiB per host,
64 MiB total. What the manager adds:

| Bound | Recommendation | Why |
|---|---|---|
| Relays a node connects to at once | home + at most 3 standby | with Q5 (b); the list itself can be longer |
| Relayed peers per node | follow the peer limit (1,000, tested 4,096) | one loopback socket and one task per relayed peer: 4,096 file descriptors on a busy node is within default limits only if raised; measure |
| Bandwidth a node relay gives others | a per-relay cap the owner sets in the checkbox's details, off for the server relay; D285's capacity rule decides automatic relays | home connections may be metered (D285) |
| Relay-side CPU | measure in slice 1 on the perf VM: Gbit/s and CPU per Gbit through one relay, 1 and 8 flows, India ↔ Germany profile | D167: every round measures relayed throughput and added latency |
| Idle | zero probe traffic while idle (already true); keep-alive per Q5 | D81 |

## Q10. Data path and platforms

`RelayPaths` hands relayed ciphertext between the engine and the relay
through a loopback UDP socket per peer (seam C, D313 Q1). That was chosen
when Linux ran kernel WireGuard; Linux now runs GotaTun in-process (D163
amendment), so the packet could go from the engine to the QUIC connection
without the loopback hop.

| Option | Cost | Work |
|---|---|---|
| **(a) Ship the loopback shim as built; measure its per-packet cost against an in-process hand-off on the perf VM (recommended)** | one extra loopback send and receive per packet on relayed pairs only | none now |
| (b) Hand relayed packets to the relay connection inside GotaTun's socket factory | saves the loopback hop | a GotaTun fork change (kept upstreamable, #260 rule), so its own measured question |

**Recommendation: (a)** now; bring (b) back only if the hop costs more than
the relay leg itself, which D313 Q1 expected it would not.

Platforms: `relay_path` and `seam` are `target_os = "linux"` only. The Mac
(mba) is part of the NetBird replacement (#580), and a Mac on hotel or
office Wi-Fi is a typical relayed node. `relay_path` itself uses the seam
only for relay address observation, which D391's server-published candidates
replace on GotaTun nodes. **Recommendation:** make `relay_path` build on
macOS in slice 1, without the seam; iOS follows with the client core
(`docs/design/ios-client-grill.md`), where Q5's single warm connection is
what keeps the network extension idle.

---

## Decisions for the owner

| # | Question | Recommendation |
|---|---|---|
| Q1 | First production relay transport | Ship the manager with the built QUIC relay first, TLS/WebSocket 443 next slice (changes D391's order) |
| Q2 | Where nodes get the relay list | Pushed by the server in each node's mesh configuration, persisted on the node; `--relay` for tests only |
| Q3 | Relay credentials | Keep deployment-CA certificates (no shared secret); add a relay leaf with a relay URI that leg B refuses; 7 days, renewed at half-life; re-check live connections on revocation and expiry; accept that node relays stop admitting after 7 days of server outage |
| Q4 | Who runs relays first | Only the server's relay in slice 1 (in the server process, UDP 443); node relays and automatic datacenter relays in slice 2 |
| Q5 | Which relays a node stays connected to | One warm home relay on a slow keep-alive; standby relays only while a pair needs them |
| Q6 | When a pair is relayed | Predicted hard-NAT pairs at once (mapping differs between two observers); others direct first with the 5 s backstop |
| Q7 | Failover details | Keep the rule and the 5 s steady interval; setup default = the lower host id's home relay; accept ~1 RTT on losing the only link |
| Q8 | Privacy | Accept metadata visibility, counters only, owner-controlled relays; per-pair authenticated probes before relays outside the owner's control |
| Q9 | Resource bounds | Home + at most 3 standby connections; per-relay bandwidth cap for node relays; measure relay CPU and fd use in slice 1 |
| Q10 | Data path and platforms | Keep the loopback shim and measure it; build `relay_path` for macOS without the seam in slice 1 |

### Measurements still owed (cheap, in slice 1)

- Relay throughput, added latency and CPU per Gbit through the server relay
  (perf VM, 1 and 8 flows, the India ↔ Germany profile), D167.
- Loopback shim cost per packet against direct GotaTun on the same pair.
- Idle cost of one warm relay connection at 1 s and 25 s keep-alive, Linux
  and macOS; on an iPhone when the extension exists.
- J536b's matrix rerun with the relay on: the five unreachable profiles must
  connect, and each relayed pair must report its reason.
