# Separating peers before decryption under floods

**Job:** J1269 · **Issue:** #260 · **Decision:** D397 · **Decision owner:** kayg · **Status:** research and design

The receive path shares UDP socket space and crypto capacity between all WireGuard peers. J1249 showed that changing CoDel's signal rate cannot preserve TCP bulk service when the hub runs out of receive capacity. The owner kept uncapped CoDel on 2026-11-26. This grill asks whether to give peers fair access to receive work earlier, using the existing WireGuard wire format.

## 1. The problem

J1249 ran ten CUBIC upload peers and one probe-only peer against a one-vCPU `gotatun-cli` hub. ECN was disabled. Its 90-peer UDP fixture held the offered payload rate constant across modes. Values are three-window medians. [J1249 setup, cells and ranges](../../research/aqm-latch/2026-11-26/summary.md)

| 90 UDP peers | TCP with default AQM | TCP with AQM off | Effect of capping CoDel at 16 / 64 / 256 |
|---|---:|---:|---|
| 1.0 Gbit/s offered | 1.05 Gbit/s, p99 20 ms | 0.45 Gbit/s, p99 99 ms | TCP fell to 0.59 / 0.88 / 0.98 Gbit/s (−43% / −16% / −6%). UDP delivery rose from 19% to 64% / 35% / 24%. |
| 2.0 Gbit/s offered | 0.013 Gbit/s, p99 56 ms | 0.006 Gbit/s, p99 13.8 s | TCP was below 0.08 Gbit/s in every mode. Default also kept the probe-only peer's p99 at 57 ms, against 4.3 s with AQM off. |
| No added UDP | 2.71 Gbit/s, 0.369 CPU-s/Gbit, p99 11.7 ms | 2.91 Gbit/s, 0.343 CPU-s/Gbit, p99 11.0 ms | Default cost 7% goodput and 8% CPU/Gbit in this fixture. |

At 2.0 Gbit/s, the hub received about 2.13 Gbit/s of UDP flood traffic on its link. With AQM off or tightly capped, J1249 measured 0.9–1.5 million socket drops per 20 s. With default AQM, socket drops fell to about 62,000 and CoDel dropped 12.5% of TCP packets it judged. The counters suggest two places where TCP loses service. The socket can discard a packet before the engine gets a turn, and dropping it after decryption has already spent the crypto work. J1249 measured the combined behavior. A pre-decryption scheduler and an earlier socket-admission mechanism each need their own measurement. [J1249 counters and interpretation](../../research/aqm-latch/2026-11-26/summary.md)

## 2. What exists

| Stage | Where | Current behavior |
|---|---|---|
| UDP receive | GotaTun UDP socket and receive batch | Datagram buffers and receive timestamps are shared across peers on the default path. Datagram loss at the socket happens before userspace sees the batch. |
| Mesh handshake admission | `PeerAdmissionUdpReceiver` and `PeerAdmission` | Consumes direct-path probes and budgets the expensive check on initiations. It validates MAC1 and checks the recovered sender key against installed peers. Configured or confirmed endpoints have a bounded reserve for initiations. Transport data bypasses that check. |
| Receiver-index lookup | GotaTun `PacketLookup` | A device-wide table maps a locally allocated 32-bit index to a peer. Data, replies and cookies have receiver indices. An initiation carries the initiator's sender index and needs the handshake path. A matching index gets the peer handle before packet authentication. |
| Receive crypto and commit | GotaTun `PreparedIncomingRun`, `flush_incoming_run`, `complete_incoming_data` | Groups prepared packets by peer within a receive batch. It uses bounded in-flight work and ordered completion. Session validation, AEAD, replay and allowed inner sources govern delivery. Grouping within one batch leaves a heavy peer able to fill shared receive and crypto capacity across batches. |
| AQM and TUN write | GotaTun receive delivery, D397 and the mesh TUN adapter | Per-peer CoDel uses receive-to-delivery sojourn, with a 1 ms target and 10 ms interval. It marks eligible inner packets CE and drops selected packets that cannot be marked. Authenticated small frames have a bounded per-peer exception. |
| Post-decryption scheduling | J1268, in progress | The requested scope is bounded peer and inner-flow scheduling inside the engine. It can isolate traffic on the way to TUN after authentication and inner-header parsing. |

The receiver-index table and ordered crypto path are in the pinned fork at `0853f42`. The mesh wrapper already carries kernel timestamps through its receive batch. J1230/J1239 tried multiple receive lanes. Gains of 7–11% in round 1 came with higher CUBIC p99 and 20% greater forward receiver CPU/Gbit. In round 2, splitting batches increased TUN writes by 69%. The owner parked receive lanes on 2026-11-26. [GotaTun receive path at the mesh pin](https://github.com/kaygdotorg/gotatun/blob/0853f42bc28f09beeac547c26bbe37f07107be5c/gotatun/src/device/mod.rs) · [Mesh admission](../../crates/plugins/mesh/src/handshake_admission.rs) · [D397 integration](../../crates/plugins/mesh/src/gotatun_node.rs) · [Receive-lane results](../../research/gotatun-multiqueue/README.md#7-round-2-fixing-the-receive-lanes-j1239)

## 3. How others do it

- **WireGuard** routes data by receiver index and authenticates it with the session key. The rotating MAC2 cookie is a handshake defense that demonstrates reachability under load. It provides no proof about later data packets. Endpoint roaming relies on authenticated traffic. [Protocol and cryptography](https://www.wireguard.com/protocol/) · [Cryptokey routing and roaming](https://www.wireguard.com/#cryptokey-routing)
- **QUIC** uses connection IDs for demultiplexing across address changes and has a separate path validation exchange. Its anti-amplification limit applies to an unvalidated address. This is a precedent for independent routing and trust decisions. Its wire-level validation cannot be added transparently to WireGuard. [RFC 9000 §§5.1, 8 and 9](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1)
- **OpenVPN** documents a control-channel HMAC that rejects packets before TLS work. That is a protocol-supported early authentication layer. Equivalent data admission would require an authenticated envelope and keys at both ends of the WireGuard path. [OpenVPN TLS control-channel security](https://openvpn.net/as-docs/tls-control-channel/)
- **FQ-CoDel** uses deficit round robin over active queues, with a shared memory limit and delay control per queue. The useful precedent here is work-conserving scheduling under a global cap. For ciphertext, the visible peer hint is the scheduling key. Inner flow headers become available after decryption. [RFC 8290 §§3–4](https://www.rfc-editor.org/rfc/rfc8290.html#section-3)

## Q1. What identifies a candidate peer before decryption?

| Option | Behavior and cost |
|---|---|
| **(a) Reuse the receiver-index lookup and treat the source endpoint as a hint under pressure (recommended)** | The lookup already runs. Charge work to the current peer instance across overlapping session indices, keeping the index and generation on queued work. Compare a known source only when admission needs it. Authenticate before updating endpoints or committing the packet. |
| (b) Use endpoints as peer keys | Cheaper to locate upstream where only the socket tuple is visible. Shared NAT and relay paths can collapse peers into one bucket, and rebinding can split one peer across buckets. A configured candidate can be stale. |
| (c) Require newly authenticated framing before scheduling | Stronger classification if the frame and keys are available. Adds per-packet verification, MTU and rollout costs and a new compatibility boundary with ordinary WireGuard peers. |

**Recommendation: (a).** Place the decision at the existing data lookup, before per-peer lock waits, crypto reservation and AEAD. Validate the current peer instance and session again before commit. Drop unknown indices without allocating per-origin state. Keep cold joins, responses, cookies and direct-path probes on the existing control paths, with bounded service when data is continuously ready. Old and new live indices should share one peer budget during rekey, and removing or replacing a peer must retire its queued work. Preserve the ability of a legitimate packet from a new endpoint to authenticate. The extra source comparison and queue bookkeeping have no CPU/Gbit measurement yet.

## Q2. How should peers share crypto work?

| Option | Behavior and cost |
|---|---|
| **(a) Work-conserving deficit round robin over active peers, with a shared bounded buffer (recommended)** | Let a sole active peer borrow spare work. When several are backlogged, give each a bounded turn and retain peer-local FIFO order. Charge per datagram plus bytes so small packets still account for fixed parse and AEAD costs. Bound queued bytes and packets as well as in-flight crypto per peer and globally. Costs a queue insertion and scheduling decision on contended turns. |
| (b) Fixed per-peer packet/byte token buckets | Bounded and simple to reason about. A fixed rate can throttle a lone fast peer on an idle hub. Rate and burst need tuning across cores, packet sizes and 1,000–4,096 configured peers. An overfull shared socket still drops before the bucket runs. |
| (c) Increase the shared FIFO or worker pool | May help a short burst or increase aggregate capacity. Every busy peer still competes in arrival order and more buffering can increase sojourn. J1249 saw 11.3–11.7 MB queued with disabled or tightly capped AQM at high load. |

**Recommendation: (a).** Start with pooled descriptors and an active list. Keep an inline path when no competing peer is waiting and batch within each peer's turn. Drain a bounded UDP batch before returning to ready peers. A globally full pool must still make room for a newly active peer, for example by reclaiming queued work from a peer above its share. An illustrative 32-packet limit at 1,500 B would allocate 45.8 MiB at 1,000 peers or 187.5 MiB at 4,096 if provisioned per peer. A shared pool of 512 × 2 KiB instead costs 1 MiB of packet backing plus descriptors, retained receive backing, in-flight work and peer state. These are sizing examples. Measure actual allocations, charged GRO segment counts, peak and idle RSS, contiguous run lengths and wakeups before choosing limits. [D393 scale and D81 idle requirements](../../DECISIONS.md) · [RFC 8290 shared queue limits](https://www.rfc-editor.org/rfc/rfc8290.html#section-4.1)

Equal peer shares give ten continuously backlogged TCP peers roughly 10% of scheduled work against 90 equally backlogged UDP peers, assuming equal work per packet. This is a scheduling estimate. It is neither a goodput prediction nor a minimum under link, socket or parser saturation. A peer that uses many inner flows still gets one share. Many distinct enrolled peers can collectively use many shares. Per-account or traffic-class guarantees would need a separate owner decision and measurements.

## Q3. How much can unauthenticated traffic spend?

| Option | Behavior and cost |
|---|---|
| **(a) Bound unverified work and give an authenticated endpoint a provisional preference under pressure (recommended)** | An index/confirmed-endpoint match can get earlier service without acquiring a security privilege. A mismatch shares a small, bounded roaming allowance, with service reserved for it during overload. Apply a global cap to failed verification work and bound memory independently of source churn. Adds pressure-state bookkeeping and can delay legitimate migration during a flood. |
| (b) Spend the full peer budget on any index match | Preserves migration with minimal branching. Forged packets with a live index can exhaust the named peer's crypto turn. Index rotation and randomness do not make a visible 32-bit field authentic. |
| (c) Require the last authenticated endpoint | Keeps ordinary traffic on the fast path. A hard endpoint filter breaks roaming and NAT rebinding, and an endpoint can also be spoofed or shared. |

**Recommendation: (a).** A source address, endpoint match, index or packet counter grants neither trust nor authorization. Require successful AEAD and the existing replay checks before an endpoint update. Keep the existing allowed-inner-source check on delivery. Failed verification may spend bounded work but cannot refresh a reserve, create a new queue identity or earn the authenticated small-frame exception. Keep separate accounting for candidate classification, rejected AEAD/replay and authenticated delivery. Qualify the protection explicitly. An observer that can match a live index and the expected endpoint can still contend for that peer's tentative service. Cross-peer isolation remains the goal in that case. Keep bounded join and rekey service independent of the roaming allowance. Exercise NAT rebinding, shared endpoints, relay transitions, overlapping keys, peer removal, and invalid data carrying live or retired indices in isolated defensive tests. [WireGuard data and replay rules](https://www.wireguard.com/protocol/#nonce-reuse--replay-attacks) · [Existing endpoint-reserve limits](../../crates/plugins/mesh/src/handshake_admission.rs)

## Q4. Where should the first slice run?

| Option | Behavior and cost |
|---|---|
| **(a) Keep a single socket and schedule in GotaTun before crypto (recommended)** | Reuses receive batching, parser, index lifecycle and packet pool. Removes identified hot-peer work before AEAD. It cannot reclaim datagrams already dropped at the socket. |
| (b) Add kernel-level admission before socket enqueue | Can protect socket capacity if socket drops still dominate. Requires a bounded map synchronized with session and peer churn, including a separate control path, and platform-specific placement. Any trusted decision still belongs to the engine. |
| (c) Reopen receive lanes | May split work across cores and socket queues. J1230/J1239 measured p99 and CPU losses from splitting outer flows and receive batches. It also requires more queues to reason about during rekey and migration. |

**Recommendation: (a).** Measure where drops and work move first. Revisit (b) only if socket overflow or parsing remains the first loss point and TCP still starves after the userspace slice. Compare matched *received* offered load, socket drops, userspace queue loss, packets and bytes sent to crypto, valid delivery, and per-peer service. Report CPU saturation, driver loss and shared-socket overflow separately. [J1249 socket counters](../../research/aqm-latch/2026-11-26/summary.md#reading-the-numbers) · [J1239 receive-lane results](../../research/gotatun-multiqueue/README.md#7-round-2-fixing-the-receive-lanes-j1239)

## Q5. How does this compose with J1268 and D397?

| Option | Behavior and cost |
|---|---|
| **(a) Schedule ciphertext peers before crypto and authenticated peer/flow work at the TUN boundary (recommended)** | The first decision protects crypto and the second protects delivery. Preserve the receive stamp so D397 still accounts for time spent before decryption. Two holding points need a shared memory and latency budget. |
| (b) Use J1268 alone | Addresses bulk versus interactive traffic in an authenticated peer and at TUN. All packets still enter the shared receive and crypto path. |
| (c) Replace CoDel with upstream drops | Reduces work on discarded ciphertext. Ciphertext admission cannot inspect the inner ECT field or offer D397's mark-first feedback. J1249's count cap (a different mechanism) reduced TCP delivery at equal offered load. |

**Recommendation: (a).** Pass the current peer handle, generation and original receive stamp through ordered authenticated completion to J1268's enqueue boundary. Keep one replay/endpoint commit point. The post-decryption scheduler can use authenticated inner flow keys. Feed D397 once at the delivery decision, preserving the original receive stamp, and keep its small-frame allowance after authentication. Record arrival-to-crypto and completion-to-TUN delay separately so a moved queue remains visible. Before decryption, shed on budget exhaustion. Any outer-header CE marking proposal needs a separate RFC 6040 propagation and compatibility proof. Keep uncapped CoDel as decided. [D397](../../DECISIONS.md#397-gotatun-bounds-its-own-queue-marking-ecn-first-owner-2026-11-15-260-serves-the-2026-11-10-bufferbloat-goal) · [RFC 6040 §4](https://www.rfc-editor.org/rfc/rfc6040.html#section-4)

## Q6. What earns another slice?

| Option | Evidence required |
|---|---|
| **(a) Keep rule based on per-peer service and ordinary traffic (recommended)** | Compare baseline, J1268 alone, pre-decryption scheduling alone and both together. At equal offered load, report minimum peer goodput, probe p99 including unanswered samples, socket loss, goodput and CPU/Gbit. Measure 1 and 8 flows, no added UDP, and 10 and 90 UDP peers at 1.0 and 2.0 Gbit/s, plus a point beyond each tested hub's own capacity. |
| (b) Use aggregate throughput and p99 alone | Easy to run. J1249's off mode delivered 1.25 Gbit/s aggregate in the 90-peer 2.0 Gbit/s case while TCP got 0.006 Gbit/s. A useful aggregate can hide starvation. |

**Recommendation: (a).** Reuse J1268's ordinary traffic keep rule and the J1249 offered-load controls. Require better worst-peer service under receive overload, no ordinary traffic regression outside repeated-run spread, bounded recovery and memory at 1,000 and 4,096 peers, and D81's zero idle wakeups. Test both ECN modes, short and MTU-size datagrams, multiple bulk flows within one peer, and lower-rate probes from a separate peer. Retain order and replay guarantees through CPU concurrency and peer churn. Even an improved scheduler cannot reserve capacity on a saturated uplink. [Mesh keep rules](gotatun-architecture.md) · [J1249 repeatable fixture](../../research/aqm-latch/2026-11-26/summary.md#reproduce)

## Owner question list

1. Classify with the existing receiver index and an endpoint hint under pressure?
2. Allocate crypto with work-conserving, bounded per-peer fair dequeue?
3. Give confirmed endpoints provisional preference with a bounded roaming allowance and continued authentication?
4. Start inside the single-socket engine and use socket-loss evidence to decide whether kernel admission merits a spike?
5. Compose with J1268 after authenticated completion and retain D397's uncapped mark-first feedback?
6. Judge the slice on worst-peer service under overload alongside ordinary TCP, CPU/Gbit, correctness, memory and idle costs?
