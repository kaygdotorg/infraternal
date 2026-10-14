<!-- Author review checklist for mesh transport slice 2, #129. -->
# Author review

- Contract is additive: optional server role/path fields, legacy status remains readable, capability opt-in separates older infraternal agents.
- Foundational libraries unchanged: existing kernel WireGuard, Quinn/rustls, TCP/OpenSSL, SQLx and nft/iptables.
- Candidate identity uses the enrolled roots and TLS server name, current seven-day certificate, ordinary authority ledger and admitted fingerprint. No mesh address is authority. Exact nonce Pong precedes Hello and actor replacement.
- Losing/cancelled candidates own and retire endpoints/drivers; mesh coordinator owns additional listener leases. Component down clears proposal and proves fallback before retiring a live mesh session.
- Existing shim IDs, writer sequence and durable output offsets survive transport replacement; bounded retained input replays suffixes in legal frame sizes. The attachment sender waits for authoritative Ack credit at 4 MiB; a full writer leaves sibling senders and the shared actor runnable. Internal invalid-command refusal remains attachment-scoped.
- Retained TCP receive preserves coalesced stream IDs; native proof reuses its existing stream/decoder. Regression tests failed before decoder and advertisement fixes.
- Port allocation uses kernel port zero and validates the actual bound port, bounded retries and explicit 51820 refusal; public discovery receives the actual port. Every peer receives 25-second keepalive.
- Freshness uses authenticated, deduplicated QUIC frame counters; raw UDP cannot reset it. Watchers cancel with sessions. New fields reuse existing bounded protocol/JSON and netlink decoders and their fuzz targets; no new wire parser or foundational engine.
- Root proof refuses host network/mount namespaces, supplies a public fixture login in a private mount namespace, transfers private identity only by inherited zeroizing pipe and cleans node state on failure. Translated-address review checks cover both declared firewall backends; final input/forward checks run before conntrack acceptance.
- Measurements distinguish 2 live nodes/1 PTY/1000 inventory from 1000 mutually authenticated transport pairs and 200 retained-input states. Historical build-host measurements are diagnostics only. New acceptance measurements run on the named perf VM under the shared benchmark lock, with source/artifact hashes and load recorded. No deployment.
- Performance acceptance remains subject to measured D41/PROCESS budgets and the RTT + 250 ms recovery / local direct + 2 ms echo targets. Reports must distinguish real PTYs, retained-input states, public inventory and authenticated transport pairs. Final acceptance and the fast gate are recorded on #129; this checklist alone does not assert that they pass.

## Connection-preserving switching (#201, D263)

- QUIC switches below the authenticated connection. Trusted peer tuple leases
  map the admitted enrolled and mesh addresses into the same connection-ID
  space; every datagram still requires the connection packet keys. The mesh
  address adds no authority. TCP requires a separately proved replacement when
  an enrolled QUIC connection was unavailable.
- No terminal attachment or plaintext input is replayed during a QUIC path
  change. The bounded recent ciphertext queue can resend encrypted packets;
  QUIC packet numbers discard duplicates before stream delivery. Writer IDs,
  input sequence, output offsets and the same terminal attachment are checked.
- Backup copying requires the admitted peer's advertised capability. One owned
  endpoint receive clock schedules copies and retires with its leases; no
  detached worker survives component down. Each recent queue is bounded to
  64 KiB and 64 datagrams. Two ends at 1000 transports allow 128 MiB of recent
  payload, plus routing metadata and the existing engine state.
- Ordinary mesh-to-enrolled copies retain individual 20 ms deadlines; an older
  entry's clock cannot send younger entries early. The shared endpoint budget
  is 32 send calls per receive poll, including segmented calls. Due entries
  remain pending across budget exhaustion and socket backpressure. Completed
  enrolled returns consume their originals once; capability withdrawal cancels
  negotiated copies without cancelling pending legacy enrolled recovery.
- The proposed additive bit 6 dual reply on #201 keeps enrolled primary replies
  immediate and permits the same ciphertext on the admitted mesh alternative,
  eligible immediately. It shares the existing history, clock and send budget;
  alternative admission cannot displace pending enrolled returns. Duplicate
  hints never promote the primary route. Unknown coordinates stay dormant,
  capability withdrawal cancels alternatives, and component removal or lease
  retirement prevents pending work from selecting a replacement socket. Alternative replies add no
  connection, writer, stream or admission authority. Implementation and
  acceptance of this clarification remain pending.
- A candidate owns fresh acknowledgement probes until its bounded proof ends.
  Idle mesh detection requires both a physical mesh reply and fresh authenticated
  counters. Enrolled copies alone cannot prove a live mesh. Simultaneous
  component removal is read after the timeout so disabled proposals stay retired.
- Cancellation tests use a file/WAL namespace pool matching production. An
  in-memory pool can lose its schema when SQLx retires its final checked-out
  connection; a failed namespace fixture alone does not prove a production
  storage defect. The cancellation-safe immediate transaction remains covered.
- Real SSH acceptance records natural bootstrap Done and exact kernel handshake
  order without a pre-canary mesh wait. Unrestricted route hints are diagnostics,
  never packet provenance. The unheld natural-join profile timestamps the first
  authenticated post-success fenced Output and the complete fresh marker on
  the same terminal attachment. Start, bootstrap success and kernel handshake
  to each witness are upper bounds including readiness, terminal setup, the
  initial echo, counter queries, firewall work and marker input/echo. They do
  not identify the earliest mesh byte of natural joining or the original SSH
  shell's handoff.
- The controlled standing profile intentionally holds the initial mesh join
  until an enrolled terminal exists, then measures its surviving attachment
  after release. It is separate from natural unheld acceptance. The separate
  fenced-canary profile blocks enrolled ingress before creating its readiness
  PTY; its first authenticated Output has causal mesh provenance and includes
  firewall overhead. A failed readiness operation remains a failed sample and
  cannot acquire a post-success witness. These profiles are reported separately,
  as are silent-cut status and byte delivery.
- The 1000-transport cost fixture proves paths before starting their watchdogs;
  startup, ramp, warmup and steady failures remain separate receipts. It measures
  physical adapter sends, including ciphertext copies. It does not claim 1000
  daemons or kernel mesh nodes. Fixed-order windows retain allocator state and
  counter overhead; failed watchdog cohorts are not accepted cost evidence.
- Release acceptance, both static size ceilings and the complete fast gate are
  recorded on #201. This checklist does not assert outstanding measurements pass.
  The proposed dual reply has no accepted healthy-1000-transport or 31-sample
  per-venue release result claimed here; those measurements, its regressions
  and the final gates remain required.
