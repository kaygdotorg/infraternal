<!-- Functional proof, performance measurements and unwaived limits for mesh transport slice 2, #129. -->
# Mesh transport slice 2 [215,227,228], #129

> Raw screenshots, logs and receipts referenced by this report were removed under D262. The
> recorded results remain; new outputs belong in job scratch and should be attached to the
> relevant issue with the `issue-attach` helper.

The real kernel/PTY proofs pass. Performance acceptance is **not complete**:
the measured cut-to-fallback time misses D41 and PROCESS §6, and the mesh echo
p99 misses the local D41 reference. No threshold or owner decision was changed.
The existing static size overrun also remains. Production testing on monitor01
and o1 belongs to the orchestrator; this job used no other host and deployed
nothing.

## Behavior and scope

The node plugin proposes only an applied server mesh address. The transport
supervisor retains a live connection while a candidate proves the enrolled
server name, pinned mutual TLS identity and exact nonce Pong before Hello.
It preserves the native proof stream and decoder, including coalesced TCP
frames and their stream IDs. Failed probes leave the live session running.
The seven-day certificate and server enrollment ledger remain authoritative.

The mesh coordinator owns the server's additional authenticated listener
lease. Component shutdown cancels that listener and clears the proposal;
the node moves to the proven enrolled fallback. Retained intent also permits
a restart over the mesh while the enrolled fallback port is unavailable.
Status exposes observed transport, endpoint and a fixed public reason.
Kernel port-zero allocation advertises the actual bound UDP port, excludes
51820 and gives every configured peer a 25-second persistent keepalive.
No new library or engine was selected.

Work was split into contract, port policy, plugin API, retained input,
capability metadata, pre-Hello admission, freshness, bounded replay,
listener lifecycle, coordination, applied proposal, node bridge, status,
decoder, supervisor, test feature, greeting regression, kernel proof and
watcher benchmark commits. The benchmark commit is `e7496405`; the kernel
fixture commit is `2e2e017d`. All were pushed individually. The author's
[review checklist](mesh-agent-transport-review.md) records the invariants.

## Real kernel proof

The optimized server fixture runs in private network **and mount** namespaces
with real root, kernel WireGuard, nftables, mutually authenticated transports,
the production remote supervisor and one surviving detached PTY. The shipping
static binary provides the embedded infraternal daemon and PTY shim; the node
test process calls the production remote supervisor with credentials inherited
through stdin. Private identity never enters files or argv. A public fixture
login prevents reading the real root login configuration. Runtime node state
is removed on both success and failure.

Both runs have **two live nodes, one live PTY, 1,000 public inventory members
and 999 configured kernel peers on each side**. This is not 1,000 live nodes
or 200 live PTYs. Both sides use default-drop stateful input firewalls; only
the existing server port 7443 is granted. There are **zero WireGuard port
grants**. Actual dynamically allocated ports, encrypted counters, firewall listings and
test transcripts were recorded in receipts removed under D262. The baseline
firewall inputs remain in `mesh-agent-transport/`.
Assertions check that neither port is zero or 51820, every peer has keepalive,
and encrypted traffic counters increase in both directions.

The same open terminal attachment survives preference, a packet-drop cut,
fallback, recovery, abrupt node connection stop, restart with underlay 7443
blocked, and component shutdown. Continuous numbered input is checked against
exact output, not merely terminal liveness or approximate snapshots.

| Optimized profile | Zero delay | 300 ms RTT |
| --- | ---: | ---: |
| Expected / received bytes | 4,437 / 4,437 | 23,736 / 23,736 |
| Enable to observed mesh path | 1.651 s | 10.514 s |
| Observed working mesh to observed move | 0.916 s | 1.650 s |
| Packet cut to observed fallback | **2.078 s** | **4.864 s** |
| Retained mesh restart | 0.518 s | 2.251 s |
| Test duration | 7.23 s | 71.41 s |
| End load averages | 20.53 / 22.79 / 26.57 | 30.32 / 24.94 / 27.02 |

The delayed profile adds 150 ms ±15 ms in each direction with kernel netem;
it adds no random packet loss. The cut drops WireGuard packets in private
firewall chains without changing the interface or routes. An earlier debug
fixture used interface down/up: a separate kernel experiment showed one peer
route became zero, preventing recovery. That fixture was corrected without
rewriting slice-1 route management. This is not proof that slice 1 repairs an
administrative interface reset.

Times end when the fixture observes node status over an authenticated RPC;
they include status RPC delay. Working-path counters are sampled with a
configured 200 ms interval **plus RPC time**, so the second move figure is
an observed interval, not a precise timestamp of the first successful packet.

PTY echo confirmation uses 31 sequential samples per phase. It is not browser
glyph or input-to-photon timing:

| Profile / path | p50 | p99 |
| --- | ---: | ---: |
| Zero delay / direct | 0.501 ms | 2.081 ms |
| Zero delay / mesh | 0.903 ms | **15.255 ms** |
| Zero delay / fallback | 0.437 ms | 5.290 ms |
| 300 ms RTT / direct | 308.702 ms | 351.067 ms |
| 300 ms RTT / mesh | 316.097 ms | 373.321 ms |
| 300 ms RTT / fallback | 317.231 ms | 342.241 ms |

D41 requires <300 ms reconnect at zero network overhead; PROCESS §6 uses
900 ms at 300 ms RTT. Both measured packet-cut results fail. The guard uses
2 s + 3 RTT, capped RTT 5 s, after an earlier healthy 1,000-connection cohort
observed 1.184 s authenticated silence at load 58.14. It avoids that false
fallback but cannot meet the reconnect budget as implemented. The transport
idle timeout stays 60 s; the authenticated guard bounds loss independently.
These trade-offs are reported for review, not accepted as a budget waiver.

Historical zero-delay and delayed JSON/transcript receipts, plus observed firewall
outputs, were removed under D262. The retained baseline firewall inputs are
`mesh-agent-transport/server-firewall.nft` and
`mesh-agent-transport/node-firewall.nft`.

## Transport cost at 1,000 connections

Each optimized run has 1,000 real mutually authenticated QUIC connection pairs,
1,000 client endpoints and eight concurrent joins. The guarded run additionally
has 1,000 individual freshness futures using the production deadline. Every
connection and watcher remains live. Each sampling window exceeds 16 seconds
so the 15-second baseline actually sends. Bulk counter sampling adds diagnostic
work to all runs; resident growth includes both sides of each pair and setup.

| Configuration | Window | CPU cores | RSS increase | Encrypted UDP payload/s |
| --- | ---: | ---: | ---: | ---: |
| 100 ms, 1,000 watchers | 18.542 s | 0.8268 | 220,753,920 B | 314,828 B |
| 100 ms, no watchers | 17.686 s | 0.6955 | 217,104,384 B | 308,697 B |
| Existing 15 s, no watchers | 17.114 s | 0.0321 | 113,811,456 B | 3,576 B |

CPU = process ticks / 100 Hz / elapsed seconds. The guarded run ends at load
44.18 / 30.45 / 28.80, the equal-interval run at 41.14 / 30.66 / 28.90 and the
15-second run at 38.80 / 30.81 / 28.99. The guarded total costs about 25.7 times
baseline CPU and 88 times baseline payload rate. Separate runs under changing
host load do not isolate allocator ownership or a causal watcher RSS delta.
The absolute cost and all three baselines are retained, rather than reporting
only the small added watcher state.

Freshness state is **208 B/path ×1,000 = 208,000 B**; task allocation is included
only in total resident growth. Guarded incremental pair RSS averages
**220,754 B/pair ×1,000 ≈220.8 MB**. This is not per-daemon RSS or evidence of
D41's <15 MB idle daemon budget. Mesh transport has periodic observations and
keepalives; it does not establish zero idle wakeups. Maximum observed
authenticated silence is 489,555 µs guarded versus 416,677 µs without watchers
at 100 ms, below the guarded deadline in this run. Raw UDP cannot refresh it.

Historical raw records and matching transcripts were removed under D262. The
retained `mesh-agent-transport/` directory contains the firewall input fixtures
and `regressions.md`.

## Retained input at 200 terminals

The optimized retained-input model exercises 200 independent terminal routes
and 6,200 writes using protocol framing through real Unix socket pairs. It is not
200 PTYs. On the resized host at load 29.28 / 31.02 / 29.37, write p50/p99 is
4,279 / 18,748 ns; peak retained capacity across all routes is 1,600 B and full acknowledgement
releases all retained bytes. State is **96 B/terminal ×200 =19,200 B**. The
hard pending-input cap is **4,194,304 B/terminal ×200 =838,860,800 B**; it is
allocated only for pending data and backpressure refuses further input at the
cap. Full-cap replay is split into legal protocol frames. The real PTY proof
above establishes actual byte retention across transport changes.

The historical 200-terminal model transcript was removed under D262.

## Gates, provenance and reproduction

Machine: infraternal-dev, 12 vCPUs and 64 GB after the resize; compiler pinned
to Rust 1.99. All reported optimized measurements ran sequentially under
`systemd-run --user --scope -p CPUWeight=10000` without concurrent job-owned
builds. Other jobs were active; this is not pinned performance acceptance.
The historical machine and binary identity receipts were removed under D262;
the reported sizes and load remain in this report. The x86 static binary is **20,705,152 B**, **+90,496 B** versus
recorded slice-1 `a5f744fb` (20,614,656 B). The unchanged static limit is
16,404,816 B. D205's known overrun is reported, not hidden. ARM static checks
are not reached when the fast gate stops on that x86 size failure.

Targeted fmt/clippy/tests passed before each implementation commit. The new
path tests cover preference, bad issuer, wrong nonce, retained mesh restart,
mesh down and TCP fallback. Real TLS decoder and capability tests failed
before their fixes. The server listener tests cover leased binds, wildcard
reuse, retirement and authenticated identity. The new proof uses the opt-in
`mesh-transport-proof` feature; defaults and dependencies are unchanged.
The no-default-feature CLI compile check passes. The separate TypeScript fast gate
passes its compiler, production bundle/transfer budget and all 36 protocol
tests. No UI code changed.

An initial milestone fast run failed two existing mesh state fixture tests
because the absolute `CARGO_TARGET_DIR` was omitted. Corrected all-feature
targeted execution passes 2/2 in 0.08 s. That failure is retained on #129 and
is not a host-load exception. Final branch-head fast output is posted verbatim
on #129 with the head SHA; performance misses above remain unwaived even when
all non-size rows pass.

Build the shipping binary with `cargo build --release --locked -p infraternal
--target x86_64-unknown-linux-musl`. Build the optimized fixture with
`cargo test --release --locked -p infraternal-server --features
mesh-transport-proof --lib --no-run --message-format=json`; use its reported
test executable. Run it in the CPUWeight scope with `sudo -n unshare -mn env
INFRATERNAL_MESH_PROOF=1 INFRATERNAL_TEST_RTT=300
INFRATERNAL_MESH_BINARY=<absolute shipping binary>` and filter
`mesh_transport_real_namespaces_preserve_the_terminal --ignored --nocapture
--test-threads=1`. Repeat with RTT zero for the undelayed profile.

For the timer experiment build `cargo test --release --locked -p
infraternal-agent --all-features --lib --no-run`, then run the reported
executable in the same scope with filter
`mesh_idle_timer_cost_at_one_thousand_connections --ignored --nocapture
--test-threads=1`. Use `INFRATERNAL_MESH_IDLE_SAMPLES=320`, idle 60000 ms and
the guarded/keepalive combinations in the table. Run the 200-terminal model
from the server executable with filter `input_retention_cost_at_200_terminals`.
Never overlap these measurements with builds from this job.

The final gate uses the job's absolute scratch `CARGO_TARGET_DIR`,
`RUST_TEST_THREADS=1`, the job-local askpass runner, and unique
`TRACER_TEST_PORT=4329`. Large traces and transient build targets remain in
the job's scratch directory until cleanup; only public evidence is committed.
