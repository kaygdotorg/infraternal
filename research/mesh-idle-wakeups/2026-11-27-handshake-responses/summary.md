# What wakes a silent mesh hub during rekey (#260, D81, J1302)

[J1255 removed the Linux UDP write-space wakeups](../2026-11-26-write-space/summary.md).
Its wave-free measurements still showed timerfd and Tokio wakes. J1280's later 420 s
silent cells averaged 5.40 wakeups/s at 1,000 peers and 22.18/s at 4,096, with
10 s peaks of 46.52/s and 182.83/s. Spreading the first quiet rekey increased
both means. This run traces the two waves on the subsequent dev fork pin.
[J1280 evidence](https://git.kayg.org/kayg/infraternal/issues/260#issuecomment-106305)

## Method

- Product base `21345e5cbc7d38c0080174f573f56349999a16a1` with GotaTun
  `f0bdc417f6b3e63fd7432295185455b20f9cbdb3`. Built the
  [J1253 hub test](../harness/) and the J1234 BoringTun peer simulator on
  compute01 with release optimization, debug info and frame pointers. The
  production Node runs in the harness process.
- One batch on infraternal-perf-01, a Ryzen 7 3700X VM running Linux
  `6.12.113+deb13-amd64` and perf `6.12.113`. `perf-run --root` set the
  CPU and memory limits. The hub used vCPUs 1–2 and passive peers used vCPU
  3. The veth joined two fixture network namespaces with no default route.
  After establishment, the peers answered initiations and generated no
  application traffic. Each measured cell held for 420 s.
- `sched_waking` recorded the waker's call chain on every CPU and filtered
  the wakee by the fixture's initial thread IDs and runtime thread name.
  `sched_switch` filtered either direction. The analysis follows
  fork and exit events to include replacement Tokio blocking-pool workers
  and discard candidates outside the hub. A matching switch-in gives waking-to-run
  time and the following switch-out gives CPU residency. If preempted,
  the next run keeps the previous source until the thread blocks again.
  The reported blocked intervals begin at a sleeping switch-out and end at
  the next wake. Intervals already in progress at capture start are censored.
  [Linux scheduler tracepoints](https://github.com/torvalds/linux/blob/v6.12/include/trace/events/sched.h)
- A separate per-hub-process `cpu-clock` recording sampled every 500 µs of
  CPU time. `/proc` process runtime, including exited threads, cross-checks
  the residency totals.
  Residency belongs to the scheduling episode and can include unrelated
  work after that wake. Samples provide call-stack evidence for the work
  executing within each episode. [Linux perf record](https://github.com/torvalds/linux/blob/v6.12/tools/perf/Documentation/perf-record.txt)
- The hub-veth capture retained only Ethernet, IPv4, UDP and the first four
  WireGuard bytes, which identify each message's type. Monotonic and realtime
  clock readings at both ends align the packet and scheduler timelines.
  The fixture's namespace counters track datagrams and socket drops
  independently.


## Results

The hub's own route replacements produced 70.1% of scheduler wakes at
1,000 peers and 61.0% at 4,096. UDP reception accounted for 17.5% and
27.2%. At 4,096 peers, route multicast produced 654 wakes in the t=162 s
bin, with zero WireGuard packets in that second. The first inbound
responses appeared at t=175 s at both scales. The earlier route burst
and the response burst are both visible at 1,000 peers, with 498 route
wakes at t=173 s and zero WireGuard packets.

| Peers | Observed duration (s) | Mean voluntary switches/s | Peak 10 s switches/s | Route-repair share of peak (switches/s) | Hub CPU (s) | Inbound responses |
|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 421.374 | 10.42 | 171.84 | 143.66 | 1.090 | 2,000 |
| 4,096 | 421.916 | 48.96 | 622.74 | 314.26 | 5.150 | 8,192 |

The source counts below are `sched_waking` events. Residency is time
scheduled after the attributed wake, and samples are the independent
`cpu-clock` observations inside those episodes.

| Waker | 1,000 wakes | 1,000 residency (ms) | 1,000 samples | 4,096 wakes | 4,096 residency (ms) | 4,096 samples |
|---|---:|---:|---:|---:|---:|---:|
| Own route replacements, netlink multicast | 3,076 | 40.71 | 64 | 12,605 | 170.66 | 246 |
| WireGuard UDP reception | 769 | 321.31 | 635 | 5,624 | 1,944.22 | 3,834 |
| Tokio unpark via eventfd | 192 | 22.57 | 44 | 1,570 | 28.84 | 36 |
| Tokio futex, including time-driver dispatch | 143 | 127.48 | 252 | 342 | 1,282.78 | 2,557 |
| Other hrtimer wake | 141 | 29.66 | 52 | 264 | 101.46 | 201 |
| Other futex | 32 | 144.15 | 274 | 140 | 692.01 | 1,328 |
| GotaTun deadline timerfd | 33 | 369.45 | 738 | 110 | 817.80 | 1,633 |
| Other socket receive | 5 | 0.33 | 1 | 3 | 0.21 | 0 |
| Startup of a new blocking-pool thread | 0 | 19.82 | 37 | 0 | 109.79 | 213 |
| UDP write space | 0 | 0 | 0 | 0 | 0 | 0 |
| **Total** | **4,391** | **1,075.48** | **2,097** | **20,658** | **5,147.77** | **10,048** |

The route-repair thread was the wakee for the route multicast events. It
spent 68.6/277.0 ms of kernel-accounted CPU in total at 1,000/4,096 peers,
including its 30 s inventory checks. Its route-multicast episodes slept a
mean 19.6/7.8 ms and then waited 15.5/14.3 µs for a CPU. At 4,096 peers
the largest on-CPU group followed UDP receipt, and 3,219 of those 3,834
samples reached the inbound packet task. The deadline timerfd woke only
33/110 times over the window, with X25519 appearing on CPU after those wakes.
A further 1,051 samples following Tokio futex wakes reached the endpoint
scan at 4,096. The residency table includes the receiving thread's work,
while the CPU cost of writing the routes accrues to the writer's own
scheduling episodes.

Every captured wake matched a later switch-in. Parsed residency tracked
process CPU to within 15 ms at 1,000 peers and 3 ms at 4,096. At both
scales, the capture matched all UDP counters and found only type-2
responses on ingress. There were zero UDP errors, zero UDP receive-buffer
drops, zero packet-capture losses and zero recorded perf losses. The
hold exited 0 in 890.965 s, with 9 of 537,625 aggregate jiffies stolen.
These are single traced cells on the current pin. J1280 used an earlier
pin and untraced cells, so the two jobs provide a historical comparison
with different instrumentation.


## Why the route listener wakes

The route-repair thread sleeps in `RouteMonitor::wait_for_deleted_peer_route`.
The measured waker is the hub's own blocking route writer. The IPv6 chain was
`PeerRouteWriter::replace → Socket::request → inet6_rtm_newroute → fib6_add
→ nlmsg_notify → netlink_broadcast_filtered → pollwake`. The IPv4 chain
also goes through route replacement and netlink multicast. The subscriber
wakes and reads each delivered message. Its route book treats an add or
replace on the mesh link as having no effect on the underlay, and only a
deletion can request peer-route repair. The notification has already done
the waking by then. [Route listener](../../../crates/plugins/mesh/src/wireguard.rs)

The code accounts for why this work bunches up around rekey. GotaTun
withdraws the confirmed address when the last session expires and learns it
again on an authenticated response. The node consumes that state for both
handshake reserve membership and live route MTUs. The fixture gives the
hub peers without coordinator-configured endpoints. With no confirmation,
the route updater uses its 1,200 B fallback. Once the endpoint is confirmed,
it derives a budget from the underlay again and replaces differing routes.
This is a code-path explanation checked against the packet and wake
timeline from one pin. The exact fallback and restored MTU sequence was
inferred from the route updater. [GotaTun expiry](https://git.kayg.org/kayg/gotatun-fork/src/commit/f0bdc417f6b3e63fd7432295185455b20f9cbdb3/gotatun/src/device/peer_state.rs#L255)
[Product route updater](../../../crates/plugins/mesh/src/node_peer_routes.rs)

## Follow-up

Prototype the wakeup reduction in the product route listener. Discard an
unambiguous add or replace notification for a mesh-owned host route before
it reaches the listener's receive queue. Keep peer deletions, other links'
route and policy changes, ambiguous datagrams and loss recovery on the
existing path. A namespace test should count wakeups while writing those
routes, verify a real mesh route deletion is still repaired, and exercise
an underlay change. Compare both silent-hub scales on the same pin. This
targets the measured wake and preserves the confirmed-endpoint withdrawal
used by the handshake reserve.

WireGuard's response processing still performs key agreement and sends the
initiator's empty transport packet for key confirmation when there is no
queued data. Any batching experiment on that path has to preserve delivery
and response latency. [WireGuard protocol](https://www.wireguard.com/protocol/)

## Evidence

The issue attachment includes per-thread counters, one-second packet and
scheduler timelines, recorder loss checks, raw 10 s driver rows, binary
hashes and the reproduction kit. The original fixed-TID attempt exposed
blocking-pool thread retirement. The completed batch followed those
threads over their full lifetimes. [J1302 evidence on #260](https://git.kayg.org/kayg/infraternal/issues/260#issuecomment-106727)
