# One mesh node as a hub for 10 to 4,096 peers (#260, J1234)

Measured on infraternal-perf-01 (backup01, AMD Ryzen 7 3700X VM, perf slice cpus 1-3, 6 GB; steal 0 in every
hold), 2026-11-25, through `perf-run --root` (machine-state snapshots before/after in `raw/pr/`, every hold quiet).
Base: origin/dev `de6f9dce6`, GotaTun pin `e87fef91`.

**The hub is the production `Node`** (GotaTun engine, real snapshot apply, real TUN, routes and nft rules, the real
handshake admission guard and packet filter), run as an ignored test (`harness/hub-bench.patch`, no product code
changed). The peers are simulated by `peersim`: real WireGuard peers (boringtun `Tunn`, one UDP socket and one key
each) in one process, inside a second network namespace. The two namespaces are joined by a veth pair, have no default
route, and nothing runs in the host namespace (network hygiene rule, 2026-11-22; `egress-guard` untouched).
CPU layout: hub on cpus 1,2; simulator and sink on cpu 3. Run counts: 2 runs (r2, r3) per cell in the headline table,
plus a first pass (r1) with an older driver; ranges are [min-max] over runs. Numbers are medians.

## Headline table (source mode `spread`: every peer in its own /24, the hub does not know its endpoint beforehand)

| Measure | N=10 | N=100 | N=1,000 | N=4,096 |
|---|---|---|---|---|
| RSS, node up, no peers | 12.0 MiB | 12.0 | 12.0 | 12.0 |
| RSS, peers configured (snapshot applied) | 13.8 MiB | 14.4 | 21.2 | 44.1 |
| **per peer, configured** | 189 KB (fixed cost dominates) | 25 KB | 9.7 KB | **8.2 KB** |
| RSS, all peers connected (sessions up) | 14.3 MiB | 15.2 | 23.4 | 50.2 |
| **per peer, connected** | 241 KB | 34 KB | 11.9 KB | **9.8 KB** |
| RSS after load, every peer has sent (flow cells) | 21.2 MiB | 26.7 | 83.3 | 273.8 |
| **per peer, after load** | 962 KB | 155 KB | **74.8 KB** | **67.0 KB** |
| RSS 15 s after load (pool partly released) | 15.8 MiB | 21.2 | 76.1 | 263.5 |
| open fds | 26 | 26 | 26 | 26 |
| idle wakeups/s, node up, nothing connected | 0.35 | 0.35 | 0.35 | 0.35 |
| idle wakeups/s, peers configured | 0.95 | 1.0 | 0.9 | 0.8 |
| idle wakeups/s, 30-70 s after sessions came up | 0.5 | 0.5 | 26 | **65** |
| idle wakeups/s, 55-75 s after the last traffic | 0.6 | 0.55 | 0.6 | **0.5** |
| idle wakeups/s, every peer sends a 25 s keepalive | 1.6 | 6.7 | 22.5 | 42.7 (0.28% CPU) |
| CPU per Gbit, 1 sender, ~2.1 Gbit/s (simulator-limited) | 0.76 cpu-s | 0.77 | 0.76 | 0.78 |
| CPU per Gbit, 1 sender, 976 Mbit/s | 0.98 | 0.98 | 0.99 | 1.02 |
| CPU per Gbit, 1 sender, 390 Mbit/s | 1.44 | 1.44 | 1.46 | 1.52 |
| CPU per Gbit, 100 senders, 976 Mbit/s | - | 1.04 (10% loss) | 1.00 | 1.02 |
| CPU per Gbit, 100 senders, 390 Mbit/s | - | 1.45 | 1.48 | 1.54 |
| handshake storm, cold, all peers at once | 4.5 ms | 34 ms | **6.0 s** | **28.2 s** |
| handshake storm, rekey of live sessions | 4.6 ms | 33 ms | 0.3 s | **17.5 s** (6.3 s in the first pass) |
| hub CPU for the whole cold storm | 0 | 0.03 s | 0.38 s | 1.86 s |
| snapshot apply, full list from empty | 36 ms | 41 | 126 | **501** |
| snapshot apply, one new peer joins | 38 | 45 | 129 | **412** |
| snapshot apply, one peer's policy changes | 49 | 50 | 116 | **424** |
| snapshot apply, identical list again | 1.4 | 5.8 | 59 | **214** |
| routes / nft ruleset lines | 12 / 51 | 102 / 186 | 1,002 / 1,536 | 4,098 / 6,180 |
| `Node::counters()` for all peers | 0.02 ms | 0.09 | 0.9 | 3.4 |

`pivot-r2-r3-spread.md` has every row (including loss, thread breakdowns and the packet counters), `results.csv` has all
runs of all holds, `raw/` has the logs, hub stderr (the `INFRATERNAL_CUTOFF_MEASURE` stage lines), the nft rulesets,
simulator and sink output.

Per peer cost of programming (full apply): 122 us at 4,096, 126 us at 1,000, 411 us at 100.
CPU per peer for a cold storm (admission + two Curve25519 operations): 0.45 ms at 4,096 (1.86 s / 4,096).

## Against the budgets in DECISIONS and J1212's grill

| Budget | What it says | Measured here |
|---|---|---|
| D81 idle CPU zero | no work while nothing happens | Holds when settled: 0.35-0.5 wakeups/s and 0.00-0.05% CPU at every N. **It does not hold for the first minutes after peers connect:** 24-26 wakeups/s at 1,000 and 54-70 at 4,096 (0.2-0.4% CPU), in the two engine threads, from 30 s after the sessions came up until about 55 s after the last traffic. With real 25 s keepalives: 22.5/s at 1,000, 42.7/s at 4,096 (0.28% CPU). The mechanism is not isolated (see fixes 6). |
| D176: 44 KB per idle QUIC connection | the relay manager's per-connection baseline | A hub peer with a session and no traffic costs **9.8 KB** (4.5 times less than a QUIC connection). Once a peer has sent traffic its packet-filter flow cell makes it **67-75 KB**, 1.5-1.7 times a QUIC connection. |
| D394: 52 MB per 1,000 peers with flows (52 KiB flow table each) | memory design number | 83.3 MiB total at 1,000 (71 MiB above the 12 MiB baseline, 74.8 KB per peer incl. node state), 273.8 MiB at 4,096 (67 KB per peer). The flow table is the bulk: 15 s after load 263.5 MiB are still held. |
| D331: 11-14 MiB stay per endpoint after load | pool release is a goal | After load at N=10: 21.2 MiB, 15 s later 15.8 MiB (5 MiB released); at 4,096 only 10 MiB of 274 MiB are released within 15 s. |
| D393: designed for 1,000, tested to 4,096 | mesh scale | Works at 4,096: 4,096 sessions, 4,098 routes, 6,180 nft lines, 26 fds. Two things scale badly: change cost (O(N) per change, below) and storm recovery (admission budget, below). |
| D169 (kernel engine): 66 ms for 1,000 peers, 10 us for a one-peer change | route/peer programming budget | GotaTun node: 126 ms for 1,000 peers (1.9 times), **116 ms for a one-peer change at 1,000 (about 12,000 times)** and 424 ms at 4,096. A one-peer change costs as much as the full apply. |
| J552: per-refresh cost 71 ms at 1,024, 288 ms at 4,096 | refresh cost | Identical-list re-apply: 59 ms at 1,000, 214 ms at 4,096 (same shape, 20% better). |
| relay-manager grill Q9: one loopback socket and task per relayed peer, 4,096 fds | resource bound to measure | The hub itself holds 26 fds at 4,096 peers (one UDP socket shared by all peers). Only relayed pairs would add a loopback socket each, and this run has none. |
| handshake admission (`handshake_admission.rs`) | NODE_BUDGET 1,000 key agreements/s, 500/s for unknown endpoints, 100/s (200 total) per source IP | See "first thing that breaks". |

## The same hub with other source addresses (one run each, `raw/out-r1-single`, `raw/out-r1-known`)

The handshake admission guard has per-source, per-network and per-node budgets, so how the peers reach the hub
decides the storm time. `spread` is the headline above; `single` puts every peer behind one source address (a whole
site behind one NAT); `known` gives the hub each peer's endpoint in the snapshot, as a coordinator's candidates would.

| | cold storm 1,000 | cold storm 4,096 | rekey storm 1,000 | rekey storm 4,096 | full apply 1,000 / 4,096 |
|---|---|---|---|---|---|
| `spread` (r2, r3) | 6.0 s | 28.2 s | 0.33 s | 17.5 s | 126 / 501 ms |
| `single` (one address, 200/s per source) | **18.0 s** | **43.5 s** | 6.0 s | 22.9 s | 135 / 495 ms |
| `known` (endpoints configured) | **0.34 s** | **1.56 s** | 0.33 s | 17.5 s | 219 / 865 ms |

Reading it: with endpoints configured the hub dials the peers itself at apply time (hub-initiated handshakes are not
subject to the admission budget), so the cold storm is 18 times faster than when it waits for peers to dial in. A rekey
storm in which the peers initiate is admission-limited either way (17.5 s at 4,096 in both modes). Configured endpoints
also cost more to apply (865 ms at 4,096 against 501) and, while the peers are not yet answering, the hub wakes 61/s (1,000)
and 305/s (4,096) in the 20 s after the apply (idle window "configured", `known` rows) to retry them. How long that goes on
for peers that stay offline (the engine's 25 s keepalive timer would re-dial them) was not measured and is the first thing to
measure next for D81. The 100-sender steps in `known` lose 5-10% at 976 Mbit/s offered, against 0-0.01% in `spread`.

## What breaks first, and why

Nothing on the data path breaks as the peer count grows. CPU per Gbit is the same at 10 and at 4,096 peers (1.44 vs
1.52 cpu-s/Gbit at 390 Mbit/s, 0.98 vs 1.02 at 976 Mbit/s, 0.76 vs 0.78 at the simulator's ceiling), and 100 concurrent
senders cost the same as one (1.45-1.54 at 390 Mbit/s). The two hub CPUs reach about 2.1 Gbit/s with one sender; that
number is limited by the single-CPU simulator, not by the hub, so it is a floor.

What breaks, in the order a growing mesh meets it:

1. **Handshake storm recovery (admission budget), from about 1,000 peers.** A cold storm of 1,000 peers takes 6.0 s
   (exactly two 5 s retry rounds: only 500 of 1,000 get through in the first second), 4,096 peers take 28.2 s, and a rekey
   storm of live sessions 6-18 s. The hub CPU needed is small (0.38 s at 1,000, 1.86 s at 4,096, about 0.45 ms per
   handshake, 70-80% of it Curve25519), so this is policy, not capacity: `UNKNOWN_SOURCE_BUDGET` (500/s) and
   `NODE_BUDGET` (1,000/s) cap recovery at 4,096 peers to at least 4-8 s, and peers that retry on WireGuard's 5 s
   timer round that up to 10-28 s. When the peers share one source address (a site behind one NAT) the per-source budget (200/s) is the cap
   instead: 18.0 s for 1,000 peers and 43.5 s for 4,096 (table below). The guard drops silently, so peers cannot tell "busy" from "lost".
2. **Per-change programming cost, from about 1,000 peers.** A one-peer change re-programs every peer: 116-130 ms at 1,000,
   410-430 ms at 4,096, the same as a full apply, and even an identical snapshot costs 59 ms / 214 ms. At 4,096
   peers a coordinator that pushes one change per second keeps one core 40% busy for nothing.
   Profile (`profile/prof-addone.txt`, `prof-apply.txt`, compute01, 4,096 peers): 44% of the one-peer change is inside
   `netlink::Socket::request` (route add/replace for every peer, v4 and v6; kernel `fib_table_insert`, `ip6_route_add`),
   9.4% self time in `Device::routes_with_mtu_overrides`, 7% in `RouteMonitor::wait_for_deleted_peer_route`; the full apply
   spends 29% in `wait_for_deleted_peer_route`, 9% in the nft commit (`nf_tables_commit`, set element adds), and 10-15% in
   Curve25519 (the per-peer static key agreement at configuration). The `CUTOFF_STAGE` timers in the node cover only
   about 12 ms of the 424 ms (validate 1.7, inventory 7.5, journal 3), so the cost is in the route and engine programming
   that they do not time.
3. **Memory after load, from about 1,000 peers.** 67-75 KB per peer that has talked (flow cell), so 83 MiB at 1,000 and 274
   MiB at 4,096, only 4% released 15 s after load.
4. **Overload latch in the engine's loss control (not peer-count dependent, found on the way).** Once 100 UDP senders offer
   more than the hub can take, the receive-side CoDel controller drops 27-93% of the packets (54%, 27%, 91% at N=100, 1,000, 4,096 in r2/r3; 93% in r1) and stays in that state: at
   4,096 peers 100 senders deliver 184-225 Mbit/s of 2.2 Gbit/s offered (hub CPU 13.6 s per 10 s, 6.7 cpu-s/Gbit), and later 10-sender steps
   at a modest 390 Mbit/s still lose 35% (N=10, 100) to 94% (N=1,000) in r2/r3, with the controller on. With `GOTATUN_AQM=off` the same step delivers
   1.74-1.84 Gbit/s with 0-2% loss and the 390 Mbit/s step loses nothing (`raw/out-aqmoff-spread`, N=1,000 and 4,096). The
   test traffic is UDP, which CoDel cannot mark, so TCP may behave differently; this needs a TCP measurement before anyone
   acts on it. It is listed because it is the largest single throughput loss seen in the whole run and it is an
   engine-wide latch, not a peer-count effect.

## Ranked fixes (not built)

1. **Make snapshot apply incremental** (route and nft reconcile diff against what is installed, touch only changed
   peers, no per-apply `routes_with_mtu_overrides` dump). Expected: one-peer change and identical re-apply from
   424 / 214 ms to a few ms at 4,096. Largest user-visible gain; no security trade-off. Evidence above.
2. **Decide the storm budget on purpose.** Either keep the budgets and document 6-28 s recovery at 1,000-4,096 peers, or
   let the reserved budget scale with the number of known endpoints (a known endpoint skips the per-source budget but
   shares a 500/s reserve) after the flood tests are rerun. Measured effect of knowing the endpoints: cold storm 28.2 s to
   1.56 s at 4,096 (hub-initiated), but peer-initiated rekey storms stay at 17.5 s. CPU is not the constraint: 1,000 handshakes/s is about 0.45 s
   of CPU per second. Peers' fixed 5 s retry makes the tail worse; jittered shorter first retries would cut it.
3. **Curve25519 backend.** 48% (cold storm) to 70% (rekey storm) of storm CPU is `curve25519_dalek` serial u64
   field arithmetic. A vectorised backend would roughly halve storm CPU. This is a dependency feature choice, so it is the
   owner's after measurement (foundational-choice rule), not a job's.
4. **Overload latch.** Reproduce with TCP, find why the dropping state persists after the offered load falls, and check
   the interaction with the uncapped UDP receive buffer (D331) that lets a deep backlog build. High value if it reproduces
   with TCP; the loss is 90% of goodput.
5. **Flow-cell memory.** 52-67 KB per talking peer: allocate small and grow, and free cells of idle flows within seconds
   (D331's pool release, applied to the filter). Would take 274 MiB at 4,096 toward the 50 MiB class.
6. **Settle time of the idle wakeups.** Find which per-peer timers (passive keepalive, session timers) produce the 24-70
   wakeups/s for the minutes after a connect or a load burst and make them zero or batch them. Needs a per-thread stack
   sample during that window; not isolated here.
7. **Replace the O(N) endpoint scan.** Every wake reads all peers' stats (`live_peer_endpoint_snapshot`, `Tunn::stats`,
   about 4.5% of cold-storm CPU, quadratic in a storm) and a node with peers wakes every 15 s; make it event-driven.

## Method, limits and honesty notes

- Peer counts 10 / 100 / 1,000 / 4,096; one hub process per count; each run: baseline idle, snapshot apply, idle, cold
  storm, idle windows (peers served by the simulator), 25 s keepalives, 1/10/100 concurrent senders at maximum rate, 976
  Mbit/s and 390 Mbit/s, every-peer-talks memory, idle after load, rekey storm, snapshot changes, counters.
- Simulator: one thread on cpu 3; its ceiling (about 2.1 Gbit/s, 6.5 CPU-s per 10 s) caps the "max" rows. 1 and 10 sender
  "max" rows at N <= 1,000 are simulator-limited, not hub-limited. Load is UDP (1,252-byte payload, the mesh MTU is 1,280
  because no endpoint is known at apply time), counted by a sink in the hub namespace.
- Handshakes in the storm rows retry every 5-6 s as WireGuard does. The cold-storm time therefore moves in steps of
  about 5 s; the repeat runs agree to within 0.4%.
- r1 (first pass, `raw/out-r1-spread`) used an older driver: only two rate points, one idle window per state, and the
  simulator did not serve its sockets during idle windows, which made the hub retry its own keepalives and handshakes.
  Its idle numbers after connect are therefore wrong (hub wakeups 62-248/s) and are not used. The aqmoff hold has the same
  idle flaw; only its throughput rows are used. r2 and r3 are the headline.
- The rekey storm at 4,096 took 6.3 s (r1) and 7.5 s (aqmoff) when the simulator was silent between steps and 17.5 s
  (r2, r3) when it kept answering; both are real, and which one a production hub sees depends on how many peers had an
  endpoint confirmed. Stated as 6-18 s.
- Profiles (`profile/`) are `perf record -g` of the hub on compute01 (a loaded build host, so shapes and proportions
  only, not time) with an unstripped build of the same code; the perf VM has no `perf`.
- No TCP and no netem: throughput and loss figures are UDP on a veth. They say how the node scales, not what a user's
  flow sees.

## Open questions for kayg

1. **Storm recovery policy.** Is 6 s (1,000 peers) to 28 s (4,096 peers) to recover after a hub restart or network
   blip acceptable? Recommendation: keep the budgets (they protect against floods), but make the reserved budget
   follow the number of known endpoints and give peers a faster first retry, after the flood tests are rerun.
2. **Does D393's 4,096 test point mean "recovers in a few seconds" or just "works"?** The numbers say "works"; the grill
   should state which one the relay manager's Q9 limit relies on.
3. **Run the TCP version of the overload step** before anyone changes the AQM: it needs a TCP-capable peer simulator
   (kernel WireGuard peers in namespaces), a separate job.
