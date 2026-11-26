# Multi-queue TUN and receive lanes for GotaTun (#260, J1230)

GotaTun plan step 4 ([gotatun-architecture.md](../../docs/design/gotatun-architecture.md), rank 4):
can a Linux multi-queue TUN plus several UDP sockets per device close the 8-flow reverse
throughput gap to kernel WireGuard? This is a measurement with a prototype on a scratch fork
branch. Nothing here changes the product.

## 1. Fixture

J1199's cross-VM kit ([kit/](kit/)), engine rows only:

- A = calternal-perf-01 (4 vCPU), B = infraternal-perf-01 (6 vCPU), both on backup01.
- Each VM runs everything inside its own netns `j30` on an ipvlan child of eth0 (10.70.3.196 and
  .197). The netns has no default route, and an nft table inside it drops and counts anything
  leaving for an address outside 10.70.3.0/24. egress-guard is untouched.
- Every row uses `wg set`, MTU 1390, and the same captured `infraternal_mesh` guard table.
- Load is iperf3 for 60 s (2 s omitted), full speed, CUBIC 1 and 8 flows and BBR 8 flows, in
  both directions. Reverse means B sends and A receives.
- Latency comes from rr.py: 64 B request/reply every 20 ms, loss-aware p50/p99/p99.9. No ping.
- CPU is whole-machine busy time over the 40 s steady window, with steal excluded.
- Every hold uses the lock protocol: a `/run/j1230.lock` marker, and it waits for every other
  `/run/j1*.lock` and every perf/build flock on both VMs.
- Each hold runs from a frozen copy of the kit. Editing a running `series.sh` breaks the run;
  this happened at the end of c1.

Rows:

| row | what |
|---|---|
| G | `gotatun-cli` at the dev pin `e87fef91` (J1199's static musl ring + mimalloc build, sha256 `94e7b745…`) |
| G2 | two G tunnels side by side (ports 51820/51821, tunnels 10.66/10.67, flows split 4+4) |
| M*n* | multi-queue TUN alone, *n* queues (fork `c9a01d9`, `GOTATUN_TUN_QUEUES=n`, sha256 `6c738437…`) |
| L*n* | receive lanes plus as many TUN queues (fork `b9eb3ee`, `GOTATUN_LANES=n GOTATUN_TUN_QUEUES=n`, sha256 `f0c4bb4d…`) |
| L*n*n | receive lanes alone (same binary, `GOTATUN_LANES=n`) |
| K | kernel WireGuard |

## 2. Ceiling first (hold c1)

Hold c1 ran 2026-11-25 14:09–15:00Z, with rows in the order G G2 K G2 G. All 30 windows exited
0. Raw data is in [results/c1-windows.csv](results/c1-windows.csv) and
[results/c1-rows.csv](results/c1-rows.csv). Throughput is in Gbit/s:

| window | G.a / G.b | G2.a / G2.b | K | G2 vs G |
|---|---|---|---|---:|
| reverse CUBIC 8 | 3.349 / 3.369 | 3.938 / 3.932 | 4.093 | **+17.2%** |
| reverse BBR 8 | 3.507 / 3.512 | 4.134 / 4.120 | 4.034 | **+17.6%** |
| reverse CUBIC 1 | 3.327 / 3.328 | (one tunnel) 3.245 / 3.299 | 2.959 | – |
| forward CUBIC 8 | 3.162 / 3.142 | 3.102 / 3.099 | 3.131 | −1.7% |
| forward BBR 8 | 3.115 / 3.116 | 3.081 / 3.059 | 3.090 | −1.4% |
| forward CUBIC 1 | 3.264 / 3.247 | 3.248 / 3.239 | 2.690 | – |

- The A/A floor (G.a against G.b) is at most 0.6% in every reverse cell.
- **Reverse is limited by one pipeline, not by CPU.** The receiver A is busy for 1.90 of 4 vCPUs
  on G, 2.26 on G2 and 2.50 on K. CPU per Gbit on A is the same for G and G2 (0.565–0.575 s per
  Gbit), so a second pipeline buys throughput without making bytes cheaper.
- **Forward is capped by the fixture.** Every engine stops at about 3.1 Gbit/s, kernel
  WireGuard included, while neither VM is CPU-bound. Forward rows can only show regressions.
- Per-thread CPU points at no single thread. Tokio moves the tasks over all workers (the top
  thread on A runs at 0.34 cores), so the serial stage is a task, not a thread.
- Two whole devices double everything: the TUN reader and writer, the UDP socket, and the
  receive and send tasks. The ceiling therefore does not say which stage limits. It only says
  that 17% is available to a design that parallelises the right one.

## 3. The two candidates

Both candidates are bench switches in the fork (branch `j1230-multiqueue`). Both are off by
default, and leaving them unset is byte-for-byte today's behaviour.

**Multi-queue TUN** (`GOTATUN_TUN_QUEUES=n`, `gotatun/src/tun/tun_async_device/multiqueue.rs`)

- Opens *n* `IFF_MULTI_QUEUE | IFF_VNET_HDR` queues with a raw `TUNSETIFF`, because the `tun`
  crate refuses more than one queue.
- The crate keeps one extra descriptor for name and MTU queries. That descriptor is detached
  with `IFF_DETACH_QUEUE`, so the kernel never steers a packet to it.
- Decrypted packets are split by a symmetric hash of the inner addresses, protocol and ports.
  Queue 0 is written inline by the existing writer. Queues 1 and up each have one writer task
  fed by a bounded channel, so a flow always uses one FIFO.
- All queues are read by the device's one reader, which polls readiness and rotates the
  starting queue.
- The kernel's TUN flow table learns a flow's queue from our writes, so a flow's replies come
  back on the queue its data went to.

**Receive lanes** (`GOTATUN_LANES=n`, `gotatun/src/lanes.rs`)

- **Why not `SO_REUSEPORT`.** Every datagram of one peer has one outer 5-tuple. `SO_REUSEPORT`
  (by hash or `SO_INCOMING_CPU`) therefore puts all of it on one socket, and one peer cannot be
  spread that way.
- **Sender.** It tags each data packet with a lane when it reserves the counter, using the same
  inner-flow hash, in reserved header byte 2 (outside the AEAD, like the J1159 side mark).
- **Send path.** At the bottom of the UDP send path, a lane-*i* datagram leaves from a socket on
  listen port + *i* to the peer's port + *i*. It carries the side mark, so the receiver does not
  roam to the lane port, and the tag is cleared before sending.
- **Receiver.** It runs one `handle_incoming` task per lane socket, each with its own incoming
  order store. A flow stays on one lane, so it stays in order.
- **What stays on lane 0.** Handshakes, cookies and keepalives, so roaming, NAT refresh and
  handshakes see one socket as before.
- **What is unchanged.** The send pipeline: one TUN reader, one outgoing order store, and the
  single drainer of the handshake queue (lock-order rule 3).
- **Idle.** A lane arms its own 5 s idle check on its first datagram after idle, and releases
  its receive buffer after a quiet period, so it wakes zero times when idle (D81). Lane 0 still
  owns the shared pool's release (D331).
- **Limits.**
  - Both peers need the same lane count.
  - The port convention does not survive a NAT that rewrites ports. A product version would learn
    each lane's endpoint from the peer, or have the peer advertise it, like the J1211 side socket.
  - The 8,192-counter replay window is shared by a session's lanes, so lanes may drift that far
    apart before the slower lane's datagrams are dropped.
  - Packets queued during a handshake are drained by the one send task, as before.

**Smoke test** ([kit/smoke.sh](kit/smoke.sh), run as root on compute01 in a throwaway netns pair):

- With 2 lanes and 2 queues, the receiver's input counters showed lane 0 at 8,984 datagrams /
  249 MB and lane 1 at 8,078 / 246 MB.
- The tunnel showed `rx-0 rx-1 tx-0 tx-1`.
- TCP OFO-queue events were in the range of the single-lane control.

**Fork gate** on `0ca4afc` (the fork's own flake, cargo 1.95.0):

- fmt 0, clippy `-D warnings` 0.
- Lib tests: 292 passed, 1 failed, 11 ignored. The failure is the load-sensitive
  `aqm::blocked_tun_keeps_kernel_age_until_ordered_dequeue`, which passes alone 3/3 on both
  `0ca4afc` and the pin.

## 4. Candidates measured (hold m2)

Hold m2 ran 2026-11-25 16:41–17:52Z, with rows in the order G M4 L4 L2 L4n G K. All 42 windows
exited 0. Raw data is in [results/m2-windows.csv](results/m2-windows.csv) and
[results/m2-rows.csv](results/m2-rows.csv). The control for "vs G" is the mean of G.a and G.b.

**Reverse throughput** (B sends, A receives), Gbit/s:

| window | G.a / G.b | M4 | L4 | L2 | L4n | K |
|---|---|---|---|---|---|---|
| CUBIC 8 | 3.343 / 3.367 | 3.373 (+0.5%) | 3.499 (+4.3%) | 3.680 (+9.7%) | **3.725 (+11.0%)** | 4.304 |
| BBR 8 | 3.503 / 3.486 | 3.335 (−4.6%) | 3.458 (−1.1%) | **3.751 (+7.3%)** | 3.734 (+6.8%) | 4.327 |
| CUBIC 1 | 3.351 / 3.340 | 3.343 | 3.349 | 3.319 | 3.391 | 3.034 |

**rr p99 in ms** (64 B request/reply every 20 ms, no probe lost in any window):

| window | G.a / G.b | M4 | L4 | L2 | L4n | K |
|---|---|---|---|---|---|---|
| reverse CUBIC 8 | 7.21 / 7.36 | 6.49 | 8.47 | 11.30 | 16.13 | 6.24 |
| reverse BBR 8 | 21.09 / 28.58 | 15.94 | 12.81 | 19.93 | 14.12 | 22.95 |
| reverse CUBIC 1 | 4.95 / 4.94 | 7.27 | 3.54 | 5.11 | 3.93 | 1.56 |
| forward CUBIC 8 | 13.23 / 12.31 | 11.92 | 33.15 | 19.57 | 30.22 | 9.57 |
| forward BBR 8 | 10.89 / 10.64 | 9.81 | 7.36 | 8.28 | 8.96 | 8.36 |

**CPU per Gbit, whole machine, steal excluded** (s/Gbit):

| window | side | G.a / G.b | M4 | L2 | L4n |
|---|---|---|---|---|---|
| reverse CUBIC 8 | A (receiver) | 0.563 / 0.563 | 0.587 | 0.555 | 0.556 |
| forward CUBIC 8 | B (receiver) | 0.768 / 0.764 | 0.807 | 0.918 | 0.931 |
| forward BBR 8 | B (receiver) | 0.767 / 0.760 | 0.807 | 0.928 | 0.927 |

**Idle and memory.**

- Idle wakeups stay at zero: every GotaTun row is at 0.0–0.5 wakeups/s for its processes before
  and after load (G 0.4/0.0 and 0.5/0.1, L2 0.3/0.2, L4 0.1/0.2, L4n 0.5/0.1, M4 0.3/0.0).
- Process RSS before load is 14.7–16.0 MiB on A and 18.2–21.4 MiB on B for every row. 15 s after
  load it is 38.7–47.6 MiB on A and 26.8–37.3 MiB on B; G itself is at 38.8–40.2. That is before
  the 5 s quiet period plus the release completed, and it is the same for all rows.

**Reading.**

1. **The multi-queue TUN alone buys nothing.** M4 is within the floor at CUBIC 8 and loses 4.6% at
   BBR 8, at 4% more receiver CPU per Gbit. The TUN writer is not the serial stage. This matches
   J88h's 0.005 ms TUN enqueue.
2. **Receive lanes are the lever.**
   - 2 to 4 lanes lift reverse 8-flow throughput by 7–11%, well outside the 0.7% floor. They
     close 39% of the gap to kernel WG at CUBIC 8 (3.355 → 3.725 against 4.304).
   - Without the extra TUN queues, lanes do slightly better (L4n against L4).
   - They stay short of the two-tunnel ceiling (3.94). The rest is in what one device still
     shares per peer: one send pipeline on B, the per-packet peer-state lock each lane takes, and
     one session.
3. **Lanes worsen CUBIC latency under full load and cost CPU on the forward receiver.**
   - **CUBIC p99 grows with the number of lanes**, in both directions and at the same forward
     throughput: forward 12.8 → 19.6 (2 lanes) → 30.2 ms (4 lanes). The VMs' eth0 runs `fq` with
     `flow_limit 100p` (its `flows_plimit` drop counter is non-zero on both). Every outer 5-tuple
     gets its own 100-packet allowance, so n lanes let a loss-based sender keep n times the
     standing queue. BBR, which does not fill buffers, gets lower p99 with lanes (reverse
     21–29 → 14–20 ms, forward 10.8 → 7.4–9.0 ms). The 1-flow probe also gets faster (reverse
     CUBIC 1 p99 4.95 → 3.5–3.9 ms) because it no longer shares the bulk's outer flow.
   - **The forward receiver B spends 20% more CPU per Gbit with lanes** at the same throughput
     (0.766 → 0.918–0.931). Likely causes, not yet profiled, are smaller `recvmmsg` batches per
     socket, more task wakeups, and contention on the peer mutex that every lane takes per
     packet.

Against the [shared keep rule](../../docs/design/gotatun-architecture.md#shared-r4b-hold-and-keep-rule),
a throughput cut is kept only if throughput improves outside spread, both p99s do not regress
and no probe is lost.

- **M4** fails: no throughput gain.
- **L2, L4 and L4n** pass on throughput and lost probes, but fail on p99. CUBIC 8 p99 regresses
  in both directions, and the forward receiver's CPU per Gbit regresses by 20%.

## 5. macOS

macOS has no multi-queue `utun`. There is one descriptor per interface, and it takes one packet
per `write` with no GSO metadata. The multi-queue TUN half of this study is Linux-only. The
receive lanes are plain UDP sockets and receive tasks, so they would work unchanged on macOS (and
on iOS inside the packet tunnel extension). The TUN write would stay one serial stage there.
Whether that stage or the receive task limits a Mac has to be measured on the mba before anyone
relies on it.

## 6. Recommendation and owner questions

**Verdict: do not merge either candidate.**

- **Multi-queue TUN:** no gain; drop it. Revisit only if a later profile shows the TUN write
  limiting.
- **Receive lanes:** a real throughput lever (+7–11% reverse, 39% of the kernel gap). They fail
  the keep rule on CUBIC p99 and on receiver CPU, so they stay on the scratch branch. Fixing them
  needs two things before another hold:
  1. Bound the standing queue across lanes, not per lane. Candidates are an engine-side bound on
     bytes in flight per peer across all lanes, or 2 lanes as the ceiling. Measure with
     rate-limited windows (J1160's @2.0 Gbit/s) as well, so the p99 cost is separated from the
     higher rate.
  2. Profile the forward receiver to find the 20% CPU (batch size per socket, lock wait on the
     per-packet peer mutex).
- **Product cost if lanes are kept later:**
  - Lane endpoints must be learned or advertised per peer. The fixed port + *i* convention fails
    behind NAT. The J1211 side-socket advertisement is the model.
  - Peers that do not advertise lanes keep one socket, because stock WireGuard drops marked
    datagrams.
  - The mesh's own TUN (`infraternal-linux-tun`) needs nothing for lanes alone.

**Questions for the owner.**

1. **Should the receive-lane work continue as its own job?** The fixes needed are the cross-lane
   queue bound and the receiver CPU profile. Each lane adds one UDP socket (port + *i*), one
   receive task and its receive buffer (released after 5 s quiet), and nothing at idle. The
   protocol change is the reserved-byte lane tag plus the existing side mark, and it applies
   only between our own peers. Recommendation: yes, with 2 lanes as the target, held to the
   same keep rule.
2. **Should the remaining gap to the two-tunnel ceiling (3.73 → 3.94) and to kernel WG (4.30) be
   chased on the send side?** That would mean several send pipelines per peer (one TUN queue
   each, the handshake-queue drain made per lane). It touches the lock-order rules in
   `device/mod.rs` and is a larger change. Recommendation: not before the lanes pass the keep
   rule.

## 7. Round 2: fixing the receive lanes (J1239)

J1239 tried to make 2 lanes pass the keep rule by fixing the two failures above: CUBIC p99 and the
forward receiver's CPU. Fork branch `j1239-lanes2` (kayg/gotatun-fork) is J1230's branch rebased
onto the dev pin `cd295c2e`, plus four bench switches, all off by default:

| switch | commit | what it does |
|---|---|---|
| `GOTATUN_LANE_SOCKBUF=split` | 8f9d77c | the n lane sockets share one socket's forced 7 MiB SO_RCVBUF/SO_SNDBUF |
| `GOTATUN_LANE_BATCH_LOCK=1` | 73085aa | a receive turn keeps the peer lock across its data packets |
| `GOTATUN_TUN_GROUP_FLOWS=1` | b5556a4 | a queued TUN write run is grouped by inner flow before GSO coalescing |
| `GOTATUN_SNDBUF_BUDGET=<bytes>` | 9118284 | one SO_SNDBUF budget per device, split over the lane sockets |

The kit is [kit-r2/](kit-r2/): J1230's fixture (netns `j39`, the same VMs, the lock protocol and
the guard table) plus:

- `qs.py`: every 250 ms over the steady window, the per-socket queue bytes and drops (from
  `/proc/<pid>/net/udp`), UDP buffer errors, TUN drops and eth0's `fq` backlog/`flows_plimit`, on
  both VMs.
- Rate-capped windows (`cubic:8@2000`: iperf3 `-b 250M` per stream, 2.0 Gbit/s in total).
- One extra profiled forward window per chosen row: `perf record -a` (cycles) plus `perf stat`
  syscall tracepoints on B. Debian's `perf` 6.12.117 is unpacked under /root/j1239 and not
  installed. Profiled windows are never used as results.
- `qsum.py` (queue CSV) and `pdiff.py` (absolute-cycle profile diff).

### 7.1 Diagnosis hold d1

Hold d1 ran 2026-11-26 00:51–01:28Z with rows G, L2n, L2s and L2b. All 20 windows exited 0. Data:
[r2-d1-windows.csv](results/r2-d1-windows.csv), [r2-d1-queues.csv](results/r2-d1-queues.csv),
[r2-d1-profile/](results/r2-d1-profile/).

**Where the standing queue sits.**

- **Forward (A sends).** The queue is A's socket write memory: skbs in eth0 `fq` and the NIC ring.
  - Its mean is 3,499 KiB with one socket and 5,711 KiB summed over two lane sockets (+63%), while
    `fq`'s backlog in packets stays the same (171 vs 157).
  - `fq`'s 100-packet flow limit counts UDP GSO super-packets (up to 64 datagrams each), so every
    outer flow, and so every lane, holds megabytes.
  - The probe's loaded p50 follows that queue divided by the rate: 3.5 MiB at 3.1 Gbit/s is about
    9.3 ms (G's p50 is 9.30 ms), and 5.7 MiB is about 15 ms (L2n's p50 is 14.74 ms).
  - J1230 named the right mechanism (`fq` per outer flow), but the unit is GSO packets, not
    datagrams.
  - The forced 7 MiB socket buffers (14 MiB in the kernel) never bind, so L2s cannot bound the
    queue.
- **Reverse.**
  - No socket drops, no RcvbufErrors, and G has no retransmits. The inner flows are
    window-limited, and the receiver's socket queue is about 1 MiB.
  - At the 2 Gbit/s cap, p99 is equal (G 3.49, L2n 3.60, L2b 3.53 ms). The reverse p99 growth at
    full speed comes with the higher rate, not with the lanes themselves.

**Where the forward receiver's extra CPU goes.** From `perf record -a`, 20 s at the same 3.1 Gbit/s
on B, total cycles go from 160 to 190 G (+19%):

- Crypto is unchanged: chacha20-poly1305 open is 18.2 vs 18.4 Gcycles; it only moves between
  threads.
- The extra cycles spread over per-packet work: tokio's `batch_semaphore` (+1.3 G), kernel spinlock
  slow path, page clearing, allocation, and the inner stack (nft, fib, netif_receive).

Syscalls in the same 20 s on B:

| | G | L2n | L2n vs G |
|---|---:|---:|---:|
| TUN `write` | 275,418 | 465,615 | +69% |
| `recvmmsg` | 353,354 | 561,821 | +59% |
| `futex` | 247,237 | 517,228 | ×2.1 |
| context switches | 1.75 M | 2.04 M | +17% |

Each lane socket sees half the rate, so each receive turn returns about half as many datagrams, and
the decrypted run it hands to the TUN writer is about half as long. The writer coalesces only
adjacent packets of a flow within what is queued, so TUN frames get smaller and their number grows.
The batch peer lock (L2b, 0.874 vs 0.901 s/Gbit) is within noise of L2n, so it was dropped.

### 7.2 Candidate hold r2

Hold r2 ran 2026-11-26 02:41–04:24Z with rows in the order G.a Lc.a Lg Lw Gc Lc.b G.b K. All 66
windows exited 0 and no probe was lost in any window. Data:
[r2-windows.csv](results/r2-windows.csv), [r2-rows.csv](results/r2-rows.csv),
[r2-queues.csv](results/r2-queues.csv).

Rows:

| row | lanes | switches |
|---|---|---|
| Lc | 2 | flow grouping + send budget of 1.75 MiB asked (3.5 MiB effective in total, G's own occupancy) |
| Lg | 2 | flow grouping |
| Lw | 2 | send budget |
| Gc | 1 | both switches, no lanes: what the switches do on their own |

Throughput (Gbit/s):

| window | G.a / G.b | Lc.a / Lc.b | Lg | Lw | Gc | K |
|---|---|---|---|---|---|---|
| reverse CUBIC 8 | 3.360 / 3.350 | 3.606 / 3.654 (+8.2%) | 3.645 | 3.611 | 3.340 | 4.125 |
| reverse BBR 8 | 3.494 / 3.502 | 3.763 / 3.749 (+7.4%) | 3.763 | 3.770 | 3.493 | 4.090 |
| reverse CUBIC 1 | 3.352 / 3.341 | 3.346 / 3.354 | 3.335 | 3.353 | 3.321 | 2.955 |
| forward CUBIC 8 | 3.165 / 3.135 | 3.157 / 3.110 | 3.099 | 3.125 | 3.177 | 3.125 |

rr p99 in ms (64 B request/reply every 20 ms):

| window | G.a / G.b | Lc.a / Lc.b | Lg | Lw | Gc | K |
|---|---|---|---|---|---|---|
| reverse CUBIC 8 | 7.44 / 7.42 | 9.15 / 11.45 | 9.19 | 9.31 | 7.73 | 6.44 |
| reverse CUBIC 8 @2G | 3.64 / 3.79 | 6.53 / 3.29 | 4.85 | 3.17 | 4.11 | 2.51 |
| reverse BBR 8 | 23.08 / 27.59 | 19.02 / 19.58 | 20.11 | 18.38 | 38.79 | 27.99 |
| reverse CUBIC 1 | 4.87 / 4.83 | 4.01 / 3.82 | 4.14 | 3.96 | 5.31 | 1.53 |
| forward CUBIC 8 | 12.73 / 13.73 | **54.48 / 54.31** | 19.81 | **52.57** | **58.49** | 10.17 |
| forward CUBIC 8 @2G | 3.99 / 3.96 | 4.19 / 4.13 | 4.81 | 4.68 | 4.26 | 2.75 |
| forward BBR 8 | 10.95 / 10.18 | 8.44 / 9.41 | 6.09 | 7.00 | 10.59 | 8.35 |
| forward CUBIC 1 | 7.52 / 7.72 | 7.06 / 7.21 | 5.16 | 6.63 | 7.93 | 1.93 |

Forward receiver B, CPU per Gbit (whole machine, steal excluded, s/Gbit):

| window | G.a / G.b | Lc.a / Lc.b | Lg | Lw | Gc |
|---|---|---|---|---|---|
| forward CUBIC 8 | 0.762 / 0.769 | 0.877 / 0.864 | 0.899 | 0.865 | 0.762 |
| forward CUBIC 8 @2G | 0.753 / 0.754 | 0.863 / 0.823 | 0.857 | 0.830 | 0.763 |
| forward BBR 8 | 0.763 / 0.775 | 0.889 / 0.885 | 0.895 | 0.894 | 0.761 |

**Idle and memory.**

- Idle wakeups stay at 0.0–0.5/s for every GotaTun row, before and after load.
- RSS before load is 14.5–18.6 MiB on A and 18.3–21.1 MiB on B. Fifteen seconds after load it is
  31–65 MiB on A and 27–38 MiB on B for every row; G itself is at 33–37 / 32–37. That is before
  the 5 s quiet period plus the release completed, as in J1230.

**Reading.**

1. **The lanes' throughput gain reproduces.** Reverse 8-flow throughput is +7.4–9.1% in every
   lane row (the A/A floor is at most 0.3%). The 1-flow and BBR p99 get lower with lanes, as in
   J1230.
2. **The send budget is wrong.**
   - Capping the sockets' write memory moved the queue upstream into GotaTun's own send pipeline,
     where all inner flows share one FIFO. `SndbufErrors` went from 142 to 8,191–9,657 per window.
   - Forward CUBIC 8 p99 rose to 52–58 ms with lanes (Lc, Lw) and without them (Gc). The
     regression belongs to the budget, not to the lanes.
   - Rejected.
3. **Flow grouping does not remove the CPU cost.**
   - It cut TUN writes by only 12%: 409k against 466k in 20 s (G: 275k). Lg's CPU per Gbit is
     0.899, the same as plain lanes.
   - The merged queue rarely holds runs of both lanes at once. The real cause is the smaller run
     per receive turn on each lane.
   - Rejected.
4. **Lanes still fail the keep rule.**
   - CUBIC 8 p99 regresses at full speed in both directions: reverse 7.4 → 9.2–11.5 ms, forward
     12.7–13.7 → 19.8 ms (Lg).
   - The forward receiver spends 13–17% more CPU per Gbit.
   - At the 2 Gbit/s cap, p99 is mostly within spread in reverse but 5–20% higher forward.

### 7.3 What would be needed, and owner questions

The two failures have one root each, and neither is a small fix:

- **p99: the forward queue scales with the number of outer flows** at the sender's `fq` (GSO
  packets × 100 per flow). Bounding it from the socket side only moves it into the engine's FIFO.
  The ways out:
  - Keep one outer 5-tuple for all lanes and let the receiver pick the lane socket, for example
    with an `SO_ATTACH_REUSEPORT_CBPF` program reading the lane byte. Then `fq` sees one flow, as
    today. Risk: UDP GRO can merge datagrams of different lanes into one receive, which would break
    per-flow order unless GRO is off on lane sockets or the receiver re-splits.
  - Or give the engine's send pipeline per-inner-flow queuing (rank 2 of the roadmap), so a queue
    pushed back from the socket stops being one FIFO.
- **CPU: every lane halves its receive batch,** so per-packet fixed costs (TUN write, wakeups,
  semaphore) double per byte. The ways out:
  - Coalesce receives deliberately (wait a few tens of µs for more datagrams). Tokio's 1 ms timer
    is too coarse for that, so it would need a different wait primitive.
  - Or merge the lanes' decrypted runs per flow in one place before the TUN write. That puts back a
    serial stage, which is what lanes remove.

Questions for the owner:

1. **Should receive lanes continue at all?**
   - Two rounds have not found a cheap fix, and each remaining route is a design change:
     - one outer 5-tuple with BPF socket steering, which is a new kernel-facing dependency;
     - per-flow queuing in the send pipeline;
     - receive coalescing with a sub-millisecond wait.
   - Recommendation: park lanes. Do roadmap rank 2 (per-peer/per-flow FQ in the engine) first,
     because it fixes the p99 side for lanes and for the single pipeline alike. Revisit lanes after
     it, with the reuseport-steering variant measured for both GRO on and GRO off.
2. **Should the reuseport-steering variant be prototyped now** as a measurement job?
   Recommendation: only after rank 2. Its order risk under GRO needs its own proof, and its gain
   is capped by the same CPU cost per byte.

The four bench switches stay on the scratch branch, off by default. Nothing here changes the
product.
