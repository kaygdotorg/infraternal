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
