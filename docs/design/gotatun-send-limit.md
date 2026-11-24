# GotaTun send-side limit (our own small-queue limit)

**Job:** J1140 · **Issue:** #260 · **Status:** measured, not shipped (NO-SHIP, see Verdict) ·
**Decision owner:** kayg · **Cites:** D331 (send buffer), D332, D397

## Problem

Kernel TCP keeps only about 1 ms of each flow's data below its socket (its small-queue limit).
Behind a TUN device that limit cannot work: the TUN orphans every skb it hands to the engine, so
the inner TCP flows never see what waits below them. D331 made GotaTun's UDP send buffer
effectively uncapped (7 MiB requested, 14 MB after the kernel doubles it, forced past
`wmem_max`). J1139 measured the result on the cross-VM pairing (sender calternal-perf-01,
receiver infraternal-perf-01, 2 vCPUs each): at full speed the ICMP probe waits mostly in the
sender's eth0 `fq` qdisc, which holds 2.8–3.6 MB of GotaTun's bulk (p50). Kernel WireGuard keeps
that qdisc near 0. A static small `SO_SNDBUF` (425 KB) emptied the qdisc but cost 18–26%
throughput, and the backlog moved into GotaTun's own UDP send queue.

The goal of J1140: keep only a few hundred microseconds of our own traffic below the socket,
adaptively, and hold the rest in GotaTun's queue, where the sending-side CoDel (J1136, `aqm.rs`)
can see its age and mark CE or drop. Throughput within noise; full-speed and equal-rate loaded
p99 down.

## What was built (fork `kayg/gotatun-fork`, branch `j1140-send-limit` on `841ef3e`; the e6efb96 version is `j1140-send-limit-e6efb96`)

All of it is opt-in and Linux-only; nothing changes unless a mode is chosen.

1. **The limit is the socket's own send buffer, resized at run time** (`udp/socket/send_limit.rs`).
   The kernel already refuses new datagrams once the socket's accounted bytes reach `SO_SNDBUF`
   and wakes the sender when they fall to half, so no timer or thread is needed.
2. **Slack-driven mode (`auto`)**, sized like the kernel's byte queue limits: on each wake-up
   after `EAGAIN`, `SIOCOUTQ` gives the bytes still below the socket. Less than one GSO
   super-datagram means the wire nearly idled, so the limit grows by a quarter (at most once per
   ms). A 100 ms window that never starved gives back its smallest slack minus a headroom.
3. **Rate-sized mode (`rate`)**, the TCP rule: the fastest send rate of the last second times
   1 ms, floored at 512 KiB, capped at the configured send buffer. It reads no slack.
4. **Fixed mode** (`<bytes>`) for comparison rows.
5. With the socket limited, the backlog has to stand where CoDel judges it. Two existing pieces
   were combined for that: the 4000-slot post-encryption UDP send queue was capped at 256 slots
   (`GOTATUN_BENCH_UDP_TX_BUFS=256`, about 1 ms at 3 Gbit/s), so the queue moves back into the
   plaintext read-ahead; and J1136's sending-side CoDel (`GOTATUN_AQM_TX`, 1 ms / 10 ms)
   judges and marks it before encryption.

## Findings

**1. On this pairing the socket's accounting does not bound the qdisc.** Paired reads of the
engine socket's charged bytes (`tx_queue` in `/proc/<pid>/net/udp6`, read immediately before
and after each `tc` read, about 2 ms apart) show eth0's qdisc holding more than the socket has
charged in 60–75% of full-speed samples (base, CUBIC 1: qdisc p50 2.44 MB, charged p50
1.52 MB, with a 14 MB buffer). The kernel path that releases the charge was not found (in v6.12,
`skb_scrub_packet`, the ipvlan L2 transmit and `fq` do not orphan these skbs, and TX timestamps
show `skb->sk` is still set at the driver). It does mean a wake-up slack signal is not a reliable
"the wire is about to idle" signal here.

**2. The link is not the bottleneck; CPU load is.** A raw single-thread UDP-GSO sender in the
same netns pushes 3.8–4.1 Gbit/s with eth0's qdisc at 0, sitting exactly at its `SO_SNDBUF`.
Under GotaTun both vCPUs are busy, TX completion is late, the virtio ring stays full (hundreds of
millions of requeues since boot) and the qdisc fills. eth0 has `tx-udp-segmentation: off`.

**3. Most of the probe's qdisc wait comes from sharing one `fq` flow with our own bulk.** A
separate 200 B UDP flow with kernel TX timestamps, sent during GotaTun's full-speed CUBIC 1 load,
waited p50 348 µs / p99 1.55 ms between qdisc enqueue and driver hand-off (3,000 of 3,000
stamped). GotaTun's own probe waits 1.5–4 ms there (J1139), because every GotaTun datagram to a
peer has the same 5-tuple, so `fq` queues the probe behind our bulk.

**4. The trade-off curve has a cliff just under 512 KB** (old base: dev `1fa726794`, GotaTun `e6efb96`; cross-VM pairing, clean 60 s windows,
c1 and c3; Gbit/s, p50 / p99 ms; every candidate row with the 256-slot queue and CoDel 1 ms
unless named otherwise):

| row | full CUBIC 1 | full BBR 8 | equal-rate CUBIC 1 | equal-rate BBR 8 |
|---|---|---|---|---|
| base (c1 / c3) | 2.93, 4.56 / 8.38 · 2.92, 4.34 / 7.74 | 3.03 / 11.80 · 3.02 / 12.10 | 2.83 · 3.44 | 3.75 · 3.65 |
| fixed 2 MB | 3.00, 4.43 / 7.96 | 3.10 / 11.50 | 2.99 | 4.52 |
| slack-driven (`auto`, settles 0.9–1.8 MB) | 2.97, 3.84 / 6.91 | 3.09 / 11.50 | 2.60 | 4.43 |
| fixed 1 MB | 2.99, 3.58 / 6.54 | 3.08 / 11.80 | 3.50 | 3.85 |
| **fixed 512 KB (c1 / c3)** | **2.90, 3.15 / 5.59 · 2.89, 3.20 / 5.89** | 3.04 / 11.60 · 3.04 / 11.80 | 2.93 · 2.74 | 4.19 · 4.89 |
| fixed 512 KB, no queue cap, no CoDel | 2.88, 4.50 / 7.99 | 3.01 / 12.10 | 2.56 | 3.98 |
| fixed 384 KB | **2.59 (−12%)**, 2.97 / 4.64 | **2.62 (−13%)** / 9.60 | 3.09 | 5.08 |
| fixed 256 KB | **2.46 (−16%)**, 2.92 / 4.54 | **2.42 (−20%)** / 9.17 | 3.16 | 4.23 |

- The limit alone changes nothing (fixed 512 KB without the queue cap: the backlog moves into
  the 4000-slot UDP queue). The cap plus CoDel is what turns it into lower latency; CUBIC 1 needs
  only about 7–14 CE marks per 40 s window.
- The best point (fixed 512 KB) cuts CUBIC full-speed p99 by 24–33% for about −1.2% throughput,
  but it sits right at the edge of a cliff: 384 KB already loses 12–13%. The slack-driven mode
  stays clear of the cliff because finding 1 makes it see false starvation, so it settles at
  1–2 MB and gives back most of the gain.
- BBR 8 at full speed does not move (Linux BBR ignores CE; only the throughput-losing rows cut
  its inflight).
- Equal-rate BBR 8 p99 is **worse** in five of six capped rows (3.65–3.75 → 3.85–5.08 ms).

**5. On the new base (dev `95c3291cd`, GotaTun `841ef3e`, replies first on) the gain is larger
and reaches BBR, but so does the cost** (holds d1, d2; Gbit/s, p50 / p99 ms, sender CPU s/Gbit):

| row | full CUBIC 1 | full BBR 8 | eq. CUBIC 1 p99 | eq. BBR 8 p99 |
|---|---|---|---|---|
| base (d1 · d2) | 2.93, 4.29 / 8.47 · 2.93, 4.56 / 7.85, 0.785 | 3.01, 6.85 / 11.3 · 3.01, 7.04 / 11.5, 0.664 | 3.17 · 2.40 | 3.22 · 3.45 |
| rate-sized limit + cap + CoDel | 2.87, 2.56 / 4.98 · 2.88, 2.50 / 4.73, 0.834 | 2.91, 4.93 / 10.2 · 2.96, 5.00 / 10.3, 0.734 | 2.34 · 2.51 | 2.89 · 3.58 |
| fixed 512 KiB + cap + CoDel | 2.88, 2.58 / 5.05 · 2.87, 2.52 / 5.01, 0.862 | 2.96, 4.84 / 9.75 · 2.96, 4.86 / 9.67, 0.742 | 2.54 · 2.45 | 3.43 · 3.48 |

Full-speed p99: CUBIC −40%, BBR −10–15%; equal rate neutral. Cost in every pair:
−1.7% (CUBIC) / −1.7–3.3% (BBR) Gbit/s, outside noise (the base repeats to 0.1%), and +6–11%
sender CPU per Gbit. At ~3 Gbit/s the rate-sized limit sits at its 512 KiB floor.

**6. Where the NIC qdisc does not fill, the limit buys nothing** (backup01 single host, J1136's
harness on the J872 kit, 6 vCPUs, ~6 Gbit/s; two holds per cell, each against base B of its
hold): limit off costs nothing (±0.2% Gbit/s, ±0.03 ms p99); the rate-sized and fixed 512 KiB
rows cost 0 to −0.7% Gbit/s and +0.03 to +0.09 ms p99 in every cell (CUBIC and BBR, 1 and 8
flows).

## Verdict

**NO-SHIP as a default.** It fails the ship rule (throughput within noise, and loaded p99 down at
full speed and at equal rate): on the CPU-bound virtio pairing it trades 1.7–3.3% throughput and
6–11% CPU for a large full-speed p99 cut with equal rate unchanged, and on backup01 it costs a
little and gains nothing. The useful setting also sits close to a cliff (384 KiB already loses
12–13% on the old base), so one floor is not safe across hosts. D331's send buffer stays as it
is; no new decision is recorded. The fork branch `j1140-send-limit` stays unpinned as the record
(everything in it is off unless chosen).

A socket-side limit can only trade the "our own `fq` flow" part of the probe's wait against
throughput. The cause sits in that shared flow, which is what the next section targets.

## What would remove the cause instead

- **Interactive packets in their own `fq` flow.** Finding 3: a separate flow waits ~0.35 ms
  (p50) where GotaTun's own flow waits 1.5–4 ms. Sending small datagrams (probes, ACKs,
  keystrokes) from a second UDP socket gives them a different 5-tuple, so `fq` round-robins them
  ahead of our bulk with no throughput cost. It touches the WireGuard endpoint model (the peer
  sees two source ports and roams to the latest), so it is a protocol question for kayg. It
  complements J1143's in-engine "replies first" lane.
- **A delay-based gate from TX timestamps.** The kernel delivers `SCM_TSTAMP_SCHED`/`SND`
  stamps on this path, so the engine could measure its own datagrams' below-socket wait directly
  instead of inferring it from accounted bytes. It costs error-queue reads on the send path and
  still trades throughput at the same cliff, so it is listed for completeness, not recommended.

## Knobs (all off unless set; bench use)

- `GOTATUN_SEND_LIMIT=off|auto|rate|<bytes>` overrides `UdpSocketFactory::send_limit`.
- `GOTATUN_SEND_LIMIT_MIN`, `_MAX` (bytes); `_STARVED`, `_HEADROOM`, `_WINDOW_MS` (`auto`);
  `_TARGET_US` (`rate`).
- A `gotatun-send-limit` stats line (limit, wake-ups, starved wake-ups, resizes) rides on
  `GOTATUN_AQM_STATS_MS` / `GOTATUN_AQM_STATS_PATH`.
