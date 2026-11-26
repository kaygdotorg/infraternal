<!-- GotaTun's receive-side AQM under a UDP flood from some peers beside TCP from others, at equal offered load (#260, D397, J1249). -->
# GotaTun's AQM in the mixed case: a count cap moves capacity from TCP to the flood

**Job:** J1249, round 2 after J1241 (`research/aqm-latch/2026-11-25/summary.md` on branch `j1241-aqm-latch`), which
left unmeasured what a UDP flood from some peers does to TCP peers behind the same hub socket.
**Measured:** 2026-11-26, 04:25-05:07 UTC, all perf and build locks held on three VMs of one host (backup01).

## Verdict

1. **With many flooding peers, the shipped AQM (uncapped) serves TCP peers best.** With 90 flooders at 1.0 Gbit/s
   it gives TCP **1.05 Gbit/s at p99 20 ms**; with the AQM off TCP gets 0.45 Gbit/s at p99 99 ms.
2. **A cap on CoDel's signal count helps the flooders, not TCP.** In the same case TCP gets 0.59 / 0.88 / 0.98 Gbit/s
   with a cap of 16 / 64 / 256, while flood delivery rises from 19% to 64% / 35% / 24%.
3. **At 2.0 Gbit/s of flood no policy protects TCP.** Ten TCP peers fall from 2.7 Gbit/s to 0.003-0.07 Gbit/s in
   every mode, with 90 flooders and with 10. What the shipped AQM still protects there, with 90 flooders, is delay:
   p99 54-58 ms, against 86-130 ms (cap 256), 0.09-1.2 s (cap 64) and seconds or unanswered probes (cap 16, off).
4. **When 10 heavy peers carry the flood, the policies hardly differ.** At 1.0 Gbit/s the medians are TCP
   0.73-0.82 Gbit/s and p99 14-16 ms. Off is equal or slightly ahead (TCP 0.82 for both, p99 14.0 against 16.2 ms,
   though one repeat had 70 ms) and delivers the whole flood against 86%.
5. **J1241's UDP collapse is confirmed at equal offered load.** At 2.0 Gbit/s from 90 peers the AQM delivers
   0.32 Gbit/s of the flood beside TCP (0.45 with no TCP, one run), AQM off delivers 1.24 (1.26).
6. **The AQM also costs something with no flood at all** in this fixture: TCP 2.71 against 2.91 Gbit/s (-7%),
   CPU 0.369 against 0.343 s per Gbit (+8%), and p99 no better (11.7 against 11.0 ms).

No product change, no change to the fork pin.

## Set-up

| VM | Role | Detail |
|---|---|---|
| infraternal-perf-01 (6 vCPU) | hub | `gotatun-cli`, one process, **pinned to vCPU 2** (eth0 interrupts vCPU 1); TCP sink on 3-4, UDP sink on 5 |
| calternal-perf-01 (4 vCPU) | 10 TCP peers + 1 idle peer | kernel WireGuard, one interface per peer, one cubic upload each, ECN off |
| calternal-perf-02 (4 vCPU) | flooders | J1234's `peersim` (userspace WireGuard, open loop, paced), two processes of 45 peers on their own vCPUs |

- Everything in one network namespace per VM on an ipvlan link, no default route, a drop rule for anything outside the
  VM LAN and for IPv6 (all six counters stayed 0). Tunnel MTU 1390. Flood datagrams carry 1,320 B of UDP payload.
- Engine: fork pin `a0be34f8` plus the measurement switch on fork branch `j1249-aqm-count-cap` (`5a85615`; built
  static musl, ring + mimalloc, sha256 `7712c3a1…`). One binary for every mode: `GOTATUN_AQM` unset (default),
  `=off`, or `GOTATUN_AQM_COUNT_CAP=16|64|256`. The cap spaces signals as `interval / sqrt(min(count, cap))`, so one
  peer gets at most about 400 / 800 / 1,600 signals per second (uncapped: no bound).
- Each cell: fresh engine and sessions, TCP starts, the flood starts about 5 s later, a 20 s window opens 3 s after
  that. 66 matrix cells (3 repeats, mode order rotated), plus 5 calibration cells. No cell failed.
- Round trips: every TCP peer also sends a 64 B request every 10 ms on a second TCP connection, timed from the
  scheduled send. "lost" as a p99 means at least 1% of requests had no answer 3 s after the window.

**Equal offered load** (J1241's caveat): in every cell the flood was sent at exactly 1.000 or 2.000 Gbit/s of payload
and 1.066-1.067 or 2.133-2.134 Gbit/s arrived at the hub's link. The hub's NIC counted no drop in any cell.

## Results

Median of 3, rates in Gbit/s. Every column, with ranges: [`tables.md`](tables.md); every cell: [`cells.csv`](cells.csv).
Raw JSON per cell is attached to #260.

### 90 flooders, 1.0 Gbit/s

| | default | off | cap 16 | cap 64 | cap 256 |
|---|---|---|---|---|---|
| TCP goodput | **1.05** | 0.45 | 0.59 | 0.88 | 0.98 |
| slowest TCP peer, Mbit/s | **72** | 29 | 10 | 15 | 66 |
| TCP peers p99 RTT, ms | 20 | 99 | 20 | 17 | 17 |
| flood delivered | 19% | **96%** | 64% | 35% | 24% |
| total delivered | 1.23 | **1.38** | 1.23 | 1.23 | 1.22 |
| engine CPU-s per delivered Gbit | 0.81 | **0.72** | 0.81 | 0.82 | 0.82 |

### 90 flooders, 2.0 Gbit/s

| | default | off | cap 16 | cap 64 | cap 256 |
|---|---|---|---|---|---|
| TCP goodput | 0.013 | 0.006 | 0.004 | 0.007 | 0.040 |
| TCP peers p99 RTT, ms | **56** | 13,821 | lost | 90 (87-1,194) | 111 |
| idle peer p99 RTT, ms | **57** | 4,289 | 1,854 | 151 | 86 |
| flood delivered | 16% | **62%** | 50% | 39% | 25% |
| total delivered | 0.33 | **1.25** | 1.00 | 0.80 | 0.54 |
| engine CPU-s per delivered Gbit | 3.02 | **0.80** | 1.00 | 1.26 | 1.85 |

The cap 256 TCP figure (0.011-0.072) overlaps the default's (0.004-0.030). Neither is protection.

### 10 flooders

| | 1.0: default | off | cap 16 | cap 256 | 2.0: default | off | cap 16 | cap 256 |
|---|---|---|---|---|---|---|---|---|
| TCP goodput | 0.82 | 0.82 | 0.73 | 0.79 | 0.016 | 0.051 | 0.007 | 0.009 |
| TCP peers p99 RTT, ms | 16 | 14 (14-70) | 16 | 15 | 117 | 120 | 172 | 120 |
| flood delivered | 86% | 100% | 96% | 88% | 70% | 75% | 74% | 72% |
| engine CPU-s per delivered Gbit | 0.60 | 0.56 | 0.59 | 0.60 | 0.71 | 0.65 | 0.67 | 0.69 |

### No flood

| | default | off | cap 16 | cap 256 |
|---|---|---|---|---|
| TCP goodput | 2.71 | **2.91** | 2.69 | 2.72 |
| slowest TCP peer, Mbit/s | 234 | 236 | 166 (99-207) | 229 |
| p99 RTT, ms | 11.7 | 11.0 | 12.7 | 12.5 |
| engine CPU-s per delivered Gbit | 0.369 | **0.343** | 0.371 | 0.367 |

## Reading the numbers

- **Dropping after decryption costs capacity.** The engine used a full vCPU in every cell. A packet the AQM drops
  has already been decrypted, while a packet lost at the full socket buffer costs the engine nothing. So the harder
  the AQM drops, the less the engine delivers in total (0.33 against 1.25 Gbit/s at 90 flooders x 2.0).
- **Why TCP starves at 2.0 (inferred from the counters, not isolated).** All peers share one receive socket. With the
  AQM off or tightly capped it sits near its 14.7 MB limit (median 11.3-11.7 MB queued, 0.9-1.5 million datagrams
  dropped per 20 s), and TCP's packets are tail-dropped with the flood's. With the default the socket drops far less
  (62,000), but the same shared delay puts the TCP peers' own controllers into long episodes: 12.5% of the TCP
  packets judged were dropped. Either loss rate is enough to stall cubic.
- **A count cap is a per-peer rate limit on signals, not a share.** Its effect depends on each flooder's packet rate:
  at 90 peers x 1.0 Gbit/s a flooder sends about 1,050 packets/s, so cap 256 (1,600/s) behaves almost like no cap.

## Answer for D397 (J1241's question)

**Do not cap the count.** With many flooding peers the shipped controller keeps the most TCP goodput (1.0 case, p99
within 3 ms of the best mode) and the lowest delay (2.0 case). With 10 heavy flooders the cap changes little and
never helps TCP; there, and with no flood at all, AQM off is equal or slightly better. This job does not reopen
D397's choice: the sender-side queue it was made for is not what this fixture loads.

The cap's cost is TCP goodput (-43% at cap 16, -16% at cap 64, -6% at cap 256
in the 90 x 1.0 case) and, under heavy overload, delay for everyone including idle peers. What it buys is delivery for
senders that ignore loss.

The case no setting fixes is TCP starving at 2.0 Gbit/s of flood. A fix would have to separate peers **before**
decryption and the shared queue (per-peer admission, or fair dequeue across peers). That is a design question; nothing
here measures such a design.

## Limits

- One engine process on **one vCPU**, which was the bottleneck even without a flood. A hub with more cores, and the
  product's mesh node (packet filter, nft table), were not measured.
- **ECN off** (`tcp_ecn=0`). With ECN-capable TCP the AQM marks TCP instead of dropping it, which may change the
  TCP columns of every AQM mode. Not measured.
- One flooder style: smooth, paced, userspace senders. J1241 saw bursty kernel senders collapse far less.
- Uploads to the hub only, LAN round trips under 1 ms without load (no netem), 20 s windows, 3 repeats, three VMs of
  one physical host (steal at most 0.01 s per window).
- CPU is the engine process's own time; receive interrupt work on vCPU 1 (13-24% busy) is not in it.
- The calibration cells (`calibration-cells.csv`, one run each) are not part of the medians.

## Reproduce

```sh
# Fork: branch j1249-aqm-count-cap, gotatun-cli (ring, mimalloc, static musl).
# peersim: branch j1234-many-peer-hub, research/many-peer-hub/harness/peersim, plus
#   harness/mixed/peersim-underlay.patch. wg: nixpkgs pkgsStatic.wireguard-tools (the .wg-wrapped ELF).
# BIN holds gotatun-j1249, peersim and wg. Copy harness/mixed and ../fair-bench/kit/lock.sh (same
# relative paths) to a frozen folder; the plan file lists LOAD:MODE:SCENARIO:REP lines, then END.
python3 -I harness/mixed/drive.py --out RAW --bin BIN --plan PLAN
python3 -I harness/mixed/summarize.py OUT RAW
```
