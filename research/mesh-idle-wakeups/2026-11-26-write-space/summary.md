# Mesh socket wakeups after peers connect: the write-space events (#260, J1255)

Follow-up 1 of J1253 (`../2026-11-26/summary.md`). Harness: J1253's, unchanged (`../harness/`).

## Change

tokio registers a UDP socket for readability and writability, edge triggered. Linux reports write
space each time it frees a datagram the socket sent, so every datagram sent woke the parked engine
worker. GotaTun fork `28c9195` (one commit on `0853f42`) registers the Linux and Android socket for
readability only. A send runs its system call at once; only on `EWOULDBLOCK` is a second descriptor
of the socket registered for writability, until that send goes through
(`gotatun/src/udp/socket/read_watched.rs`). macOS and Windows are unchanged.

## Rows

- **dev** = origin/dev `07e307f28` (J1253 merged; fork `0853f42`).
- **head** = `10d99ca38` (fork `28c9195` plus a node test). The final head `bbc25f053` differs by
  one `mut` removed in that test; product code is identical.
- Idle matrix on infraternal-perf-01 (x86_64): one `perf-run --root` hold of 81 minutes, steal 0,
  plus a 12-minute hold repeating the realistic cell (`perf/`, `perf/repeat/`,
  `perf/machine-state/`, driver `scripts/`). Hub test binaries sha256: dev `087d7a6e…`, head
  `9eef8767…`, peer simulator `752d7564…`.
- Throughput and p99: the cross-VM product kit (J1204's `kit-macro` as J1252 ran it),
  calternal-perf-01 and infraternal-perf-01, static x86_64 musl `infraternal`: dev `68c29955…`,
  head `bf7d9628…` (33,908,856 -> 33,914,104 bytes, +5,248).

## Where the wakeups came from, before and after

`perf record -e sched:sched_waking`, 4,096 connected silent peers, two 10 s recordings per build,
compute01 (shared host: shares are the evidence here, not rates) (`attribution/`).

| Source | dev t=20 | dev t=40 | head t=20 | head t=40 |
|---|---:|---:|---:|---:|
| socket write space (a sent datagram was freed) | 610 (91%) | 535 (95%) | 0 | 0 |
| eventfd write (tokio unpark) | 28 | 15 | 22 | 27 |
| timerfd (timer task deadline) | 13 | 8 | 10 | 8 |
| futex (thread hand-off) | 12 | 5 | 9 | 5 |
| hrtimer, TUN | 6 | 1 | 5 | 0 |
| total | 669 | 564 | 46 | 40 |

## Idle wakeups (perf VM)

Wakeups are voluntary context switches per second over every thread of the hub, mean of the whole
run. "sent" counts UDP datagrams the hub sent.

| Scenario | Peers | wakeups/s dev | head | change | CPU % dev | head | sent dev | head |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| connected, silent (200 s, 2 runs each) | 1,000 | 20.3 / 21.3 | 3.6 / 3.5 | -83% | 0.13 / 0.13 | 0.12 / 0.11 | 8,496 / 8,497 | 8,498 / 8,499 |
| connected, silent (200 s, 2 runs each) | 4,096 | 87.2 / 88.0 | 22.7 / 22.3 | -74% | 0.84 / 0.83 | 0.80 / 0.77 | 40,840 / 40,444 | 40,857 / 40,453 |
| realistic peers (150 s) | 1,000 | 36.1 | 22.4 | -38% | 0.08 | 0.07 | 4,044 | 4,041 |
| realistic peers (150 s, 3 runs each) | 4,096 | 86.2 / 81.8 / 82.7 | 60.6 / 61.7 / 68.5 | -24% | 0.23-0.25 | 0.21-0.25 | 12,600-16,630 | 13,582-18,656 |
| after traffic (90 s) | 1,000 | 26.9 | 1.3 | -95% | 0.06 | 0.03 | 4,000 | 4,000 |
| after traffic (90 s) | 4,096 | 39.3 | 2.2 | -94% | 0.22 | 0.19 | 16,384 | 16,384 |
| peers send 25 s keepalives (90 s) | 1,000 | 23.0 | 22.1 | -4% | 0.11 | 0.12 | 870 | 756 |
| peers send 25 s keepalives (90 s) | 4,096 | 40.6 | 27.1 | -33% | 0.28 | 0.28 | 7,341 | 7,398 |
| offline (180 s from apply) | 1,000 | 13.4 | 1.3 | -90% | 0.28 | 0.24 | 5,702 | 5,318 |
| offline (180 s from apply) | 4,096 | 58.3 | 3.8 | -93% | 1.13 | 1.07 | 23,424 | 22,699 |
| offline, 2 candidates | 1,000 | 31.9 | 2.4 | -92% | 1.12 | 1.09 | 12,644 | 12,762 |
| offline, 2 candidates | 4,096 | 161.7 | 27.5 | -83% | 11.39 | 11.29 | 57,523 | 58,205 |

- **The connected-silent row splits in two.** Until t = 170 s (keepalives only): 4,096 peers
  76.3 / 77.3 -> 4.8 / 5.7 per second (-93%), 1,000 peers 19.5 / 19.0 -> 1.7 / 1.7 (-91%). From
  t = 170 s every keepalive-only session expires and re-handshakes: 149 / 149 -> 125 / 117 at 4,096.
  That wave is most of what is left in the 200 s mean.
- **J1253's open row** (4,096 connected silent, 7-12% more wakeups after J1253): both dev runs
  reproduce it (87.2 / 88.0 against J1253's 88.5; J1253's older base was 78.7, not rebuilt here).
  Those extra wakeups were write-space events and are gone.
- What still wakes the hub with realistic or keepalive-sending peers is datagrams arriving
  (realistic 4,096 receives about 164/s), which is work to do.
- Realistic 4,096 datagram counts differ run to run in both builds (dev 12,600 / 16,630 / 13,774,
  head 18,656 / 13,582 / 17,322); the ranges overlap.
- Offline 1,000 and 4,096: head's smaller "sent" is all in the first window (initiations that left
  during the apply are not counted); every retry round after it sends the same number.

## Throughput and p99 (cross-VM, 1 and 8 flows)

Four holds on the two VMs, 64 windows of 60 s, cubic, all exit 0, 0 probes lost, guard counters
0 packets (`kit/windows.csv`, `kit/rows.csv`, `kit/udp-counters.csv`). Row order (I = dev, H =
head): `m1` H I I H and `m2` I H H I, both directions; `m3` I H H I H I I H, reverse only; `m4`
H I I H H I I H, forward only. Paired deltas are `../../gotatun-hasher/macro_pairs.py` (median over
holds; A/A gap = largest gap between two rows of the same build in one hold; for `m3` and `m4` it
compares the first two such rows). p99 is the 64 B round trip under load, median over the 8 windows
of each build, with their range.

| cell | holds | Gbit/s dev | head | change | CPU s/Gbit dev | head | change | A/A gap Gbit/s, CPU | p99 ms dev | p99 ms head |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|
| forward, 1 flow | 3 | 3.079 | 3.109 | +1.0% | 1.209 | 1.193 | -1.2% | 0.5%, 1.5% | 9.15 (8.25-10.06) | 8.83 (8.08-10.23) |
| forward, 8 flows | 3 | 3.157 | 3.186 | +1.0% | 1.241 | 1.217 | -2.1% | 0.6%, 2.7% | 12.16 (11.77-12.67) | 12.17 (12.01-12.60) |
| reverse, 1 flow | 3 | 3.317 | 3.323 | +0.1% | 1.027 | 1.020 | -1.6% | 1.0%, 1.7% | 4.70 (4.47-5.16) | 4.83 (4.29-5.19) |
| reverse, 8 flows | 3 | 3.296 | 3.303 | +0.2% | 0.991 | 0.988 | -1.6% | 1.0%, 5.9% | 7.38 (7.16-7.99) | 7.40 (7.13-7.65) |

- **No cell is slower.** Forward throughput is 1.0% higher, a little over the A/A gap. p99 ranges
  overlap in every cell.
- **The blocked-send path ran under load.** Node A (the forward sender) counted 232-312 send-buffer
  errors (`EWOULDBLOCK`) per row with a forward 8-flow window, about the same on both builds.
- **Receive-buffer drops, not explained:** in `m1` and `m2` the second head row (`H.2`) lost 186 and
  880 datagrams in node A's receive buffers, of about 40 million received in the row; no dev row
  did. `m1` and `m2` counted per row only, so the window is unknown. 8 further head rows with
  per-window counters (`m3` reverse, `m4` forward) had none, nor did the other head rows. In all:
  head 2 rows of 12, dev 0 of 12.

## Pins

- Fork: `a_bound_socket_is_registered_for_readability_only`,
  `a_blocked_send_watches_writability_only_while_blocked`, `two_blocked_sends_both_finish`,
  `a_cancelled_blocked_send_leaves_no_watch`. The blocked cases use a real `EWOULDBLOCK` (a unix
  datagram pair behind the socket type, because loopback UDP never blocks).
- Node: `mesh_sockets_are_registered_for_readability_only` (main and side socket, from
  `/proc/self/fdinfo`). On dev it fails: `main socket is watched for writability: [8000201d]`.

## Limits and follow-ups

- Peers are simulated behind a veth; a real NIC frees sent datagrams in batches, so the saving per
  datagram will differ.
- One run per cell on the perf VM except connected silent (2) and realistic 4,096 (3).
- macOS (kqueue) keeps its write registration; not measured.
- Android: the fork change covers it; no Android build was made here.
- The relay's loopback shim sockets (`relay_path.rs`) are still registered for writability and
  never wait for it. Only relayed traffic reaches them; not measured.
- The 180 s re-handshake wave is now the largest idle cost of a hub with silent peers.
