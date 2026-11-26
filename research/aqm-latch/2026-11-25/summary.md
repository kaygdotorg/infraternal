<!-- Does GotaTun's receive-side loss control latch after overload? Confirm or refute with TCP (#260, J1241). -->
# GotaTun loss-control "overload latch": no latch, but a real UDP overload collapse

**Job:** J1241 · **Question:** J1234 finding 4 (`research/many-peer-hub/2026-11-25/summary.md` on branch
`j1234-many-peer-hub`): after 100 UDP senders overload a hub, the receive-side CoDel controller "stays in that state",
and later 390 Mbit/s steps lose 35-94%. Does that happen with TCP, and can the controller stay in a drop state after
load falls?

## Verdict

1. **No latch.** The controller cannot stay in a drop state after load falls. In every run here, TCP or UDP, the traffic
   after an overload arrived in full, and the engine counted no drop and no CE mark in any later step.
2. **TCP does not collapse.** Under a 100-flow TCP overload on the perf VM the hub delivered more with the AQM than
   without it.
3. **J1234's collapse during the overload is real, and the AQM causes it.** With J1234's own harness, 100 open-loop UDP
   senders get 161 Mbit/s of 2.4 Gbit/s through, and the engine's counters show CoDel dropping 92.6% of the packets it
   judged. It lasts exactly as long as the overload.
4. **J1234's lossy 390 Mbit/s rows did not reproduce.** Cause unknown.

No product change and no fork change: there is no latch to fix, and bounding the drop rate is a design choice (D397).

## 1. The state machine

`gotatun/src/aqm.rs` at the fork pin `a0be34f8` (`Codel::should_signal`, one `Codel` per peer):

| Event | What is cleared |
|---|---|
| A packet's sojourn below target (1 ms) | everything (`*self = Codel::default()`) |
| A gap between above-target observations longer than the interval (10 ms), or a drain seen by age or by receive stamp | deadline, signal count, owed signals |
| An age that is negative or over 1 s | everything |

The signal count, which sets the drop rate, is never carried across a silence longer than 10 ms. There is no timer and no
hysteresis. The only thing kept after a drain is byte credit for frames of 256 bytes or less, which can only exempt a
packet. A drop state persists only while the sojourn stays at 1 ms or more.

**While it does stay there, nothing bounds the drop rate.** Signals are spaced `interval / sqrt(count)` apart and `count`
rises with each one, so after `t` seconds of unbroken above-target sojourn the rate is about `t / (2 * interval^2)`:
about 5,000 signals per second per peer after 1 s, growing. A sender that reacts to loss slows down and the episode
ends. A sender that does not is, after a fraction of a second, losing nearly every bulk packet.

## 2. Overload and recovery, perf VM (quiet, under `perf-run --root`)

Set-up (`harness/run.py`, `harness/matrix.sh`): two network namespaces joined by a veth with no default route; the
GotaTun CLI of fork `a0be34f8` as the hub, pinned to one CPU; 100 kernel WireGuard interfaces as peers, one `iperf3`
client each; 10 s phases. Raw rows: `perf-vm/matrix.csv`, `perf-vm/single-flow.csv`.

| Phase (delivered Mbit/s) | TCP, AQM default | TCP, AQM off | TCP with ECN, default | UDP, default | UDP, off |
|---|---|---|---|---|---|
| 10 flows x 39 Mbit/s | 390 | 390 | 390 | 390 | 390 |
| 100 flows, overload | 1406 | 807 | 936 | 1773 (27% lost) | 1850 (24% lost) |
| 10 x 39, 1 s after | **390** | 390 | **390** | **390 (0% lost)** | 390 |
| 10 x 39, after 5 s more idle | 390 | 390 | 390 | 390 | 390 |
| 1 flow (UDP: 600 offered) | 2641 | 3770 | 3530 | 600 | 600 |
| 10 x 39, after 10 s more idle | 390 | 390 | 390 | 390 | 390 |

Engine counters (`perf-vm/*.aqm.txt`): drops or marks stop within 0.4 s of the overload clients exiting and stay at zero
through all later phases.

The 2641 single-flow cell is not an AQM cost: that phase had no drop and no mark. Three repeats each of "fresh engine"
and "after overload" (`single-flow.csv`), delivered Mbit/s, median (min-max):

| | AQM default | AQM off |
|---|---|---|
| Single flow, fresh engine | 3482 (2579-3540) | 3575 (3161-3607) |
| Single flow, after overload | 3666 (3253-3712) | 3607 (2704-3780) |
| The 100-flow TCP overload before it | **1513 (1439-1633)** | 1020 (940-1242) |

The low values (2579, 2704) occur in both modes, with the hub CPU not full.

Three more repeats on compute01, a loaded build VM (`compute01-repeats.jsonl`; noisy, not performance numbers), agree on
recovery: 390.4-390.5 Mbit/s 1 s after the TCP overload in all six runs.

## 3. J1234's own harness, same perf VM

Built from J1234's `hub-bench.patch` on `de6f9dce6` (fork pin `e87fef91`) and its `peersim`; run by its `run.py`.
`harness/j1234-recheck.sh` (10 and 1,000 peers, 1 and 10 senders, 3 s idle windows) and `harness/j1234-recheck2.sh`
(1,000 peers, 1, 10 and 100 senders, J1234's defaults). Rows: `j1234-harness/send-rows.csv`.

1,000 peers, 100 senders, unpaced step:

| Run | Offered | Delivered | Loss | Hub CPU (of about 22 cpu-s) |
|---|---|---|---|---|
| AQM as shipped, counters off | 2404 | 161 | 93.3% | 13.5 |
| AQM as shipped, counters on | 2400 | 162 | 93.3% | 13.5 |
| AQM off | 1853 | 1853 | 0.0% | 16.9 |

From the counters of the second run (`stats-n1000.aqm.txt`): 1,961,256 of 2,119,050 judged packets dropped (92.6%). The
share per 0.5 s sample climbs 23%, 73%, 84%, 89%, 92% and settles at 97%, and the mean sojourn per sample stays near
23 ms after the first. That fits an episode that never ends (the counters log means and maxima, not the minimum). The
next step (975.6 Mbit/s) has **no drop at all**.

- **Dropping does not relieve this overload.** The drop happens after decryption, the senders are open loop, and the
  standing delay does not move.
- **The AQM-on and AQM-off rows do not carry the same load.** The simulator and the sink share one CPU. When the hub
  drops, the sink idles and the simulator sends faster (2.4 against 1.85 Gbit/s). The AQM-off row never overloaded the
  hub, so "off delivers 1.8 Gbit/s" overstates the gap. The 93% drop share under AQM is measured and does not depend on
  that comparison. The extra offered load may be what keeps the delay pinned.
- **The same traffic through kernel peers did not collapse** (section 2, UDP: 27% lost with the AQM against 24%
  without, about 5% dropped by CoDel). The counters there show a median sojourn of about 29 ms too; the likely
  difference is that bursty senders let the delay dip below target and reset the count. That was not isolated.
- **The 10-sender unpaced step loses about half in both modes** (47.6% and 55.3% with the AQM, 49.3% without, in the
  second script; 0% in the first). With the counters on, that step shows no AQM drop. It is not this controller.
- **`send_10_400mbit` lost nothing** in all seven runs here (four with the AQM, three without; 10 and 1,000 peers).
  J1234's r2 and r3 saw 35% at 10 and 100 peers and 93-95% at 1,000. Not reproduced, and 100 peers was not rerun; cause
  unknown.

## 4. Limits

- 100 peers in section 2 and one hub CPU; no netem, so round trips are well under a millisecond.
- No run mixed an unresponsive UDP overload with TCP peers. The controller is per peer but the UDP socket queue is
  shared, so TCP peers behind such a flood would see the same sojourn. Whether they are starved is **not measured**.

## 5. Recommended follow-ups

1. Correct J1234 finding 4: not a latch; a collapse that lasts while open-loop senders overload the hub.
2. A design job (owner's choice, D397) on bounding the drop share when drops do not shorten the delay, for example a
   cap on `count`. First measure the mixed UDP-flood-plus-TCP case, with equal offered load in both AQM modes.
3. In the many-peer harness, give the sink its own CPU so the offered load does not depend on what the hub drops.

## Reproduce

```sh
# gotatun-cli from the fork pin; static iperf3 and wg from nixpkgs pkgsStatic; binaries in bin/ beside the script.
perf-run --root -- harness/matrix.sh OUTDIR
perf-run --root -- harness/single.sh OUTDIR
perf-run --root -- harness/j1234-recheck2.sh OUTDIR     # binaries and run.py in j34/ beside the script
```
