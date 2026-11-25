<!-- Does GotaTun's receive-side loss control latch after overload? Confirm or refute with TCP (#260, J1241). -->
# GotaTun loss-control "overload latch": refuted

**Job:** J1241 · **Question:** J1234 finding 4 (`research/many-peer-hub/2026-11-25/summary.md` on branch `j1234-many-peer-hub`):
after 100 UDP senders overload a hub, the receive-side CoDel controller "stays in that state", and later 390 Mbit/s steps
lose 35-94%. Does that happen with TCP, and can the controller stay in a drop state after load falls?

**Verdict: no latch.** In every run here, TCP or UDP, AQM on or off, the traffic after the overload was delivered in
full from the first phase (started 1 s after the overload ended). No product change and no fork change.

## 1. The state machine has no state that outlives the congestion

`gotatun/src/aqm.rs` at the fork pin `a0be34f8` (`Codel::should_signal`, one `Codel` per peer):

| Event | What is cleared |
|---|---|
| A packet's sojourn below target (1 ms) | everything (`*self = Codel::default()`) |
| A gap between above-target observations longer than the interval (10 ms), or a drain seen by age or by receive stamp | deadline, signal count, owed signals |
| An age that is negative or over 1 s | everything |

The signal count, which sets the drop rate, is therefore never carried across a silence longer than 10 ms. There is no
timer and no hysteresis. The only thing kept after a drain is byte credit for frames of 256 bytes or less, and credit can
only exempt a packet, never drop one. A drop state persists only while the sojourn stays at 1 ms or more, which means
packets really are still waiting.

## 2. Why J1234's rows looked like a latch

Re-read from the committed raw rows (`raw/out-*/rows-*.csv`, 130 `send_*` rows):

- **The lossy 390 Mbit/s step needs no overload before it.** At 10 peers (r2, r3) the steps before it are clean (the
  hub carried 2.08 Gbit/s with no loss) and `send_10_400mbit` still loses 35.0%. At 100 peers it loses 34.5% and 35.1%.
  r1, with the older driver, loses nothing at 10 and 100 peers.
- **It tracks the load generator's CPU.** The simulator spin-paces on the one CPU it shares with its sink. Clean 390
  Mbit/s rows use 8.01 s of simulator CPU (median); every lossy one uses 8.68-9.90 s, while the **hub** uses less CPU
  than in a clean row (2.2-4.4 s against about 5.7 s).
- **Part of the loss is in front of the hub.** At 1,000 peers (r2) the hub's `Udp.InDatagrams` is 409,717 in the lossy
  row against 762,198 in the clean row of the same offered rate.
- **The AQM-off comparison was not like for like.** The `aqmoff` run repeated only the `send_100_*` steps. There is no
  AQM-off row for `send_10_400mbit`.

The most likely cause is the harness (simulator and sink competing for one CPU). That is an inference from these
counters; the exact drop point inside that harness was not instrumented here.

What is real in J1234: during the **max** step, 100 open-loop UDP senders never slow down, so the sojourn never falls
below target and the controller keeps dropping for as long as the overload lasts. It drops after decryption, so the
drops do not relieve the hub.

## 3. Measured: overload, then recovery

Set-up (`harness/run.py`): two network namespaces joined by a veth with no default route; the GotaTun CLI of fork
`a0be34f8` as the hub, pinned to **one** CPU; 100 kernel WireGuard interfaces as peers, each with its own `iperf3`
client; phases of 8 s. Host: compute01, a shared build VM at load 20-32, run as a root proof. **Absolute throughput from
this host is noisy and is not a performance number**; the pass/fail question (does the paced load come back in full?) is
not sensitive to it.

TCP, three interleaved repeats per mode (`compute01-repeats.jsonl`), delivered Mbit/s, median (min-max):

| Phase | AQM default (ECN mode, Not-ECT traffic, so it drops) | AQM off |
|---|---|---|
| 10 flows x 39 Mbit/s before | 390.5 (390.5-390.5) | 390.5 (390.4-390.5) |
| 100 unpaced flows (overload) | 567 (499-647) | 671 (387-679) |
| 10 x 39 Mbit/s, 1 s after | **390.4 (390.4-390.5)** | 390.5 (390.4-390.5) |
| 1 unpaced flow, after | 1751 (1361-1844) | 1928 (1207-2057) |
| 1 unpaced flow, fresh engine | 1983 (1864-2286) | 1281 (1068-1377) |

The single-flow rows overlap and swap order between modes; they show no after-overload penalty and support no other
claim.

UDP, 100 x 30 Mbit/s offered as the overload, then 10 x 39 Mbit/s:

| Run | Paced loss 1 s after | Paced loss 5 s after (after post1) |
|---|---|---|
| AQM default, run 1 | 0.00% | 0.00% |
| AQM default, run 2 | 0.00% | 0.27% |
| AQM off | 0.00% | 0.00% |

The engine's own counters (`GOTATUN_AQM_STATS_MS=500`, `tcp-overload.aqm.txt`, `udp-overload.aqm.txt`) show the same
thing from inside: drops stop within one 0.5 s sample of the end of the overload and the mean sojourn returns from tens
of milliseconds to 0.03-0.2 ms (one UDP sample reads 0.7 ms).

During the UDP overload both modes lose most of the offered load (56-67% by the clients' count). Many `iperf3` UDP
clients lost their control connection and never reported, so these runs cannot rank AQM on against off during UDP
overload.

## 4. Limits

- Not a rerun of J1234's own simulator. It uses real kernel WireGuard peers and TCP, which is what the question asked.
- 100 peers, not 4,096. The controller is per peer and the state machine above does not depend on the peer count.
- One veth, no netem: round trips are well under a millisecond.
- The numbers are from a loaded build VM. `harness/matrix.sh` repeats the matrix on the perf VM.

## 5. Recommended follow-ups

1. Correct J1234 finding 4 before anyone acts on it.
2. If the many-peer harness is used again for loss figures, give the sink its own CPU, record what the simulator really
   sent, and run every step in both AQM modes.
3. Open question for a separate job: whether drop-based signalling should apply to unresponsive UDP at a CPU-bound hub,
   where a drop after decryption saves little. That is a design question (D397), not a bug found here.

## Reproduce

```sh
# gotatun-cli from the fork pin; static iperf3 and wg from nixpkgs pkgsStatic. Root, build VM or perf VM only.
perf-run --root -- harness/matrix.sh /home/claude/j1241/out/m1      # perf VM: binaries in bin/ beside the script
python3 harness/run.py --hub BIN/gotatun --iperf BIN/iperf3 --wg BIN/wg --out DIR --tag t --proto tcp \
  --flows 100 --secs 8 --hub-cpus 0 --server-cpus 2 --client-cpus 3-7 --phases base,overload,post1,single
```
