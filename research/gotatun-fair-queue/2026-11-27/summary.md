# Per-peer and per-flow fair queue (#260, J1268)

**Result: research only; do not integrate this GotaTun candidate.** In the 8-flow bulk case the fair-queue build reduced throughput by 4.5%, raised p99 by 5.5%, and raised engine CPU per delivered Gbit by 8.3%. The 1-flow p99 improved sharply, but throughput fell by 10.2%. The mixed 90-peer flood case also regressed TCP goodput and both peer p99s. The short keep rule fails before the one-hour soak is considered.

## Candidate and compatibility

The measured fork branch is `j1268-fair-queue` at `e859bf61171669b3c99a91d0ff63bb2ed476d426`, based on the required baseline `28c9195fa260ff1187f7d072f4b5747f3a5cb820`. It adds a bounded, two-level DRR queue at the GotaTun TUN writer: one scheduling level per authenticated peer and another per inner flow, with FIFO order within each flow. It bounds total, per-peer and per-flow bytes and limits flow state. The key is an opaque `u64` carried with the peer's authenticated packet run; the TUN writer does not interpret it. That seam remains compatible with J1269's proposed split before decryption, which can pass the same peer identity while flow classification remains a later stage.

The fork commits are `cc621f3` (queue), `2c04368` (bounded ready intake), and `e859bf6` (formatting). The Infraternal source head used for the run was `b792d2e30a3e41a8c2e5461207147ab1d1a899de`.

## Measurement

One locked batch on 2026-11-27 compared the baseline and fair candidate on the x86_64 perf VMs. The hub ran in `perf.slice` on CPUs 1–3. The direct suite used one 30-second paired ABBA hold at one and eight TCP flows. The same hold then ran four mixed cells in `base, fair, fair, base` order: ten bulk TCP peers plus one probed idle peer alongside 90 paced UDP flood peers offered 1.0 Gbit/s. Each mixed result is a 20-second window; the summaries include the two samples per arm.

The fixtures ran only in their job namespaces. The direct pair used two veth-connected namespaces. The three-VM mixed fixture used namespace-local ipvlan links, no default route, and a namespace egress guard. All six outside-LAN/IPv6 counters remained zero, all engines stayed alive, and no probe was lost. The `perf-run` wrapper exited 0 after 782.194 seconds; steal was 2 of 468,759 jiffies. Initial loads were low. The TCP VM clock offset was +0.5403 s, so the scheduled mixed window has up to that much cross-host start skew; base and fair cells were interleaved in the same hold.

The detailed direct and mixed tables are in [direct-summary.md](direct-summary.md) and [mixed-summary.md](mixed-summary.md). Per-cell mixed measurements are in [cells.csv](cells.csv); host setup, offsets and guard counters are in [meta.json](meta.json).

## Results and keep decision

| Case | Baseline | Fair queue | Change |
|---|---:|---:|---:|
| 1 flow throughput | 3.45 Gbit/s | 3.10 Gbit/s | -10.2% |
| 1 flow p99 | 8.27 ms | 1.89 ms | -77.1% |
| 1 flow CPU/Gbit | 0.547 s | 0.611 s | +11.6% |
| 8 flows throughput | 3.40 Gbit/s | 3.24 Gbit/s | -4.5% |
| 8 flows p99 | 57.78 ms | 60.95 ms | +5.5% |
| 8 flows CPU/Gbit | 0.556 s | 0.602 s | +8.3% |
| Mix90 TCP goodput | 1.068 Gbit/s | 0.965 Gbit/s | -9.6% |
| Mix90 TCP p99 | 16.8 ms | 19.5 ms | +16.1% |
| Mix90 idle-peer p99 | 16.8 ms | 19.7 ms | +17.3% |
| Mix90 CPU/delivered Gbit | 0.783 s | 0.859 s | +9.7% |

Fair scheduling raised the slowest TCP peer's goodput from 54.5 to 72.7 Mbit/s in the mixed case, but aggregate TCP goodput fell and the TCP and idle-peer p99s rose. This is not enough to keep the candidate: the target 8-flow p99 regressed, throughput loss exceeded the 3% limit, and CPU/Gbit increased. The direct suite has one ABBA pair and the summary does not establish a valid A/A noise verdict, so these numbers are descriptive rather than a statistical claim. The direction of the mixed result is consistent with the direct 8-flow result.

The single-ABBA hold fails the short keep rule; no one-hour soak was run. It also does not claim to satisfy the full D348 R4b matrix. Recommendation: merge this report as research only and leave the GotaTun fork code out of the product branch. If kayg wants another iteration, first change one scheduling cost or service-budget hypothesis, then require a fresh 8-flow p99 win with at most 3% throughput loss and no regression in the mixed case before spending on a soak.

## Questions for kayg

- Should the current GotaTun implementation remain available for a retune? Recommendation: keep it on the fork for reference, but do not integrate it; its primary 8-flow and mixed targets both moved the wrong way.
- Is another tuning pass worth a new hold? Recommendation: defer until there is a specific, materially different hypothesis. Repeating the same implementation would not resolve the missing keep-rule win, and the current single hold does not justify a one-hour soak.

## Harness notes

Two setup attempts before this final batch produced no benchmark traffic. The complete batch succeeded after rebuilding the helper simulator with the existing [`peersim-underlay.patch`](../../aqm-latch/harness/mixed/peersim-underlay.patch); the helper source had previously been compiled without that patch and ignored `PEERSIM_UNDERLAY`. The final driver exited 1 only during post-run summarization because this engine's AQM log omits the optional `seen_tcp` and `drops_tcp` fields. All four raw mixed-cell JSON files were present; the scratch summarizer was adjusted to omit that unavailable metric, not to treat it as zero. The reported AQM aggregate counters and latency metrics come from those same raw cells.
