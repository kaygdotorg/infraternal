<!-- Locked authorized-VM performance evidence for the initiating TCP checks [242], #173. -->
# Round 5 performance

Machine `infraternal-perf-test`, kernel `6.12.69+deb13-amd64`, 4 CPUs; one-minute load across apply samples 0.20–2.66. All runs held `/var/lock/perf-bench.lock` under `systemd-run --user --scope -p CPUWeight=10000`. Builds and transfers ran outside the lock. Only this VM supplies performance numbers.

Baseline is merged pre-repair `c89fe001`; head production code is `94342e78` (repairs `2b02a2d5` / `b6d51a7f`). Both use the unchanged optimized release profile. Artifact/code hashes and source equality are retained in adjacent files. The coordinator is the unchanged production fixture retained in the preceding round.

All 24 coordinator-change proofs and 32 apply cohorts pass. Apply order is base/head/head/base (12 rounds/cohort), then head/base/base/head (36 rounds/cohort), with narrowing and widening each round. Each candidate/backend/count has 384 per-node timings in the combined sample. No samples or initial campaign results were discarded.

| Frontend | Installed peers/node | First order median shift | Reverse order median shift | Combined base → head (µs/node) | Combined shift |
| --- | ---: | ---: | ---: | ---: | ---: |
| nft | 10 | +7.05% | +0.12% | 27858.5 → 28089 | +0.83% |
| nft | 1000 | -0.66% | -0.28% | 50152.5 → 49433.5 | -1.43% |
| compat | 10 | +2.06% | -0.15% | 184145 → 184190 | +0.02% |
| compat | 1000 | +2.16% | -1.58% | 185106 → 184800 | -0.17% |

The original positive shifts are retained. Reverse ordering reduces the nft 10-peer shift from +7.05% to +0.12% and changes both compatibility shifts to improvements. Combined changes range from −1.43% to +0.83%; the compatibility 10-peer difference is +45 µs/node. Cohorts overlap. These samples show no repeatable material apply slowdown; they do not prove zero cost or a tail-latency improvement. The initiating-SYN checks are required for D242 correctness.

The following is change-at-coordinator to the last of the two live receivers acknowledging refusal (milliseconds). Both persistent TCP and UDP deliveries are checked in both address families, and post-acknowledgment continuation is refused. Each cell is one complete run; this table is not a latency percentile.

| Frontend | Installed peers/node | Change | Local | 150 ms RTT |
| --- | ---: | --- | ---: | ---: |
| nft | 10 | RuleRemoval | 41.23 | 137.69 |
| nft | 10 | PeerRetirement | 57.45 | 143.41 |
| nft | 10 | DefaultTightening | 51.47 | 107.15 |
| nft | 1000 | RuleRemoval | 125.38 | 207.18 |
| nft | 1000 | PeerRetirement | 139.99 | 220.00 |
| nft | 1000 | DefaultTightening | 958.07 | 6037.02 |
| nf_tables | 10 | RuleRemoval | 259.81 | 259.16 |
| nf_tables | 10 | PeerRetirement | 337.93 | 429.34 |
| nf_tables | 10 | DefaultTightening | 264.10 | 348.39 |
| nf_tables | 1000 | RuleRemoval | 237.94 | 383.23 |
| nf_tables | 1000 | PeerRetirement | 441.69 | 496.92 |
| nf_tables | 1000 | DefaultTightening | 1071.69 | 6138.87 |

The 1,000-peer/150 ms default-tightening result remains roughly six seconds: full snapshots pass through existing bounded chunk delivery. This was present in the preceding round and remains a delivery finding; no instantaneous coordinator-to-all-node claim is made.

Scale limitation: three live nodes, two receivers. The additional peers are synthetic public keys installed and counted in each kernel, rather than 1,000 independent live workers. Peak node-fixture RSS across change cases is 8,409,088 bytes/node × 1,000 = 8,409,088,000 bytes projected across nodes. This is the mesh fixture, not the complete infraternal host daemon. Raw node/coordinator RSS, measured underlay RTT, per-node acknowledgment times, kernel counts and load are preserved in `performance-summary.json` and `performance/`.

Raw dumps remain in files. Both campaigns, including all per-sample records, are preserved in checksum-recorded archives; no captured payloads or secrets are included.
