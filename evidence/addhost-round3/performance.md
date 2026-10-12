<!-- Pinned-VM setup-step and bounded-admission measurements for host provisioning round 3, #169. -->
# Performance evidence

Source: `a3f9e7c9`; static payload source includes all production repairs through `2481499a` (later commits change fixtures only). Measurements use `netbird ssh --no-browser root@10.69.69.208`, serially under `flock /var/lock/perf-bench.lock`, with a disposable Docker systemd target and the real standalone network-SSH server fixture. Machine `infraternal-perf-test`, Linux 6.12.69, 4 cores. Debug controller test image, stripped static release host payload 20,132,112 bytes; these are setup diagnostics, not a release-controller latency budget or a controlled comparison against an older build.

The ten undelayed and five 150ms-RTT runs all pass. Delay is 75ms each direction in the owned target namespace; no host load generators. The local link has no imposed delay. Only the owned controller addresses 4929/4930 and disposable target are used. Raw logs are in `perf/`; capabilities stay in private pipes, never logs or argv. Previous shared-build-host measurements are superseded as performance evidence.

| Setup step | Undelayed range, ms (n=10) | 150ms RTT range, ms (n=5) |
| --- | ---: | ---: |
| network_discovery | 63.221–77.748 | 1267.396–1281.219 |
| check | 69.204–91.717 | 356.553–418.951 |
| invitation | 3.375–4.164 | 3.218–6.650 |
| payload_lookup | 43.294–112.137 | 348.198–389.935 |
| upload | 236.149–404.228 | 2789.698–2868.900 |
| join | 115.017–157.975 | 1012.672–1129.041 |
| install | 79.807–110.916 | 378.756–473.868 |
| start | 157.025–205.643 | 470.521–555.229 |
| linger | 37.915–48.627 | 344.345–396.232 |
| facts | 2.263–12.440 | 153.121–156.480 |
| readiness | 15.215–51.052 | 332.226–376.983 |
| commit | 28.249–79.848 | 341.145–396.262 |
| authority_commit | 0.523–0.796 | 0.547–0.931 |

| Profile | Completion range, ms | Median, ms | Initial one-minute load range |
| --- | ---: | ---: | ---: |
| local | 2010–2566 | 2355.5 | 1.05–1.71 |
| delay | 8915–10022 | 9984.0 | 1.23–1.81 |

Both injected-install-refusal retries pass and send one accepted file input of 20,132,112 bytes, then reuse the verified payload without a second file input: avoided 20,132,112 bytes per retry. Reuse is 147.080ms undelayed and 510.608ms delayed. These are single observed samples, not percentile or speedup claims. Initial loads 1.38 and1.40; `perf/retry-{local,delay}.log`.

The foreign-base refusal retains the foreign file, retires only the new host record (active 1, prior 1), leaves 0 infraternal processes and 0 private session scopes. Retirement acknowledgement 0.049ms; the synchronous fence/owned writer started before this wait, so this is not total transaction latency. `perf/foreign-refusal.log`.

Bounded destination admission at1,600 pending hosts: 100 samples of 8 simultaneously held reservations each, 800 requests all refused, map capacity 1,792, inline Attempt 136 bytes ×1,600=217,600 bytes (or243,712 bytes at map capacity), string capacity91,200 bytes. Controller RSS baseline 28,184KiB, held 29,156KiB, delta 972KiB (~622 bytes/pending host; includes allocator/container overhead). The inline retirement handle adds 8 bytes/attempt relative to the former 128-byte layout:12, 800 bytes at1,600 hosts,14,336 bytes at allocated capacity. Each sample times all 8 operations: p50=16.379ms, p99=49.079ms, not per-host latency. 4-core VM load 1.48/1.05/0.76; `perf/admission.log`. No new idle periodic work is introduced; retirement retries exist only while a failed host record awaits a writer.

The original review writer-contention regression and separate-file/two-connection SQLite BUSY regression pass on the VM (1/1 each). Functional native repetitions retain their original assertions and are not timing evidence. This suite 21/21 plus initial real OpenSSH smoke 1/1 completes. No browser timing or physical-iPhone performance claim is made.

Reproduction: ship the compiled controller test executable, its matching loader/libraries and static payload; hold the shared lock and invoke `docs/verification/addhost-round3/perf-run.sh`. The controller wrapper `perf/run-server-test` records its exact loader invocation. SHA256 hashes accompany the report. No dependency, release setting or threshold changed.
