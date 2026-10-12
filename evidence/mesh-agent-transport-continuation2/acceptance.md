<!-- Records current-source D215 perf VM acceptance and its functional limits; issue #129. -->

# D215 continuation 2 evidence

All acceptance timings below were measured on `infraternal-perf-test` through NetBird SSH, under `/var/lock/perf-bench.lock`, using the same frozen static musl shipping CLI and optimized server fixture. Source and remote artifact hashes are recorded in frozen-source.json, frozen-artifacts.json, frozen-agent-artifact.json and remote-artifact-sha256.txt. No production source changed in this continuation.

The namespace proof runs two real kernel nodes, one surviving real PTY and 1,000 public inventory entries. Inventory entries are not running infraternal agents. Each echo row contains 31 samples per path; p99 is the largest sample in this small fixture, not a high-confidence population estimate.

| Configured RTT | Direct echo p99 | Mesh echo p99 | Mesh minus direct | Silent cut to echo | Recovery limit | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 0 ms | 0.764 ms | 0.819 ms | 0.055 ms | 201.825 ms | 250 ms | PASS |
| 150 ms | 163.811 ms | 168.835 ms | 5.024 ms | 342.243 ms | 400 ms | PASS |
| 300 ms | 327.442 ms | 328.238 ms | 0.796 ms | 332.341 ms | 550 ms | PASS |

The local mesh echo target is direct + 2 ms: measured overhead is 0.055 ms. Delayed rows include independent netem jitter (7 ms per side at RTT 150; 15 ms per side at RTT 300); differences are recorded, not attributed causally to the mesh implementation. All three lifecycle proofs also pass mesh restoration, restart with the original port unavailable, and component down. Exact bytes expected/received: 0 ms: 2925/2925, 150 ms: 13264/13264, 300 ms: 22833/22833.

Load start/end (one/five/fifteen minute averages and process fields):
- RTT 0: `0.00 0.06 0.17 1/229 128394` → `0.08 0.08 0.18 2/2240 130459`.
- RTT 150: `0.08 0.08 0.18 1/2231 130468` → `0.43 0.18 0.21 1/2245 132541`.
- RTT 300: `0.43 0.18 0.21 1/2236 132550` → `0.45 0.28 0.24 2/2250 134627`.

The separate MAT-R5 real-mTLS QUIC discard regression passes at 201.891 ms against its 300 ms local reference. Inherited translated-address ingress checks pass for nft and nf_tables, endpoint persistence refusal preserves its kernel endpoint, and restart removes orphan routes. These four functional checks ran in disposable build-host namespaces; they are not timing evidence.

MAT-R4 exact 4 MiB actor credit regression passes: the next byte waits, another writer progresses, and the waiting byte resumes once after Ack. Fresh optimized server checkpoint: embedded 38 passed/0 failed/2 ignored; runtime 38 passed/0 failed/5 ignored (including perf namespace child/parent fixtures); exact standby parser 1 passed/0 failed. An initial empty embedded filter is retained as invalid evidence and superseded by embedded-all-current.log.

## Scale and retention

| Perf fixture | Population | Sampling window | Live pairs | False interruptions | CPU cores used | RSS delta, both peers |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| guarded | 1,000 QUIC pairs | 16.604152 s | 1000 | 0 | 0.867 | 225,730,560 B |
| unguarded | 1,000 QUIC pairs | 16.653018 s | 1000 | 0 | 0.961 | 212,738,048 B |

Guard state: 208 B/path × 1,000 = 208,000 B. Guarded RSS delta is 225730.56 B/pair × 1,000, including both test peers and harness state; this is not 1,000 full infraternal daemons. The guarded fixture takes an extra diagnostic authenticated-counter snapshot per guard poll. The paired runs have different load/scheduling and do not prove a CPU saving or isolate shipping watcher overhead. Both use 100 ms keepalive; the 60,000 ms setting is the transport idle timeout, not the sampling duration.

Guarded load: `1.14 0.46 0.31 2/239 134667` → `1.13 0.49 0.32 5/239 134675`. Unguarded load: `0.03 0.24 0.25 5/232 134745` → `0.17 0.25 0.25 3/233 134746`.

The separate 200-state retained-input fixture performs 6,200 real Unix-socket writes: p50 2,423 ns; p99 6,163 ns; peak aggregate retained capacity 1,600 B; zero capacity after complete Ack. Its test-layout state is 104 B × 200 = 20,800 B, excluding transport/task allocations. Worst-case retained payload cap is 4,194,304 B × 200 = 838,860,800 B (800 MiB), allocated only for outstanding input. These are 200 retained-input states, not 200 live PTYs.

## Binary size and gate status

Original +90,496 B attribution is already committed at 6a749975, with item-level cargo-bloat/section reconciliation in ../mesh-agent-transport-round2/bloat-attribution.md. The final frozen shipping CLI is 21,074,624 B, a further +369,472 B from the historical 515d3712 shipping size; that extra comparison includes reviewed dataplane integration and round-two behavior, and is not a per-module size attribution.

The first full fast gate passes fmt, VT native fmt, Clippy and cargo-deny; it fails the loaded TCP relay-spacing test and the unchanged x86 static limit of 16,404,816 B. The spacing regression passes unchanged in isolation and on the locked perf VM (20,362 us). This is not a waived workspace failure: a serialized final-head gate is still required. The static limit remains unchanged and its failure requires owner budget resolution or a separate size-reduction change before merge.

The required gate latency self-test is dispatched to the locked perf VM through gate-bin/python3; all other Python invocations and all builds/functional checks remain on the build host. The original build-host self-test failure is preserved but its timing values are not acceptance evidence.
Raw `.log` files are committed as byte-preserving `.log.gz` archives; raw-log-manifest.json records their uncompressed hashes and sizes.
