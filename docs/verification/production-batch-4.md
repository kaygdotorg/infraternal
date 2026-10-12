<!-- Records the terminal-fidelity and event-driven ended-session production integration, #160/#168. -->
# Production batch 4

Branch `release-prod-4` starts at live `1f77a449`. Reviewed terminal-fidelity
`27db08cf` and ended-sessions `14d01feb` are merged in that order, one merge
commit each (`69babc92`, `49438882`). CA custody branches and `64d4e213` are
excluded; `evidence/prod4/excluded-ancestry.txt` records ancestry checks. Only
this branch is pushed; no deployment or issue closure is part of this job.

## Integration and follow-ups

Production process-birth and non-following executable-link checks remain.
Replay cursor/paint fencing and locale selection coexist with census-before-open
ordering, saved exit status and event-driven pidfd/kqueue discovery. Native
fixture readers retain bounded census handling, session-bound replay validation,
ordered final output and final Close assertions.

The approved #174 fallback is limited to private restart fixtures (`4a4ead30`)
and the bounded nine-second exec probe (`e0fb30a9`). Production restart validation
is unchanged. Real-shim fixtures share a parent-creating short state root
(`c5dc93b0`), and retirement count baselines wait for host-observed AttachTerm
(`160add59`). Every failing-first output is retained.

A new fidelity regression was confirmed during integration: the byte ring can
coalesce replay and live output while a renderer write awaits paint. Blanket
suppression then drops fresh query replies. On the production renderer, all
bytes arrived and painted but accepted reply bytes stayed at zero for 15 s.
`8ab20914` limits that write to the already validated replay cursor; the existing
paint callback enables replies for the live suffix. `38a09ea8` adds the real
renderer regression and fixture setup barrier. No wire format, engine, timer or
UI primitive changed. The split adds a paint boundary only for a region spanning
replay and live bytes; ordinary live writes retain the existing path.

## Native typing comparison

The same real-PTY fixture ran on `infraternal-perf-test`, Debian kernel 6.12.69,
x86_64, four CPUs, CPUWeight 10000, under `/var/lock/perf-bench.lock`, at RTT 0.
Each condition uses 1,000 samples. Runs are interleaved base/head three times.
Exact image hashes are in `evidence/prod4/static-images.json`; the production
Rust image remains identical through the later test-only commits.

| Run | Base PTY echo p50 / p99 (ms) | Head PTY echo p50 / p99 (ms) |
| --- | ---: | ---: |
| 1 | 0.31 / 0.62 | 0.80 / 2.70 |
| 2 | 0.77 / 3.31 | 0.56 / 3.34 |
| 3 | 0.57 / 2.25 | 0.39 / 1.63 |

Median **run** p50 is 0.57 → 0.56 ms; median run p99 is 2.25 → 2.70 ms.
The p99 ranges overlap (base 0.62–3.31, head 1.63–3.34 ms), with mixed paired
deltas and all typing references below D41's 5 ms budget. There is no reproducible
head slowdown beyond observed noise; three runs do not establish statistical
significance. Every head run passes the native fixture budgets. Base run 3 fails
same-session flood growth (23.12 ms versus 16.67 ms); it is retained. Median
same-flood echo p99 is 18.31 → 16.12 ms. Load moves from 0.33/0.12/0.03 to
1.02/0.35/0.11 during finite fixture bursts, with existing fixture cleanup.
No VM build, account or host-key change was made.

Raw evidence and reproducible runner: `evidence/prod4/perf-interleaved.log` and
`perf-interleaved.sh`. The VM has a bash login shell, so the existing native
latency fixture is used directly rather than a prompt-specific zsh oracle.

## Idle and exit discovery at scale

All local measurements use CPUWeight 10000 on `infraternal-dev`, x86_64, 12
reported CPUs, with natural host load recorded in each log. The direct RTT-0
release probe observes **zero** schedule-ins over 2.201 s when empty, after
unattached adoption and after every exit; RSS is 4,636/5,028/5,164 KiB. Its 100
sequential SIGKILL-to-leg-B census samples have p50 **1,836 µs**, p99 **27,383 µs**
and max **68,831 µs**, below 400,000 µs (load 36.57/45.91/50.70).

The retained default 300 ms RTT-proxy run also has zero activations and passes:
p50 158,080 µs, p99 202,253 µs, max 211,845 µs at load 44.76/44.40/51.58.
These values include approximately 150 ms of artificial outbound delay and
are not daemon-only overhead. `release-idle-direct.log` and
`release-idle-scale.log` distinguish the two configurations.

The production server inventory actor with **200 real unattached shims** observes
zero daemon activations over 2.203 s, one daemon thread and 5,452 KiB daemon RSS
(27.26 KiB/session amortized, including the common daemon). After all exits it
observes zero activations over 2.201 s and 5,228 KiB RSS. Two hundred pushed exits
have p50 8,979 µs, p99 31,935 µs and max 42,160 µs, below 400,000 µs, at load
57.08/52.71/52.83. This is daemon RSS and server-watch delivery, not whole-PTY
memory or a browser latency claim. The exact default server test executable was
saved before running the ignored scale oracle directly, avoiding the Cargo
build lock. Final EOF stderr is fixture channel teardown; the test passes.
Evidence: `release-idle-direct.log`, `release-idle-scale.log`, `release-scale-200.log`.

## Browser controls and source gates

Default touched-crate gates pass: agent 42 tests plus two transport tests;
server 192/0 with 15 ignored plus integration/doc targets; shim 73/0 with 13
ignored, detach 2/2, mouse 1/1 and pidfd 2/2. Remote-feature gates pass: agent
66/0 with 12 ignored and server 301/0 with 34 ignored, plus their integration,
shim and doc targets. Two earlier auth socket closures pass isolated repeats and
the complete default replay; no failure is waived. Both restart steps pass all
16 matching tests. Real-session discovery finds and replays all 16 survivors;
queue/review and release session-exit-credit, retention and bounds scripts pass.

Tracer check, 159 source tests (10,958 assertions), production build and unchanged
D188 budgets pass. After the replay fix, critical JS gzip/Brotli is
293,817/244,107 bytes; deferred 49,717/43,905; largest on-demand chunk
15,090/13,408. The three production-renderer query cases pass, including the
new queued-live boundary (56.8 s total). The final dead-session barrier replay
passes all seven cases (1.8 min).

The full live-base browser control is 50/55; first head is 55/61. Focused
interleaved base/head runs 2 and 3 each have two passes and four failures.
Add-host retry and manager-loading first-head failures pass unchanged in both
head replays. The four persistent cases also fail on live base: sessions-canvas
30 s watchdog, theme long tasks, first-run 5 s connection poll and access first
paint. Final full source replay is 57/62: those four cases plus the saved-Close
attach baseline race, subsequently fixed and verified 7/7 above. No product
performance budget is relaxed. `browser-{base,head}-{1,2,3}.log` preserves every
valid control; `browser-head-final.log` preserves the final broad run. The
accidental duplicate baseline launch and a separately occupied backend port are
retained as invalid setup attempts and excluded from comparisons.

Production captures are under `evidence/prod4/captures/`; they are attached for
owner/independent visual review, with no author visual-quality verdict or real
phone claim. The final screenshot set includes ended states and mobile manager.

## Static images and review

| Image | Bytes | Historical maximum | Interpreter |
| --- | ---: | ---: | --- |
| Live base x86_64 | 20,093,776 | 16,404,816 | absent |
| Head x86_64 | 20,205,936 | 16,404,816 | absent |
| Head aarch64 | 18,010,544 | 13,817,816 | absent |

The x86 delta is +112,160 bytes (+0.558%). Both targets are stripped static
images. Historical size ceilings remain failing and unchanged; the excluded
size-baseline commit is not used. The independent base image is frozen before
reusing its dependency cache for head builds; no base build subsequently writes
that cache. Cached head static subtrees are copied to the native gate target for
its normal recipe. This does not change compiler flags, dependencies or profiles.

Self-review checks lifetime registration/retirement and PID reuse, descriptor
ownership/CLOEXEC, no periodic work, saturated census FIFO and capacity retry,
current-watch database fencing, account/host isolation, first saved exit and
irreversible Close, canonical replay cursors, bounded queue conversion, exact
paint release, input response gating and unchanged budgets. Existing parser
fuzzing remains; the follow-up changes queue consumption, not a wire parser.

The full fast gate and exact final head/output are recorded on #160/#168. Raw
workspace outputs and the separate TypeScript fast gate are retained in this
same evidence directory. Earlier setup and load failures are kept, rather than
removed from the record.

Full `scripts/verify fast` milestone at code head `160add59`, verbatim:

```text
+---------------------------+--------------+
| Rust gate                 | Result       |
+---------------------------+--------------+
| fmt                       | PASS         |
| VT native fmt             | PASS         |
| clippy                    | PASS         |
| test                      | PASS         |
| cargo-deny                | PASS         |
| static builds             | FAIL (1)     |
+---------------------------+--------------+
```

The first milestone attempt stopped in the RTT self-test (p99 363.26 ms);
its unchanged retry passed p50 286.31/p99 308.69 ms and every Rust test.
`fast-milestone-retry.log` preserves the complete completed output. Separate
TypeScript fast passes, including 36 protocol tests/34,462 assertions; static
failure otherwise stops the combined dispatcher before TypeScript. The final
documentation-head replay is quoted verbatim on both tracking issues.
