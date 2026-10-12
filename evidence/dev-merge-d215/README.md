<!-- D215 integration, regression and acceptance evidence for issue #129. -->
# D215 merge into the development line

Code checkpoints pushed only to `dev-merge-d215`; no deployment or movement of
`dev`. Base `c0d01d22`, reviewed transport `30ccbcfe`, review `857350ce` (MERGE,
MAT-R6 P2). Merge `dedcc2a3`; additive browser admission contract `4121ef14`;
MAT-R6 repair `0af8b6df`.

The merge preserves dev's replay fences, census/pidfd retirement, ownership-only
links, add-host/start-fresh, CA custody and release behavior. SESSION_OWNER stays
on bit 3; SHARED_WRITER uses bit 4. Deferred ExitAck retires its peer. Primed
fixtures now require the replay fence and path-status fixtures require census.
The parked final-output fixture retains an owner through its late observer.

MAT-R6 fails before the repair at its original browser-control assertion. The
repair owns one bounded, cancellable Input/Resize worker per attachment, with
Credit outside that FIFO. Four real-router/Unix-actor cases pass: control and
Credit/Ack progress, Resize ordering, overload absorption, pending byte/slot
bounds and cancellation. See [the author checklist](credit-review.md).

## Validation

| Check | Result |
| --- | --- |
| Full fast Rust checks | 930 passed, 0 failed, 108 ignored; 95 result rows, including 24 compile-out tests |
| fmt, VT fmt, CLI compile-out, Clippy, cargo-deny | PASS |
| Static size | FAIL: 22,319,408 bytes > 16,404,816; static PIE, no PT_INTERP |
| Tracer compiler/unit tests/build/transfer budget | PASS: 168 tests; critical gzip 294,984 / 307,200 bytes |
| Protocol compiler and serial tests | PASS: 36 tests; earlier overlapping-Cargo timeout retained |
| Functional browser selection, local default 300 ms profile | 63 passed, one three-scene fixture timed out |
| Isolated three-scene fixture, unchanged dev and merged sources | Both hit the existing 30 s deadline |
| Isolated three-scene fixture, local zero-RTT debug profile | PASS; default-profile failure is still recorded |
| Fuzz targets build | PASS, all bins; existing server SSH feature enabled |
| Session scripts and idle canary, locked perf VM | Six scripts PASS after public login-fixture isolation |

The generated screenshots came from the production tracer build. They are
attached for the owner's review, without a visual-quality claim:
[ended session](screenshots/ended-1440x900-ink.png),
[retired exit 7](screenshots/retired-exit-7-1440x900-ink.png),
[ended sidebar](screenshots/sidebar-after-1440x900.png),
[desktop release refusal](screenshots/release-verification-1440.png),
[phone release refusal](screenshots/release-verification-393.png).
No tracer/UI source changed from the dev baseline.

## Native comparison

All measurements below ran on `infraternal-perf-test`, x86_64, four CPUs, under
`/var/lock/perf-bench.lock`. Order: dev, merged, merged, dev. Each category has
100 samples per run, a real infraternal agent and three real PTYs, at 300 ms RTT
with the existing jitter profile. Individual load records accompany each log.

| Artifact / round | Normal echo p99, ms | Sibling flood p99, ms | Same-session flood p99, ms | Same-session growth, ms |
| --- | ---: | ---: | ---: | ---: |
| dev / 1 | 327.15 | 307.03 | 359.29 | 32.13 |
| merged / 1 | 327.67 | 319.97 | 404.50 | 76.83 |
| merged / 2 | 325.87 | 302.45 | 378.96 | 53.09 |
| dev / 2 | 326.38 | 311.35 | 485.26 | 158.88 |

Normal/sibling rows pass. All four same-session rows exceed the 334 ms echo and
16.67 ms growth limits. The baseline itself fails and varies substantially;
these two runs per artifact do not establish a causal slowdown. No budget is
waived or raised, and native acceptance is not green.

The public login fixture follows the reviewed namespace proof's private mount
pattern. It selects the existing zsh test profile without changing the VM's
host accounts. The initial prompt-dependent runs failed and remain preserved.
Corrected scripts pass lifecycle bounds, delayed-credit exit, exit-after-detach,
100 pushed census exits and retained/restarted exit status. The canary reports
zero scheduled activations for the idle infraternal agent, attached infraternal
agent and shim in their unchanged 2.2 s windows. Empty daemon RSS is 4,964 KiB;
peak under the 50 MiB flood is 8,388 KiB. At 1,000 distributed daemons, the empty
per-unit extrapolation is about 4.73 GiB; this is not a 1,000-daemon concurrency
measurement. The 24-restart oracle preserves all 4,710,396 payload bytes; credited
and starved 50 MiB floods pass. A separate 1,000-keystroke canary passes p99
326.81 ms / 334 ms. These do not replace the failed same-session comparison.

The browser FIFO's configured payload maximum is 4,194,432 bytes per blocked
attachment, or 838,886,400 bytes at 200 blocked attachments, in addition to the
existing actor's durable retention. This is a bound, not measured server RSS.

## Provenance and limitations

`perf-provenance.json` seals the production source and both static artifacts.
Remote artifact hashes match. Dev is 21,857,264 bytes; merged is 22,319,408 bytes,
a 462,144-byte increase from the native transport/retention integration and
browser admission worker. Both exceed the unchanged size gate. D243 remains
unchanged; a size reduction or an owner-approved measured exception is outside
this integration checkpoint. ARM/static follow-on checks are not reached after
the x86 size failure.

Raw logs are byte-preserving gzip archives indexed by `log-manifest.json`.
Earlier failures, cancelled browser runs and corrected fixture runs are kept
separately. Build-host test durations are diagnostics, never timing acceptance.
The final branch-head gate and handoff status are recorded verbatim on #129.
