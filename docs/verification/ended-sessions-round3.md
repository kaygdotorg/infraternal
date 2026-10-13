<!-- Event-driven live-session census, D81 idle/latency measurements and review evidence for #168. -->
# Ended sessions: round 3

> Raw screenshots, logs and receipts referenced by this report were removed under D262. The
> recorded results remain; new outputs belong in job scratch and should be attached to the
> relevant issue with the `issue-attach` helper.

Issue [#168](https://git.kayg.org/kayg/infraternal/issues/168), branch
`ended-sessions`, baseline `dd867a58151a5bbcd8ce224c34c8596a9ecfcfb6`.
The orchestrator approved event-driven discovery within D81. No decision,
foundational dependency, wire frame, shim protocol, deployment or budget changed.

The infraternal agent registers each created/adopted shim with a process
lifetime watcher. Linux holds one CLOEXEC pidfd per shim in one epoll queue
registered with the existing Tokio reactor. macOS uses one CLOEXEC kqueue with
`EVFILT_PROC/NOTE_EXIT`, one-shot registrations and lifetime tokens; queued exits
cannot borrow a reused PID. Retired registrations are released. Neither backend
adds a task/thread per shim or an idle timer. The existing launch-child reapers
are unchanged.

The safe `pidfd_open` wrapper stays in the existing audited shim PTY/process
boundary (D40), uses `nix::libc`, bounds PIDs and owns the returned descriptor.
Registry insertion checks authenticated birth identity across registration.
Unsupported kernels use only connect/reconnect and open/close/exit checks;
permission/resource errors do not silently disable tracking. `contracts/wire.md`
now describes this event-driven contract. The only manifest change enables the
existing nix `event` feature; there is no new dependency or lockfile change.

Censuses still publish only when the sorted live set changes and once at connect.
A full control queue retains the pending census and retries on capacity, without
an inbound request or a timer. ES-01's census-before-open-Result FIFO and client
first-positive-census fence are unchanged. A controlled writer test fills all
eight slots, retires a rendezvous, releases capacity, and receives the negative
census after all eight ordered Pongs without sending another request.

## Idle and exit detection

Raw run receipts were removed under D262; the recorded measurements and results
remain in this report.
Every measurement runs locally on infraternal-dev under
`systemd-run --user --scope -p CPUWeight=10000`; fixture-owned shim scopes carry
that weight. Machine: Linux x86_64, 12 reported CPUs. No load generator or remote
benchmark host was used.

The exact independently built baseline is **20,142,672 bytes**, matching round 2.
Its unchanged canary fails with **10 scheduler activations in 2.200 s**
(`idle-baseline-red.log`). The release head records **zero** in each unchanged
2.201-second window (`static-idle-exit-latency.log`):

| Daemon state | Scheduler activations | RSS KiB |
| --- | ---: | ---: |
| Empty | 0 | 4,916 |
| One adopted, unattached shim | 0 | 5,236 |
| After 100 watched exits | 0 | 5,388 |
| 200 live, unattached shims | 0 | 5,672 |
| After all 200 exits | 0 | 5,444 |

The last two rows come from the real production server inventory actor probe
(`server-scale-200.log`): one daemon thread, **200 real shims**, no terminal
attachments. Total daemon RSS at 200 is 5.54 MiB, below the 15 MiB budget; amortized
across those sessions it is 28.36 KiB/session including fixed daemon costs.
This measures daemon RSS, not aggregate shell/shim or kernel memory.

The probe allows 100 ms of finite startup/exit cleanup before the unchanged
2.2-second canary; it does not change the canary threshold or add daemon work.
One initial adoption sample observed a single startup schedule-in; two independent
five-second observations then measured 0/0 (`adoption-wake-diagnostic.log`). The
existing full-gate canaries are also run unchanged.

| SIGKILL to observed census | Samples / initial live shims | p50 µs | p99 µs | Max µs |
| --- | --- | ---: | ---: | ---: |
| Real release daemon to leg-B server peer | 100 / 1 | 1,005 | 2,891 | 3,464 |
| Real release daemon to production server inventory watch | 200 / 200 | 9,691 | 23,022 | 27,701 |

Both measurements start at signal submission and await only the pushed census;
no attach, Ping or refresh request drives detection. All maxima are below the
former **400,000 µs** worst case. The server actor fixture uses a debug test
runner and a release daemon. Recorded load: **7.91/20.98/32.81** for the
single-live-shim run; **28.80/20.38/27.88** for the 200-shim run.

The source-import kernel harness independently holds 200 real process lifetimes.
Its own descriptor count is **7 → 208 → 8**: exactly **200 pidfds + one shared
queue**, then only the queue after all lifetimes retire. Registration took
103,184 µs; stop/drain took 140,336 µs under load **56.46/42.60/35.37**
(`watcher-scale-200-final.log`). The protected daemon's FD table correctly rejects
inspection; no dumpability protection was relaxed.

## Reconciliation at 200 sessions

The production reconciliation and existing scale-test source are byte-identical
to the baseline. Saved separate baseline/head executables prevent later Cargo
writes from corrupting the comparison. Three initial alternating pairs and five
reverse-order pairs ran under substantial concurrent load and are retained in
`reconciliation-200.log` and `reconciliation-200-reverse.log`.

The controlled follow-up uses five A-B-B-A rounds: **10 runs per version**,
**100 samples/run**, **200 sessions across 50 accounts**, SQLite memory, with all
200 closures verified each time (`reconciliation-200-abba.log`). Median run
statistics:

| Metric | dd867a58 | Head |
| --- | ---: | ---: |
| p50 µs | 1,660.5 | 1,640.5 |
| p99 µs | 2,482.5 | 2,545.0 |
| Close all 200 µs | 17,864.5 | 17,725.5 |

No material measured regression is established; these samples do not establish
statistical significance or whole-server throughput. Each run records its load
and machine. The earlier noisy measurements are not presented as improvements.

## Acceptance and static size

Native strict touched-crate all-target/all-feature clippy passes. The
infraternal-agent suite passes **63 tests, 12 ignored**, including kernel exit
isolation, cleanup, forced unsupported-kernel fallback, resource failure and
control-capacity census retry (`native-gates.log`). The native shim boundary
checks pass **2/2** (`helper-crate-gates-final.log`). Source-import kernel tests
pass **6/6**; the 200-lifetime probe is run explicitly. macOS all-target cross
compilation and strict pedantic clippy pass, including token-regression test
compilation (`macos-clippy-final.log`). **macOS runtime is untested** on this Linux
host; the surrounding existing launch implementation remains Linux-specific.

Real-session integration passes **3/3**, and the real idle/exit oracle **1/1**
(`real-daemon-green.log`). The 16 surviving shims were discovered in **11 ms**
and every survivor reattached/replayed; clean and abrupt exits are excluded.
The initial run lacked the fixture's fixed scratch parent. A serial rerun then
reproduced the already reported SIGKILL/listener-teardown handshake race. The
fixture now waits for its owned shim's pidfd death before restart discovery;
all original acceptance assertions remain. Production discovery/authentication
is unchanged. Separate detection latency still starts at SIGKILL, not at death.

Server inventory acceptance passes **5/5**, including ES-01 database ordering,
ES-02 saved status, account-scoped bounded exits and unavailable inventory.
Production browser acceptance passes **8/8** (the original seven plus ES-01
ordering), **2.0 minutes**, default 300 ms RTT, ports **5188/5189**
(`browser-acceptance.log`). Browser plugin unavailable; the repository Playwright
harness was used. Review screenshots were removed under D262; this job does not
judge its own visual quality. Strict tracer checking, **159
source tests**, the default production build and all unchanged D188 transfer
budgets pass (`client-acceptance.log`). The separate complete TypeScript fast
gate also passes: 166 tracer/shared tests and 36 protocol tests with 34,462
assertions (`ts-fast-final.log`). Its initial differential test waited on the
concurrent workspace Cargo lock and exceeded its unchanged 30 s timeout; an
isolated protocol target removes that build-lock collision without changing the
test or its budget. No UI source changed.

Locked default release x86_64 musl: **20,142,672 → 20,153,072 bytes**, **+10,400
bytes (+0.052%)**. Both are stripped static PIEs with no interpreter
(`size-baseline.txt`, `size-head.txt`). The historical **16,404,816-byte** ceiling
is unchanged and already fails on dd867a58.

## Self-review and final gate

Self-review covers audited syscall/descriptor ownership; CLOEXEC and PID reuse;
one readiness source and watcher cleanup; no recurring fallback or retry timer;
authenticated birth fencing; control saturation/FIFO; irreversible Close;
unavailable-link handling; unchanged ES-01–04 acceptance; account/host isolation;
protected process state; module documentation; existing UI reuse; and unchanged
budgets. Parser code and wire shapes are unchanged, so no new parser/fuzz target
is introduced. No push beyond this authorized branch, deployment or issue
closure was performed.

The full fast milestone at code head `6257a59b` passes every Rust test, including
all existing zero-activation canaries and previously stalled restart tests. Its
only failure is the unchanged historical static ceiling. No restart stall or
load-failure waiver remains. `fast-milestone.log` preserves the complete output;
the final evidence-head replay and SHA are recorded verbatim on #168.

Milestone `scripts/verify fast`, verbatim summary:

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

Static row, verbatim:

```text
PT_INTERP: absent; size: 20153072 bytes (baseline 16142672 + allowance 262144 = max 16404816)
binary exceeds the 16404816-byte size budget: 20153072 bytes
```

Reproduction uses the owned `ended-sessions-round3` scratch build/archives and
short `es168r3` fixture root. The fixed 16-shim fixture also requires its existing
`ended-sessions` scratch parent. An early unweighted cold native build read the
old manifest before the nix feature was enabled and is not acceptance evidence.
Baseline archives and saved executables remain isolated during measurements;
owned temporary targets/checkouts are removed at completion. Full raw logs,
including initial failures and corrected setup, are retained as evidence.
