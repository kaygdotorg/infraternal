<!-- Records the #168 round-two fixes, acceptance evidence and measured limits. -->
# Ended sessions: independent review fixes (#168)

> Raw screenshots, logs and receipts referenced by this report were removed under D262. The
> recorded results remain; new outputs belong in job scratch and should be attached to the
> relevant issue with the `issue-attach` helper.

Baseline: `a23432f2387dcbff5f19429966feb65c8d9abb35`. Independent acceptance
source: `origin/review-ended-sessions` at `87e53fc5`. Fixes and acceptance
commits: `bc656a96`, `8230b4e3`, `a6c60d8a`, `281160bf`, `92b9f49b`,
`c251f3fd`, `b5beff06`, `b7ee41f9`, `b4e70c8c`, `9c88d6a0`.
Additional control-frame fixture corrections: `1e3e5862`, `2ad79ae0`,
`6d34eacd`, `63392d9c`.

## Behavior and acceptance

- **ES-01:** the infraternal agent queues the new-session census before its
  successful open Result in one bounded FIFO. Queue saturation prevents a
  success from overtaking its census. The server acquires its SQLite writer
  before cloning the latest inventory watch; browser snapshot emission also
  refreshes the watch after acquiring the connection. New browser windows
  retain their confirmed IDs until their owning host first confirms them in
  a census. A real final Close stays final. Foreign-host events cannot clear
  that fence. No schema, dependency or frozen wire-field change was needed.
- **ES-02:** a census-closed row can accept its first authoritative saved exit
  status. Closure time remains unchanged; conflicting statuses, ownership,
  authentication and cursor bounds retain their existing checks.
- **ES-03:** the Python latency fixture consumes bounded correlated control
  traffic while waiting for Pong/open Results. It retains only the latest
  control census separately from terminal events and keeps terminal stream,
  cursor and credit validation.
- **ES-04:** status snapshots release superseded records for windows this
  device never opened. Current wire-capped status records and windows actually
  opened remain available, including opened-window exit statuses.

The independent browser and model acceptance assertions are unchanged. The
database race test was adapted to the watch-based reconciliation API: its
writer is held, a new live census is published before persistence (the FIFO
invariant), and the older blocked reconciliation must never close that row.
The saved-exit test is unchanged. The startup fixture test additionally opens
a real PTY and verifies its census precedes the Result and usable marker.

Failing baseline/model receipts were removed under D262; their result summaries
remain here:
`es01-baseline-red.log`, `es02-baseline-red.log`, `es03-baseline-red.log`,
`es01-model-red.log`, `es04-red.log`, `host-fence-red.log`. Acceptance tests
were not weakened. The two extra host-isolation tests failed before their fix.

## Verification evidence

Strict clippy for touched crates and all targets/features passed; cargo fmt
passed. `clippy-final.log` preserves the final native check. Focused native
results: infraternal-agent library **33 passed, 6 ignored**;
server inventory **5 passed, 1 ignored**; authenticated terminal exit **2
passed**; latency fixture **1 passed**. The ignored scale test was run
explicitly below. No parser changes or new dependencies require a new fuzz
target.

`real-session-valid.log` records all **3/3** real-engine integration tests
passing in **0.76 s**, including **16 surviving shims discovered in 5 ms**,
reattachment and replay, clean exit and SIGKILL exclusion. Machine:
infraternal-dev, x86_64, 12 reported CPUs, user scope CPUWeight=10000,
load **41.01/34.51/34.66**. The pre-existing 16-shim stall named in the brief
did not reproduce in this run. Both restart-control tests that previously
stalled also passed separately (`restart-focused.log`).

Production browser acceptance passed against the real built frontend at
300 ms simulated RTT on a unique port. The unchanged dead-session browser
suite passed **7/7** under CPUWeight=10000; a matched detached baseline
passed **7/7**. The raw browser receipts and production screenshots were removed
under D262; their recorded results remain above.

`client-final.log` records strict TypeScript checking, **159 passing unit
tests**, the default production build and unchanged D188 budgets:

| JavaScript group | gzip bytes / budget | Brotli bytes / budget |
| --- | ---: | ---: |
| Critical | 291,798 / 307,200 | 242,503 / 256,000 |
| Deferred | 50,456 / 51,200 | 44,450 / 45,056 |

On-demand chunks and every font budget also pass. Browser harness builds use
the cluster preview profile; the D188 default-profile build was run separately.

## Reconciliation at scale

`scale-final.log` contains three alternating baseline/head runs under one
CPUWeight=10000 scope on infraternal-dev: debug SQLite-memory reconciliation,
**200 sessions across 50 accounts**, **100 samples per run**, all 200 closures
verified. Load **32.60/37.36/37.91**, x86_64, 12 reported CPUs.

| Run | Baseline p50 / p99 (µs) | Head p50 / p99 (µs) | Baseline / head close 200 (µs) |
| --- | ---: | ---: | ---: |
| 1 | 1,793 / 6,453 | 1,734 / 2,382 | 18,475 / 22,005 |
| 2 | 1,877 / 2,629 | 1,862 / 2,780 | 21,228 / 20,036 |
| 3 | 1,848 / 5,390 | 1,845 / 2,602 | 30,062 / 18,212 |

Median run p50: **1,848 → 1,845 µs**. Median close-all: **21,228 → 20,036 µs**.
No measured regression; this does not establish a statistically significant
improvement or whole-server/200-PTY throughput or memory behavior.

## Static size and full gate

Locked default release x86_64 musl binary, stripped static PIE with no
interpreter: **20,138,640 → 20,142,672 bytes**, **+4,032 bytes (+0.020%)** versus
`a23432f2`. `size-baseline.txt` and `size-head.txt` preserve the measurements.
The unchanged gate ceiling is **16,404,816 bytes** and already fails on the
baseline. No size gate or D188 budget was raised or waived. The final full
`scripts/verify fast` is run on the evidence commit; its exact output and head
SHA are recorded in the final #168 issue comment.

The full gate also exposes an **unresolved idle failure**: the unchanged
400 ms census timer schedules the infraternal agent while completely idle.
The repaired startup fixture reaches the existing zero-activation canary
instead of failing earlier on the unsolicited census. Initial full gate:
11 scheduler entries / 2.201 s. Weighted sequential comparison using the same
repaired fixture: exact baseline static binary **12 / 2.200 s**, head debug
binary **10 / 2.201 s** (`idle-baseline.log`, `idle-head-repeat.log`). Both
contain the unconditional timer. This is deterministic idle work, not a
load-dependent timeout. The canary and 400 ms contract are unchanged.

The branch remains **HOLD** for a fully green gate. The owner needs to reconcile
the recorded census contract with D81's zero-idle default; this job does not
choose a new foundational process-death mechanism, disable SIGKILL discovery
or relax the idle assertion. The first full gate's Rust rows are fmt PASS,
VT native fmt PASS, clippy PASS, test FAIL (101), cargo-deny PASS and static
builds FAIL (1). The final full gate on the last evidence commit is recorded
verbatim on #168; neither failure is waived.

Checking beyond that first failing integration binary found three more
fixtures assuming that the next frame was a terminal reply or Pong. Their
existing security, exact-byte and typed-retention assertions are preserved:
the UID fixture now validates the exact startup census; queue probes reuse
the correlated bounded ping helper; retained exit/Close checks reuse a
census-validating reader with one original socket deadline. Green evidence:
`remote-fixture-green.log` (5 remote daemon tests),
`queue-fixture-green.log` (2,640,000 bytes exactly once across 12 streams),
`retention-fixture-green.log` (typed exit, restart and retirement race).
`ts-fast-separate.log` additionally records **166 tracer/shared tests** and
**36 protocol tests** passing, including Rust/TypeScript differential decoding.
The broader run (`workspace-remaining-final.log`) passed server library
**297/297 (33 ignored)** and shim library **65/65 (13 ignored)**, including the
deterministic seeded corpus. It stopped at the mouse integration probe because
the manual command omitted the pinned Zig PATH that `scripts/verify` supplies;
`mouse-corrected-env.log` records the corrected environment rerun (**1 passed**).
Separate workspace doc tests also pass (`doc-tests.log`). Every other
CLI integration suite passed, with the two corrected census assumptions having
their separate green reruns above (`cli-remaining.log`). No failure was waived.

## Reproduction and self-review

Build targets and detached baseline checkout use the owned
`$HOME/.cache/codex-scratch/ended-sessions-round2` directory. Test fixtures need
a short private state root (`$HOME/.cache/codex-scratch/es168r2`) and the
existing 16-shim test's private scratch parent. Long state roots correctly
fail the Unix socket path limit. CLI image-validation tests require non-group-
writable fixture executables; the owned build used umask 022. Security checks
were preserved.

An early shared Cargo target overwrote a head test executable with the
baseline executable. Those measurements/checks were rejected and labelled
invalid. Modified packages were cleaned and rebuilt; final scale runs use
separate saved executables and no subsequent baseline Cargo writes to the
head target. The valid logs above supersede the discarded runs.

Self-review checked bounded control queues, saturation ordering, unavailable
inventories, account/host isolation, monotonic final Close, first-status
authentication and immutability, opened-window retention and wire-cap cleanup.
Existing UI components are reused (D160); no one-off visual primitives,
foundational engine decisions, core plugin changes or deployments were made.
