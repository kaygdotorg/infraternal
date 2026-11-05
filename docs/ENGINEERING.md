<!-- Adopted engineering practices, D351 (#344), based on J194 research. -->
# Engineering practices (ADOPTED)

**Status:** ADOPTED by kayg on 2026-11-04, D351 (#344), following J194’s
proposal. Review enforces these practices; cheap checks implement the adopted
items incrementally. D351’s specific choices below supersede the proposal.

The owner's request: "we should keep our codebase performant, maintainable as
it grows btw. [...] rules should enhance our workflow and make us write better,
more performant, more reliable and maintainable code in the end; not arbitrary
limitations."

This page lists the practices we adopted, ranked by value for cost,
and the ones we turned down. It builds on what already holds: D5 (measure,
speed wins), D40 (strictness), D41 and D188 (budgets), D243 (size reporting),
D318 (one event route), D345 (doc comments) and `docs/PROCESS.md`.

## How a practice earns a place here

1. **It answers a defect class we actually hit,** or a decision kayg made. Each
   item below cites our own evidence: issues, review findings, the spawn log.
2. **Its check costs less than the bugs it prevents.** Cost means build time,
   friction and false positives. We measured the top items before proposing
   them (see "Dry runs").
3. **It checks behaviour, not shape.** We do not cap file length, function
   length or complexity scores. Those numbers do not track the bugs we
   ship, and our own data shows such a limit gets silenced rather than obeyed
   (167 `#[allow(clippy::too_many_lines)]` in `crates/`).
4. **It has an escape hatch with a reason.** An exception is written as
   `#[expect(lint, reason = "...")]` next to the code, never as a blanket allow.
   `expect` fails once the exception is no longer needed, so the list
   shrinks by itself.
5. **The cheapest enforcement wins:** a compiler or clippy lint, then a
   `verify quick` row, then a review checklist item, then a habit.

## How infraternal differs from calternal

calternal's ADR 0070 was the starting point. We read it and kept what fits.
The products differ in ways that change the rules:

| | calternal | infraternal | Consequence for us |
|---|---|---|---|
| Runs as | an unprivileged server | a root host daemon on every machine, plus a server | Privilege, file and process hygiene matter more than module size (P8) |
| Hot path | document edits | keystrokes, terminal floods, mesh packets | Blocking or allocating on the event loop is a latency bug (P2, P11) |
| Failure that hurts most | lost notes | a frozen terminal, a host that cannot be re-added, a lockout | Bounded resources and crash-safe destructive operations (P1, P7) |
| Untrusted input | files people write | network peers, remote hosts' output, people's terminals | Parsers fuzzed in practice, text sanitized at one place (P5, P6) |
| Durable state | plain files, atomic writes | SQLite + migrations across many parallel branches | Migration versions that cannot collide (P4) |

What we take from calternal, adapted: one helper for durable writes (their
`write_atomic`; for us the goal is latency as much as atomicity), bounded
queues, crash-only thinking for destructive steps, `expect` with a reason as
the exception mechanism, and turning down coverage percentages.

What we turn down, and why it is wrong *for us*, is in "Turned down" below.

## Ranked practices

Value is what the practice prevents, weighted by how often we hit it. Cost is
what it adds to every slice. The order is value for cost.

| Rank | Practice | Value | Cost | Enforcement |
|---|---|---|---|---|
| P1 | Every queue, map and budget is bounded and keyed | high | low | clippy `disallowed_methods` + review item |
| P2 | Nothing blocks the async runtime | high | low | one durable-write helper, `disallowed_methods`, loop-lag metric |
| P3 | Time goes through a seam; tests wait on events, not clocks | high | medium | `disallowed_methods` + `quick` diff row + review item |
| P4 | Migration versions cannot collide | medium | very low | timestamp versions + `quick` row (56 ms) |
| P5 | Fuzz targets actually run | high | low | corpus replay in `fast`, time-boxed nightly fuzz |
| P6 | Untrusted text is made safe in one place | medium | low | one helper + its fuzz/property test + review item |
| P7 | Destructive operations prove before they change, and survive a kill | high | medium | review checklist + one kill-between-steps test per step |
| P8 | Root daemon checklist, and root tests run as root | high | medium | checklist + a root gate row |
| P9 | D345 doc comments, checked | medium | low | `quick` diff row now; per-crate `missing_docs` lint as crates reach zero |
| P10 | Lint exceptions carry a reason and expire | medium | very low | `clippy::allow_attributes_without_reason` |
| P11 | No allocation per byte or frame on the data path | medium | low | allocation-counting tests (pattern exists in the shim) + perf harness |
| P12 | Dependency hygiene is reported like size | low | very low | report duplicate count per slice; unused-dependency check |
| P13 | New UI features load on demand by default | medium | very low | habit + the existing D188 gate |
| P14 | Gate the merged result, not the branch | medium | low | habit, already partly done |

### P1. Every queue, map and budget is bounded and keyed

**Rule.** Every channel, queue, cache, map, pool and rate limit has a stated
bound and a stated full behaviour (wait, refuse with a reason, or evict the
oldest). Bounds are kept per caller (per key, per host, per /64 or similar),
never only process-wide, so that one caller cannot use up what everyone
shares. A process-wide cap is a backstop behind per-caller caps, never the
only cap.

**Evidence.** This is our most repeated security review class:

- #263: a global device-code bucket let one network refuse every caller (P2-1);
  then one IPv6 /64, then a /48, filled the pending cap (P2-1, P2-2 in the next
  round); four networks still locked everyone out of sign-in in round 3.
- #303 P2-1: denied and over-limit calls wrote unthrottled audit rows; after the
  fix, the global 100,000-row cap let any key erase the audit trail.
- #220: pre-auth handshake unbounded (P1), a 3 GiB queue at 4,096 hosts (P2),
  per-host quota (P2).
- #270 (J38): a fixed 256-event queue retired the stream with close code 1013.
- #303 P3-7: a key without owner rights could use up the global bootstrap
  socket pool.

**Cost.** Low. There are 11 `unbounded_channel` call sites in production code
at `a89ebb0ae` (most in `infraternal-server/src/embedded*.rs` and
`plugins/desktop/src/source_worker.rs`), so the exceptions are few.

**Fit.** Strong. A root daemon reachable from the network must hold up against a
caller who sends too much, whether through a bug or on purpose.

**Enforcement.**
- clippy `disallowed-methods` for `tokio::sync::mpsc::unbounded_channel` and
  `std::sync::mpsc::channel`. Each justified site gets
  `#[expect(clippy::disallowed_methods, reason = "bounded by ...")]`.
- Review item for every new piece of state that grows with input: *What is
  the bound? What happens when it is full? Who shares it? Can one caller fill
  it for everyone?*

**Measurement.** Memory per unit × expected count (PROCESS §1). For example,
queue bytes per host × 4,096 hosts goes in the slice's issue.

### P2. Nothing blocks the async runtime

**Rule.** Inside async code, no call may wait on the disk, a lock held across
`.await`, a child process or a sleep. fsync and other durable writes go
through one helper that runs on the blocking pool and documents its
ordering (file, then directory). Short `/proc` reads and `metadata` calls
are allowed with a comment where measured cheap. Anything that waits on
a device is not.

**Evidence.**
- #334 (J163): `sessions new` fsynced on the infraternal agent's event loop and
  froze **every** terminal on the host for up to 32 s on a contended disk.
- #281 follow-up (J168): proxy-secrets fsync at start regressed `remote_client` tests.
- J103e: restore wrote and fsynced the engine choice for fresh state.
- This job found two more directory fsyncs awaited on the runtime:
  `infraternal-agent/src/logins.rs:502` (`restore_at`) and
  `infraternal-agent/src/rootless_sessions.rs:141` (`revoke`). Details are in
  #344, finding 1.

**Cost.** Low. There are 66 `sync_all`/`sync_data` call sites in total, most
already in sync code or `spawn_blocking` (29 uses). Clippy has no
"blocking inside async" lint. Text scanners mark false positives
(our scan: 53 hits, 17 in production-looking code, 2 real fsyncs). So we do
not gate on a scanner.

**Fit.** Strong. Latency is priority one (D5), and one stalled worker
stalls every session it multiplexes.

**Enforcement.**
- One helper module, for example `durable::{write_file, sync_dir}`, async on
  top and `spawn_blocking` inside. clippy `disallowed-methods` for
  `std::fs::File::sync_all`, `sync_data` and `std::thread::sleep`, with the
  helper's module as the only `expect`.
- Review item: *Does this async function touch the disk, a process or a
  blocking lock? If so, where does it leave the runtime?*

**Measurement.** The event-loop lag probe runs in tests and the benchmark
harness only (D351), never in shipped builds. A release-build check proves
that exclusion. The probe reports max and p99 lag; a test helper checks that
the infraternal agent remains responsive while a disk write is held pending.
The timeout is a generous deadlock guard, not a performance claim. Performance
numbers belong to the pinned performance harness.

### P3. Time goes through a seam; tests wait on events, not clocks

**Rule.**
- Durations use the monotonic clock. Wall-clock time is read only where it is
  stored or shown, through one small clock seam the tests can control.
- Deadlines that must survive a restart or a clock step (approvals, key
  expiry, recovery waits) are checked against a stored monotonic elapsed
  time or the server's own clock, never only against a wall-clock difference.
- Functional tests never assert speed and never sleep and hope. They wait
  for the event (a socket readable, a log line, a state change) under one
  generous overall timeout. Timing claims live in the perf harness
  (kayg's standing instruction).
- Where a product budget really must be tested, the test starts its clock at
  the thing the contract bounds, not at process spawn (the J163 fix).

**Evidence.**
- #334: QUIC/TCP race tests 6/20 under load because the 2 s budget started at
  `spawn(run)` and included agent startup. `status_restart` fixtures stamped
  "recent" with wall time. The flakes `agent_daemon`, `session_exit_events`
  and `cancelling_remote_dispatch` each cost gate reruns across many jobs
  (spawn log, 2026-11-01 to 11-04).
- #309 P1: a forward clock step bypassed the 24 h wait. API keys (J97): clock
  rollback. #303 P3-3: expiry read the clock before waiting for the writer.
- At `a89ebb0ae`: 221 `sleep` calls in Rust test files, **1,008
  `waitForTimeout` calls** in Playwright specs, and 85 `SystemTime::now` reads in
  production and test code.

**Cost.** Medium. The seam itself is small. Converting existing tests is
real work, so we do it only for tests that flake, plus all new tests.

**Fit.** Strong. Our gates run on shared, loaded VMs. A test that assumes an
idle machine fails there and trains everyone to rerun.

**Enforcement.**
- clippy `disallowed-methods` for `std::time::SystemTime::now` outside the clock
  seam (`expect` with a reason where a raw read is right).
- `verify quick` row: a *new* `waitForTimeout(` or `thread::sleep(` line in the
  diff fails unless a reason comment says `// sleep: <reason>` on the preceding line. Existing calls are
  untouched: no count ratchet, no mass edit.
- Tokio tests that test timeouts use `start_paused = true` and advance time.

### P4. Migration versions cannot collide

**Rule.** New migrations are named with a UTC timestamp version,
`YYYYMMDDHHMMSS_name.sql`. The existing `0001`–`0040` files stay as they are.
A `verify quick` row checks that a branch adds no version dev already has,
and that no two files share one.

**Evidence.** #285 renumbered three times (0037/0038 → 0039/0040 → 0041/0042),
and J119's review of it opened with "P1 migration collision". The API-key
review (J97, #269) found a migration conflict too. The orchestrator kept a
hand-made number map across #309, #285 and #303 (spawn log, 2026-11-02 and
11-03). A branch migration deployed to the test server moves its database ahead
of dev, so a later renumbering also breaks that database. The dry run found **23 of 127 active unmerged branches** colliding
with dev right now.

**Why timestamps work.** sqlx-core 0.8.6 (`migrate/migrator.rs:160-179`) applies
every embedded migration whose version is not yet recorded, in version order,
and never compares against the highest applied one. Our build script parses the
version as `i64` (`build_support/migrations.rs:24`). So two branches can merge
in either order. A migration that depends on another branch's table still needs
the later timestamp, and review catches that the same way it catches any
ordering dependency.

**Cost.** Very low: the check takes 56 ms per run.

**Fit.** Strong. It removes a recurring orchestration cost at the source.
calternal has no such problem (files are the truth there).

### P5. Fuzz targets actually run

**Rule.** Every fuzz target's seed corpus replays in `verify fast` as an ordinary
test on the stable toolchain. A nightly job fuzzes each target for a fixed time on
a build VM and adds new crashes to the corpus as regression seeds.

**Evidence.** We have 36 targets in `fuzz/fuzz_targets` (wire, shim frames,
auth cookie, login request, remote decoders, release verification and more).
`docs/PROCESS.md` §1 promises "fuzzing of every parser" nightly, but
`scripts/verify nightly` runs only the VT corpus, and no gate row runs a fuzz
target. The protocol parser is a "strictest review" area (CLAUDE.md).

**Cost.** Low for replay (seconds; the seeds are small and the harnesses are
already built by the workspace test). Nightly fuzz costs VM time only at night.

**Fit.** Strong. The harnesses exist; only the habit of running them is missing.

**Enforcement.** One gate row that replays the seed corpora through each
target's entry function, plus the nightly job.

### P6. Untrusted text is made safe in one place

**Rule.** Text from peers, remote hosts, people or AI clients that we print to a
terminal, put in a page or return to an AI client passes through one shared
sanitizer per destination (terminal, HTML, tool output). That sanitizer has a
property or fuzz test covering control, bidi and format characters.

**Evidence.** #303 P3-2 (removal output reached the terminal with `U+202E`),
#263 P3-3 (bidi host names on the approval page), #303 P3-4 (remote setup stderr
reached the AI client as tool output), and #281 P3-A (redaction missed
surrounding whitespace, a related "one place" problem for secrets).

**Cost.** Low.

**Fit.** Good. A terminal product shows text from everywhere.

**Enforcement.** The helper, its test, and a review item: *Does any untrusted
text reach a terminal, a page or an AI client without the sanitizer?*

### P7. Destructive operations prove before they change, and survive a kill

**Rule.** A step that destroys or replaces state (an install, a key, a unit, a
session) first proves everything it can prove read-only. It then records what it
is about to do, and leaves a restorable copy until the new state is confirmed.
Every exit path restores, including signals and a killed process. Each such step
has a test that kills the process between its steps and checks the result.

**Evidence.** #305 needed three review rounds on this one class: Replace
destroyed the old install before checking re-enrollment (P1-1), stopped the unit
before proving cleanup (P1-2), deleted rollback copies (P2-3), skipped restore at
the deadline and on signals under dash. #263 P3-1: the user's key copy survived
Ctrl-C and SIGTERM. #281 P1 (r1): a revocation was acknowledged before Traefik
applied it.

**Cost.** Medium: the kill tests take effort. They are required only for
destructive steps.

**Fit.** Strong. calternal's crash-only rule (their C5) is right, but for us the
risky code is root shell scripts and process lifecycles, not file writes.

**Enforcement.** Review checklist, and the kill-between-steps test as part of
"done" for these steps.

### P8. Root daemon checklist, and root tests run as root

**Rule.** Code that runs as root or drops privileges follows this checklist:

- Use file descriptors, not paths, for anything a less-privileged user could
  swap (open the directory, then `*at` calls). Check owner and mode on the
  opened fd.
- Never resolve privileged binaries through `PATH`. Use fixed, root-owned
  candidates.
- Re-arm `PR_SET_PDEATHSIG` after `setuid`, and recheck the parent.
- Create owner-only directories with the final mode in the create call, never
  by repairing it afterwards.
- No secret goes in argv, environment, logs or a world-readable file. Key
  material is zeroized when dropped, and temporary copies are removed on every
  exit, signals included.
- Never bind a port and release it for a child to take (TOCTOU). Pass the
  listening socket instead.
- System accounts and IDs are checked for collisions before use.
- Tests that cover root behaviour run as root in a gate row.

**Evidence.** #281: lost PDEATHSIG after `setuid` (P2-A), rootful directory
mode (P1-B), health-port TOCTOU (P3-C), uid 65532 collision (P2-B), a test that
failed only as root (P3-D), six tests failing as root in one round. #263: sudo
through `PATH` (P2-3), install-by-path TOCTOU (P3-4), key readable by the
invoking user (P3-5). #285: zeroize of a candidate key. J37: credential
directory TOCTOU. #265: keychain key readable through DYLD injection.

**Cost.** Medium. A root gate row costs a build slot on compute01 as root
(it is already done by hand per the brief).

**Fit.** This is infraternal's own concern. calternal has no equivalent.

**Enforcement.** The checklist in the review template for any diff that touches
privilege, plus a `scripts/verify root` row run in the root clone.

### P9. D345 doc comments, checked

**Rule.** D345 as written. The check covers new and changed items only, so it
asks for exactly what D345 asks for and nothing retroactive.

**Evidence.** The dry run (heuristic, calibrated below) finds 3,561 of 5,878
production items without a doc comment (61%), 388 of them `pub`. Every
production file already has a `//!` module header.

**Cost.** Low for the diff check (a text scan of the diff, well under a second).
Turning `missing_docs` plus `clippy::missing_docs_in_private_items` on for a
whole crate makes sense only once that crate is near zero.

**Enforcement.** A `verify quick` row that fails when an added or changed
`fn`/`struct`/`enum`/`trait`/`type`/`const`/`static`/`mod` in the diff has no
`///` above it. Then the per-crate lint as each crate is cleaned (small crates
first: `infraternal-session`, `infraternal-protocol`, `infraternal-status`).

### P10. Lint exceptions carry a reason and expire

**Rule.** Use `#[expect(lint, reason = "...")]`, not `#[allow]`, and turn on
`clippy::allow_attributes_without_reason`.

**Evidence.** At `a89ebb0ae`, `crates/` and `fuzz/` hold 479 single-line and
22 multi-line `#[allow(...)]` attributes, and **none** has a reason. There is
one `#[expect]`. The largest groups: 167 `too_many_lines`, 165
`unwrap_used`, 35 `expect_used`, 31 `too_many_arguments`, 20 `dead_code`.
Of the 202 `unwrap_used`/`expect_used` allows, at least 187 are on test code
(175 in test, bench, fuzz or example paths, 12 more directly on a test item).

**Cost.** Very low. Setting `allow-unwrap-in-tests = true` and
`allow-expect-in-tests = true` in a workspace `clippy.toml` makes those ~187
attributes unnecessary while keeping production code strict (D40). If Q5
also drops the two length lints, about 100 attributes remain to convert,
one commit per crate.

**Fit.** Good. It makes exceptions reviewable and self-cleaning.

**Adopted choice (D351).** Turn off `too_many_lines` and `too_many_arguments`
workspace-wide and remove their local allows. Review whether a module has one
clear job; line and argument counts do not decide that.

### P11. No allocation per byte or frame on the data path

**Rule.** Terminal output, keystrokes and mesh packets reuse buffers. A new
allocation per byte, line or frame on these paths needs a measurement.

**Evidence.** J49 cut the flood peak from 19.8 MB to 10.2 MB. The shim already
has allocation-counting tests (`infraternal-shim/tests/unit/allocation.rs`,
`heap_accounting.rs`).

**Cost.** Low: extend the existing pattern to the server's stream path.

**Measurement.** Allocations per MiB of flood and RSS at 50 sessions in the perf
harness (PROCESS §1). This is a perf number, never a functional assertion.

### P12. Dependency hygiene is reported like size

**Rule.** No new rule, only visibility. Each slice reports its change in the
duplicate-crate count next to its size delta. An unused-dependency check runs
once per release.

**Evidence.** `Cargo.lock` has 50 crate names at two or more versions out of
469. Most come from two generations of the RustCrypto stack side by side
(`digest` 0.10/0.11, `sha2`, `hmac`, `aes-gcm`, `rand` 0.8/0.9/0.10). That
means more bytes (D243) and more code to audit. `cargo deny` already covers
licences, sources and advisories.

**Fit.** Partial. Removing duplicates is size work, decided case by case,
not a gate.

### P13. New UI features load on demand by default

**Rule.** A new feature that is not on the first screen goes in the D188
on-demand class unless measured otherwise.

**Evidence.** The deferred budget was hit repeatedly: J64 (61,936 / 61,440),
J106 (62,025), J100 and J73b, then the J128 diet. Each time the fix was moving
code to on-demand, after the fact.

**Cost.** Very low.

### P14. Gate the merged result, not the branch

**Rule.** The final gate before merge runs on the branch merged onto current
dev, not on the branch alone.

**Evidence.** #303 P2-3 (a stale adapter after rebase failed clippy); merges
that passed on their own base and needed rework on dev (J73b after J106 landed),
and 11 tracer specs red on dev after a merge (J113).

**Cost.** Low. The orchestrator already does this for big merges (`m281`).

## Turned down

| Idea | Why not, for infraternal |
|---|---|
| File length caps (calternal A1–A3) | The bugs above come from behaviour (bounds, blocking, privilege), not file length. A cap forces splits in the middle of review rounds and adds an allow-list to maintain. "One job per module" stays a review item. |
| Function length and cognitive-complexity limits (B1, B2) | Our pedantic `too_many_lines` already exists and is silenced 167 times. A second, similar number would be silenced the same way. |
| Crate-layer table gate (A5) | We have about 20 crates, Cargo already forbids cycles, and today's edges are sane (plugin → agent edges are optional or dev-only). Revisit when a real violation appears. |
| Web import-cycle and ESLint layers (A6, B7) | The tracer is strict TypeScript with `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`. ESLint would add install time to every gate for no recorded bug. |
| Unwrap count ratchet (B4) | Already stricter: `unwrap_used`/`expect_used` are denied workspace-wide. |
| Public-API diff (B8) | Nothing is published. The action registry (D318) is the API that matters, and it has its own contract tests. |
| Coverage percentage | It rewards easy lines. P7 and P5 ask for tests of the failure paths instead. |
| Model checking with loom or shuttle | Our concurrency is tokio tasks and channels, not custom lock-free structures. loom requires swapping in its types. Revisit if the shim grows a lock-free ring. |
| A blanket `unsafe` change | D40 holds: `forbid` workspace-wide, `deny` with audited blocks in the shim. Nothing in the evidence points at unsafe code. |
| Compile-time rules (crate splits, feature rules) | Measure first (`cargo build --timings` once per month on a VM). `verify quick` and shared caches (#329, J149) address the pain directly. |

## Dry runs (J194, 2026-11-04, origin/dev `a89ebb0ae`)

These are historical proposal measurements. Scripts lived outside the repo (`~/.cache/j194/` on
`code`). Full output is on #344.

1. **P4 migration guard.** 56 ms per branch. Over 127 active unmerged branches,
   7.9 s in total, 23 fail. sqlx out-of-order behaviour was confirmed from source.
2. **P2 blocking on the runtime.** A text scan finds 53 hits inside `async fn`,
   17 in production-looking code, 2 real directory fsyncs (#344 finding 1). The
   scanner's noise is why P2 enforces with a helper plus `disallowed-methods`,
   not with the scanner.
3. **P10 lint count.** `allow_attributes_without_reason` would fire on all
   ~501 `#[allow]` attributes. About 187 go away with `allow-unwrap-in-tests`
   and `allow-expect-in-tests`, and 198 more with Q5.
4. **P9/P1/P3 lint counts.** Heuristic: 3,561 undocumented items, 11 production
   `unbounded_channel` sites, 85 `SystemTime::now` reads. Real clippy on
   compute01 (`-W missing_docs -W clippy::missing_docs_in_private_items -W
   clippy::disallowed_methods`): `infraternal-protocol` 41 hits (heuristic 9),
   `infraternal-plugin-api` 132 (heuristic 80). The lint also counts fields and
   variants, so turning it on workspace-wide would give several thousand
   warnings more than the heuristic's count. That is why P9 checks the diff.
   The extra lints added no measurable time: each run took 2–8 s, with
   compilation the only visible cost.

## Adopted scope and checks (D351)

The implementation is tracked on #344. New and changed items need doc comments
checked against the merge base, alongside the existing coverage ratchet. A new
fixed test sleep needs `// sleep: <reason>` immediately above its call, including
`tokio::time::sleep` and Playwright `waitForTimeout`.

Changes touching root-install, proxy, mesh or shim run that area's namespace
tests in an unprivileged sandbox (user, network, mount and PID namespaces, a
read-only host root, no sudo). The test server covers browser and passkey
flows; this gate covers the namespace-only code paths; behaviour that needs
real host root is named as not covered (PROCESS §11). Neither replaces the other.

Nightly fuzzing runs on dev-02 for about one hour across all 36 targets,
outside build peaks at night IST. Crashes become Forgejo issues with their
reproducers attached. Authentication is read from a mode-0600 file,
never a command argument. Timestamp migration enforcement is a separate job
under D347; existing numbered migrations stay.

The numbered proposal questions and owner answers remain on #344 as history.
