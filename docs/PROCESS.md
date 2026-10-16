<!-- Build, review and verification workflow for infraternal contributors. -->
# How infraternal is built

Adopted by the owner on 2026-10-06 (P1). This file is the standing process.
`CLAUDE.md` points here, and each job prompt includes the Definition of Done.

The principle: **machines enforce performance, people decide matters of
judgment, and nothing waits on either.**

## 1. Performance is a gate, not a review

- Benchmarks run only on the pinned perf VM (`perf-test-69-63`). It is
  shared with calternal and is used only for benchmarks, never for builds.
  Each run holds the shared lock (`scripts/perf-run`, agreed with the
  calternal session). Built binaries are copied to the VM.
- Each budget in DECISIONS 41 and 81 is a CI check that fails on a
  regression:
  - keystroke overhead and frame time, measured from the real UI;
  - flood throughput;
  - reconnect time;
  - zero idle wakeups;
  - RSS at realistic scale (for example 50 sessions, not 1);
  - bundle size;
  - first paint.
- Nightly: a trend of every budget, plus fuzzing of every parser.
- Memory is always reported per unit × the expected count. A number for one
  session is not evidence.

## 2. Each lane can be reviewed when it arrives

Definition of Done (it is in every job prompt):

1. The contract is followed. Contract changes are proposed on the issue
   before the code changes, and they are additive where the contract is
   frozen.
2. Atomic commits. Each commit builds, is formatted and lint-clean
   (`cargo fmt --check`, `cargo clippy` for the touched crates, `bun run
   check` for touched TypeScript) and passes the tests of the code it
   touches. Between commits, iterate with `scripts/verify iterate` (#204): the
   same fmt, VT fmt, clippy, tests, cargo-deny, plugin compile-out,
   TypeScript and repository artifact checks, without the two static release
   builds, linkage, D244 key-heap and D243 size checks. The full
   `scripts/verify fast` (static builds included) is the final gate: it runs
   at milestones and always on the branch head before you report done, hand
   off to review, push for integration or merge; its output is quoted
   verbatim on the issue. A green `iterate` run is never quoted as the final
   gate. The commit body gives the why, the rejected alternatives, and the
   decision or issue references. (Owner, 2026-10-11: the full gate on every
   commit cost about half of each job's time on the shared build host.)
3. Tests against real engines (real PTY, real sshd, real Docker or Podman).
   Parsers have fuzz targets. Each bug that is found gets a failing test
   first.
4. Numbers against the budgets, at scale. The machine and its load are
   recorded.
5. Module doc comments. Non-obvious code explains its invariants.
6. The issue is updated: start (branch and base), findings, finish (head and
   gate output, verbatim).
7. The author runs the reviewer checklist for its area before it reports
   done.
8. Raw screenshots, logs, traces and measurement receipts live outside the
   checkout under `$HOME/.cache/codex-scratch/<job>/evidence/`. Attach selected
   files to the issue with the orchestrator-provided `issue-attach <N> <file>...`
   helper; do not commit generated evidence.

Then an independent reviewer job (with a different model or prompt, and
given only the diff and the contracts), then a fix round if one is needed.
Reviews and fixes run at the same time as the next lane's build.

## 3. Decisions never block builders

- Foundational choices (libraries, engines, transports, crypto, UX patterns)
  go to the owner as grill questions with measured trade-offs. Jobs measure.
  They never choose (CLAUDE.md, "Foundational choices").
- Open questions run as time-boxed spikes next to the lanes. Spike code is
  never merged.
- A lane starts only when its ground is decided.

## 4. Integrate all the time, and dogfood at once

- Small, frequent merges to `dev`. The gate runs on the merge result every
  time. Integration fixes are part of the merge commit, and they are
  explained.
- Each merge to `dev` deploys a preview (infraternal-dev now, monitor01 when
  the tracer runs). The owner tests the real build.
- Each change that the owner can see has a three-line "how to test" note on
  its issue. Each problem that the owner reports becomes an issue with a
  failing test before the fix.

## 5. Capacity

- infraternal-dev (8 cores): at most about 3 Rust lanes and 1 review at the
  same time.
- An M5 Ultra Mac Studio arrives soon. Planned use: native macOS and iOS
  builds and the macOS agent (S2), Safari and iOS Simulator testing, and
  extra build lanes through Linux VMs (OrbStack).
- Jobs avoid wording that tooling filters flag. Process-termination tests
  are described neutrally ("abrupt stop", "restart").

## 6. High-latency test profiles [D122, D130]

- Test links default to a 300 ms round trip with ±30 ms round-trip jitter.
  `INFRATERNAL_TEST_RTT=0` disables delay for a local debug run.
- `scripts/latency_proxy.py` is a loopback-only, rootless byte-stream relay. It
  sits between Chromium and the tracer test double, and between native test
  clients and the real infraternal agent over the fixture socket pair. The
  relay delays each direction by half the configured RTT. It samples jitter
  for each active burst and reuses that sample across TCP chunks, because TCP
  read boundaries can split one HTTP request or WebSocket frame. The relay
  preserves stream bytes and order; it needs neither root nor `tc`.
- Native fixtures keep session sockets in a short per-run scratch directory
  (`INFRATERNAL_TEST_STATE_ROOT`, defaulting to
  `$HOME/.cache/codex-scratch/infraternal`). `fixture_state` checks that the
  generated Unix-socket path and its longer `.upstream` test relay path fit
  Linux `sun_path`; worktree-relative target paths can exceed that kernel
  limit.
- `python3 scripts/latency_proxy.py self-test --samples 31` measures the
  configured loopback RTT and prints `METRIC name=network_rtt_selftest ...`.
  `scripts/verify fast` runs the short three-sample version. The full
  `scripts/verify latency` profile runs the relay self-test, a real agent/PTy
  echo and flood gate, `verify-auth-browser`, and the production tracer browser
  suite. Playwright uses `TRACER_TEST_PORT` (default 4621); concurrent runs
  must choose distinct ports.
- The TCP relay does not emulate the requested 0.5% packet loss: dropping bytes
  would corrupt a reliable TCP/WebSocket stream, and the available CDP
  `packetLoss` setting is documented for WebRTC rather than HTTP/WebSocket
  traffic ([Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/tot/Network/)).

  The gate therefore reports `loss=unsupported`; packet loss needs a separate
  transport-level mechanism that preserves TCP semantics.
- The input-to-photon report uses fixed `METRIC` records. Keystroke-to-glyph
  p99 is report-only until predictive echo #50 lands, then its budget is 17 ms.
  Echo confirmation is bounded by RTT + 34 ms. Flooding either another PTY or
  the same PTY may grow echo p99 by at most one 60 Hz frame (16.67 ms).
  Returning sign-in to a usable terminal uses the 5 s budget tracked in #52.
  Reconnect-to-resumed is bounded by RTT × 2 + 300 ms; at the default 300 ms
  RTT this is 900 ms, while D41's under-300 ms reconnect budget remains the
  zero-network-overhead reference.

## 7. Rust build speed and static binary size

- `scripts/verify fast` checks the stripped, static release binaries against
  exact measured ceilings, with no growth allowance (D243):

  | Target | Measured ceiling |
  | --- | ---: |
  | `x86_64-unknown-linux-musl` | 21,320,560 bytes |
  | `aarch64-unknown-linux-musl` | 19,513,808 bytes |

  These ceilings pin the normalized combined-source artifacts measured on #201.
  A fresh checkout and empty target reproduce the x86 artifact byte for byte.
  The recipe retains the approved native AES-GCM fallback and size optimization
  for release and host-facts plugins; terminal, mesh and cryptographic
  dependencies retain speed optimization (D243, D264, D272). Combined-source
  size and runtime receipts remain required for acceptance.
  The obsolete #57 ceilings were below every shipping build and obscured growth.
  Larger images fail. Smaller images also fail until that target's ceiling is
  ratcheted down to its new measured size; a cut cannot leave slack for later
  regrowth. Update both targets and this table with evidence on the issue.
  An intentional increase needs a justified, target-specific measured owner
  exception under D243. The gate never updates a ceiling automatically.
  Attribution, retained feature costs and runtime tradeoffs are recorded
  on #198 and [#201](https://git.kayg.org/kayg/infraternal/issues/201).
- The job launcher provides `sccache` through `RUSTC_WRAPPER`; keep the cache
  enabled for repeated builds. Put Rust build output in a job-specific
  `CARGO_TARGET_DIR` under `$HOME/.cache/codex-scratch/` rather than `/tmp`.
- Native x86_64 GNU development and test links use mold when installed, with
  `cc` as the fallback. Static musl release links continue to use the pinned
  Rust toolchain's LLD. The checksum-pinned Zig toolchain is used for vendored
  C dependencies; `scripts/auth-toolchain` stages it for the static build.
- The release profile uses `opt-level = 3`, LTO, one codegen unit and stripping.
  It keeps `panic = "unwind"` so tokio can isolate a panic to its task rather
  than ending every session. Change release settings only with measured runtime
  results from the pinned performance VM, as specified in section 1.
- For size investigations, use `cargo bloat --release --crates` for native
  builds or pass the x86_64 musl target to inspect the static release profile.

## 8. Backend grill first, design grill second (owner, 2026-10-08)

Every feature goes through two grills, in this order:

1. **Backend grill, extensively.** The orchestrator questions the owner until the backend design tree is empty. The decisions are recorded in DECISIONS.md and the feature's issue, and Codex jobs start building at once.
2. **Design grill, extensively.** Then come the design questions and mockup iterations, as many rounds as it takes to reach "good enough", while the backend builds in parallel.

The aim is that the backend is finished when the design is approved, so approved UI is wired to real behaviour instead of a test double. Every status report says plainly what is shipped, what is built but not wired, and what is mockup only.

## 9. Every backend job gets a break-it review (owner, 2026-10-08)

When a Codex implementation job finishes, an independent Codex reviewer starts automatically on its branch head (`~/.local/state/codex-jobs/infraternal/auto-review.sh`, template `review-template.md`). The reviewer gets the diff, the contract and the claims, not the author's reasoning. Its only goal is to prove the work wrong: correctness and concurrency edge cases, defensive input and authorization checks, data safety, resource leaks, re-measured performance claims and contract drift. Each finding is a failing test committed on `review-<job>`, plus an entry in its findings file and a comment on the issue for P0/P1, ending with a verdict. The implementation's next run must make those tests pass before merge. Sol reviews security, data and sync work; Luna reviews the rest.


## 10. Branches, commits and pushing (owner, 2026-10-10)

- Every change is an atomic commit, and every commit is pushed. Work that
  exists only on this build host can be lost.
- `dev` holds the dev builds. Merges, decisions, TASTE rows and process docs
  land on `dev` and are pushed straight away.
- `main` holds stable builds only. It moves forward from `dev` when a build is
  declared stable, never by direct commits.
- Job and release branches are pushed as soon as they have commits. Unfinished
  job work that can't be committed yet is snapshotted to `wip/<job>` so it
  isn't lost.
