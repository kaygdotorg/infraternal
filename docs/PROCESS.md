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
  `scripts/verify fast` runs a three-sample zero-delay byte-forwarding check
  without a timing bound; the configured RTT measurement stays in the latency
  profile. The full
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
  | `x86_64-unknown-linux-musl` | 21,389,232 bytes |
  | `aarch64-unknown-linux-musl` | 19,561,656 bytes |

  Release jobs (not `scripts/verify fast`, which every job runs) also run
  `scripts/test-static-reproducibility.py`. It builds both targets again from a detached checkout with separate
  Cargo registry, Rustup and target roots. It forces compilation through the
  shared sccache server, compares the shipping bytes and checks that the cache
  wrapper receives Rust and native C path-remap flags before compilation. Rust
  flags keep registry source mappings after the enclosing `CARGO_HOME` mapping;
  rustc applies the later match, which keeps sources under `/cargo/<crate>`.
  This catches release output that depends on a job's build locations.

  The release-9 merge back into dev (#24) retains the optional per-user host
  and updates only the existing `rustls-webpki` dependency to 0.103.16 for
  RUSTSEC-2026-0382. Fresh builds of dev `fe047e2d3` and the merged source use
  the same pinned static recipe on infraternal-dev:

  | Source | x86_64 bytes | aarch64 bytes |
  | --- | ---: | ---: |
  | Dev before | 21,385,264 | 19,570,256 |
  | Release 9 merged, with the TLS patch | 21,387,248 | 19,559,400 |
  | Delta | +1,984 | −10,856 |

  Both exact caps above use the measured merge bytes, with no allowance
  (D243). The existing TLS engine and features stay selected; no protocol or
  build-profile change is included. Receipts and compatibility gates are on #24.

  The RUSTSEC-2026-0382 lockfile update to rustls-webpki 0.103.16 measures
  21,387,248 / 19,559,400 bytes with the same pinned static recipe: +1,024 /
  +1,408 bytes versus release 9. Both exact caps ratchet to these measured
  values; the receipts are on #24.

  Release 9.3's socket authority read cap (#240) measures 21,389,296 /
  19,561,656 bytes with the same pinned static recipe: +2,048 / +2,256 bytes
  versus release 9.2. Both exact caps ratchet to these measurements with no
  allowance (D243); the release artifacts and receipts are on #24. The
  rustls-webpki 0.103.16 lockfile update measured 21,387,248 / 19,559,400
  bytes for release 9.2, +1,024 / +1,408 versus release 9.

  The release 9.3 merge back into dev (#24, #240) keeps dev's optional
  per-user host and brings in the authority read cap unchanged; dev had not
  touched the auth or websocket sources since the merge base. The merged
  source measures 21,389,232 / 19,561,656 bytes with the same pinned static
  recipe: -64 / +0 bytes versus release 9.3. The x86_64 cap ratchets down to
  that measurement and the aarch64 cap stays (D243).

  The reply-reservation production fix (#24, D307) measures 21,387,120 /
  19,558,856 bytes with the same pinned static recipe: -64 / -256 bytes
  against release 8. Replies expire while older typing waits or the queue
  is full; expected expiry and opaque writer refusals avoid error allocation.
  Both exact caps ratchet down to these measurements (D243). No protocol,
  dependency or build-profile change is added.

  Release 9 merges the reviewed reply reservation and shared-layout recovery
  histories, then picks the quiet session-list warm-up and its standalone test
  fix (#24, #243, #249). Same pinned stripped static measurements:

  | Stage | x86_64 bytes | aarch64 bytes |
  | --- | ---: | ---: |
  | Release 8 | 21,387,184 | 19,559,112 |
  | Reply reservation | 21,387,120 | 19,558,856 |
  | Layout recovery | 21,386,224 | 19,557,992 |
  | Quiet warm-up and final | 21,386,224 | 19,557,992 |

  Final deltas versus release 8 are -960 / -1,120 bytes;
  both exact caps retain no growth allowance (D243). Link-time effects make
  the individual reductions non-additive. The TypeScript-only picks
  leave both native images byte-identical. Migration 0030 is the only added
  migration; production's 0001–0029 SQL remains unchanged. Qualification and
  artifact receipts are recorded on #24, #243 and #249. No dev or delta-review
  branch is included, and this release qualification does not deploy.

  Release 8 integrates D307, synchronized output and input ordering (#206),
  the stale-screen note (#248), and the display-only phone column minimum
  (#243, D309). The stripped static measurements are:

  | Stage | x86_64 bytes | aarch64 bytes |
  | --- | ---: | ---: |
  | Release 7 | 21,385,264 | 19,570,256 |
  | D307 | 21,387,824 | 19,559,624 |
  | Synchronized output, colour and input ordering | 21,387,184 | 19,559,112 |
  | Stale-screen note | 21,387,184 | 19,559,112 |
  | Phone minimum and final | 21,387,184 | 19,559,112 |

  Final deltas are +1,920 / −11,144 bytes versus release 7. The release-6
  D307 delta is not additive on this combination. The release-8 brief permits
  at most +20,000 x86_64 bytes: the result is 18,080 bytes below that stop
  line. Both exact caps retain no growth allowance (D243). The note and phone
  changes leave both native files byte-identical. No migration is added;
  production's 0001–0029 SQL files remain unchanged. Measurements and release
  qualification receipts are recorded on #24, #206, #243 and #248.

  The initial shared layout recovery fix (#243) ratcheted the ceilings to
  21,386,992 / 19,558,632 bytes: −192 / −480 versus release 8. It adds migration
  0030 to backfill transactional receipt counts. Build-time SQL formatting
  compaction preserves every original migration checksum; historical layout
  repair happens through normal snapshot revisions. Static receipts and the
  production-shaped two-device checks are recorded on #243.

  The release-9 recovery review fixes (#243) preserve bounded fallback and queued
  membership IDs, then share ID assignment and recovery recognition to offset
  their code. Same-recipe rebuilds against `bd5ee1dd7` measure 21,386,224 /
  19,558,248 bytes: −768 / −384. Both exact ceilings ratchet downward to these
  measurements. No dependency, profile or migration SQL changes are included;
  both architecture receipts and the review regressions are recorded on #243.

  Release 7 measured 21,385,264 / 19,570,256 bytes after the reviewed Retry and Mesh merges,
  #246 source-path normalization, and the #236 migration collision correction:
  +40,960 / +34,656 bytes over release 6. Retry measured 21,352,208 /
  19,542,304 bytes; Mesh measured 21,385,264 / 19,570,256. Build normalization
  preserved those sizes. Reserving existing names in unshipped migration 0029
  adds +0 / +0 bytes. The exact caps retain no growth allowance (D243).
  Release jobs run the cross-root reproducibility check after `scripts/verify fast`.
  Release 6 measured 21,344,304 / 19,535,600 bytes. From release 5, #244 adds 3,776 /
  3,320 bytes and #243 adds 114,656 / 104,592 bytes, totaling 118,432 /
  107,912 bytes. D308 accepts the shared-layout increase after its first
  trim; release 6 x86_64 remained 24,928 bytes below its +140 KiB stop line.
  Release 5 added the Mesh view (#236) at +81,760 / +56,992 over release 4;
  D306 accepted that increase. Each cap stays at its exact measured size
  until a later measured reduction ratchets it down. Release 4's one-off D243 exception was accepted
  within the task's +64 KB ceiling for D299's versioned `--json` envelope and
  D303–D305 command behavior, together with #237's status truth (+17 KB).
  The trim follow-up is owed.

  The release-2 measurements were: the release-retry line (next paragraph,
  21,080,848 / 19,316,360) plus D300 host-link doubt (#234), already-added
  "Open a terminal" (#189), host removal that uninstalls itself (#235) and
  authority reads retried through a busy store (#240): -704 / +6,288 bytes
  in all (D243).

  The earlier release-retry measurements (#230 merged into the #189
  production line, 3048580c1): the production line measured 21,090,448 /
  19,316,264 bytes; the merge is 9,920 / 160 bytes smaller. Taking the
  commit guard only after terminal proof adds back 256 / 128 bytes, and
  keeping the root restage command within one kernel argument another
  128 / 128 bytes; binding the root program once removes 64 / 0 (#230). Lifetime-safe
  retry adds its runtime-lock helper, kernel endpoint checks and helper
  refresh; its SSH management crate moves from s to z (#230), which more than
  offsets that code on x86_64. The faster add-host path (#189) keeps its
  session image and its own size work. Combined-source artifacts use
  `.cargo/rustc.sh`, which remaps repository, build and dependency source
  roots once; the native wrapper normalizes generated compiler metadata.
  The earlier #198 reductions remain: unused native APIs, duplicated action
  metadata construction, OpenSSL's unused VAES/AVX-512 AES-GCM dispatch, and
  unused Axum extractor features were cut (D243, D264, #198). The x86_64 build
  retains AES-NI and generic AES-GCM dispatch, checked against a NIST vector
  using the shipping static crypto archive.
  The release, host-facts, SSH and host-orchestration crates use size
  optimization; terminal, mesh and cryptographic data paths retain speed
  optimization (D243, D264, D272).
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
