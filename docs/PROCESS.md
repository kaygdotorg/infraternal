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
2. Atomic commits. Each commit builds and passes `scripts/verify fast`. The
   commit body gives the why, the rejected alternatives, and the decision or
   issue references.
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

## 6. Backend grill first, design grill second (owner, 2026-10-08)

Every feature goes through two grills, in this order:

1. **Backend grill, extensively.** The orchestrator questions the owner until the backend design tree is empty. The decisions are recorded in DECISIONS.md and the feature's issue, and Codex jobs start building at once.
2. **Design grill, extensively.** Then come the design questions and mockup iterations, as many rounds as it takes to reach "good enough", while the backend builds in parallel.

The aim is that the backend is finished when the design is approved, so approved UI is wired to real behaviour instead of a test double. Every status report says plainly what is shipped, what is built but not wired, and what is mockup only.

## 7. Every backend job gets a break-it review (owner, 2026-10-08)

When a Codex implementation job finishes, an independent Codex reviewer starts automatically on its branch head (`~/.local/state/codex-jobs/infraternal/auto-review.sh`, template `review-template.md`). The reviewer gets the diff, the contract and the claims, not the author's reasoning. Its only goal is to prove the work wrong: correctness and concurrency edge cases, defensive input and authorization checks, data safety, resource leaks, re-measured performance claims and contract drift. Each finding is a failing test committed on `review-<job>`, plus an entry in its findings file and a comment on the issue for P0/P1, ending with a verdict. The implementation's next run must make those tests pass before merge. Sol reviews security, data and sync work; Luna reviews the rest.
