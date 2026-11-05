# infraternal agent contract

Before you start any work, read `DECISIONS.md`, `docs/ARCHITECTURE.md` and
`docs/PROCESS.md` (how work is built, reviewed and merged).
Decisions are referenced by their number. Only the owner (kayg) can change one.

## Priorities

1. Performance and latency come first. Measure. When a change slows something
   down, it needs a benchmark that justifies it.
2. Correctness and security: the protocol parser, the auth code and the
   handling of secrets get the strictest review.
3. Polish on mobile. The PWA must feel native on an iPhone.

## Rules

- Follow the adopted [engineering practices](docs/ENGINEERING.md) (D351).
- License: AGPL-3.0-only. Every crate and package states it. Commercial code
  lives in its own repository, `kayg/infraternal-enterprise` (D277), never in
  this one. Dependencies must be compatible with AGPL.
- Vocabulary: "infraternal agent" means the host daemon. "AI agent" means
  Claude, Codex and similar tools. Never use "agent" alone in user-facing text
  when it could mean either.
- Reuse first. Before you create a component or helper, look for an existing
  one in `packages/ui` and extend it. Do not create basic UI from nothing.
  bits-ui is for headless primitives only. Use sveltebits.xyz only as a
  visual reference. Never copy its code: its license (MIT + Commons Clause)
  is not compatible with AGPL.
- Taste: read `docs/design/TASTE.md` before any UI work and check your work
  against it. Every annoyance the owner spots is added there the same day.
- Review UI from screenshots of a real production build. Save screenshots,
  logs and other raw receipts outside the checkout under
  `$HOME/.cache/codex-scratch/<job>/evidence/`; Codex jobs attach the selected
  files to the issue with the orchestrator's `issue-attach` helper. They do not
  judge their own visual quality.
- Code explains itself. Use module docs and comments for choices and
  invariants that are not obvious.
- No secrets in the repo, in logs or in argv. No prices in the repo.
- No other products' names in code or code comments. Never write that something
  is "like", "inspired by", "re-implemented from" or "the same as" another product.
  We implement features our own way. Documentation (docs/, research/, DECISIONS)
  may name products as examples. Code may name something only where it directly
  integrates with or depends on it (for example calling a CLI we support, or a
  library we ship), and then only factually.
- Commit atomically and push every commit (owner, 2026-10-10). Development goes
  to `dev`; `main` holds stable builds only (docs/PROCESS.md §10). Deploy only
  when the task tells you to.

## History and tracking (owner rule)

- Atomic commits: each commit makes one logical change, builds, and passes its
  gate. Do not mix refactors, features and formatting.
- A commit message says what changed and why: the problem, the choice made,
  and the alternatives you rejected. Put the decision number or the issue
  (`#N`) in it. A reader must understand the commit without this session.
- Every piece of code ships with documentation-style comments (D345): each
  module, type, function and exported symbol says in plain, friendly words
  what it is for and how to use it, plus non-obvious invariants and reasons.
  Comments never count as lines of code. Docs will be generated from them.
- Code comments are the documentation. Each module starts with a doc comment
  that explains its role. Non-obvious code explains its invariants and the
  reason for it, not only what it does.
- Forgejo issues (`kayg/infraternal` on git.kayg.org, through `scripts/fj`)
  record every request, decision and piece of work. Open an issue before you
  start work. Comment when you start (branch and base SHA), for each finding
  (with evidence), when you are blocked, and when you finish (head SHA and the
  gate output, verbatim). Jobs never close issues. Memory tools such as Honcho
  are a convenience, not the record.

## Foundational choices (owner rule)

- A library or engine that the foundation depends on (terminal state,
  crypto, database, transport, renderer, and so on) is never chosen inside a
  job. The orchestrator brings it to the owner as a grill question with
  measured trade-offs: speed, memory per session multiplied by the expected
  number of sessions, correctness, and consistency with the rest of the
  stack. A job may measure candidates. It does not decide.

## Gates

Iterate with `scripts/verify iterate` (the same checks without the static
release builds and their linkage, key-heap and size checks). Before you report
that work is done, run `scripts/verify fast` and quote its output. Each slice adds its own gates (integration, browser, bench). A green
gate is not proof: include measured numbers and issue-attached screenshots.
