# infraternal agent contract

Before you start any work, read `DECISIONS.md` and `docs/ARCHITECTURE.md`.
Decisions are referenced by their number. Only the owner (kayg) can change one.

## Priorities

1. Performance and latency come first. Measure. When a change slows something
   down, it needs a benchmark that justifies it.
2. Correctness and security: the protocol parser, the auth code and the
   handling of secrets get the strictest review.
3. Polish on mobile. The PWA must feel native on an iPhone.

## Rules

- License: AGPL-3.0-only. Every crate and package states it, except `ee/`
  (commercial). Dependencies must be compatible with AGPL.
- Vocabulary: "infraternal agent" means the host daemon. "AI agent" means
  Claude, Codex and similar tools. Never use "agent" alone in user-facing text
  when it could mean either.
- Reuse first. Before you create a component or helper, look for an existing
  one in `packages/ui` and extend it. Do not create basic UI from nothing.
  bits-ui is for headless primitives only. Pick components from
  sveltebits.xyz when they fit.
- Review UI from screenshots of a real production build. Codex jobs attach the
  screenshots. They do not judge their own visual quality.
- Code explains itself. Use module docs and comments for choices and
  invariants that are not obvious.
- No secrets in the repo, in logs or in argv. No prices in the repo.
- Do not push or deploy unless the task tells you to.

## Gates

Before you report that work is done, run `scripts/verify fast` and quote its
output. Each slice adds its own gates (integration, browser, bench). A green
gate is not proof: include the evidence (screenshots, numbers).
