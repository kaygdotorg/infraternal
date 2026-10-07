<!-- Role: where our UI behaviours were inspired from. Kept in docs only (CLAUDE.md: no product names in code). -->
# Behaviour references and licences

Code and code comments never name other products (CLAUDE.md). This file records,
for licence hygiene, which publicly visible behaviours inspired which of our
components. Each one was written from scratch from observed behaviour; none of
their code was copied. sveltebits.xyz code is MIT + Commons Clause and is
incompatible with AGPL; MetalForge Pro source was never accessed.

| Our component | Behaviour reference |
|---|---|
| `packages/ui/src/countup.ts` | sveltebits count-up |
| `packages/ui/src/glitch.ts` | sveltebits glitch-text |
| `packages/ui/src/tooltip.ts` | sveltebits warm-tooltip; motion rules from Emil Kowalski's animation standards |
| `packages/ui/src/faulty-terminal.ts` | sveltebits faulty-terminal |
| `packages/ui/src/tick.ts` | sveltebits spring-check |
| `packages/ui/src/branched.ts` | sveltebits branched-menu |
| segmented tabs (`docs/design/segmented-selection.md`) | MetalForge segmented control (behavioural decode) |
| toasts (`docs/design/toast.md`) | MetalForge toast (behavioural decode) |
| reflective share card (#76) | sveltebits reflective-card |
