<!-- Maps full-suite failures to isolated merge and production-parent invocation exits for #163. -->
# Browser diagnostics

Full required gate: 423 passed, 81 failed, 38 skipped across 542 cases (2.5h).
Every failed file was rerun alone. Later runs select the failing independent cases;
files with shared fixtures run in full. Exit 0 is passing, 1 is a test failure.
The two early addhost timing files also pass alone, although they passed in the complete retry.

| File | Full failures | Merge isolated exit | Production exit | Merge retry exit | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| test/add-host-prototype.spec.ts | 1 | 1 | 1 | — | fails on both trees |
| test/canvas.spec.ts | 2 | 1 | 1 | — | fails on both trees |
| test/cell-metrics.spec.ts | 1 | 0 | — | — | passes alone |
| test/clusters-flight.spec.ts | 1 | 0 | — | — | passes alone |
| test/clusters-frames.spec.ts | 2 | 0 | — | — | passes alone |
| test/clusters-grid.spec.ts | 8 | 1 | 1 | — | fails on both trees |
| test/clusters-keyboard-split.spec.ts | 1 | 1 | 1 | — | fails on both trees |
| test/clusters-shortcuts-spam.spec.ts | 4 | 0 | — | — | passes alone |
| test/clusters-swipes-both.spec.ts | 4 | 0 | — | — | passes alone |
| test/clusters-swipes.spec.ts | 2 | 1 | 0 | 0 | passes alone |
| test/clusters-zoom-bench.spec.ts | 1 | 0 | — | — | passes alone |
| test/clusters.spec.ts | 6 | 1 | 1 | — | fails on both trees |
| test/core-screen.spec.ts | 1 | 1 | 1 | — | fails on both trees |
| test/font-metrics.spec.ts | 1 | 0 | — | — | passes alone |
| test/font-weight.spec.ts | 1 | 0 | — | — | passes alone |
| test/glass-ghost.spec.ts | 16 | 1 | 1 | — | fails on both trees |
| test/mesh-perf.spec.ts | 1 | 1 | 0 | 0 | passes alone |
| test/motion-audit.spec.ts | 1 | 1 | 1 | — | fails on both trees |
| test/onboarding.spec.ts | 1 | 1 | 1 | — | fails on both trees |
| test/palette-navigation.spec.ts | 1 | 1 | 1 | — | fails on both trees |
| test/perf-hud.spec.ts | 1 | 1 | 1 | — | fails on both trees |
| test/platform-consistency.spec.ts | 3 | 1 | 1 | — | fails on both trees |
| test/predictive-backspace.spec.ts | 2 | 0 | — | — | passes alone |
| test/predictive-echo.spec.ts | 2 | 1 | 0 then 1 | 1 then 1 | screenshot fails on both under load; glyph passes |
| test/recovery-ui-hold.spec.ts | 4 | 1 | 1 | — | fails on both trees |
| test/renderer-regression.spec.ts | 3 | 1 | 1 | — | fails on both trees |
| test/sessions-canvas.spec.ts | 6 | 1 | 1 | — | fails on both trees |
| test/terminal-theme.spec.ts | 1 | 1 | 1 | — | fails on both trees |
| test/terminal.spec.ts | 2 | 1 | 1 | — | fails on both trees |
| test/unicode-fidelity.spec.ts | 1 | 0 | — | — | passes alone |

Browser source, harness, UI and codecs match the production parent; real/server.ts
is the sole frontend-tree difference and is unused by this mock-server gate.
The native CLI fix-ups do not change that source equivalence. Runtime build date
and commit labels vary. Before/after load is retained per invocation.

Predictive screenshot comparison: the first production run passed at load 9.55 /
14.17 / 19.66. Subsequent merge and production runs both passed the glyph case
and failed the screenshot visibility assertion (hidden after capture), at final
loads 27.57 / 30.40 / 29.48 and 39.04 / 34.32 / 31.14 respectively. All attempts
are retained; a passing parent run alone was not treated as a waiver. The glass
parameter matrix shares one stale toast expectation; one exact parameter fails
on both parents after 120 seconds. The interrupted diagnostic is labeled.
