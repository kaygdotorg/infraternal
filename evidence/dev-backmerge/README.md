<!-- Indexes unedited gates, load samples and production-build screenshots for #163. -->
# Backmerge evidence

Resolution and review reasoning: [verification note](../../docs/verification/dev-backmerge.md)
and merge commit `90247165280a1d1231151aa703ec713838706794`.

- `verify-fast-setup.log`: authoritative required Nix fast gate; all Rust rows pass except the accepted static-size ceiling.
- `static-aarch64-final.log`, `static-cli-stubs-final.log`: separately complete the checks skipped by the x86_64 size ceiling.
- `tracer.log`: required compiler/source tests/production build/transfer budget, before Playwright.
- `verify-ts.log`: remaining fast-gate TypeScript checks and protocol differential tests, separate production output directory.
- `cli-tests.log`, `clippy-final.log`: focused resolution checks before the aggregate gate.
- `playwright-scoped.log`: complete required browser suite, port 4637, weighted scope.
- `browser-isolated-*.log`: failed files rerun alone on the merge, port 4643; each records load.
- `browser-production-*.log`: production-parent comparisons for persistent failures, port 4641.
- `browser-reruns-driver.log`: rerun invocation exit status index.
- `playwright.log`: interrupted initial run, retained without claiming completion.
- `real-shell.log`: merged CLI setup fixture, passkey enrollment and a real PTY round trip.
- `real-captures.log`: merged static binary and production bundle, desktop/phone ink/paper screenshots.
- `real-host-facts-production.log`, `real-host-facts-parent.log`: optional pre-existing real spec failures on both trees.
- `verify-fast.log`, `verify-fast-rtt-load.log`, `attach-credit-rerun.log`: intermediate gate/setup and host-load evidence.
- `environment.log`: machine and load sample. Finding/step text files mirror issue comments.

Screenshots are [desktop ink](captures/canvas-real/desktop-ink.png),
[desktop paper](captures/canvas-real/desktop-paper.png),
[phone ink](captures/canvas-real/phone-ink.png), and
[phone paper](captures/canvas-real/phone-paper.png). No visual-quality judgment
is claimed by this merge job. Auth capabilities and private material are never
captured; browser traces and automatic failure screenshots are disabled.

- `browser-matrix.md`, `browser-case-*.log`: complete failure mapping and later
  selected-case comparisons, including all predictive retries and load samples.
- `remote-output-before.log`, `remote-output-after.log`, `setup-output-before.log`,
  `setup-output-after.log`: meaningful failing/passing real CLI regressions.
- `verify-fast-clean.log`, `workspace-cache-clean.log`: clean rebuild after
  correcting shared baseline artifact contamination.
- `socket-gone-rerun.log`, `socket-gone-dev-baseline.log`: focused timeout
  rerun and absent baseline case; no baseline waiver claimed.
