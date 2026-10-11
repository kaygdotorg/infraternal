<!-- Records the production-to-dev merge, resolution invariants and reproducible gates for #163. -->
# Production backmerge

The merge commit is `90247165280a1d1231151aa703ec713838706794`, with parents
`5bc58323ab14a99613df16c1dbe254e99bda3d28` (dev) and
`6320f5b52f75c14b6ae0bc92b7ab1974f5570982` (production). The brief identifies
that production tree as deployed under `707a4572`. Only `dev-backmerge` is pushed.
The merge body explains each conflicted file and the rejected alternatives.
No decision, engine or external dependency version was changed.

The deployed session bounds, TLS cookie handling, CA handoff, dead-session
handling, add-host and machine/CA/inbox UI remain. Dev mesh and removable CLI
plugins remain. Production tracer/UI/protocol files are identical except
`apps/tracer/real/server.ts`: it combines prepareData/state/PID support with
strict in-memory extraction of the dev CLI setup-token envelope. The deployed
transport dry-run enum keeps its serialization; dev action metadata uses
`CliDryRun`. Browser resume uses bit 0, native writer fencing bit 1 and renewal
bit 2; no collision requires renumbering. Cargo.lock has zero added, removed or
changed external package records relative to production; only local graph
entries differ. The stray incoming root result.md was removed as instructed.

## Compatibility fixes

Two regressions found during review have separate atomic commits and failing
black-box tests. `b9f21b82` corrects remote CLI schemas to describe deployed
status records and hosted responses; it preserves their bytes. `f5a9d02c`
preserves production root token readers alongside dev data.token readers.
The setup fixture uses an unregistered public string and prints no response
values. Each regression fails before its fix and passes after it.

## Native and TypeScript checks

Checks ran on infraternal-dev: Intel Core i9-9900K, 8 logical CPUs, 33,591,037,952
bytes RAM, Linux 6.12.111+deb13-amd64. Shared-host load samples are retained in
`environment.log` and browser rerun logs. Benchmarks and final gates run under
`systemd-run --user --scope -p CPUWeight=10000`; no load generators ran.
Scratch build targets live under `$HOME/.cache/codex-scratch/dev-backmerge/target`.

The required Nix fast command passed fmt, VT formatting, CLI compile-out,
clippy, workspace tests (zero failed, 66 ignored), and cargo-deny.
Its accepted static-size exception is 20,295,024 bytes on x86_64, against
16,404,816 bytes maximum. The executable is static-pie without PT_INTERP.
Both CLI unavailable JSON checks pass. ARM also builds --locked and is statically
linked without PT_INTERP: 18,062,680 bytes versus its 13,817,816-byte ceiling.
The static ceiling stops the aggregate command before TS, so `ts_verify_fast`
was also run directly, with a separate production output directory.

Tracer check, all 147 source tests, production build and transfer budget pass.
Protocol tests: 36 passed, zero failed, 34,462 assertions. Critical transfer is
291,616 gzip / 242,438 Brotli bytes; deferred is 48,181 / 42,486 bytes. Largest
on-demand chunk is 15,015 / 13,342 bytes. All are under their configured limits.
The required transfer budget ran on the production build before Playwright.

An initial native credit fixture could not create target/acPID because external
CARGO_TARGET_DIR left the relative target/ parent absent. The script is identical
on both parents; creating its empty runtime parent allowed the rerun to pass:
no output/snapshot for 350ms unfunded, control responsive, funded replay 149 bytes
in 909.7ms. The final complete workspace gate passed without a load exception. A later
auth socket timeout passed on focused rerun; the requested dev baseline has
no such test, so no baseline waiver was claimed. A reused baseline Cargo target
then contaminated fingerprints; all workspace artifacts were cleaned and the
merge gate rebuilt cleanly. The authoritative setup gate passes every native
row except the acknowledged static ceiling (709 passing test invocations,
including compile-out and subprocess tests; 66 ignored).
An earlier RTT preflight failed under load (p50 504.96ms/p99 628.07ms); the final
weighted gate passed (289.62ms/291.67ms). Superseded unweighted build output is
retained, and that compile was cancelled to free this job's Cargo lock.

## Browser and real-engine evidence

The complete suite uses TRACER_TEST_PORT=4637. An interrupted unweighted run is retained separately and is not claimed as
a complete result. A wrong-directory invocation failed setup and was corrected. Failed files are rerun alone on a detached merge
checkout, port 4643; persistent failures are compared with the production parent,
port 4641. Each isolated invocation records before/after load. The complete result is 423 passed, 81 failed, 38 skipped (542 cases, 2.5h).
[The comparison matrix](../../evidence/dev-backmerge/browser-matrix.md) maps
every failed file to isolated runs. Persistent failures reproduce on production;
other cases pass alone. Predictive screenshots initially passed on production
at load 9.55/14.17/19.66, then the same visibility assertion failed on both
trees at loads 27.57/30.40/29.48 and 39.04/34.32/31.14. The glyph case passes
on both. Full results are recorded in unedited logs and #163.

Real-shell smoke passes: owner enrollment, one native PTY and returned shell
echo (1 passed, 23.1s). Real production-build captures also pass against the merged
x86_64 static binary (1 passed, 29.4s). Desktop and phone, ink and paper images
are attached under [captures](../../evidence/dev-backmerge/captures/canvas-real/).
They are handed off for visual review; this merge authors no UI changes.

The optional host-facts spec fails on the merge and production parent. Its
Kernel expectation targets the default core view, while Kernel is extended-only
in unchanged production details-facts.ts. Its low-memory assertion observes zero
sessions instead of the one it assumes. These failures do not invalidate the
passing real-shell smoke and are preserved as pre-existing evidence.

## Author review

D16/D198/D201/D202 are checked: action metadata owns public commands and generated
skills; disabled plugin roles compile out; server init remains confirmed; no
node action creates a server. Production private stdin, dump hardening, same-PID
CA handoff and restart/rollback tests remain. Auth B1/S1/S2/N1 checks find no
transaction, verifier, source-admission or credential-storage changes. Native
cookie/TLS/session tests pass. Protocol codecs and existing fuzz targets are
unchanged, with matching capability allocations. New Rust modules have role
docs, and non-obvious compatibility invariants are commented. No secrets,
prices or new product comparisons were added. Issue #163 holds start, findings,
step SHA and verbatim gate output; it is left open.
