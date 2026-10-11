<!-- Author checks and independent-review evidence for production add-host fixes, #169. -->
# Add-host author review

Reviewed against `docs/ssh-bootstrap-evidence.md` and
`docs/reviews/ssh-bootstrap-87-repair.md` checklists.

- Admission: unchanged exact owner/session/origin checks and root consent.
  D139 prevents sudo availability from selecting root; D229 covers server init.
- Private readiness: additive boolean on authenticated leg-B terminal.open;
  browser cannot supply commands, uid overrides or arbitrary paths.
  Fixed non-login sh emits confirmed PTY output; ordinary login PTYs unchanged.
- Lifetime: register session before attachment awaits; exact attempt cleanup
  precedes rollback. Cancellation and failed attachment regressions pass.
  Private deadline covers lost replies and leaves zero durable exit artifacts.
- Diagnostics: retain numeric status only. Server logs omit messages, remote
  output, address, credential references and authentication material. Log test
  proves one line and excludes private sentinels. No host trust changes.
- Recovery: existing directory ownership/private checks remain strict; 71/72
  explain the operator action rather than weakening deletion protection.
- Bounds: Failure remains 120 bytes, 122880 bytes for 1024 retained events;
  at the existing 16-batch cap, 1966080 bytes inline worst case, unchanged.
  Ordinary sessions gain no timer or idle polling. No dependencies added.
- UI: extends existing details disclosure, with no duplicated component/styles.
  Production build transfer budgets pass. All 27 add-host browser cases pass
  on port 4891. Screenshot `failure-details.png` is attached for independent
  visual review; author does not judge visual quality. No physical iPhone test.
- Real engines: isolated startup profiles configure actual tmux/zellij or a
  never-returning menu/bash. Real daemon/shim PTYs bypass startup and provide
  the readiness marker; these are readiness-boundary tests, not a full remote
  enrollment on an unrelated host. Existing installer filesystem and lifecycle
  tests cover setup/refusal/rollback. No external hosts contacted.
- Contracts: additive readiness/status changes proposed on #169 before code.
  Existing parser fuzz targets remain; no new parser or foundational engine.

Targeted gate and before/after outputs accompany each fix. Final full fast
output and branch head are recorded verbatim on #169 before handoff.

## Production base and gate provenance

The initial worktree was incorrectly based on dev commit `93b00f5a`.
Only the four fixes were ported onto production `1c08c4b7`; no dev-only
lifecycle, retention, transport or dependency changes were imported.
Use `production-*` logs for the corrected-base gates. Earlier logs remain
as the failing-test and investigation record, not production acceptance.
Production targeted gates: readiness bootstrap25/1 ignored and shim62/12;
cleanup bootstrap27/1 and SSH7/1; diagnostics bootstrap28/1 and SSH47/0.
Production tracer source tests:137 passed, zero failures; browser27 passed
in5.6 minutes on port4891. `failure-details.png` is the refreshed production
capture for independent review. The final full gate and static sizes are
quoted on #169 after the final branch head is checked.
