<!-- Index of reproducible Connect-regression evidence and author review for #195. -->
# Add-host Connect regression (#195)

See [review.md](review.md) for the cause, test gap, scope and security checklist.
The issue is the state of record; its final comment records the final head SHA,
serialized head-gate output and push outcome. No deployment is part of this job.

## Reproduction and regression

- `regression-before.txt`: release-5's generated initial check fails locally in
  automatic authentication, before SSH opens and without a child exit status.
- `bisect.txt` and `bisect-finding.txt`: source-contract bisect between release 4
  and release 5 identifies `436dfb9723e2f17161c8b2a1e6af2fa9cff7d3de`.
- `trace.txt`: pinned loopback server accepts none authentication, Ed25519 trust,
  negotiated algorithms and exec. This trace contains no signing secret.
- `resume-mesh-tests.txt`: three check variants across NetBird, Tailscale and
  absent provider metadata use nine physical connections, request zero later
  credentials and refuse a changed pin. Provider metadata coverage does not
  claim a deployed Tailscale server run.
- `auth-order-tests.txt`, `ssh-tests.txt` and `resume-ssh-clippy.txt`: controlled
  fallback, exact-script admission, unchanged trust and strict crate checks.

## Diagnostics and UI

- `warn-before.txt` / `warn-after.txt`: the WARN regression fails without
  failure_kind, then passes with classified coordinates and no private output.
- `empty-details-resume-before.txt` / `resume-browser-after.txt`: the fallback
  formerly repeated the summary; all three focused browser cases now pass.
- `resume-browser-full.txt`: all 33 functional production wizard cases pass.
- `connect-failure-1440.png` / `connect-failure-393.png`: production screenshots
  for independent review, not an author visual-quality verdict.
- `resume-copy-tests.txt` / `resume-ts-after.txt`: copy tests and strict TS pass.

## Native gate and baseline

- `resume-agent-tests.txt` / `resume-agent-after.txt`: the production-base EOF
  regression omitted the ordered replay-complete event; the corrected test
  retains its credit-funded output and exit assertions. Runtime code unchanged.
- `resume-native-clippy-after.txt`: both touched native crates pass strict clippy.
- `baseline-build-after-cache-repair.txt`: exact release-5 x86_64 musl baseline
  builds static at 20,329,648 bytes, above the frozen 16,404,816-byte cap.
- `head-x86-build.txt` / `head-arm-build.txt`: branch static builds.
- `verify-fast.txt` is the interrupted disk-full run, not a passing gate.
- `verify-fast-resume.txt` records the parallel milestone including the audit
  capture failure (zero captured events). `audit-rerun.txt` passes that unchanged
  test in isolation. The final head gate serializes tests to avoid overlapping
  test subscribers; its final output is recorded on #195.

Build-host test durations and self-test metrics are not performance evidence.
Functional counts, artifact byte sizes and production screenshots are the
evidence reported here; no timing budget or physical-iPhone result is claimed.
