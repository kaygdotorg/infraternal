<!-- Production tracer screenshots for independent review of #151's refusal guidance and existing sessions action. -->
# Session memory refusal captures

Captured by `real/host-facts.spec.ts` against this branch's static musl binary,
using the real server, infraternal agent, shim and shell. The host memory floor
is configured above actual available memory through its authenticated action;
no mock replaces admission. The default is restored after the test.

The spec writes to `$HOME/.cache/codex-scratch/tracer-<pid>/evidence/session-bounds/`.
Attach selected review images to #151 with the orchestrator's `issue-attach` helper;
the repository does not retain generated screenshots.

- `refusal-desktop.png`: desktop viewport 1440x1000.
- `refusal-phone.png`: phone viewport 393x852, device scale factor 3.
- `sessions-phone.png`: the existing host sessions picker after activating the
  shared toast's Sessions action on the phone viewport.

The phone capture uses Chromium device emulation, not physical iPhone Safari.
Functional assertions pass; visual quality is for independent review.
