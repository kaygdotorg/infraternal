<!-- Records the local author review of the narrowly scoped round-two release fixes (#87). -->
# Author review

- Host trust: one independently observed allowed key, negotiation pinned to its type;
  explicit replacement challenge compares the old pin; atomic rename and directory fsync.
- Authentication: removal requires its private purpose registry and real UV passkey;
  host UUID/session/owner/deadline/signing credential rechecked; ordinary login, wrong
  host, replay, logout and role loss refused. No account key enters this operation.
- Secrets: CLI/SSH/enrollment input stays on private stdin or scoped sockets;
  no credential files, argv, arbitrary stderr or browser network traces.
- Plugin boundary: optional remote feature owns the action and uninstall handler;
  internal uninstall is absent from browser descriptors; no compiled-in idle task.
- Files: uninstall validates the private owned root, marker, exact unit ExecStart,
  launcher, enable link and lack of an in-progress bootstrap; request supplies no paths.
- Lifetime: successful acceptance write releases the independent uninstall helper;
  failed writes discard the continuation. Server mutation survives HTTP cancellation;
  certificate revocation uses the existing quiescence fence and durable tombstone.
- UI: one registry label, one removal callback, shared confirmation/button/toast;
  confirmation names the host; result distinguishes requested cleanup from completion.
  Production screenshots are attached for independent visual review.
- Terminal: committed exit delivery persists status and waits for final output to paint;
  clean exit closes the window and nonzero status keeps its scrollback.
- Distribution: one pinned Zig, both stripped static architecture payloads beside the
  server, complete-directory publication and checksums; no release profile weakening.
- Migration: dev d82d0fb9 ownership, foreign keys and integrity retained.

Gate logs and actual container measurements are recorded in the completion evidence.
