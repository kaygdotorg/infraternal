<!-- Author checklist for the D215 merge and browser durable-credit fix, issue #129. -->
# Integration review checklist

- Preserve dev's SESSION_OWNER bit 3; shared negotiation uses additive bit 4.
  Ordinary/shared writer replacements remain independent; all ownership and
  dead-session shipping CLI cases passed in the 24-test checkpoint.
- Deferred decoder ExitAck removes its peer, not the whole shim. Existing replay
  completion precedes live primed output; census precedes correlated path status.
- No auth, CA custody, enrollment, add-host or release implementation replaced.
  Branch contains both merge parents; no deploy or change to dev itself.
- Browser dispatch validates ranges before admission. One Input/Resize FIFO per
  attachment preserves order. Credit bypasses the FIFO. All Bytes are shared
  slices, never a second terminal payload copy.
- Eight permits count running and queued requests. Byte permits count actual
  wire storage through the durable-Ack wait. Maximum retained FIFO payload is
  4,194,432 bytes per attachment: 838,886,400 bytes for 200 blocked attachments,
  separate from the existing actor's 4 MiB durable-input retention per writer.
  This is a configured maximum, not observed RSS; no timing claim from the build
  host. Idle workers await channels without a timer.
- Dropping/replacing/revoking an attachment aborts its worker; each owned permit
  and queued Bytes is released. Overflow sends stream Close 1013 and reuses the
  existing trailing-frame absorption, leaving control and siblings runnable.
- MAT-R6 fail-first reproduction preserved. Expanded real-router/Unix-actor
  cases cover Credit/Ack release, ordered Resize, slot and byte bounds, cancelled
  queued input, and stream-only overload. Four exact-source cases and the full 930-pass Rust gate pass; size and native same-session flood acceptance fail as recorded in README.md.
