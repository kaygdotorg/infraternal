<!-- Records author security/lifecycle review and evidence boundaries for review fixes #154 [168][184][217][224]. -->
# Author review — round 2

- Authorization: CA export requires effective UID 0, root-owned executable and
  root ownership without group/world write on every parent. Non-root replacement
  remains supported and deliberately cold. General executables and unmarked
  rollbacks receive null stdin. The marker is compatibility metadata, not a
  release signature; the D184/D224 opened-fd verification hook remains deferred.
- File identity: the receiver opens once with close-on-exec/no-follow, validates
  the opened inode and executes it with `fexecve`. Tests replace the path after
  opening and prove the original inode executes. Additional real-exec tests
  cover closed stdin before/after opening the image: code stays above fd2 and
  cold null input remains owned through exec with CLOEXEC explicitly cleared. Path aliases, parent escapes,
  writable executables and set-ID remain refused.
- Channel identity: kernel credentials must match the preserved PID and UID
  before receiving bytes. The named 0600 control socket carries only a bounded
  target path. Same-UID foreign PID import remains refused.
- Entry and cleanup: first main action disables dumpability; stdin import and
  detachment precede cold configuration. Injected null-open/dup failures close
  fd 0. Child launchers explicitly detach stdin; PTY shells retain their explicit
  slave descriptor. SSH prompt helper proc authorization is preserved by its
  existing dumpable policy after stdin detachment; it never imports the CA.
- Secret memory: dedicated bounded seed/frame/receive mappings require `mlock`
  and `MADV_DONTDUMP`, confirmed by kernel `smaps`. Drop clears entire mappings.
  OpenSSL-owned signing state, its immediately zeroized API export copy, and
  kernel socket buffers are documented residual copies. No valid private handoff frame
  corpus or plaintext CA seed is persisted; transfer material never enters
  arguments, environment values or diagnostics.
- Failure isolation: EPIPE, invalid target and failed reload keep serving.
  Deleted current inodes reopen the configured install path. Restart endpoint
  setup failure logs and leaves health serving. Tests exercise real subprocesses
  and sockets, with failing-before evidence for each fix.
- Lifetime: runtime shutdown waits at most four seconds. Owned-child blocking
  cleanup escalates at two seconds and bounds reaping at three; async cancellation
  cannot cancel that escalation. Tests use idle children, never CPU generators.
- Signals: SIGHUP stays blocked through exec and early server startup, then is
  unblocked after handler registration. Embedded infraternal agent children reset
  their signal mask so PTY shells do not inherit the server's reload policy.
- Audit: requests log kernel peer PID/UID, escaped target and warm/cold/refused
  outcome. Signal requests explicitly lack peer credentials. Successor startup reports
  the actual retained-issuer install result, correlated by unchanged service PID. Transfer contents
  and lengths are excluded. Real request logging is regression-tested.
- Parser: exact bounded frame length/version/DER/issuer/key validation is retained.
  ELF note parsing checks aligned exact records. Deterministic mutation tests and
  the actual five-minute cargo-fuzz run complement real-engine integration.
- Scale: the root shipping proof uses 25 replacements, 50 users, 10000 retained
  records and 128 live PTYs, checking CA state, PID, shim continuity, reattachment
  and resumed input. Retained rows are not claimed as live QUIC connections.
  The rootless shipping proof checks explicit cold reply/state and null stdin.
- Distribution: both static architectures are measured against the unchanged
  production Rust base. The historical size ceiling is not raised. All other
  fast rows must pass; supplementary ARM/TS and feature-off checks are recorded.
- Plugin boundary: all handoff behavior is removed by the remote cargo feature;
  the new syscall wrapper is in the existing D40 audited shim boundary, behind
  its remote-activated feature. Only existing workspace dependencies are reused.

Full counts, machine/load, latency changes, transcripts and remaining limits are
in [README.md](../README.md). Independent review remains required by PROCESS §2.
