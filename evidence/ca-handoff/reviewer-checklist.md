<!-- Records the author review and measured evidence for warm CA handoff (#154, D168, D217). -->
# Author review

- Authentication: anonymous socket peer UID and preserved PID are checked before
  reading any bytes. No named signing channel or reusable token exists. A foreign
  process is refused even under the same UID. The named control socket carries
  only a binary path and is 0600 inside an owned 0700 directory.
- Secrets: no key in disk, arguments, environment or diagnostics. Serialization
  and receive buffers use Zeroizing; direct fd reads avoid buffered stdin copies.
  The receiver installs only the exact retained issuer and replaces stdin with
  `/dev/null` before spawning child processes. Dumpability is disabled.
- Lifetime: the bounded frame is queued before exec; the writer is closed. Exec
  destroys the old address space before installation in the successor. There is
  no old signer waiting for confirmation and no courier retaining one. Failed
  export/import and ordinary starts remain cold-locked under D168.
- Executables: both sides validate the original path, every parent directory,
  ownership, write permissions, regular executable type and absence of set-ID.
  Group-writable directories require an earlier owned private ancestor;
  executable files and world-writable directories remain refused.
  Symlinks and parent-directory escapes are refused before canonicalization. Only the service UID and root
  may change approved code; neither is an adversary for the same service.
- Parser: maximum frame 2090 bytes; exact length/version/DER consumption; Ed25519
  seed, issuer key and self-signature checked with the existing crypto engine.
  Deterministic mutation/truncation properties and a fuzz target exercise it.
- Runtime: restart cancels listeners and drops the Tokio runtime before exec;
  PID and invocation are retained. Independent PTY shims are preserved through
  25 replacements and 128 terminal reattachments. Requests acknowledge intent;
  deployment health and CA status determine completion.
- Plugin boundary: lifecycle code and action are behind the existing remote
  cargo feature. Action `remote.server.restart` belongs to the remote descriptor;
  shared help/instructions feed skill output. No foundational dependency added.
- Operations: generated systemd units declare SIGHUP ExecReload only when the
  feature is compiled. Keep KillMode=process; stop/start remains cold. Deployment
  stages verified regular binaries, health-checks CA state and rolls back through
  the same command. Pre-handoff releases require a cold compatibility transition.
- Performance: evidence records the real shipping binary, CPU/load, restart and
  refusal brackets, 50 users, 10000 retained host records and 128 real PTYs.
  Retained host records are not claimed as 10000 live QUIC connections.
- Distribution: both stripped static architectures compared with the unchanged
  production base using the same pinned toolchain/profile. D205 allows the old
  size ceiling to fail; budgets and release optimization are not altered.

Independent review remains the orchestrator's next step under docs/PROCESS.md §2.
