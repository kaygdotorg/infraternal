<!-- Author and independent security/lifecycle review for exact-byte replacement, #157/#154, D217/D224/D226. -->
# Replacement review

- Explicit replacement admission requires the canonical signed manifest and
  signed VERSION identity. Both existing compiled release keys remain accepted.
  Legacy checksums alone, changed bytes, truncation, oversize, permission and
  parent-path violations are refused. Self reload's exception compares exact
  immutable bytes with the kernel-pinned running image; it never trusts a changed
  installation pathname.
- Linux freezes the execution image with all four memfd seals before signature
  verification. Hashing, compatibility inspection, probe and fexecve share that
  image. Native tests rewrite the admitted source inode and verify sealing.
- Admission probes before listeners/runtime stop. Preparation retains a separate
  current image and separate CA receiver for late exec refusal. Same-PID real
  sealed exec and current-image recovery both reopen a listener and restore the
  unlocked CA in root containers. Rootless tests retain the cold policy.
- The CA seed stays in protected memory/socket frames; fixture files contain only
  public issuer material, synthetic trust and public release signatures. Probe
  children receive an empty environment, null stdio and no control fd3. Existing
  dumpability, peer credentials, marker and root-only warm policy are preserved.
- Embedded infraternal agents and shims launch the exact running kernel image,
  with direct audited child signal/control-fd handling. Real anonymous-image PTY
  input/output passed; baseline launch refused terminal.open.
- The final author descriptor check added a real inherited non-CLOEXEC fd3
  probe regression (red), then isolated fd3 through the audited shim helper and
  reserved image/null descriptors above it. Both image tests pass. The recovery
  oracle separately bounds debug fixture/admission preparation and retains its
  original 30-second recovery observation window; production limits are unchanged.
- Independent read-only review found the SSH prompt display-path regression.
  The remedy snapshots kernel-running bytes into existing private staging and
  checks peer device/inode plus the trusted source digest after direct-parent
  authorization. Writable FD closes before execution, server remains
  nondumpable and cleanup is session-owned. The reviewer re-read the remedy and
  found no further critical or important issue. The final source/docs recheck
  also found no material issue. Fresh root-container replacement and late-refusal
  cases retain the PID, restore the unlocked CA and serve a real listener.
- Reuses existing OpenSSL verifier, SHA-256, nix and audited shim boundary. No new
  foundational library, role or action definition. Plugin feature-off checks
  belong to the final repository gate.
- macOS has a private verified copy, with documented same-owner rewrite risk and
  potential post-exec staging residue. No Mac runtime evidence was collected.
- Both-exec-refusal fallback was inspected for recovery-stdin lifetime; the real
  recovery test refuses only the candidate. Performance measurements on this
  shared host do not certify terminal latency or live-session scale budgets.

Receipts and scale/load qualifications are indexed in README.md. Independent
review is evidence from source inspection, not a substitute for test output.
