<!-- Author checks for the D255 transport primitives; full orchestration remains pending. -->
# Author checks

- Strict native SSH authentication/host trust and the erased-credential
  fail-local master behavior are preserved. Source routing uses native SSH
  rather than silently discarding source/interface/family restrictions.
- Closed-input handling accepts only a completely decoded canonical refusal;
  successful or malformed output cannot hide an input-delivery failure.
- Duplex child ownership retires the process group before reaping its leader;
  diagnostics are bounded and never logged. Cancellation drops all pipe owners.
- Standard pipe duplicates are nonblocking and CLOEXEC. Actual pipes preserve
  binary bytes; no periodic reader, new framing parser or terminal engine.
- The early shell is launched inside the existing session shim. Real-process
  proof preserves its session id and writer and checks pending-input replay.
- SSH and remote cargo features gate the hidden command. No server can be
  created by it; execution uid is the current effective uid, not an argv field.
- New source modules start with role docs. Existing helpers and codecs are
  reused. No dependency, library choice, migration or UI primitive is added.
- Host/session ownership, real-login integration, persistent setup events and
  admitted SSH-to-mTLS replacement are remaining work, explicitly not claimed.
- No provisioning performance acceptance, VM throughput/RSS campaign, new fuzz
  campaign, visual verdict or physical-device claim. The only timing gate
  forwarded to VM208 is the repository's unchanged RTT self-test under flock.
- Owner live fixtures were never read or changed. No credentials were searched,
  printed or written. Branch push only is authorized; no deployment/issue close.
