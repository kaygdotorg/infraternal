<!-- Additive SSH bootstrap API and integration boundary for #87, D138–141/156/168/170. -->
# Contract: SSH bootstrap

Status: proposed on #87 before implementation. The system OpenSSH adapter is
authorized for bootstrap by the job brief; it uses the server identity in place
(D141 H12). General host actions still use infraternal agents (D9). This does
not select a foundational SSH library or change frozen wire frames.

## Admission and progress

The additive `/v1/bootstrap/ws` WebSocket uses the server's pinned Origin,
unlocked authenticated session cookie and owner authority. Bodies are bounded
at 32 KiB. Only credential references enter requests; decrypted material is
resolved by a trusted, passkey-unlocked vault adapter in server memory.

An initial `start` request contains up to 100 targets, each with a stable
request-local id, a manual `user@host[:port]` or discovered-host id, optional
credential reference, mode (`rootless` by default or `root`) and explicit
`root_consent`. A batch credential reference applies where no per-host
reference exists. Root without consent is refused before any SSH invocation;
rootless SSH as uid zero is refused even when sudo exists. Discovery resolves
only authorized inventory entries; clients cannot assert mesh reachability.

Each event carries target id, attempt, monotonically increasing sequence,
step (`check`, `install`, `facts`, `connect`, `done`, `failed`), human message,
elapsed milliseconds and a bounded log tail. Failed events include kind
`unreachable`, `auth`, `mesh-policy`, `host-key`, `unsupported` or `install`.
Host-key failures may include observed SHA256 fingerprints; observations are
untrusted and never update known_hosts. Log tails contain only allowlisted
diagnostics, never raw remote output, stdin, credential material or tokens.

The server admits at most eight active hosts by default, across batches.
Backpressure never blocks another host's installation. Event state is bounded
and replayable by sequence; falling behind returns an explicit resync notice.
`retry` selects a failed target in this batch and reuses its host binding,
replacing its invitation. Running/successful targets cannot be retried.
Disconnect cancels outstanding work and runs rollback; no idle polling.
Session revocation ends the socket and cancels its work.

## SSH and installation

OpenSSH reads its existing config, identity files and known_hosts directly.
Force `StrictHostKeyChecking=yes`, `UpdateHostKeys=no` and disable forwarding.
Unknown or changed keys fail closed. Pasted private keys go to `ssh-add` on
stdin through a private ephemeral ssh-agent socket. Passwords/passphrases go
through a one-use askpass socket; neither enters argv, environment or files.
The helper program and socket path contain no secrets. Cleanup kills children
and removes the private directory on completion, failure or cancellation.

The check emits a fixed, bounded record: OS, architecture, init, uid,
passwordless sudo, user systemd availability, linger and existing installation.
It performs no facts scan (D156). Linux x86_64/aarch64 with usable systemd are
the first supported targets. Unavailable init/user manager yields unsupported.
Linger is reported; bootstrap never enables it without separate authorization.

Upload a configured matching static binary over an authenticated SSH stdin
stream to an installation-owned staging directory. Verify its SHA256 before
execution. Install data under D17's data directory; the user/system launcher
is `~/.local/bin/infraternal` or `/usr/local/bin/infraternal`. Never overwrite
an unrelated file, unit or installation. Repeated operations serialize on the
host. Keep a previous binary and service until authenticated check-in succeeds;
failure restores them or removes only a fresh bootstrap's own artifacts.

## Remote integration (#78)

A trusted backend binds host UUID, execution uid, owner and mode after the
check and before issuance. Reuse EnrollmentStore's exactly 900-second,
single-use invitation; locked CA blocks bootstrap before host mutation (D168).
The join adapter must authenticate the server before sending this invitation.
Proposed private stdin envelope version 1: host UUID, mode, token, trusted CA
pin; URL is nonsecret and has no userinfo, query or fragment. This envelope is
an integration proposal, not an existing CLI at base 1ce3ed3.

The backend waits for that exact host's authenticated transport and collects
cheap facts over it, then proves a terminal opens through the existing session
router before marking done. SSH command exit, TCP reachability or redeemed
invitation alone is never evidence of readiness. Full acceptance requires o1
and o2 rootless installation, terminal proof and removal (D170).

Mesh-policy requires trusted discovery evidence that the target is a mesh
peer, reachable on another mesh path, and TCP SSH is refused or filtered.
Authentication errors, DNS failure or general mesh outage are not policy
evidence. The message describes a possible policy restriction, not certainty.
