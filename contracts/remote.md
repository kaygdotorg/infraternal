<!-- Remote infraternal agent identity and transport invariants for #78; additive to bootstrap/wire/shim v1. -->
# Contract: remote infraternal agents, phase 1

Status: proposed on #78. Implements D9, D64, D114, D128 and D130–137.
Later owner decisions are on the local `main` ref; this lane does not amend
`DECISIONS.md`. This contract describes the target, not implementation status.

## Identity and enrollment

Each remote host has a random UUID, an immutable rootless/rootful mode and
the execution uid. The server authorizes host creation and token issuance;
neither a browser terminal request nor a CSR may choose the execution uid.
Rootless sessions use the uid recorded at enrollment, not the server uid.

Join capabilities contain 256 random bits, are valid for exactly 900 seconds,
and are bound to one host id and its mode. Store only SHA-256 of the canonical
token, with issuance and expiry timestamps. Issuing a replacement invalidates
the previous token. Refuse negative or overflowing timestamps. Redemption
requires `issued_at <= now < expires_at`, the bound identity/mode and an
unrevoked host. One SQL transaction must consume the capability and publish
the signed certificate authority record; concurrent redeemers have one winner.
A failed identity, CSR or mode check must not consume the token.

`infraternal agent join <url>` is an operator/test adapter [132]. Read the
capability and trusted server CA pin from stdin or inherited descriptors,
never URL parameters, argv, logs or plaintext repository files. Authenticate
the enrollment server before sending the capability; do not use TOFU or a
TLS verification bypass. Generate the Ed25519 host key locally as already
specified by bootstrap §2 step 6. Validate the CSR signature and algorithm;
construct identity, usages and validity on the server instead of copying
CSR extensions. The private host key never leaves the host.

## CA, certificate lifetime and rotation

The CA primitive is proposed separately with measurements on #78. The
conservative proposal is Ed25519, matching the existing host-key contract;
it is not an amendment to an owner decision. Reuse the existing crypto
implementation before introducing a foundational library.

Server CA material belongs in `$XDG_DATA_HOME/infraternal/ca/`, defaulting to
`~/.local/share/infraternal/ca/`, outside SQLite. Directories are 0700;
encrypted key envelopes and certificates are 0600. Private material is
encrypted with authenticated encryption and published by fsync/atomic rename.
The unlock source remains an owner question on #78: a memory credential/FD
or an owner unlock after restart. A plaintext adjacent unlock-key file does
not provide independent protection. Missing or wrong unlock material fails
closed, never regenerating a CA or admitting remote hosts.

Certificates live seven days [133]. Store certificate fingerprints, host id,
issuer generation, validity and revocation state in SQLite; never CA or host
private keys. Renew over the authenticated live control stream, binding the
CSR to the same host and existing public key. Publish the new identity on
disk atomically without replacing terminal connections. Renew well before
expiry using a single scheduled deadline, not a polling loop. CA rotation
retains the previous trusted generation until all of its valid certificates
have expired or been replaced. Distribute new trust over the existing
authenticated channel before changing issuer; never remove a still-needed
pin. Retain issuer-generation identity in every certificate record.

## Transport and sessions

Managed hosts dial out only [64]. QUIC/quinn/BBR uses the server UDP port
(7443 by default); TCP/TLS 1.3 on that same numbered port is the fallback.
Both require certificate verification and current host authority. QUIC uses
native streams and unwrapped wire frames; TCP uses the existing mux envelope.
Control is stream zero. Preserve all v1 wire, shim and upgrade layouts.
Use bounded admission/handshake/frame deadlines and TCP_NODELAY. Interactive
commands must remain dispatchable during bulk output [130].

Reconnect preserves session output offsets, independent stable writer ids,
authoritative shim input Acks and remaining output credit. Retry failed
connections with bounded backoff/jitter; do not spin or poll healthy idle
connections. A browser attachment is routed by the session's recorded host,
never by a browser-selected leg-B writer id. Keep Snapshot approximation
notices ordered before repaint and preserve multi-device ownership checks.

The approximately 60-second authority lease [128] is fail closed: loss of
server authority refuses new attachment and input after its deadline, while
shims keep running. Every attachment checks authority; revocation and lease
expiry wake existing holders. Phase 1 has no direct browser-to-host route.

## Removal

Revocation is a durable host tombstone, checked on every contact; cancel all
live transports at once [134]. Certificate validity alone never authorizes a
revoked host. Retain enough public identity to authenticate a removal notice
on next contact; TLS rejection alone cannot safely tell a host to uninstall.
An expired or revoked certificate may prove identity for this restricted
removal exchange only, never for terminal/action admission. An arbitrary
handshake failure must not cause deletion.

Rootless uninstall removes only the installation's own services, slots and
user-level identity/state. An operator command handles unreachable servers.
Enumerate sessions before destructive removal; ordinary transport loss or
lease expiry never kills shims. Never delete another installation's data.

## Evidence and budgets

Prove the browser/server/remote infraternal agent/shim path on o1 and o2 as
user kayg, without sudo or inbound host listeners [137]. Remove test
installations afterward. Retain machine/load, sample counts, reconnect
p50/p99, exact byte checks, renewal CPU/RSS/bytes and idle scheduler counts.
Exercise connection loss, process/server restart, 300 ms RTT, renewal during
50 MiB output and mid-session revocation. Scale toward 500 sessions with
five viewers [124]; report per-unit memory multiplied by that count.
Local primitive measurements are diagnostic, not pinned performance gates.
