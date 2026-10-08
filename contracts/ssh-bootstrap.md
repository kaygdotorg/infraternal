<!-- Additive SSH bootstrap API and integration boundary for #87, D138–141/156/168/170/181/183. -->
# Contract: SSH bootstrap

Status: proposed on #87 before implementation. The system OpenSSH adapter is
authorized for bootstrap by the job brief and D181. D183 supersedes the
previous ambient local-identity fallback with a dedicated server key. General host actions still use infraternal agents (D9). This does
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

OpenSSH reads its existing addressing config and known_hosts directly. D183
local authentication never loads the operating system's private identity files;
it uses the dedicated server key or a supplied one-connection credential.
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
Linger is reported. The authorized rootless installation requests own-user
linger through `loginctl --no-ask-password enable-linger`, without sudo. Policy
denial is a warning; rollback reverses only a setting this attempt enabled.

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
Pass the settled #78 invitation response unchanged on private stdin:
`{host_id, mode, execution_uid, token, ca_der, endpoint, server_name}`. Map
bootstrap `root` to remote `rootful` with execution uid zero; rootless retains
the observed nonzero uid. The join URL is nonsecret and has no userinfo, query
or fragment. #78 owns the operator join command and pinned HTTPS admission;
this lane must not implement a second invitation parser or CA store.

Backend operations receive the exact live browser session capability and
nonsecret owner/batch identity. Issuance atomically rechecks that unlocked
session. Reserve each host attempt from issuance through readiness or cleanup;
two batches must not replace each other's invitations. If issuance fails before
returning a host binding, the backend removes its own partial authority. Failure
cleanup retires only this batch's new authority, including after logout, while
preserving prior enrolled authority. Facts and terminal proof bind the current
attempt's certificate/generation, never an older connection for the same UUID.

The backend waits for that exact host's authenticated transport and collects
cheap facts over it, then proves a terminal opens through the existing session
router before marking done. SSH command exit, TCP reachability or redeemed
invitation alone is never evidence of readiness. The continuation brief
requires local rootless installation, terminal proof and removal first, then
o1 only if local proof passes and its key is already
trusted. The wider D170 acceptance also includes o2.

Mesh-policy requires trusted discovery evidence that the target is a mesh
peer, reachable on another mesh path, and TCP SSH is refused or filtered.
Authentication errors, DNS failure or general mesh outage are not policy
evidence. The message describes a possible policy restriction, not certainty.

## JSON shapes for the UI

The bootstrap handshake returns HTTP 403 for missing, duplicated or wrong
Origin, 401 for unavailable unlocked owner authority or missing/duplicated
cookie headers, and 503 when its socket capacity or clock is unavailable.
The ordinary server's source-admission limits also apply.

Client commands are text WebSocket messages. Unknown fields are rejected;
identifiers are 1–128 ASCII letters, digits, dots, underscores or hyphens.
`credential` is an opaque reference, never key/password bytes. Omitted fields
use rootless mode, no root consent and D183 automatic authentication. A per-host credential
reference overrides the batch reference.

```json
{"action":"start","targets":[{"id":"host-1","address":{"kind":"manual","value":"user@host:22"},"mode":"rootless","root_consent":false}],"credential":"vault-reference"}
{"action":"retry","target":"host-1"}
{"action":"replay","after":12}
```

Discovered addresses use `{"kind":"discovered","value":"inventory-id"}`.
Root requests use `"mode":"root","root_consent":true`; sudo availability
never supplies consent. Start validates all targets before scheduling work.
Only one batch may be started on a socket. Retry is limited to failed targets,
up to eight attempts per target, and never changes the target's address.

Events are individual text messages, without an enclosing array:

```json
{"sequence":13,"target":"host-1","attempt":1,"step":"check","message":"Checking SSH and host support.","elapsed_ms":2,"log_tail":["Checking SSH and host support."]}
{"sequence":14,"target":"host-1","attempt":1,"step":"failed","message":"The SSH host key is not trusted.","elapsed_ms":40,"log_tail":["Checking SSH and host support.","The SSH host key is not trusted."],"failure":{"kind":"host-key","message":"The SSH host key is not trusted.","log_tail":[],"fingerprints":["SHA256:observed-fingerprint"]}}
```

Messages above illustrate shape; clients must display the server's actual human
text rather than match it. `failure` is omitted outside failure events;
`fingerprints` is omitted when empty. Sequence is global within this batch;
attempt starts at one. `elapsed_ms` is cumulative since this attempt entered
the scheduler, including queue time, not an individual step duration. Compute
phase timing from successive events for the same target and attempt. Phase
entry order is check → install → facts → connect → done, or failed at any
point. Rollback and warnings may emit additional install events. Each attempt
ends in done or failed. Event tails hold at most eight trusted breadcrumbs;
they are not shell logs.

```json
{"error":"invalid bootstrap request"}
{"error":{"kind":"unsupported","message":"Start a host batch first.","log_tail":[]}}
{"resync":true,"oldest":20}
```

Malformed JSON uses the string error; valid commands refused at admission use
the typed failure. Such command errors do not create a host attempt. Replay
returns retained events with sequence greater than `after`; at most 1024 events
are retained. If history has fallen behind, resync precedes retained events.
Replay operates only on this live socket's batch. Disconnect cancels it and
runs rollback; a new socket cannot resume that batch. A client should retain
its displayed terminal events and deduplicate replayed events by sequence.

## Runtime integration status

The ordinary server mounts this router with one global runner. A trusted
`BootstrapFactory` can construct its backend from the exact initialized Auth
and SQLite pool. The default backend supports manual addresses and existing
server SSH identity only. It rejects vault/discovery requests and enrollment
before upload, with a human failure; it cannot produce done. Production
installation requires #78's CA, join listener, online registry, facts and
terminal router. A green component gate is not that end-to-end proof.

## Dedicated server key and automatic authentication [181][183]

The additive GET `/v1/bootstrap/ssh-key` requires one exact pinned Origin and
one unlocked owner cookie. It returns public metadata only:

```json
{"public_key":"ssh-ed25519 <base64> infraternal-server","fingerprint":"SHA256:<base64>","locked":true}
```

Responses have `Cache-Control: no-store`. A cold lock does not hide the public
half. Missing administrator-envelope custody returns 503, never an ambient
system key. The configured startup adapter creates one Ed25519 identity and
persists only its public half and administrator-wrapped ciphertext. Concurrent
starts keep the first durable identity. Failed unwrap or a different public
identity cannot unlock or replace it. Cold startup always starts locked.

`SshKeyVault`, `AdministratorSshKeyUnlock` and `SshKeySource` mirror #78's
`CaKeySource` custody boundary. The production adapter must recheck current
administrator membership and fresh passkey proof, wrap for administrators and
share the CA lock lifecycle (D168). It must never place a plaintext unwrap key
next to ciphertext. Dev currently lacks that adapter; ordinary startup can
retain a previously initialized public identity but cannot create/unlock one
without configured custody. This is an explicit integration gap, not an
automatic-unlock policy. `serve_with_provisioning` provides the configured
startup hook; updates must carry unlocked material only in memory.

Automatic authentication runs these methods in order:

1. Network-only system OpenSSH with BatchMode enabled and local identities,
   identity agents, password and keyboard-interactive authentication disabled.
   Configured addressing and existing known_hosts still apply. A successful
   command reports `network`; a provider is named only from trusted discovery,
   never an SSH banner or an IP address.
2. The dedicated unlocked server key through the scoped private ssh-agent pipe.
3. The user's browser-unwrapped key for this one connection.
4. A password supplied once through the scoped askpass pipe.

Providers are lazy; successful earlier methods never request later secrets.
Only authentication refusals advance the sequence. Unknown/changed host keys,
unsupported config, unreachable targets, mesh-policy refusals and remote
command failures stop without materializing later credentials. Exhausted
authentication returns `failure.kind: "auth", choose_method: true` for the UI.
No interactive prompt or system identity file is an implicit fallback.

An authenticated progress event adds only public method metadata:

```json
{"authentication":{"method":"network","network":"netbird"}}
{"authentication":{"method":"server-key"}}
```

Methods are `network`, `server-key`, `user-key` or `password`. The optional
network provider is `netbird`, `tailscale`, `twingate` or `other`; absence means
the provider could not be identified from trusted discovery. Existing clients
may ignore this additive field. The completion/failure and retry shapes stay
compatible with the existing bootstrap contract. One-line offline installation
continues to require #78's short-lived host-bound invitation; a token never
enters an URL or argv.
