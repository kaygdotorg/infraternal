<!-- Additive SSH bootstrap API and integration boundary for #87, D138–141/156/168/170/181/183. -->
# Contract: SSH bootstrap

Status: proposed on #87 before implementation. The system OpenSSH adapter is
authorized for bootstrap by the job brief and D181. D183 supersedes the
previous ambient local-identity fallback with a dedicated server key. General host actions still use infraternal agents (D9). This does
not select a foundational SSH library or change frozen wire frames.

## Admission and progress

The additive `/v1/bootstrap/ws` WebSocket uses the server's pinned Origin,
unlocked authenticated session cookie and owner authority. Bodies are bounded
at 32 KiB. Requests may carry credential references resolved by a trusted,
passkey-unlocked vault adapter, or explicit one-attempt browser inputs through
`auth_once` as specified below. Neither enters public progress history.

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

The additive `Backend::invitation_registered` hook publishes the host binding
to batch cleanup before durable issuance can commit. A backend whose issuance
is durable overrides the hook and invokes registration before that commit.
Cancellation then serializes revocation behind any in-flight SQLite writer;
a pre-commit read of absence is not cleanup proof. The default hook preserves
non-durable backend compatibility.

Durable provisioning records carry an unfinished-attempt retirement intent in
that same invitation transaction. Failure begins an exact-host transport fence
and owned retirement writer synchronously through `Backend::retire_failed`,
before private-session cleanup or SSH rollback awaits. A caller's cleanup
acknowledgement deadline cannot discard this obligation. The writer retires the
host record and consumes its intent together, retrying only transient writer
contention; storage refusal retains the fence and intent. Startup retires
unfinished intents before enrollment or transport listeners admit connections.
Proven installation completion must acknowledge removal of its own intent
through `Backend::completed` before reporting Done. Prior completed host records
without an unfinished intent remain outside failed-attempt retirement.

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

The additive `/v1/bootstrap/ssh-key` endpoint accepts GET and empty-body POST,
requiring one exact pinned Origin and one unlocked owner cookie. Settings uses
POST: same-origin browser GET omits Origin. Strict GET remains available to
nonbrowser callers supplying Origin. It returns public metadata only:

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

The initial automatic-authentication command is an exact allowlisted generated
read-only check: the system sniff, the system sniff plus root/rootless earlier
setup inspection, or the system sniff plus the cleanup-owned clear record.
Credential fallback may repeat only these fixed checks with empty stdin. Prefix
matches, appended commands and arbitrary input remain refused. The ownership
inspection reads existing receipts and locks existing directories; it creates
no files. This preserves one command round trip when detecting earlier setup.

## One-use browser credentials [183]

Start accepts per-target `auth_once` material; a retry accepts it only for a
failed target on the same authenticated socket. Automatic order is unchanged: an earlier successful method erases
unused browser material without loading it into an SSH helper.

```json
{"action":"start","targets":[{"id":"host-1","address":{"kind":"manual","value":"user@host"},"mode":"rootless"}],"auth_once":[{"target":"host-1","auth":{"key":"<browser-unwrapped PEM>"}}]}
{"action":"retry","target":"host-1","auth_once":{"key":"<browser-unwrapped PEM>","passphrase":"<optional once>","password":"<optional once>"}}
```

Start validates membership, uniqueness and every credential before scheduling
any host. The existing request remains valid without `auth_once`. These are
input-only strings, never event fields. The request/frame limit stays
32 KiB; the key limit is 24576 bytes and each prompt is at most 16384 bytes.
A passphrase needs a key. Empty material, NUL, unknown fields, and newlines in
prompts are refused before scheduling. Material waiting for admission expires
after 60 seconds. Once admitted, unused material is discarded on selection
of an earlier method or at the end of the bounded connection attempt; the
provider refuses to release expired material. Logout, socket close, queue expiry, cancellation and scope
retirement erase the owned inputs. Nothing enters batch history, SQLite, logs,
argv, environment or a later retry. The browser must unwrap afresh for each
attempt; retrying without `auth_once` never reuses earlier private bytes.

Events may also include `host_id`, the UUID from the trusted bound invitation.
It does not prove readiness: only `done` follows authenticated facts and the
terminal canary. Authentication evidence is recorded after the bounded fixed
check even if host compatibility later fails. A new attempt starts without
method/host metadata; immutable replay events retain the earlier attempt's
public evidence.


## First-contact host-key confirmation [183]

Unknown host keys stop the attempt before any credential fallback or host
mutation. A `failed` event may add `failure.host_key_challenge` (UUID) alongside
its public `fingerprints`. Confirm only a fingerprint verified by the owner
through a trusted channel:

```json
{"action":"confirm-host-key","target":"host-1","challenge":"<UUID from this failed attempt>","fingerprint":"SHA256:<observed fingerprint>"}
```

Successful publication returns:

```json
{"host_key_confirmed":{"target":"host-1","fingerprint":"SHA256:<confirmed fingerprint>"}}
```

Then send the existing `retry` request. Confirmation alone does not start an
installation. The exact live unlocked owner session is checked after public
trust lookups, immediately before publishing. The nonce binds the destination,
effective public SSH policy and previously observed key; it is consumed by one
confirmation attempt and expires after 120 seconds. Only this socket's failed,
idle target and last public failure can request confirmation. Retry clears that
failure; a fresh check produces a fresh observation.

At most 128 bounded public observations are held in memory. Idle expiration
is reclaimed on access, without timers. Confirmed public pins persist in the
server data directory (`ssh-trust/`, mode 0700; files 0600). Publication uses
an owned create-new temporary file, fsync and atomic rename. Replacement needs
explicit confirmation of the changed key; each challenge snapshots the previous
pin and rejects a superseded confirmation. Show one policy-permitted key,
preferring ED25519, and its exact type. Pin authenticated negotiation to that
key family. A matching normal/CA/revoked configured record, changed configuration, revoked
session or ambiguous public paths refuses confirmation. OpenSSH retains its
configured revocation and cryptographic policy. Later configured matching trust
alongside a dedicated pin requires review. External public configuration edits
are not serialized with the application; administrators must avoid racing trust
changes with confirmation. This API never edits system known_hosts.


## Bounded native facts [145][156]

After authenticated remote enrollment, `host.facts` is a control-stream-zero
Call with an empty JSON object (`{}`). The decoder accepts at most 256 bytes
and rejects arrays, scalars, unknown parameters and trailing values. Other
streams do not acquire this action. A successful Result contains:

```json
{"os":"linux","arch":"x86_64","execution_uid":1101,"version":"0.1.0","logical_cpus":8}
```

`execution_uid` is the infraternal agent's effective uid, bound to the enrolled
host's authenticated identity. `logical_cpus` is the OS concurrency policy,
including affinity/cgroup constraints; it is not a physical CPU inventory.
Collection uses platform constants and OS concurrency metadata, without
subprocesses, discovery scans or recurring polling. Invalid input returns the
short fixed error `invalid host facts request`. Provisioning still requires
its separate terminal canary before committing and emitting `done`.

Round-two failures optionally include `host_key_type` and `host_key_changed`.
The browser displays the selected fingerprint once, names its key type and gives
the corresponding `ssh-keygen -lf /etc/ssh/ssh_host_<type>_key.pub` comparison.
Helper sockets use a short private runtime directory under `XDG_RUNTIME_DIR` or
`/run`, independent of the persistent data-directory length.

## Release payloads and public install diagnostics (#87)

A server release directory contains `infraternal` plus
`infraternal-x86_64-musl` and `infraternal-aarch64-musl`, all from the same revision.
`scripts/package-release` builds and publishes the complete directory with public
checksums. A missing architecture payload produces its architecture and expected
server path as trusted public metadata; the UI tells the operator where to put it.

Failures retain the connect/upload/install/join/start boundary. Host diagnostics
are exact allowlisted public lines, including enrollment DNS and TLS failures;
arbitrary stderr never becomes UI copy or log output. Re-adding a retained host
(address or effective application SSH lookup) returns `already_added` before
issuing another invitation, and the UI directs the person to its existing terminal.
That failure may include optional `failure.host_id` with the matched UUID. The
lookup retains the bootstrap owner's and non-revoked-host filters, so only the
requester already admitted for that host's terminal receives its id. The field
is omitted from every other failure, and existing clients may ignore it.

## Verified architecture payloads (#157, D220, D224, D225)

The default server payload source uses its exact running Linux executable for
its own architecture. For the other supported architecture, it requests the
server's workspace version from `https://builds.infraternal.com/releases/<version>/`:
`SHA256SUMS`, `SHA256SUMS.sig`, `VERSION`, and `infraternal-<architecture>-musl`.
The unchanged release-signer Worker signs the manifest with Ed25519 SSHSIG,
namespace `infraternal-release`, hash SHA-512. The binary embeds both public
trust anchors from `release/allowed_signers` and verifies opened descriptors.
`VERSION` is signed content containing the exact workspace version plus newline;
this binds the release to its version rather than trusting the URL path.

The existing `install` progress phase emits “Get the arm64 binary” or
“Get the x86_64 binary” before resolution. Failures add two values to the
optional `failed_step` field: `get-arm64-binary` and `get-x86-64-binary`.
Their plain public reason is retained. Resolution expires after 30 seconds
without saved release-body bytes. Connection, headers and final verification
each retain a short bound; no whole-transfer clock applies. Download or verification
failure stops before any upload or installation transaction.

Verified payloads and signed metadata are published together by atomic directory
rename under the configured server state directory:
`releases/<version>/<architecture>/`. Every cache reuse reverifies the manifest,
version and binary; unsafe ownership, shared modes, symlinks and hard links are
refused. The cache is server-owned trusted state and published files are never
rewritten by the resolver. It has no polling or background release worker.

Only a development build (without the pipeline's compile-time
`INFRATERNAL_RELEASE_BUILD=1` marker) and a 404 for the version's manifest allow
fallback to the adjacent locally built architecture payload. Offline, TLS,
missing payload, wrong-version and signature failures never enable fallback.
Existing path-based installation adapters remain available through `BinaryPaths`;
the default server supplies the verified source through the same SSH plugin.

## Classified attempt failures (#169)

Failure adds optional `exit_status` from the authenticated command process (a
signal or unavailable status omits it). Fixed installer code 71 retains
`failed_step` and identifies the approved root/rootless directory with ownership,
permission and setup-file guidance. An unfinished transaction (72) directs the
person back to cleanup; a live setup (73) offers to wait. A retry with retained
coordinates actually finishes the original cleanup before continuing. A returned
script status is a setup failure, including status 255 after authentication;
only failures without a script status are classified as command-channel failures.
Other failures name the command boundary and next check. Arbitrary stdout/stderr
remains withheld. One server log line per failed
attempt contains only host UUID (unassigned before issuance), target id, step,
exit status and static mode; cleanup warnings do not replace the original phase.
The existing dialog Details disclosure shows the trusted failed-step label.

The optional trusted `failed_step` also admits `readiness` for private terminal
open, attach, output and cleanup failures. It uses the same server log and
Details disclosure, without adding a progress stage or exposing remote output.

Readiness retains its primary attachment through the marker and matching
authenticated status-zero `terminal.exited` notice. That notice proves the
private command's retirement; success does not open another writer. Ownership
is cleared synchronously before the subsequent authorization await. An error,
timeout or cancellation before proof retains the exact session for recovery.

Installed transport readiness (#230) waits on registry admission and actor
route notifications, with subscriptions established before inspection. Ledger
admission alone and the provisional SSH shell cannot release that fence. The
service admission phase and the greeted actor phase each receive the original
30-second startup allowance plus eight observed authenticated SSH exchanges;
the existing check or session reattach supplies a conservative RTT upper bound
including remote execution, without another command. Installed registration
advances startup once; unrelated notifications never renew the allowance.
Cancellation still applies, and each exchange has its own bound. A deliberately
unreachable first attempt can exhaust that allowance; its failure wait is
reported separately from the subsequent Retry duration. Facts, execution UID,
private terminal proof and commit remain required on initial setup and Retry.

### Verified payload reuse (#169)

An SSH installation may retain one public executable in a private marked
`infraternal.bootstrap-cache` sibling of its selected installation directory.
It contains no identity or login material. Its parent, marker, directory and
payload must satisfy the same execution-uid ownership and no-link checks as
setup data. Each retry checks the requested executable hash before reusing a
hard link, then checks the staged payload again before enrollment. Changed
content is uploaded again; a foreign cache path is refused. Publication starts
inside the owned transaction. Rollback retains this declared retry cache while
removing that attempt's installation artifacts; subsequent uploads replace its
single payload, bounding retained storage to one executable per execution mode.
The cache creates no background task and grants no host admission authority.

### Start fresh over earlier setup leftovers (#169)

The existing authenticated SSH check also classifies setup ownership, without a
second SSH command. A live directory-lock holder, installation executable, open
setup descriptor or live session socket returns `setup_running`: “Setup is already
running on this host. Wait for it to finish, then try again.” Live shims are
non-dumpable, so a session socket counts as live when the native helper's one
socket-diagnostic dump reports any socket bound to an owned `sessions/*.sock`,
matched by owner and inode, never by name; an unavailable or unexpected dump is
uncertain and retains the attempt. New setup commands
serialize on the private installation parent and hold a transaction lease across
command gaps. Its 180-second sampling interval renews only when the authored reader
publishes an increasing consumed-byte counter, never on output or keepalives. Commit and rollback retire only the
lease whose PID birth and inherited descriptor match that transaction.

A private owner marker plus the exact fresh transaction journal may return
`stale_previous_attempt` on a `check` event, with optional `leftovers` containing
`challenge`, the approved `mode`, and bounded fixed public `findings`. This is a
pause in the existing attempt, before issuing an invitation or uploading. The
same authenticated WebSocket accepts `{ "action": "start-fresh", "target": "…",
"challenge": "…" }` (registry action `ssh.start-fresh`, permission `ssh.manage`).
The target and single-use challenge belong to that socket's batch and owner;
clients never select a path, host identity or previous transaction. Socket loss,
component disable or the confirmation wait limit cancels the pause without
removing earlier leftovers.

Confirmation rechecks the owner, transaction, device/inode binding, full root
and supported staging inventory, and all liveness evidence under the same
directory lock. Only proven fresh artifacts are retired through the existing
rollback. Canonical private session sockets with no listener may be removed;
empty owned directories, marker and journal follow. Unknown files anywhere in
the setup root or old lock refuse the entire recovery before any removal.
Upgrade journals, advanced unknown staging layouts and older journals without
an inode binding are refused with an explicit unsupported/changed-format reason.
Foreign data remains untouched. A changed observation needs another host check.

Successful recovery continues the same attempt and issues one new invitation.
Content-free server logs record the previous host UUID, transaction UUID,
execution mode, fresh ownership journal and started/completed/refused outcome.
Authenticated command status and setup-step diagnostics remain available; no
file contents, process arguments, environments or arbitrary remote output enter
public findings or logs. No existing enrolled identity is adopted by recovery.

Fresh rollback also retires the infraternal agent's fixed local control socket,
`sessions/plugins.sock`, which may survive a service stop before the first server
connection (#230). The owned private runtime directory contains a mode-0600,
single-link `.lifetime-lock`. The infraternal agent takes its exclusive advisory
lock before binding any local socket. The remote supervisor retains it across
worker replacement and temporary credential errors; listener tasks and synchronous
workers keep the same ownership until their work actually stops.
The installer holds the same lock through its bounded staging lease and artifact
replacement, then hands it to the runtime at activation. A stopped process releases
its lock automatically; a surviving socket path is not itself lifetime authority.

Cleanup opens that lock on descriptor 6 and asks the verified staged infraternal
binary to validate its descriptor/path identity and take the lock nonblocking on
the inherited open description. A held lock preserves the transaction and files
(73). A successful acquisition remains held by the cleanup shell after the helper
exits, through all retirement and receipt removal. An exclusive setup guard on the
installation's parent directory also fences startup during final lock-file unlink;
runtime startup holds shared directory admission while taking its lifetime lock.
Managed startup checks its loaded host identity against the owner marker and
refuses outstanding rollback receipts under that admission guard. Publishing a
new lock beside a live legacy endpoint is refused, so an unheld new file cannot
misclassify that older runtime during later cleanup.
Unknown files, ownership mismatches and links retain their existing refusal rules.

Legacy runtimes have no lifetime lock. Only for these runtimes, the same binary
uses a nonblocking connection to the owned control socket: connection retains it
(73); errors other than refusal retain it as uncertain (77). Refusal also requires
conservative same-user bound-endpoint inspection, so a bound endpoint before
`listen` or with a retained earlier name is not removed. The native helper asks
the kernel for one socket-diagnostic dump of every Unix socket with its UID and
VFS identity and compares the owner and inode with the control file (the kernel's
device is the superblock's, which differs from `stat` on btrfs subvolumes and
split-layer overlays, so it is not compared; a false match only retains);
private process descriptors are neither required nor proof that it is stale.
Socket names are never read, so a home path with spaces or newlines, or one reached
through an alias, cannot hide a bound endpoint. A socket without a VFS binding
cannot own a filesystem endpoint.
Only fixed known records from the kernel are accepted; denied, truncated or
unexpected replies remain uncertain (77). Only a bound entry for this installation's owned control
file can retain cleanup; a different directory's or Unix user's socket cannot.
The binary
opens the receipt-bound root and private runtime directory without following links,
checks socket ownership/type/link count before probing, and repeats these checks
and the same device/inode immediately before unlinking relative to the open directory.
The session removal loop excludes the control socket.

Recovery needs no host interpreter. If the existing executable cache predates the
internal helper (76), the server uploads its matching verified binary into that
cache, then repeats inspection. Only recovery takes this path; clean installations
keep their existing command sequence. This publishes executable content only and
never changes host or transaction ownership. Failed or interrupted transfers retain
the original receipt and can be retried.

A retry with retained cleanup coordinates first finishes that exact host and
transaction's rollback, before issuing another invitation. Progress says “An
earlier setup on this host did not finish; finishing it now.” Cleanup coordinates
never authorize another transaction's lease retirement. Unattributed earlier
state still requires the existing start-fresh confirmation and full revalidation;
a receipt alone never permits adoption by a different host or server.

After a server restart, the existing retired bootstrap ledger can authorize that
same cleanup without another confirmation. It must bind the receipt's exact host
UUID to the current owner, privilege mode, observed execution uid and authenticated
SSH lookup. A recorded lookup must match; only when both lookups are absent may
an exact saved SSH address suffice. Active, unknown or mismatched records cannot
authorize automatic recovery. The live owner session and root consent are checked
again. This proof permits retirement of fresh leftovers, never adoption of an
enrolled identity; the complete shell inventory, inode and liveness checks remain.
The ledger is queried only when inspection finds earlier setup state. The
outside receipt remains inspectable after interrupted final retirement removes
the owner marker or the installation root. An existing root must retain the
receipt's exact directory inode; without an owner marker it must be empty.
An absent root still passes the process-liveness checks before receipt removal.
Neither boundary recreates an ownership marker or relaxes the ledger proof.
The final outside receipt also denotes completed service rollback before staging
retirement. A stop during staging removal may leave any subset of its markers.
Recovery validates surviving transaction/kind markers when present, known
private staging artifacts and bounded private enrollment/cache trees without
reading identity contents or following links. Unknown artifacts, foreign
markers and nested links are refused before mutation. It then retires staging
without repeating completed service changes, and finishes root/receipt removal.

Exact screen copy for the later UI pass: title “This host has leftovers from an
earlier setup”; body “infraternal didn't finish setting up here before. Start
fresh to remove what it left behind and continue.”; primary “Start fresh”;
secondary “Back”. Paths belong only in Details.

## Short CLI name [349]

Root and rootless installations also publish `infra -> infraternal` beside the
canonical PATH launcher. Creation never replaces an occupied path, including a
dangling symlink; a skipped alias produces a fixed setup warning. Rollback removes
only a link created by that attempt, and uninstall removes only an owned link whose
literal target still names the canonical launcher. Both names use canonical
`infraternal` help, usage and error text. Shell configuration is never edited.

### Bootstrap transfer progress (#378, D352)

SSH payload transfers expire after 30 seconds without an increasing remote
consumed-byte acknowledgement. Local pipe writes cannot renew this interval:
SSH can buffer the entire remaining payload while the remote is still reading.
The authored reader consumes at most 64 KiB per read and acknowledges short
reads too. Counters are canonical, strictly increasing and bounded by the
selected public wire length. The final counter starts a separate 30-second
verification/completion exchange. Private invitation input remains behind the
verified payload receipt. Duplex staging reads counters concurrently with its
writer, preserving backpressure and cancellation. Neither path has a total
transfer or attempt clock. Short commands and unresponsive connections remain
bounded, independently of transfers.

Release acquisition uses actual nonempty HTTP body bytes saved to the private
staging file. Headers, empty frames, arbitrary output and keepalives never count
as transfer progress. HTTP connect, TLS, response headers and storage completion
each have a 30-second bound. A payload source without byte observations gets a
30-second acquisition bound. Confirmation and authenticated readiness retain
their own independent limits.
