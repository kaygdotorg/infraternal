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
Admission accepts one canonical PKCS10 DER request of at most 4096 bytes,
with at most 16 constructed nesting levels, mandatory attributes and absent
Ed25519 algorithm parameters. Accepted universal values are BOOLEAN, INTEGER,
BIT STRING, OCTET STRING, NULL, OID, ENUMERATED, UTF8String, NumericString,
PrintableString, IA5String, UniversalString, BMPString, SEQUENCE and SET.
Validate each accepted value encoding and SET ordering. Refuse high tags,
unsupported value types and context tags except the request's implicit
attributes SET; ignored attributes do not justify accepting unchecked DER.

## CA, certificate lifetime and rotation

The internal CA uses Ed25519, selected by the owner in D168 after the
measurements on #78. Reuse the existing crypto implementation before
introducing a foundational library.

Server CA material belongs in `$XDG_DATA_HOME/infraternal/ca/`, defaulting to
`~/.local/share/infraternal/ca/`, outside SQLite. Directories are 0700;
encrypted key envelopes and certificates are 0600. Private material is
encrypted with authenticated encryption and published by fsync/atomic rename.
After a cold start the signing key stays locked until any administrator
unlocks it with their passkey [168]. Keep one wrapped copy per administrator;
granting or revoking the role rewraps it. A crash, host reboot, power loss,
manual stop/start, restore or migration is a cold start. An automatic update
or rollback hands unlocked material to the next process only in memory;
failed handoff is a cold start. Never lock on a timer. A plaintext adjacent
unlock-key file is prohibited. Missing or wrong unlock material fails closed
without regenerating the CA. Locked state blocks enrollment and renewal only:
the public issuers still verify existing connections and reconnects. Notify
administrators while locked and again before certificates approach expiry.

Certificates live seven days [133]. Store certificate fingerprints, host id,
issuer generation, validity and revocation state in SQLite; never CA or host
private keys. Renew over the authenticated live control stream, binding the
CSR to the same host and existing public key. Publish the new identity on
disk atomically without replacing terminal connections. Renew at half of the
seven-day lifetime [168], using a single scheduled deadline, not a polling
loop. A locked signer must not invalidate existing host authority. CA rotation
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
Remote peers advertise leg-B Hello caps bit 1 (`REMOTE_WRITER_BINDING`)
before native terminal streams can be used. Leg-A `RESUME_NEXT` bit 0 is
unchanged. Every server-opened native terminal stream begins with a raw
`Call(call_id=0, action_id="transport.bind", input_json={"writer_id":N})`;
N is the durable nonzero even server writer id, never the native stream id.
The first binding frame is limited to 128 bytes and a five-second deadline;
unknown JSON fields, reserved ids and wrong actions fail closed. Do not
consume any following frame while validating the binding. Control Hello
stays on native stream zero and precedes terminal admission.
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

Retire the matching in-memory host actor and attachment bookkeeping when its
authority is revoked or expires, freeing its bounded registry slot. Cleanup
must be specific to the admitted generation: a superseded expiry waiter must
never remove a newly admitted replacement. Ordinary transport loss retains
the actor for byte-offset recovery. Durable public tombstones remain in SQLite;
freeing runtime bookkeeping is not an authenticated host uninstall.

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
50 MiB output and mid-session revocation. Use the owner-selected D170 design point: 1,000 nodes, 200 terminals and
50 users, with 10,000-node headroom. Report per-unit memory multiplied by
the expected count; retained transport pairs are not whole-daemon memory.
Local primitive measurements are diagnostic, not pinned performance gates.

## Operator and bootstrap enrollment API (#78, #87)

The configured HTTPS API exposes `POST /remote/invitations` and
`POST /remote/join`. Both accept one JSON body of at most 8192 bytes, reject
unknown fields, bound each request (including body read) to five seconds and
share eight admission slots. Never place an invitation in a URL or a log.

Invitation issuance requires an unlocked live browser session cookie, exact
Origin and current core owner permission. This host-creation permission is
separate from administrator CA-unlock permission. Its body is
`{host_id: UUID, mode: "rootless"|"rootful", execution_uid: u32}`; the uid
comes from the bootstrap probe, or the authorized operator for tests. Issuance
creates an immutable host record or requires an existing record to match.
A replacement invitation invalidates the previous token. Its response is
`{host_id, mode, execution_uid, token, ca_der, endpoint, server_name}`:
`ca_der` is canonical unpadded base64url public DER trust, `endpoint` is the
server-selected socket address for QUIC and TCP, and `server_name` is verified
against the configured TLS certificate. The bootstrap adapter passes this
response privately through stdin to `infraternal agent join <url>`.

Join requires server-authenticated pinned HTTPS before sending a capability;
it does not require a client certificate that has yet to be issued. Its body
is `{host_id, mode, token, csr_der}`, with canonical unpadded base64url PKCS10
DER of at most 4096 bytes. The server checks the invitation before CSR proof
or signing, then repeats the authority checks in atomic redemption. Success
returns `{certificate_der, execution_uid}` only after commit. Admission and
signer errors expose no secret or detailed crypto diagnostics. The join
command verifies returned uid and certificate/key correspondence before
publishing local identity. This API never unlocks a cold CA [168].

## Normal CLI activation (partial D168 adapter)

`infraternal server --remote-listen <IP:port>` explicitly activates the remote
enrollment router, QUIC listener and TCP/TLS fallback. Both transports use the
same advertised address; wildcard IPs and port zero are refused. Without the
option, ordinary server startup retains its existing behavior. Service install
preserves the remote options.

`--remote-ca-dir <absolute-directory>` overrides the standard
`$XDG_DATA_HOME/infraternal/ca/` (or `~/.local/share/infraternal/ca/`). Its
retained public trust anchor is `issuer.pem`; this path is recorded on #34.
The directory is owned by the running uid and 0700. Trust and TLS files are
owned regular files, 0600, at most 8192 bytes, opened without following a final
symlink. Missing, unsafe or invalid trust fails startup without generating a CA.

The current adapter supports standalone HTTPS with its server leaf/key supplied
by `--tls-cert`/`--tls-key`. The leaf must chain to the retained issuer, match its
key and authenticate the public-origin hostname/IP. That issuer pins both join
HTTPS and remote mTLS. Reverse-proxy deployments and a separate public HTTPS
trust chain require a later adapter; they currently fail closed.

Normal cold startup loads public trust and the server leaf key only. Its CA
signer remains locked; enrolled hosts can reconnect and retain sessions while
join refuses signing without consuming the invitation. It never reads a CA
private key or takes an unlock secret in argv. `MemoryCaSource` already exposes
the administrator-policy and process-only handoff interfaces. Production
encrypted envelopes, administrator passkey unlock/notifications and automatic
update IPC are still unimplemented; this activation does not satisfy those
remaining D168 requirements or live renewal. Host revocation is available while
the signer is locked, as described below.

## Owner revocation API and retained authority

`POST /remote/revocations` accepts `{host_id: UUID}` with the same 8192-byte
body, five-second deadline and eight shared admission slots as enrollment.
It requires the exact Origin and an unlocked, unexpired browser session with
current core owner permission for the host. This permission is independent of
administrator CA unlock. Unknown JSON fields are refused. Missing session is
401; invalid permission is 403; successful durable revocation is 204.

Recheck session expiry, unlocked state, owner permission and host ownership in
the revocation transaction. The HTTPS router and both remote listeners share
one `EnrollmentStore` event scope. After authorized mutation, a process-owned
finalizer commits the tombstone and publishes cancellation even if the HTTP
caller has disconnected. It never makes permission checks survive an earlier
unauthorized request. Storage failure is reported; an ambiguous commit also
retires current authority conservatively. A process exit retires its transports.

Each retained connection has its exact admitted fingerprint, host identity,
revocation signal and a monotonic certificate-expiry cap. New Open/Attach
operations recheck the ledger. Streaming bytes check the signal and expiry
without a SQLite read per keystroke. Revocation wakes blocked transport reads
and writes, closing both TCP and QUIC. An already-held browser attachment may
remain for offset recovery, but it cannot forward new input through the retired
transport. Shims keep running. This implements immediate authority retirement;
authenticated removal notices and operator uninstall remain separate work.

## Live certificate renewal [133][168]

Hello bit 2 (`LIVE_RENEWAL`) enables server-driven renewal on control stream
zero. Peers without the capability never receive these actions. Control calls
use the existing server-assigned nonzero call-id allocator, independently of
terminal writer ids and native stream ids. No v1 frame layout changes.

At half-life the server sends `Call("transport.csr", {})`. Success returns
`{csr_der: [u8]}` containing at most 4096 bytes of canonical signed PKCS10.
The server signs through the live `CaKeySource` and atomically publishes public
ledger authority using the exact admitted predecessor and unchanged host key.
It then sends `Call("transport.certificate", {certificate_der: [u8]})` with
at most 8192 DER bytes. Each JSON payload is bounded to 32768 bytes before
parsing; unknown fields are refused. Success is `Result(ok=true, json={})`.

The infraternal agent verifies pinned issuer/client purpose, exact retained
host identity, same local key, seven-day lifetime and increasing expiry,
then fsyncs and atomically replaces its private local identity file. Only
successful publication may acknowledge. Reconnects use the acknowledged leaf;
the local private key and active terminal streams remain unchanged. Crypto
and filesystem publication run outside the reactor. At most one publication
job runs per host; disconnect does not turn a failed publication into success.

The server extends the retained transport's shared fingerprint/monotonic expiry
only after the publication acknowledgement and renewed ledger admission.
Revocation still cancels it at once. Old authority remains valid only until its
original cap if delivery or acknowledgement fails. Every control call has a
five-second deadline; each host has one renewal job and the server admits at
most eight concurrent exchanges. A locked signer preserves terminal authority
and retries once per hour within the remaining validity window. Healthy
connections use only the half-life/expiry deadlines, never periodic heartbeats.
Expired local identities refuse further connection attempts; arbitrary TLS
failure never removes host state.

## Shipping administrator CA authority [168]

The following additive requirements govern the production unlock adapter; the
trusted in-memory adapter alone is not acceptance. This does not change the
invitation or join request/response shape used by #87.

Administrator membership is explicit, with a positive, monotone per-user
membership generation. The initial installation owner seeds this role once.
Subsequent authorization reads current membership, never an owner boolean.
Role revocation and a later grant cannot resurrect a ceremony or encrypted copy
bound to the earlier generation. SQLite contains role/copy state metadata only,
never a CA seed, decrypted wrapping key or encrypted CA-key copy.

CA copies live in the private XDG CA directory, under `administrators/`, one
current copy per administrator. Use the existing AES-256-GCM/HKDF-SHA256 wrapping
stack and the D168 Ed25519 seed. Authenticate issuer fingerprint, member,
membership generation and wrapping salt as associated data. The browser derives
only the domain-separated CA wrapping key from its locally unwrapped account
DEK; neither PRF output nor DEK reaches the server, and CA seed/ciphertext copies
are never sent to the browser. Decrypted seeds and wrapping keys are transient
secret memory. Authenticate the GCM tag before constructing signer material;
every failing decrypt path clears its plaintext buffer.

Publication is atomic and durable in owned 0700 directories with 0600 files.
Bound copy reads to 8192 bytes and refuse unsafe ownership, permissions or
symlink reads. Removing one membership generation cannot remove another user's
or generation's copy. Role grant/revoke updates rewrap/removal state; offline
recipient wrapping follows the pending-grant rule [151].

Unlock requires a single-use, expiring passkey ceremony bound to its purpose,
original browser session, user and membership generation. Use the existing real
WebAuthn verifier and credential-counter transaction. Before installing the key,
recheck the original live session, current membership and the fresh proof's
still-registered credential under the database writer lock. A concurrent role,
session or credential revocation must fail closed. Reject malformed/oversized
requests with static errors; never reflect or log wrapping material.

Cold startup retains public trust while refusing enrollment and renewal until
any current administrator completes that unlock. Existing host authority and
sessions do not depend on the CA lock. Deliver locked and approaching-expiry
notifications to current administrators without idle polling. A configured
release CLI must use this actual adapter and encrypted store; fixture signer
injection is not a substitute. Unconfigured shipping servers still register
remote enrollment paths and return service-unavailable rather than route-not-found.
Process-only update/rollback handoff remains distinct from cold startup; update
IPC integration is a later slice.

### Administrator CA HTTP adapter

A configured remote service mounts these POST-only paths at the pinned public
HTTPS origin. All three require exact `Origin`, the existing secure session
cookie and current explicit administrator membership with a registered passkey.
The finish body is bounded to 32768 bytes and rejects unknown fields; status and
start do not consume a request body.
Missing/malformed cookies return 401; a valid-shaped unauthorized cookie or bad
Origin returns403. Admission is bounded to eight requests and exhaustion
returns 429. Finish parser errors return an empty 400; oversized finish bodies
return 413.
Responses never set a session cookie or include private CA material.

- `/remote/ca/status`, body `{}`: returns `{"locked":true}` or
  `{"locked":false}`. Existing administrator session liveness is required; a
  stale freshness timestamp does not prevent starting a new passkey proof.
- `/remote/ca/unlock/start`, body `{}`: returns the existing `login_start`
  ceremony/options plus public `ca` metadata: `member`, positive `generation`,
  base64url `salt` and `issuer_fingerprint`. The private purpose registry binds
  this 300-second single-use ceremony to its original session and membership
  generation. Neither encrypted copy nor CA seed is returned.
- `/remote/ca/unlock/finish`, body with exactly `ceremony`, existing WebAuthn
  `proof`, and `scoped_key` (array of exactly 32 bytes): requires a fresh real
  registered-passkey proof, authenticated copy decryption and final authority
  checks under the database writer lock. Returns only `{"locked":false}`.
  Failures never echo wrapping material. The scoped key is the locally derived
  CA wrapping key described above, never the account DEK or passkey PRF output.

The normal configured release CLI uses the same migrated Auth/database and cold
`MemoryCaSource` for this HTTP authority and enrollment/renewal. Unlocking one
therefore enables signing in the other; restart recreates the cold lock. Startup
refuses unsafe encrypted-copy storage rather than silently disabling unlock.
The additive setup and administrator-role actions below provide provisioning
and rewrap without changing the existing unlock contract.

### First machine certificate setup and role rewrap [151][168], #78

The declared `remote.ca.bootstrap` action uses
`POST /remote/ca/bootstrap/start` with `{}` at the pinned HTTPS origin and the
administrator's existing session cookie. It returns the usual WebAuthn ceremony
and options plus `ca.member`, `ca.generation`, base64url `ca.salt`, and
`ca.operation` (`setup` or `unlock`). The browser performs fresh user verification
and derives a 32-byte key locally using HKDF-SHA256, account DEK as input,
`ca.salt` as salt and `infraternal/ca-wrap/v1|<member>|<generation>` as info.
It sends `POST /remote/ca/bootstrap/finish` with exactly
`{"ceremony":...,"proof":...,"scoped_key":[32 bytes]}`. Success returns only
`{"locked":false}`. The add-host flow calls these two endpoints before
`POST /remote/invitations`. A retained cold CA uses its existing copy and the
same two calls to unlock; setup never replaces retained trust.

First setup publishes a complete private `active/` directory atomically under
CA state: public issuer, remote server certificate/key and encrypted
administrator copies. The CA signing key has no plaintext disk representation.
The database writer lock serializes setup and role changes. Successful setup
keeps the signer in memory and activates the configured remote listeners.
Cold startup uses retained public trust and recreates the signing lock. An interrupted publication is recovered as public locked trust; retry never creates another issuer.
HTTPS enrollment trust is independent: invitations may carry an explicit
`https_der` leaf pin or `https_system_roots:true` for a public HTTPS proxy;
legacy invitations retain their original issuer-based HTTPS trust.

The declared `remote.ca.administrators` action requires a current owner who is
also an administrator. `POST /remote/ca/administrators/start` accepts exactly
`{"user_id":...,"administrator":true|false}` and binds that change to fresh
passkey verification. `/remote/ca/administrators/finish` accepts exactly
`{"ceremony":...,"proof":...}`. Each role transition advances membership
generation and removes the old generation's wrapped copy. A recipient's copy
is pending until that administrator runs bootstrap with their own locally
derived key while the signer is unlocked. Offline keys are never fabricated or
stored centrally. Removing the last administrator or the last retained current wrapped copy is refused.

Anonymous join bodies have an eight-request pool and at most two slots per
canonical source IP. Invitation/revocation requests have a separate eight-slot
pool, after exact-origin and live-owner checks; CA operations have their own
administrator pool. Request processing, including pre-admission checks, has a
five-second deadline. Trusted forwarding policy supplies canonical IP metadata.
Remote handshakes reserve 16 slots for previously authenticated source hints,
with 48 anonymous TLS slots, four per source. Hints never grant host authority:
all peers still prove a live ledger certificate. Anonymous TCP first bytes have
48 slots with a two-second deadline, plus 16 short 100ms probes, one per source,
to permit an immediate ClientHello behind the same NAT as stalled sockets.
QUIC sends a keep-alive every 15 seconds and expires a silent transport after
60 seconds. Acknowledged probes keep healthy idle connections alive; four
intervals allow transient mobile loss while bounding stale NAT connections.

## Confirmed host removal (#87, D16/D168/D198/D202)

The remote plugin declares `remote.host.remove` once. Its summary and instructions
supply the UI label, CLI help and `infraternal skill remote.host.remove` output.
`POST /remote/hosts/actions` returns that definition only to a live server owner.

`POST /remote/hosts/remove/start` accepts `host_id` and optional `uninstall`
(default true), under the exact same-origin session policy. It returns a real
user-verifying passkey challenge and the selected public host coordinates.
A bounded private registry binds the challenge to that host, uninstall choice,
original session and owner, for 300 seconds. The finish body contains `host_id`,
`ceremony` and `proof`. An ordinary sign-in or CA challenge cannot remove a host.
A foreign host UUID, replay, expired challenge, logout, lost owner authority or
removed signing passkey is refused.

With an API key (D333), `POST /v1/actions/remote.host.remove` takes `host_id` and a
required `dry_run`. `dry_run: true` returns the review (host, label, and that the
agent is uninstalled) and changes nothing. `dry_run: false` removes the host with no
further passkey tap: inside one writer transaction the key is rechecked for
`hosts:write` (J90, clock read in the transaction), its account must be the owner's
and own the host, and the key's audit row is completed with the removal. The agent
is always uninstalled (D334). Every call is audited.

A process-owned operation keeps the authorized mutation alive after a browser
HTTP disconnect. SQLite's writer transaction serializes final authorization,
a bounded five-second node uninstall handoff and public revocation. It deletes
the visible bootstrap inventory and its application-owned SSH pin (unless another
retained host uses that pin). External SSH trust is untouched. The existing
revocation fence cuts the live QUIC/TLS channel before committing the tombstone.
Public certificate denial tombstones remain so a removed certificate stays denied.

The internal `remote.host.uninstall` action is absent from the browser action
catalogue. Only a checked managed remote installation registers its handler.
Its input contains the exact host identity and a dry-run flag; paths never come
from the action. It revalidates the owned root, marker, launcher, unit, enable
link and absence of an in-progress bootstrap. A generic `after_write` plugin
continuation sends acceptance before handing a bounded private-stdin plan to an
independent transient service. Failed or cancelled writes discard the effect.
The helper retires owned shims and removes the installed service, launcher and
data root. No task runs merely because the plugin is compiled in.

The finish result distinguishes `requested`, `unreachable` and `retained` host
cleanup. `requested` means acceptance was transmitted; it does not assert that
host cleanup completed. An unreachable host still loses server access, and the
response names the service, binary and data that may remain for local removal.
The CLI uses the same HTTPS start/finish routes, with session and passkey proof
only on bounded private stdin. Its default output is organized human text;
`--json` exposes the structured preview or result.
