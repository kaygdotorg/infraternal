<!-- Browser encryption and auth adapter contract for decisions 23–29 and 53, 97–98; issues #17 and #32. -->
# Browser key wrapping v1

The server never receives a plaintext DEK, PRF output or SSH secret. It receives
WebAuthn credential proofs, encrypted secrets, and the envelopes specified here.
Recovery words, entropy and wrapping material never reach the server, including
failed attempts and legacy accounts. Only the independent v2 authentication
verifier may be transmitted. Never log request/response bodies on these endpoints. The setup token
banner is the sole authorized secret log [26]. Serve the browser on the explicit
HTTPS origin passed to `Auth::new`; arbitrary proxy origin headers are not trusted.

## Cryptography

For the first passkey, generate a random 32-byte DEK with `crypto.getRandomValues`.
Keep it in memory only. All subsequent passkeys wrap **the same DEK**. Server-side
ciphertext length checks cannot prove that two envelopes contain the same DEK.
The client must decrypt and compare before accepting a newly installed envelope.

Use WebCrypto HKDF-SHA256 and AES-256-GCM: both are native in Safari and other
browsers. XChaCha20 would add a browser implementation and extra download/CPU
cost; AES-GCM needs careful nonce uniqueness, handled below. These primitives
and domain separation are versioned; changing them requires a new contract.

All transport binary values use canonical unpadded base64url. Legacy credentials use
`extensions.prf.eval.first = base64url(SHA256(UTF8("infraternal/keywrap/prf/v1")))`.
New enrollment uses the per-user v2 input specified below; existing ciphertext
retains v1. Discoverable challenges omit PRF until authenticated input retrieval.
Decode this into a Uint8Array before WebAuthn. The browser performs WebAuthn's
specified PRF input transformation; do **not** prehash it again yourself.
Registration requests `residentKey: required`, `requireResidentKey: true`,
`userVerification: required`, `credProps: true`, and PRF. Identified login requests PRF; discoverable login obtains it in a subsequent
local credential-specific get. Both require UV. Stop enrollment if `getClientExtensionResults().prf.enabled`
is not true. If creation does not return PRF results, perform a client-side
`credentials.get` with the same RP, credential allow-list and PRF input to obtain
results before finishing registration. This local get is for key derivation;
server authentication still requires the server's login challenge.

Passkey wrapping input key material (IKM) is the 32-byte `prf.results.first`.
For legacy recovery envelopes only, the 32-byte BIP-39 entropy is IKM.
New recovery envelopes use the browser-only v2 wrapping sibling specified below.
Neither mnemonic UTF-8 nor BIP-39's PBKDF2 seed is wrapping material. There is
no optional BIP-39 passphrase. Generate fresh random salt (32 bytes) and nonce
(12 bytes) for **every wrapping operation**, including rewraps. Never reuse a
nonce with the same derived key.

HKDF info and GCM additional authenticated data are the same UTF-8 bytes:

`infraternal/keywrap/v1|<user UUID>|<kind>`

`kind` is exactly `passkey` or `recovery`. UUID is the server's lowercase canonical
UUID. The credential-specific PRF already binds a passkey's wrapping key; its
credential ID is not needed before creation completes. Derive 32 bytes with
HKDF-SHA256(IKM, salt, info), then encrypt the 32-byte DEK using AES-256-GCM,
nonce, that AAD, and a 128-bit tag. The ciphertext is 48 bytes, tag appended.
An envelope is exactly `{salt, nonce, ciphertext}`. There is no plaintext field.
The database separately binds envelopes to user UUID, kind and credential ID.
On reading, authenticate AAD before using the DEK; fail closed on any GCM error.

Keep the PRF results in the browser only. **Remove the complete `prf` property**
from client extension outputs before sending credential proofs. Send only
`id`, `rawId`, `type`, `response` (base64url binary fields), and optional
`extensions`/`clientExtensionResults` containing `credProps` or `appid`.
The server rejects PRF output and unknown proof fields rather than storing them.
Authenticators may return unsigned residence/PRF support hints. They are not
cryptographic attestation; security depends on UV, signed RP/origin/challenge,
and browser-side successful unwrap. Syncable passkeys are supported.

Recovery hashes use Argon2id v19, m=19456 KiB, t=2, p=1, random 16-byte salt.
High-entropy capabilities (setup/session/recovery polling/API keys) use SHA256
because they have 256 random bits; a password KDF adds CPU cost without
improving resistance to guessing these capabilities.

## HTTP API

Mount `auth::router(auth)`. All actions are POST `/auth/<action>` with JSON,
32 KiB maximum, `Cache-Control: no-store`. Browser actions require the exact
configured `Origin` header, including login/setup/recovery. There is no CORS.
`device-start` and `device-redeem` use high-entropy capabilities and permit CLI
requests without Origin; browser cookies are never used by those actions.
The HTTP adapter partitions a bounded aggregate 180/minute admission ceiling
into 120 browser actions and 60 CLI device actions (see trusted ingress below).
Hosts may add stricter per-source ingress limits and must avoid body logging.
Auth additionally caps pending ceremonies at 1024 and
Argon2 work at two simultaneous calls; exhausted capacity fails closed.

| Action | JSON body | Result |
| --- | --- | --- |
| setup-check | `{token}` | `204` if current and no owner exists; `401` for wrong/expired tokens; `404` after owner creation |
| setup-start | legacy `{token,name}` or `{token,username,display_name?}` | `{ceremony,user_id,options,recovery_words}` |
| registration-finish | `{ceremony,proof,passkey_wrap,recovery_wrap}` | secure session cookie |
| status | `{}` | `{setup_required: bool, setup_token_command: string}` only |
| login-start | `{}` (legacy `{user_id}` supported) | `{ceremony,options}` |
| login-finish | `{ceremony,proof,device}` | restricted secure session cookie and `pending_transaction` |
| session | `{}` | `{user_id,username,display_name,device,fresh}` and refreshed cookie |
| add-start | `{}` + session | enrollment options; recovery_words=null |
| wraps | `{}` + session | `[{kind,key_id,wrap}]` for the session user |
| recovery-start | `{username|user_id,verifier}` | `{token,delay_seconds,ready_at}` |
| recovery-ready | `{token}` | replacement enrollment and old_recovery_wrap |
| recovery-rotate | `{recovery_wrap,recovery_verifier}` + fresh unlocked session | `{ok:true}` |
| recovery-cancel | `{}` + any live session | `{ok:true}` |
| device-start | `{device,scopes}` | `{poll_token,user_code,expires_in:600}` |
| device-inspect | `{code}` + session | requested device/scopes for approval UI |
| device-approve | `{code}` + fresh session | `{ok:true}` |
| device-redeem | `{token:poll_token}` | `{api_key}` once |
| api-list | `{}` + session | device/scopes and nonsecret revocation `id` |
| security-settings | `{}` + live owner session | `{api_key_lifetime_days}` |
| security-settings-update | `{api_key_lifetime_days: integer 1..365}` + fresh owner session | saved `{api_key_lifetime_days}` |
| api-revoke | `{id}` + fresh session | `{ok:true}` |
| logout | `{}` + session | revoked session and expired cookie |

`setup-check` is additive and read-only. While no owner exists, it compares the
candidate token hash with the stored hash in constant time and returns `204` only
for the current, unexpired setup token. Wrong or expired tokens return `401`.
Once an owner exists, it returns `404`. The check uses the same browser admission
and trusted-ingress source limits as other auth actions; it creates no ceremony,
sets no cookie and changes no setup state. `setup-start` remains the enrollment
entry point, and registration finish remains the one-shot token consumption [26,53].

A cookie is `__Host-infraternal=<opaque random id>; Secure; HttpOnly;
SameSite=Strict; Path=/; Max-Age=2592000` with no Domain. Storage slides 30 days
on authenticated use; every successful cookie-authenticated HTTP action also
refreshes the cookie. The client calls `session` on app resume to check validity. Fresh tap lifetime is five
minutes; obtain a new session via login for destructive UI actions. Server action
adapters call `Auth::fresh_session` to enforce this without duplicating policy. CLI keys
never establish a fresh browser session. Initial scopes are `hosts:read`,
`terminal:connect`, `actions:dry-run`; destructive MCP execution is not granted
by this lane. Action adapters must require the separate dry-run contract [28].

Ceremonies expire in five minutes and are consumed before validation, including
failed validation. Retries start a new ceremony. Challenges stay on the server;
a restart invalidates pending ceremonies. `bootstrap(now, announce)` creates a
fresh setup token on every process start if no owner exists, replaces any prior
hash, and calls the announcer with the clear banner. Rotation invalidates earlier
setup ceremonies at their transaction authority check.
A host integration must invoke bootstrap at startup with its log writer.
The setup token is consumed atomically only upon successful owner enrollment;
all parallel enrollments then fail. Exactly one owner is enforced in storage.

Owner enrollment stores the immutable internal UUID separately from the public
username and display name [97–98]. The username is unique and must match ASCII
`[a-z0-9_-]{2,32}`. The display name accepts up to 64 Unicode scalar values;
missing or blank display names default to the username. New requests use
`{token,username,display_name?}` and cannot mix those fields with legacy `name`.
Legacy `{token,name}` remains accepted by treating `name` as both labels, subject
to the username rule. WebAuthn registration uses the username for `user.name`
and the display name for `user.displayName`. The authenticated session returns
both labels; public status returns only `setup_required` and the non-secret
`setup_token_command` [16][202], never account labels or a capability. The command
comes from the registered action: `infraternal server setup-token`, prefixed with
`sudo` when the server runs as an installed system service (#252). Display and
copy use the same string; no data path or token is included.

Migration 0006 preserves existing display labels. A unique legacy label that
already matches the username rule is retained in lowercase; an invalid or
duplicate legacy label receives a stable UUID-derived username. The unique index
continues to arbitrate concurrent inserts. Enrollment returns HTTP 409 when a
username already exists.

First enrollment displays 24 recovery words once, asks the user to retain them,
and builds both envelopes before `registration-finish`. The server pending
state retains only the Argon2id hash. Optional second enrollment uses a fresh
session, wraps the existing DEK, and passes `recovery_wrap: null`. The two-passkey
limit is checked again under the database write lock. No passkey deletion API
is exposed, so the mandatory last passkey cannot be deleted.

Recovery requests cannot bypass the 24-hour delay or reset an active request.
A live browser device can cancel until replacement commits, including after
the delay. The recovery token expires 48 hours after request creation.
`recovery-ready` returns the old recovery envelope and new enrollment options
only after 24 hours. Locally derive its old recovery KEK from the supplied words,
unwrap the DEK, then wrap it for the replacement passkey and newly displayed
recovery words. Successful finish consumes recovery authorization, removes old
passkeys/envelopes and revokes all sessions/API keys/pending device approvals,
rotates the recovery hash, and creates a new session atomically. Cancellation
also invalidates any replacement ceremony already begun.

### Same-device recovery (D113, owner decision on #45)

D113 supersedes the unconditional delay above. `recovery-start` accepts the
`{user_id,verifier}` or `{username,verifier}` (exactly one identity).
It returns `{token,delay_seconds,ready_at}`, where `ready_at` is Unix seconds.
The independent authentication verifier is always verified. Under the same database writer lock as recovery
creation, an optional browser cookie grants a zero delay only if its session is
unlocked, unexpired and belongs to the recovered account. Missing, invalid,
expired, revoked, pending-unlock or other-account sessions retain 86400 seconds.
API keys cannot shorten the wait. An active request still cannot be reset or
accelerated by repeating `recovery-start`. Tokens retain the 48-hour expiry and
the existing cancellation/replacement authority checks.

Username lookup is internal; unknown accounts and wrong verifiers return the same
401 message. The browser holds the recovery capability and words in memory
only, shows the server's actual ready time, and asks for the words again after
a reload. It never fabricates progress or persists recovery secrets. The server
remains authoritative at `recovery-ready` even if the local clock is wrong.
Replacement unwraps the original recovery envelope before creating the new
passkey, wraps that same DEK and requires acknowledgement of the rotated words
before finish. No existing cryptographic envelope or proof format changes.

Device approvals bind exactly the requested scopes. Show the inspected device
and scopes before approving. The user code is 96 random bits (may be embedded
in a QR code); it cannot poll/redeem. Approval expires after ten minutes and
redeems once with a separate 256-bit polling capability. API-key listing and
revocation never reveal bearer keys. The multi-user schema is in core [29,31];
invite/role management remains outside this lane.

API keys expire after inactivity [D311 amendment, 2026-11-02, #269]. The server
setting `api_key_lifetime_days` defaults to 30, accepts integers from 1 through
365, and is read at each authorization check. Both settings actions require the
pinned browser Origin and a live owner session; changes additionally require
fresh passkey authority, rechecked under the database writer lock. Unknown
fields, missing values and values outside the range return 400. No UI is added.

Each key stores an absolute `expires_at` at issuance and renewal. Each check
clamps it to the smaller of its stored deadline and last renewal plus the
current lifetime. Lengthening the policy applies only on a successful renewal;
it never extends an already expired key. At the exclusive deadline the server
commits a permanent tombstone and returns the same `Denied` error as an unknown
key. An authenticated, scoped use renews at most once per hour per key; denied
scopes do not renew. Expiry checks, clamping and renewal are serialized with
revocation. Existing keys receive the default lifetime from migration time once.

Sign-in currently issues and stores keys but no CLI command reads or sends
them and no production route calls `api_authorize` (#303). Future CLI callers
use the shared invalid-key diagnostic with D303 exit 3; they never print a key.

## Admission and trusted ingress

HTTP admission has fixed 60-second partitions: 120 browser actions and 60 CLI
approval/polling actions. All admitted actions in each partition count, including
cookie-authenticated reads; logout is exempt so revocation remains available.
The admitted-action ceiling is 180/minute. Device callers
cannot consume browser capacity. Throttling returns 429 and `Retry-After: 60`;
authentication failures remain 401. Wrong browser Origins are rejected before
spending browser capacity. Request bodies are bounded at 32 KiB.

The library never trusts `Forwarded` or `X-Forwarded-For`. The host must apply
per-source admission at its trusted ingress using the actual peer address, or
forwarded addresses only from explicitly configured proxy peers that strip
caller-supplied forwarding headers. The server accepts repeatable
`--trusted-proxy <IP-or-CIDR>` entries only together with `--behind-proxy`;
only those peers may supply a single `X-Forwarded-For` address for source
admission. Other forwarding headers are ignored, and WebAuthn continues to use
the explicit `--public-origin`. Keep separate browser and device policies:
for example, at most 30 browser actions/minute/source and 10 device actions/
minute/source, beneath the global partitions. Enforce body limits and admission
before JSON parsing there. This policy is a deployment requirement; this library
cannot infer a trusted source from arbitrary HTTP headers or invent a proxy list.

## Discoverable sign-in and PRF input transition (#19, #21)

Discoverable login requires no account UUID. Its allowCredentials is empty and
its response must contain a 16-byte UUID userHandle. The server locates that
user's exact credential, verifies UV/signature and advances the latest stored
counter under the writer lock. Missing, unknown or mismatched handles fail closed.
Status is public within the existing exact-Origin and admission policy and
reveals only whether an owner exists.

New registrations and discoverable assertions evaluate the server-wide public
constant base64url(SHA256(UTF8(`infraternal/keywrap/prf/v3`))) [D108, #30].
The assertion carries `prf.eval` with an empty allowCredentials list. PRF remains
credential-specific, and the browser strips the entire PRF extension before
submitting its signed proof. HKDF info and envelope AAD stay exactly
`infraternal/keywrap/v1|<canonical UUID>|<kind>`.

Stored metadata is authoritative: NULL retains v1
(SHA256(`infraternal/keywrap/prf/v1`)); v2 retains its UUID-derived input
(SHA256(`infraternal/keywrap/prf/v2|<canonical UUID>`)). When the stored input
differs from the first assertion input, or that assertion has no PRF result,
the browser uses the existing local second prompt for the selected credential.
It does not transmit that second assertion or PRF output. We choose fallback,
without automatic rewrap: neither existing ciphertext nor metadata is relabeled.
This preserves old DEKs without a new envelope write/rotation transaction.

HTTP identified login is an authenticated fresh tap for the matching user;
unauthenticated known/unknown UUIDs receive the same 401. Public discoverable
login publishes no credential list. Every HTTP ceremony start (setup, login,
additional passkey, recovery replacement) binds to a random host-only
`__Host-infraternal-ceremony` cookie, Secure/HttpOnly/SameSite=Strict/Path=/,
Max-Age=300. Pending state stores its hash. Finish requires the starting browser
binding before consuming state; unrelated clients cannot drain a valid proof.

HTTP login-finish creates a restricted pending-unlock session, with a fixed
five-minute database expiry, and returns `pending_transaction` once. This id is
SHA256(`infraternal/unlock/v1|<opaque session cookie>`) encoded as unpadded URL-safe
base64. Domain separation keeps it distinct from the cookie and stored token hash;
no additional schema or pending allocation is needed. The browser keeps it only
in the current page call, never local/session storage, URLs or logs.

Only `unlock-session` identity and `wraps` reads are allowed; ordinary `session`,
WebSocket upgrade and all other authenticated actions deny pending authority.
After local AES-GCM unwrap succeeds, the browser calls `unlock-finish` with
`{pending_transaction}`. The server requires both the exact cookie and its id,
then atomically consumes the pending flag and begins normal sliding expiry.
Missing ids fail closed; mismatched, stale, replayed or expired ids return 401
without activating/deleting another pending row or replacing its cookie.
Failed-login cleanup sends `logout` with the same id and deletes only that exact
pending login. Completion, authenticated action responses and logout never emit
`Set-Cookie`, including on success: a response may arrive after another tab has
replaced the shared cookie. Database expiry still slides; the browser cookie's
30-day lifetime is measured from issuance and is not refreshed by identity reads.
Ordinary authenticated logout still accepts `{}` and revokes its exact database
row without clearing the shared cookie jar. Exact-Origin
logout bypasses both admission layers, so exhaustion cannot prevent revocation.

Owner boundary (#29): this id binds a completion to its login; it is not a proof
of DEK possession. A client holding its matching cookie/id can claim completion
without actually unwrapping. The passkey authenticates the user; the server
receives a client consistency signal, never plaintext DEK/PRF. The owner explicitly
deferred a server-verifiable unwrap proof. Abandonment/failed cleanup does not
activate authority, and expired pending rows are deleted on the auth path.

Socket authority covers server Hello, client Hello/Resume, all nested pending
frame/backend/database/writer awaits and terminal output. Each operation enters
with one authoritative SQLite read, except content-free Ping/Pong proofs (#199),
which reuse a non-renewing snapshot watched by committed revocation and absolute
expiry. This exception includes bounded transport echoes, cancels pending proof
writes on revocation/expiry, and never applies to application frames, terminal
payloads or backend rebinds. Each operation’s expiry snapshot and the committed
revocation generation are rechecked after waits. Backend/persistence boundaries
also read actual authority before success frames; SQLite writer locks and mutation
predicates order commits with logout/recovery. Revocation interrupts
pending operations independently of connect deadlines. Terminal open has a
60-second connect budget (#29 owner-task fallback; no earlier SSH connect budget
was specified); attachment reply waits remain bounded to five seconds. Expiry is
checked every 25 ms only during pending operations, including handshakes; idle live
sockets keep event-driven revocation and actual deadline checks without polling.
Authority reads and shutdown writes have 25 ms deadlines and fail closed.
Handshake reads never renew expiry. Already dispatched host work may complete;
revoked sockets receive no late success and no terminal row is inserted for its
late result. Cancelling work already accepted by the host requires a separate
backend protocol; this fix does not invent one.

Before owner enrollment, each restart rotates the token and replaces a stale
private setup-token.sock. The token remains only in process memory and the
private CLI socket; runtime logs do not disclose it. Enrollment consumes it once.

## Recovery resumption (#45, D25/D113)

Additive `recovery-resume` accepts the same identity and authentication fields
as recovery-start. It verifies the key on every call and takes the writer lock
before inspecting pending state. Without a pending row it creates recovery with
the D113 delay. With a row it reissues a capability and retains **exactly** its
stored ready time, even after the previous capability expires. Reissuing extends
only the capability lifetime (48 hours from this verification), never the wait.
The previous capability and any replacement ceremony bound to it become invalid.
Cancellation and successful replacement delete the row. Verifier start/resume both preserve existing deadlines.

The result is `{token,ready_at,delay_seconds}` with delay_seconds equal to the
nonnegative remaining time measured by the server. A browser may discard all
secret state and resume by supplying the key again, from any device. Its UI
shows the real remaining time and never promises that its local clock grants
server authority. No key or capability is persisted by the browser.

## Signed-in recovery visibility and audit (#45, D25)

Authenticated `session` adds `recovery_pending: {ready_at} | null`. It includes
pending state even after capability expiry because resumption keeps that deadline.
No words, verifier, capability or requesting-device identity are disclosed.

Browsers subscribe on control stream 0 with the existing Subscribe frame:
`sub_id=45`, filter JSON exactly `{"topic":"auth.recovery"}`. After subscription
and whenever state changes the server sends an existing Event frame on stream 0,
with `sub_id=45` and JSON `{topic:"auth.recovery",pending:{ready_at}|null}`.
The authenticated account determines the scope; a filter cannot select an account.
Resubscription/reconnection supplies a current snapshot. Events are coalescible
state notifications, not an audit stream. No polling timer runs on idle devices.
A signed-in browser shows a toast once per new deadline and a persistent notice
with a Cancel recovery control. Session reads on foreground return repair state.

Start (not resume), cancel (when a row existed), and complete audit rows commit in
the same SQLite transaction as their state changes. Rows contain only account ID,
event and Unix time. Invalid requests, reissues and repeat cancellation cannot
invent completion or duplicate start evidence. Notification is after commit.

## Account-scoped authority notifications (#240, D28)

Session revocation and recovery-state notifications must use independent watch
generations per account. Logout carries the account returned by its committed
session deletion and, when known, the private session hash; recovery completion
invalidates its old sessions. These internal hints never enter browser events or logs.

Subscribe before the entry authority read, including after socket admission.
Every unseen generation means recheck that account. Coalesced intermediate events
cannot be discarded based on the latest session hash: an earlier logout may have
revoked this socket. A lost source fails closed as unavailable authority. Remove
an account's channel when its last subscription ends, including concurrent drops.

Logout, recovery start/cancel/rotation and recovery completion all know their
affected account; none requires a server-wide authority event. Test-only all-account
notifications may model database changes whose account scope is unknown. Server
shutdown and component disable retain their separate lifecycle signals. Ordinary
account changes must never wake another account's sockets or pending operations.

## Browser-only recovery derivation v2 (#45, D151 owner task)

This revision enforces browser-only words for all production paths. It reuses WebCrypto HKDF-SHA256/AES-256-GCM and the
existing Argon2id verifier; it adds no cryptographic library or engine. Setup and
replacement generate 256-bit entropy with browser crypto.getRandomValues and
encode 24 English BIP-39 words locally. No v2 response generates or includes words.

From that entropy derive two independent 32-byte outputs with HKDF-SHA256,
a zero-length salt and these exact UTF-8 info strings:

- authentication: `infraternal/recovery/auth/v2`
- wrapping: `infraternal/recovery/wrap/v2`

The authentication secret is canonical unpadded base64url and is sent as
`verifier`. The server Argon2id-hashes that string with a fresh random salt;
only its PHC hash is stored. The wrapping output is browser-only IKM for the
existing recovery envelope HKDF (fresh 32-byte salt, v1 user/kind info and AAD)
and AES-GCM encryption. Passkey envelope derivation is unchanged. Independent
HKDF info strings ensure knowledge of the authentication secret does not permit
computing entropy or the wrapping output.

Registration-finish adds `recovery_verifier`; it is mandatory for a recovery
envelope in v2 and absent for additional-passkey enrollment. Setup-start and
recovery-ready return `recovery_version:2` and recovery_words:null. Replacement
also returns `old_recovery_wrap_version` (1 or 2), read from stored metadata.
Authenticated wraps include recovery_wrap_version for recovery envelopes.
Migration 0010 defaults existing accounts to authentication=1, wrapping=1.
Successful v2 enrollment/rotation stores authentication=2, wrapping=2 atomically.
Never silently relabel an old envelope; a v1 envelope unwraps with original entropy.

Recovery-start/resume accept only `{username|user_id,verifier}`. Unknown fields,
including words, fail closed. Generic denial, the existing Origin/body/admission
partitions and two concurrent Argon2 slots remain; unknown accounts take the same
bounded verifier work, with no version/account oracle. Exhausted Argon2 capacity
uses generic 429 and Retry-After: 60. Both start and resume reissue pending
authorization without changing an existing deadline.

### Signed-in replacement of legacy recovery words (R1, #45)

The legacy `recovery-upgrade` route and client path are removed. A one-time phrase
exception cannot satisfy the owner's absolute never-sent rule: old words unwrap
the retained DEK, and replacing a verifier cannot erase server knowledge of it.
No production action admits words, even on a failed attempt. The server cannot
transform an existing phrase hash into a verifier without disclosing wrapping
material; accounts with an old verifier or envelope need a signed-in device.

Authenticated `session` and `unlock-session` add `recovery_words_need_replacing`,
true if authentication or wrapping version is still 1. Public `status` retains
only `setup_required`, avoiding an account-state oracle.

A signed-in device holding the unwrapped DEK generates new words locally and
wraps that same DEK with the v2 wrapping sibling. After the caller confirms the
new words are saved, it POSTs only `{recovery_wrap,recovery_verifier}` to
`recovery-rotate`, with `X-Infraternal-User` pinned to the account used for local
envelope AAD. The server compares it to the session account, including under the
writer lock; another tab changing the shared cookie must not retarget rotation.
The word-acknowledgement callback expires when its display is dismissed.
A fresh unlocked session [28] is required. Hashing occurs
off-lock; the writer transaction rechecks live session/freshness and legacy
metadata, installs both versions as 2 together with the envelope/hash, and
cancels any pending recovery (including its begun ceremonies). Concurrent
rotations admit at most one. Passkeys and existing signed-in sessions remain
usable. No migration screen is added: D162 requires owner mockup approval first.
The client exposes a callable function for that future screen.

### Remaining wait bounds (R3, #45)

Resumption reports the stored deadline's actual remaining seconds, even above
24 hours after a clock rollback. The client accepts nonnegative safe integer
waits through the recovery capability policy maximum of 48 hours (172800 seconds)
and rejects larger or malformed durations; it does not change the deadline.
Its monotonic countdown never grants server authority.

### Threat note

The server learns the account identity, a reusable recovery authentication secret,
its hash, public envelope salt/nonce, ciphertext, timing and recovery lifecycle.
These authorize recovery after the applicable delay but do not unwrap the DEK.
A database leak contains the hash, not the bearer secret. A server receiving the
authentication output cannot derive its HKDF sibling or the 256-bit entropy.
Historical disclosure cannot be undone by rotating words while retaining the
DEK. This protocol admits no such disclosure, including for legacy accounts.
A malicious server that replaces browser JavaScript can collect browser secrets;
this contract prevents protocol disclosure, not hostile client-code delivery.
