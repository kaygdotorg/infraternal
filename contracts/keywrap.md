<!-- Browser encryption and auth adapter contract for decisions 23–29 and 53, 97–98; issues #17 and #32. -->
# Browser key wrapping v1

The server never receives a plaintext DEK, PRF output or SSH secret. It receives
WebAuthn credential proofs, encrypted secrets, and the envelopes specified here.
Recovery words necessarily reach the server over HTTPS to verify its Argon2id
hash. Never log request/response bodies on these endpoints. The setup token
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
For recovery wrapping, parse/check the English BIP-39 24 words and use the
32-byte entropy (not mnemonic UTF-8, not BIP-39's PBKDF2 seed) as IKM. There is
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
| setup-start | legacy `{token,name}` or `{token,username,display_name?}` | `{ceremony,user_id,options,recovery_words}` |
| registration-finish | `{ceremony,proof,passkey_wrap,recovery_wrap}` | secure session cookie |
| status | `{}` | `{setup_required: bool}` only |
| login-start | `{}` (legacy `{user_id}` supported) | `{ceremony,options}` |
| login-finish | `{ceremony,proof,device}` | secure session cookie |
| session | `{}` | `{user_id,username,display_name,device,fresh}` and refreshed cookie |
| add-start | `{}` + session | enrollment options; recovery_words=null |
| wraps | `{}` + session | `[{kind,key_id,wrap}]` for the session user |
| recovery-start | `{user_id,words}` | `{token,delay_seconds:86400}` |
| recovery-ready | `{token}` | replacement enrollment and old_recovery_wrap |
| recovery-cancel | `{}` + any live session | `{ok:true}` |
| device-start | `{device,scopes}` | `{poll_token,user_code,expires_in:600}` |
| device-inspect | `{code}` + session | requested device/scopes for approval UI |
| device-approve | `{code}` + fresh session | `{ok:true}` |
| device-redeem | `{token:poll_token}` | `{api_key}` once |
| api-list | `{}` + session | device/scopes and nonsecret revocation `id` |
| api-revoke | `{id}` + fresh session | `{ok:true}` |
| logout | `{}` + session | revoked session and expired cookie |

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
both labels; public status remains exactly `{setup_required}`.

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

Device approvals bind exactly the requested scopes. Show the inspected device
and scopes before approving. The user code is 96 random bits (may be embedded
in a QR code); it cannot poll/redeem. Approval expires after ten minutes and
redeems once with a separate 256-bit polling capability. API-key listing and
revocation never reveal bearer keys. The multi-user schema is in core [29,31];
invite/role management remains outside this lane.

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
five-minute database expiry. Only `unlock-session` identity and `wraps` reads
are allowed; ordinary `session`, WebSocket upgrade and all other authenticated
actions deny pending authority. After local AES-GCM unwrap succeeds, the browser
calls `unlock-finish` to activate the cookie and begin the normal sliding expiry.
The server receives a completion signal, never the DEK. It cannot independently
observe the browser's AES-GCM failure; instead abandonment or failed cleanup
never grants terminal authority, and expired pending rows are deleted on the
auth path. Failed unwrap attempts logout and surfaces failure. Exact-Origin
logout bypasses both admission layers, so public request exhaustion cannot
prevent revocation. Idle live sockets wake on committed logout/recovery and
terminate on their actual expiry deadline without idle polling.

Before owner enrollment, each restart rotates the token and replaces a stale
private setup-token.sock. The token remains only in process memory and the
private CLI socket; runtime logs do not disclose it. Enrollment consumes it once.
