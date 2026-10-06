<!-- Browser encryption and auth adapter contract for decisions 23–29 and 53; issue #17. -->
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

All transport binary values use canonical unpadded base64url. Options include
`extensions.prf.eval.first = base64url(SHA256(UTF8("infraternal/keywrap/prf/v1")))`.
Decode this into a Uint8Array before WebAuthn. The browser performs WebAuthn's
specified PRF input transformation; do **not** prehash it again yourself.
Registration requests `residentKey: required`, `requireResidentKey: true`,
`userVerification: required`, `credProps: true`, and PRF. Login also requests
PRF and requires UV. Stop enrollment if `getClientExtensionResults().prf.enabled`
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
| setup-start | `{token,name}` | `{ceremony,user_id,options,recovery_words}` |
| registration-finish | `{ceremony,proof,passkey_wrap,recovery_wrap}` | secure session cookie |
| login-start | `{user_id}` | `{ceremony,options}` |
| login-finish | `{ceremony,proof,device}` | secure session cookie |
| session | `{}` | `{user_id,device,fresh}` and refreshed cookie |
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
setup token only if no owner exists, stores its hash, and calls the announcer
once with the clear banner. A lost/expired token is not silently regenerated.
A host integration must invoke bootstrap at startup with its log writer.
The setup token is consumed atomically only upon successful owner enrollment;
all parallel enrollments then fail. Exactly one owner is enforced in storage.

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
approval/polling actions. All actions in each partition count, including
cookie-authenticated reads; the aggregate ceiling is 180/minute. Device callers
cannot consume browser capacity. Throttling returns 429 and `Retry-After: 60`;
authentication failures remain 401. Wrong browser Origins are rejected before
spending browser capacity. Request bodies are bounded at 32 KiB.

The library never trusts `Forwarded` or `X-Forwarded-For`. The host must apply
per-source admission at its trusted ingress using the actual peer address, or
forwarded addresses only from explicitly configured proxy peers that strip
caller-supplied forwarding headers. Keep separate browser and device policies:
for example, at most 30 browser actions/minute/source and 10 device actions/
minute/source, beneath the global partitions. Enforce body limits and admission
before JSON parsing there. This policy is a deployment requirement; this library
cannot infer a trusted source from arbitrary HTTP headers or invent a proxy list.
