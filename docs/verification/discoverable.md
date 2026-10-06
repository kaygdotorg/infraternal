<!-- Discoverable auth, real restart/browser evidence and scale measurements for #19/#21 [5,23,24,26,40,86]. -->
# Usernameless passkey sign-in and restart setup

Server lane: `t-server`, base `6fa27a3`. Client lane: `t-web`, base `1b4c907`,
final client `639ac27`. No push, merge or deploy was performed. Each logical
contract/dependency/schema/module/test/docs step has its own gated commit.
`docs/PROCESS.md` and `packages/ui` are absent in these checkouts; the supplied
Definition of Done and existing tracer styles were used. Screenshot quality
and physical iPhone review remain external, not self-approved.

## Contract and security choices

- POST `status` returns exactly `{setup_required: bool}` with no-store, exact
  Origin enforcement and existing admission limits. The indexed owner lookup
  reveals no identity, credential list or device information.
- Omitted `user_id` starts webauthn-rs discoverable authentication with an empty
  allowCredentials list and required UV. Conditional mediation is removed for
  a normal button-triggered prompt. Missing or malformed 16-byte UUID handles
  fail closed. The handle only selects a candidate: credential ownership and
  signature are checked against the same exact user/credential under SQLite's
  writer lock before a session is issued. Latest nonzero counters are monotonic;
  legitimate synced zero counters keep their previous policy. Pending state
  expires and is consumed before validation, including failed requests.
- Identified login is retained for existing defensive tests. Credential and PRF
  input are read in one SQL snapshot, avoiding a second query and inconsistent
  input/allow-list snapshots. Mixed legacy/new inputs use evalByCredential only
  with the identified nonempty allow-list.
- New credentials use per-user v2 PRF input; migration 0005 retains legacy NULL
  as the v1 derivation. Authenticated envelopes disclose their stored input.
  A subsequent local credential-specific get derives the wrapping key. Public
  evalByCredential enumeration and empty-list evalByCredential were rejected.
  This adds a second local prompt. PRF output and plaintext DEKs never reach
  the server; failed unwrap logs out. The legacy ciphertext regression unwraps
  the original DEK after migration. Envelope HKDF/AAD/AES-GCM remain v1.
- Every ownerless runtime startup replaces the setup hash and serves its fresh
  capability through the private same-user CLI socket. Older and spent tokens
  fail; an owner prevents new minting. Plaintext token files/logs and secret-
  valued assertions/traces were rejected. The socket stays 0600 in a 0700
  directory. Runtime replacement already removed a stale pathname; integration
  now verifies that path alongside token rotation and actual signed setup.

## Tests and red evidence

`target/passkey-job/restart-red.log`: original bootstrap failed `restart must
issue a fresh setup capability` (0 passed, 1 failed). `prf-red.log`: two distinct
users received the same global input (0 passed, 1 failed). `discoverable-red.log`
and `status-red.log`: omitted-ID login and public status returned 400 instead
of 200 before their HTTP adapter changes.

The fast gate includes software-authenticator ownership/handle/counter/replay
and exact public-status tests, migration/legacy DEK preservation, plus the
file-SQLite runtime/socket restart test. That unit integration recreates the
router and socket; it is supplemented by the actual OS-process test below.
Existing malformed proof, UV/origin/challenge/signature, concurrent authority,
recovery and session defenses remain green. Production protocol parsers were
not changed; their existing fuzz targets and Rust/TypeScript differential tests
remain in place.

`native-browser-final.log`: four real Chromium 149.0.7827.55 scenarios against
SQLite and the actual Rust router. Resident setup, empty-list selection,
authenticated PRF evaluation and native HKDF/AES-GCM preserve the DEK. Missing
PRF/residence/UV abort before owner creation; tampered origin is rejected. The
browser refuses non-UV discoverable selection, so the hostile-client check adds
its known credential allow-list to obtain a real non-UV assertion; the server
still rejects it using its original stored UV policy.

`paired-final.log`: the production client dist from t-web runs against the real
Rust router over private IPC. It completes owner setup/recovery acknowledgement,
clears cookies/localStorage, signs in with a resident PRF credential and unwraps
the DEK. Terminal sockets are closed locally because this fixture covers auth.

`process-restart.log`: the actual CLI binary runs behind an explicit loopback
proxy configuration with the pinned HTTPS RP. SIGKILL leaves the old socket;
the next real process replaces it, and `server setup-token` reads a fresh token.
The old token fails, the production browser completes setup and resident login,
and the spent token fails. A third process startup preserves the owner and
mints no capability. Only fixture process groups and private worktree data are
removed. No dev service or deploy is left running; no secrets enter argv/files
or diagnostic logs. Browser capabilities travel through private stdin/IPC.

## Release measurements at scale

Linux 6.12.111 x86_64; 8 vCPUs on Intel i9-9900K at 3.60 GHz. Rust 1.99.0,
release optimization, one owner with two enrolled ES256 passkeys, SQLite memory.
Recorded load averages: 6.36 / 8.48 / 6.06; this is a local run after compilation,
not the pinned perf VM. Evidence: `target/passkey-job/scale-latency.log`.
Nearest-rank percentiles, n=200 in each row:

| Server operation | Pending count | p50 | p99 |
| --- | ---: | ---: | ---: |
| Identified challenge | 0→200 | 32 us | 77 us |
| Identified challenge | 824→1024 | 35 us | 101 us |
| Discoverable challenge | 0→200 | 3 us | 6 us |
| Discoverable challenge | 824→1024 | 3 us | 4 us |
| Signed discoverable finish | 1024 before each finish | 222 us | 3323 us |

Admission rejects entry 1025. Local proposed auth targets (challenge p99 <1 ms,
finish p99 <10 ms) pass. Finish excludes authenticator signing, browser prompts,
network and disk latency, and includes actual ES256 verification, latest counter
checking, SQLite transaction and session insertion. These figures do not prove
phone first paint or terminal echo/reconnect budgets from decision 41.

Inline Login payload is 112 bytes × 1024 = 114688 bytes, excluding hash-table
controls, ID buffers and private verifier allocations. Whole-process RSS is
12688 KiB before the first phase, reaches 14032 KiB at full identified capacity,
and is 14036 KiB during discovery. The allocator reuses retained identified
storage, so unchanged discovery RSS does not mean zero allocation or an exact
isolated memory cost. No access-screen polling or background pruning timer was
added; pruning occurs on request. Browser render/probe evidence and explicit
390×844 preference screenshots are documented in the client README. Its inherited
CSS is dark-only; no new light-theme or physical-phone approval is claimed.

## Reproduction and self-review

```sh
nix shell nixpkgs#binutils nixpkgs#file nixpkgs#gnumake nixpkgs#perl -c scripts/verify fast
nix shell nixpkgs#gnumake nixpkgs#perl -c scripts/verify browser
# Build apps/tracer/dist in the client worktree before the paired checks.
bun scripts/browser-auth/check-tracer.mjs ../t-web/apps/tracer/dist
nix shell nixpkgs#gnumake nixpkgs#perl -c cargo build --locked -p infraternal
bun scripts/browser-auth/check-restart.mjs ../t-web/apps/tracer/dist
nix shell nixpkgs#gnumake nixpkgs#perl -c cargo test --locked --release -p infraternal-server discoverable_latency_at_pending_capacity -- --ignored --nocapture
```

Self-review checked B1/S1/S2/N1 from `docs/verification/auth.md`: transaction
rechecks and latest counters, Origin/cookie/admission boundaries, native browser
proofs and legacy envelopes, and module invariants. Only the existing approved
webauthn-rs/OpenSSL engine is used [86]; no new dependency or foundational engine
was selected. Binary static/no-PT_INTERP and AGPL/advisory gates pass for both
architectures. Fast logs are `target/passkey-job/*-fast.log`; final full output
is posted verbatim on #19 and #21 with lane heads. Physical iPhone/perf-VM and
independent visual/security review are still external checks.
