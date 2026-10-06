<!-- Auth review rework evidence and reproducible gates for decisions 5,7,20,23–29,40,53; #17. -->
# Auth verification after independent review

The old head remains reachable as `lane-auth-v1` (`a06368f538aa99e4e78caf4634e9f93e8db9b9eb`).
The lane was reconstructed locally on `s1-base` (`386acfd3dc6255c7f58f98b4f114d5d7326292ad`).
Nothing was pushed or deployed. Every new commit passes `scripts/verify fast`;
individual unedited logs are `target/auth-rework/commit-NN-fast.log`. The finish
comment on Forgejo #17 records the final head and unedited final gate output.

## Review dispositions

- B1: `auth/recovery.rs` verifies Argon2 off-thread, acquires the SQLite writer
  lock, then rechecks the exact verified recovery hash before inserting authority.
  `review_old_words_race_rotation` pauses at the actual verification/write boundary
  and commits a complete passkey replacement before resuming the old request.
  It proves denial, no recovery row, old-session revocation and new-word acceptance.
  The original review reproducer failed first: 0 passed, 1 failed in 2.02 s
  (`target/recovery-before.log`); the first fix passed in 1.96 s
  (`target/recovery-after.log`). The retained regression has no timing sleeps.
- B2: both musl gate rows now build a CLI that constructs `Auth` and the router.
  SQLite and the real verifier/crypto are linked, and initialization failure fails
  the executable check. Both binaries have no `PT_INTERP`.
- B3: dependencies, schema, security modules, HTTP/CLI integration, defensive
  tests, browser tooling and evidence have separate gated local commits.
- S1: invalid polling can spend only its 60 device slots/minute. The 120 browser
  slots remain available. All HTTP actions count, the aggregate cap is 180/minute,
  throttling is 429 with `Retry-After: 60`, and admission resets after 60 seconds.
  Tests check partition exhaustion/reset and do not trust spoofed forwarding
  headers. `contracts/keywrap.md` documents the required trusted-ingress per-source
  policy; the library cannot infer trusted proxies or peer IPs from headers.
- S2: real Chromium virtual resident/UV passkeys exercise actual option decoding,
  PRF support and fallback get, stripped finish proofs, native WebCrypto
  HKDF-SHA256/AES-256-GCM for both passkey and BIP-39 recovery envelopes, secure
  cookie login and unwrapping the same DEK. Unsupported PRF, missing residence
  and missing UV abort before creating an owner. Altered origin and a native
  browser assertion without UV fail server verification. Four isolated scenarios
  pass on Chromium 149.0.7827.55. This is not Safari evidence: no physical iPhone
  is available to this job. Safari/iPhone interoperability remains a required
  physical-device check when the product browser integration lands. There is no
  product UI in this lane, so screenshot quality review does not apply.
- N1: the facade is separate from `crypto.rs`, `setup.rs`, `webauthn.rs`,
  `sessions.rs`, `recovery.rs`, `devices.rs`, `wraps.rs` and `http.rs`. Transaction
  authority rechecks and writer-lock choices remain documented at their call sites.

## Crypto backend and cross-build choice

The exact pinned `webauthn-rs-core` 0.5.5 manifest declares unconditional
`openssl`/`openssl-sys`; `webauthn-rs` has no pure-Rust backend feature.
`default-features = false` disables attestation APIs, not the underlying C crypto.
The [1Password passkey documentation](https://docs.rs/passkey/latest/passkey/)
identifies its client/authenticator/types libraries; they do not implement the RP
verifier this server needs. A minimal verifier on RustCrypto/CBOR would newly own
attestation parsing, COSE key/curve/algorithm validation, origin/RP/challenge/UV
policy, backup flags, signature checks and counter semantics. Introducing that
unreviewed security surface into this rework was rejected in favor of retaining
the independently reviewed verifier. This choice adds C build tooling and binary
size; it does not change decision 7 or introduce dynamic libraries.

`scripts/auth-toolchain` downloads Zig 0.15.2 into `target/auth-tools/zig` and
verifies its SHA-256 before installation. Checksums are pinned for x86_64 and
aarch64 Linux build hosts from the [official Zig index](https://ziglang.org/download/index.json).
Target-qualified compiler/archiver wrappers in `.cargo/` use the bundled musl
sysroot for vendored OpenSSL and SQLite. CI installs make/perl/xz explicitly;
the documented Nix gate supplies missing native build drivers. OpenSSL/Rust
sources remain pinned by `Cargo.lock`; no advisory/license exceptions were added.

## Reproduction

```sh
nix shell nixpkgs#binutils nixpkgs#file -c scripts/verify fast
bun install --cwd scripts/browser-auth --frozen-lockfile
bun scripts/browser-auth/node_modules/playwright/cli.js install chromium
scripts/verify browser
nix shell nixpkgs#gnumake nixpkgs#perl -c cargo test --locked --release -p infraternal-server http_csrf_cookie_flags_body_limit_and_latency_evidence -- --nocapture
```

The browser fixture binds no port. Playwright intercepts the HTTPS test origin
and sends private IPC requests to the real Rust router backed by isolated memory
SQLite. Setup/recovery/PRF/DEK material stays in process/IPC memory, never diagnostic
logs, files or argv. Browser dependencies are AGPL-compatible MIT packages in a
separate AGPL-3.0-only test package and locked with `bun.lock`.

## Measurements

| Target | Before: scaffold only | After: auth-linked CLI | Whole-program delta |
| --- | ---: | ---: | ---: |
| x86_64-unknown-linux-musl | 705624 bytes | 9322720 bytes | +8617096 bytes |
| aarch64-unknown-linux-musl | 607880 bytes | 7809800 bytes | +7201920 bytes |

Both final binaries are stripped, statically linked and have no `PT_INTERP`.
The old binaries did not link auth; these deltas must not be described as isolated
library overhead. Evidence: `target/auth-rework/commit-10-fast.log` through
`commit-12-fast.log`; the final complete gate is `target/auth-rework/final-fast.log`.

Optimized SQLite-memory session lookup/slide, n=200: p50 **56 us**, p99 **137 us**.
Argon2id verification: **24 ms**, m=19456 KiB, t=2, p=1.
Evidence: `target/auth-rework/latency.log`, the release test named in reproduction.
These numbers exclude disk, network, browser, authenticator and phone latency.

The recovery-start transaction was measured against `lane-auth-v1` with matching
optimized standalone probe manifests on this host: three alternating runs,
50 recoveries/run, no other build active. Each iteration includes Argon2 and
SQLite, advances time by 48 hours to expire the previous request, and logs no
capability or recovery words. Probe source/manifests and unedited outputs remain
under `target/auth-rework/bench-{old,new}/` and `bench-{old,new}-{1,2,3}.log`.
Reproduce each run with:

```sh
nix shell nixpkgs#gnumake nixpkgs#perl -c env CARGO_TARGET_DIR=target cargo test --locked --release --manifest-path target/auth-rework/bench-old/Cargo.toml rework_recovery_start_latency -- --nocapture
nix shell nixpkgs#gnumake nixpkgs#perl -c env CARGO_TARGET_DIR=target cargo test --locked --release --manifest-path target/auth-rework/bench-new/Cargo.toml rework_recovery_start_latency -- --nocapture
```

| Run (50 samples each) | Old p50 / p95 | Corrected p50 / p95 |
| --- | --- | --- |
| 1 | 18978 / 20937 us | 19238 / 22360 us |
| 2 | 19085 / 21350 us | 19516 / 23321 us |
| 3 | 19919 / 22499 us | 19449 / 22038 us |

Median of the three per-run p50s: 19.085 ms before, 19.449 ms after (+0.364 ms,
1.9%). Median of the per-run p95s: 21.350 ms before, 22.360 ms after (+1.010 ms,
4.7%). One run is faster after the fix, so this is noisy single-host evidence,
not a statistical claim. The measured small cost is justified by eliminating
revoked-word identity takeover; the writer lock remains outside Argon2 so the
security fix does not hold the database writer across expensive verification.

## Atomic history and gate evidence

The following code/test slices each passed all five fast rows before committing.
The evidence-docs slice also runs the same gate. Full output is recorded in #17;
local logs are `target/auth-rework/commit-NN-fast.log` and `final-fast.log`.

| Slice | Commit | Auth tests in fast |
| --- | --- | ---: |
| 1. auth: specify browser key wrapping and admission (#17) | `3f7d8ee` | 0 |
| 2. build: pin a musl C toolchain for auth dependencies (#17) | `469d0e8` | 0 |
| 3. auth: add reviewed runtime dependencies and license policy (#17) | `7462cfc` | 0 |
| 4. auth: migrate identity and single-use capability storage (#17) | `21c2b6a` | 0 |
| 5. test: add authenticator and envelope verification dependencies (#17) | `5e24de4` | 0 |
| 6. auth: install owner enrollment and single-use ceremonies (#17) | `f019691` | 1 |
| 7. auth: verify login counters and sliding fresh sessions (#17) | `ecd302b` | 3 |
| 8. auth: isolate recovery authorization from hash rotation (#17) | `ea4cf43` | 4 |
| 9. auth: issue scoped device keys after fresh approval (#17) | `294effc` | 5 |
| 10. auth: mount bounded HTTP routes and link them into musl CLI (#17) | `afbe8e2` | 7 |
| 11. test: verify native browser passkeys PRF and key wrapping (#17) | `8f35170` | 7 |
| 12. test: broaden concurrent capability and recovery defenses (#17) | `bed1635` | 12 |

Final correctness coverage includes 12 passing Rust tests and four isolated real
Chromium scenarios. No secret captures or product screenshots are produced.
Server lifecycle/UI/action integration and the physical iPhone check remain
outside the functionality/evidence claimed by this auth library lane.
