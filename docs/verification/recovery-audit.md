<!-- Recovery audit fixes, browser-only derivation, legacy exception and reviewer evidence for #45. -->
# Recovery audit verification

This slice continues `mobile-recovery` from `18d5035`, using the audit on
[#45](https://git.kayg.org/kayg/infraternal/issues/45), comment 30593. D113 is the
owner's same-account recovery decision; D151 is the browser-only recovery
requirement in this job. DECISIONS.md is unchanged. The additive contract is
[contracts/keywrap.md](../../contracts/keywrap.md). Earlier evidence and the
superseded page-loss limitation are in [mobile-recovery.md](mobile-recovery.md).

## Behavior and migration

Recovery creation evaluates the same-account, unlocked, unexpired session in
its SQLite insert statement, after verification and under the writer lock.
Verification cannot preserve authority that expired while it ran. Every verifier
start/resume retains the stored ready time, including after bearer expiry;
only the bearer is reissued. Cancellation or successful replacement removes
pending state. Reloading asks for the words again and shows the server's remaining
duration, using monotonic browser time and foreground resynchronization.

Signed-in devices receive account-scoped snapshots on the existing socket Event
frame, plus session repair state. They show a toast and persistent Cancel recovery
notice. Start, cancel and complete audit rows commit with their state changes;
resuming and repeated cancellation do not invent extra lifecycle events. The
notification path has no idle polling timer. Startup reuses the already-fetched
authenticated snapshot rather than adding a session round trip.

The browser generates words and derives independent authentication/wrapping HKDF
outputs. Normal enrollment and recovery send only the authentication secret,
which the server hashes with the existing bounded Argon2id implementation. Native
WebCrypto wraps the original DEK locally. Metadata separately versions verifier
and envelope derivation, so upgrading an old verifier never relabels ciphertext.
There is no dependency or engine addition.

An existing mnemonic PHC cannot authenticate the HKDF output without the words
or a different proof protocol. The approved compatibility exception is explicit:
select **Upgrade an older recovery key** after entering the key. Its disclosure
note says the old words reach the server once to upgrade authentication. The
browser probes the verifier first, including retries after a lost successful
response. Capacity exhaustion is generic 429, not a credential-denial 401; neither
429 nor service failure triggers phrase migration. The transaction admits one
upgrade, preserving the old envelope and original recovery deadline. Replacement
then creates local rotated words and a v2 envelope. The contract threat note
explains that preserved DEKs cannot erase knowledge retained by an old server.
Fresh v2 protocol disclosure contains no material that unwraps the DEK.

## Evidence

Unedited logs, exact-snapshot gate results and machine metadata are in
`target/recovery-fixes/`. The issue holds the final SHA and verbatim gate output;
`atomic-gates/results.jsonl` records each immutable commit verification. Gate
completion is determined by that evidence, not this prose.

Failing tests preceded fixes:

- `audit-red.log`: the three server audit failures; `transport-red.log`: the
  original phrase transmission. `f1-green.log`, `f2-green.log`, `f3-green.log`
  retain the corresponding focused server evidence.
- `skew-red.log` / `skew-green.log`: browser time +7 days incorrectly enabled
  Continue during a 3600-second wait; the three related browser checks pass.
- `migration-retry-red-2.log` / `migration-retry-green.log`: selected older-key
  mode must first probe an already-upgraded verifier without resending words.
- `capacity-red.log` / `capacity-green.log`: the actual two-slot semaphore must
  report retryable admission, not legacy credential failure.
- `identity-work-red.log` / `identity-work-green.log`: real SQLite acquisition
  counts were 1 versus 2 for known/unknown identities; both now use one indexed
  owner/candidate lookup and real Argon2 verification, with generic denial.
- `startup-read-red.log` / `startup-read-green.log`: failure of an unnecessary
  second identity read blocked startup; the terminal now mounts from the first
  authenticated snapshot. Two production checks pass, with one read.

The production recovery subset passes checksum/errors, immediate and delayed
original-DEK rewrap, failed finish retry, reload, persistent cancellation notice,
clock skew and transport privacy. The native gate exercises four real Chromium
WebAuthn/PRF auth scenarios and two recovery scenarios against Rust/SQLite. Both
recovery paths retain the original DEK, consume their capability and sign in with
the replacement passkey. Browser traces and arbitrary failure screenshots are off.

The real socket capacity test reports **16/16** signed-in devices receiving start
and cancel, and **0** events to a separately authenticated account, in **0.64 s**
(`socket-capacity-green.log`). Audit evidence includes the exact lifecycle sequence
`start, cancel, start, complete`; old tokens and cancelled ceremonies fail closed.

28 production screenshots at **393×852** and **1440×900** are attached on #45 and
listed in `screenshot-attachments.json`: immediate/delayed recovery steps, pending
notice/toast and explicit legacy warning. Word captures use public deterministic
fixtures only. They are attached for owner review; this job does not judge visual
quality. A physical iPhone/PWA and Safari passkey check remains device review.

## Measurements and limits

Machine: Linux 6.12.111, i9-9900K, 8 cores, 31 GiB RAM, Rust 1.99.0, Bun 1.4.2,
Chromium 149.0.7827.55. Load and UTC times accompany every diagnostic.

Same-toolchain production build against `18d5035`, gzip level 9 per JavaScript file:
main.js **28326 → 28761 bytes (+435)**; all JavaScript, including lazy chunks and
workers, **243840 → 245354 bytes (+1514)**. Raw JS **805662 → 810339 bytes**.
Evidence: `bundle-size.json`. No extra authenticated startup read or permanent
notification polling was added.

The existing legacy baseline at **50 live session rows**, **30 samples/path**,
had p50/p99 **19532/25056 us** without a cookie and **20327/25663 us** with one
(`scale-base.log`). The final verifier diagnostic also uses 50 live rows and
30 samples for each of delayed start, live start and ready resumption. Its loaded
paired repeats report p99 **76680–93602**, **85072–92263** and **77669–95712 us**,
respectively (`scale-final-paired.log`). The same-binary legacy control is noisy
as well. Process CPU including fixture setup is **25.10–26.85 ms/request** for
verifier runs and **25.14–32.45 ms/request** for the legacy control. These are
shared-host diagnostics, not a performance-regression or pinned-budget claim.
Earlier overloaded repeats and failed local latency gates are retained, not hidden.

Verifier-process RSS at 50 rows is about **51 MiB**, including the runtime, SQLite
and Argon2 allocations. Additional fixed notification fields are measured from
the actual types: **33 bytes/socket × 16 account cap = 528 bytes**, or
**× 256 global cap = 8448 bytes**, plus one shared watch channel. These fixed
fields exclude async-frame alignment, channel allocation and transient JSON;
they are not allocator-inclusive RSS. Argon2 remains capped at two jobs with
19456 KiB per invocation, as in the existing contract.

Native browser local derivation, 10 warmups and 100 samples: old entropy parsing
p50/p99 **400/1000 us**, v2 authentication + wrapping derivation **400/1400 us**.
`browser-kdf.json` and `browser-machine.json` record concurrent load. No timer runs
on signed-in idle devices except the finite toast; the waiting flow alone updates
its remaining-time display. D41/D81 certification on the pinned perf VM is outside
this worktree-only job; local measurements and emulation do not certify that VM
or a physical phone.

## Author reviewer checklist

- B1 / authority: exact verified hash and version are rechecked under the writer
  lock. SQLite checks cookie/account/unlock/expiry when granting the waiver.
  Resume preserves ready even after expiry; token changes invalidate old ceremonies.
  Cancellation and replacement recheck authority, and audit/notification ordering
  follows commit. Expiry and revocation race regressions precede fixes.
- S1 / admission: exact Origin, 32 KiB bodies, existing browser/CLI/source limits,
  generic denial and two Argon2 slots remain. Canonical secret validation precedes
  identity lookup. Known/unknown identities use one indexed read plus real bounded
  KDF work. Exhausted capacity cannot signal an older-key fallback.
- S2 / secrets: words, wrapping output, DEK and PRF stay local in normal v2 flows.
  Independent HKDF info strings match the contract and independent test derivation.
  Stored wrap version controls unwrap; original-DEK checks use native PRF/HKDF/GCM.
  PRF is stripped from proofs; byte buffers clear in finally blocks. Legacy phrase
  admission is explicit, version-gated and non-automatic on retryable failures.
  No request/response bodies, secrets or prices are logged or committed.
- N1 / UI/lifecycle: existing cards, capsules, word controls, ticks and count-up are
  reused. Account-scoped socket snapshots and foreground repair have a generation
  guard against stale HTTP responses. Toast, waiting timer, observer and foreground
  listener are cleaned up. Reload and clock skew cannot invent readiness.
- P1 / review boundary: module docs and invariants are present, licenses/dependencies
  are unchanged, and protocol framing uses its existing direct/stream fuzz targets
  and deterministic cross-runtime corpus. No wire grammar or hand-written byte
  parser is introduced. Owner screenshot/device review and independent security
  review follow this slice; nothing is pushed, merged or deployed.

## Reproduction

```sh
nix shell nixpkgs#binutils nixpkgs#file nixpkgs#gnumake nixpkgs#perl nixpkgs#zig_0_15 -c scripts/verify fast
TRACER_TEST_PORT=4651 nix shell nixpkgs#binutils nixpkgs#file nixpkgs#gnumake nixpkgs#perl nixpkgs#zig_0_15 -c scripts/verify-auth-browser
cd apps/tracer
TRACER_TEST_PORT=4651 bun x playwright test
```

The opt-in release tests `recovery_verifier_latency_at_capacity`,
`recovery_session_delay_latency_at_capacity` and
`recovery_notification_state_at_socket_capacity` reproduce scale diagnostics.
Use `--ignored --nocapture --test-threads=1`, record load, and do not overlap this
job's compilation with their measurement. Gate snapshots refresh changed input
mtimes; changing checkout paths also requires clearing the server package cache
so Cargo cannot reuse a test binary from another source tree.
