<!-- Recovery review corrections, reproducible evidence and owner-review handoff for #45. -->
# Recovery review corrections

Issue [#45](https://git.kayg.org/kayg/infraternal/issues/45) records the independent
review, rejected exception, failing probes and final commit gates. D113 preserves
the data key during recovery; D151 keeps recovery wrapping material in the browser;
D162 requires owner approval of a mockup before adding a replacement screen.
No decision or foundational dependency changed.

## Corrected behavior

R1: HTTP accepts only independent verifiers for recovery admission. The obsolete
phrase route and UI path are removed, including failure retries. A legacy account
reports `recovery_words_need_replacing` on its authenticated session response.
`rotateRecoveryWords` generates and wraps locally using the unlocked device's DEK;
its acknowledgement callback uploads only an envelope and verifier. The cookie
must remain fresh and unlocked at commit, and the account header must match the
local envelope's account. Dismissal revokes the callback. The transaction updates
both metadata versions, replaces only the recovery envelope, cancels old recovery
capabilities and retains existing passkeys and sessions. There is no new UI.

R2: the registration transaction obtains the SQLite writer before resampling the
live HTTP clock. Capability and ceremony deadlines are checked in the consuming
DELETE with SQLite statement time. Denial rolls back wraps, verifier, session and
audit changes. Admission time cannot authorize a later commit.

R3: the browser accepts integral remaining waits through the existing 48-hour
capability policy maximum. An honest 90,000-second remainder after server rollback
is accepted; malformed and excessive durations are denied. The original stored
server deadline and monotonic client countdown are retained.

## Reproduction and measurements

Use `TRACER_TEST_PORT=4746` for every browser invocation. Logs below are retained
under `target/`; the issue quotes final gate output verbatim.

The seven original server probes cover cancellation/completion races, restart and
concurrent resumption, HTTP expiry under writer contention, clock rollback,
HTTP denial/admission, concurrent legacy replacement and source-limit isolation.
The removed phrase-upgrade concurrency case is adapted to signed-in rotation;
it still requires one successful commit and denies reuse of old authority.
An eighth server probe checks ceremony expiry under contention.

- `r2-red.log`: reviewer HTTP + disk-WAL contention probe received 200 where 401
  was required. `r2-green.log`: capability and ceremony probes both pass (7.29s).
  `r2-ceremony-red.log` confirms the additional ceremony probe fails against the
  pre-fix authority check (200 instead of 401).
- `reviewer-browser-red.log`: both disclosure and rollback probes fail against
  the baseline. `reviewer-browser-green.log`: six focused production-browser
  checks pass; `phrase_disclosed=false`. The final rerun also passes all six
  checks in 8.9s (`reviewer-browser-final.log`).
- `r1-server-final.log`: five rotation tests pass (27.24s), using real WebAuthn,
  Argon2 and SQLite; the separate writer-contention probes use disk WAL.
  Old words are test-only
  legacy fixtures; production does not expose phrase admission.
- `native-auth-browser.log`: native Chromium 149.0.7827.55 passes four isolated
  passkey scenarios and two real-verifier recovery scenarios (same-account live
  session; absent session with enforced delay). Both retain the original DEK,
  consume the capability and sign in with the replacement passkey.
- `client-final-tests.log`: fifteen checks pass with 340 assertions. The earlier
  `r1-client-final.log` passes thirteen rotation and wait checks; crypto tests
  separately pass two tests and 312 assertions (`crypto-review.log`). Tests prove
  that the envelope retains the DEK and the authentication sibling cannot unwrap
  it, and that dismissed callbacks and cookie account switches fail closed.
- `recovery-browser.log`: 14 pass and one immediate-recovery timeout under shared
  host load. The single requested CPUWeight=10000 retry passes in 11.9s
  (`recovery-browser-immediate-retry.log`).

- `tracer-full.log`: 36/39 production-browser checks passed. The one scoped
  `--last-failed` retry passed onboarding and the renderer canary; terminal latency
  remained 33.6 ms p99 against its unchanged <20 ms budget (2/3 retry checks pass,
  `tracer-full-retry.log`). No unrelated timing test or threshold was changed.

The first R1 server fast run also exceeded existing connection deadlines under
load. Its expiry probe denied the `recovery-ready` setup with 401 before reaching
contention (expected setup 200); this is recorded separately from a replacement
failure. The single scoped retry uses `RUST_TEST_THREADS=1` to retain concurrency
inside individual probes without competing test cases. Logs are retained intact.

Session metadata uses the existing indexed session query. At 50 sessions, 1,000
samples after 200 warmups on disk SQLite WAL 3.53.3 measured p50 32.68 → 36.62 µs
and p99 75.75 → 78.43 µs. Added network round trips and idle queries: zero.
`session-scale.py` and `session-scale.json` contain the reproduction and results.
Machine: eight-core Intel i9-9900K KVM, shared load 23.80/27.89/26.20. This statement
diagnostic records the small added lookup cost; it does not certify the pinned
performance VM or physical iPhone budgets.

## Reviewer checklist and visual handoff

B1: state transitions, capability expiry, cancellation and rotation consumption
share their writer transaction. Disk contention tests assert denial and absence of
wrap/verifier/session/audit mutation. Concurrent replacements commit once.

S1: bounded typed request bodies reject phrase fields and the removed route.
Authentication precedes expensive rotation hashing; session and intended-account
authority are rechecked under the writer lock. Public status reveals no account
replacement state. No words, wrapping keys or DEKs enter production HTTP payloads.

S2: reuse existing HKDF, AES-GCM, Argon2 and WebAuthn engines. Independent-label
crypto tests verify separation, uniqueness and wrong-sibling rejection. Browser
wrapping clears temporary byte buffers; rotation retains the caller-owned DEK.

N1: no replacement screen, new UI primitive or idle poll was introduced. Existing
recovery UI removes phrase admission. Screenshots from a real production build use
public fixtures; visual quality and physical iPhone testing belong to owner review:
[phone entry](https://git.kayg.org/attachments/5aa1fbfd-9fe4-4d39-b44e-839911c94fab),
[desktop entry](https://git.kayg.org/attachments/9642811e-d138-41d3-a8b0-a3beba700d79),
[phone ready state](https://git.kayg.org/attachments/6bb8b107-47cd-4d74-b7fa-9198acfdf8a2).
The local originals are in `target/recovery-screenshots/`.

An independent AI reviewer reproduced two additional callback/account-binding
failures, then found no residual actionable issue after their failing tests and
fixes. Green automation does not replace the owner's screenshot and device review.
