<!-- Mobile terminal gestures, D113 recovery, reproduction and reviewer evidence for #44 and #45. -->
# Mobile terminal and recovery verification

Branch `mobile-recovery` starts at `56bb6f5`. The D113 authority is the owner's
comment on [#45](https://git.kayg.org/kayg/infraternal/issues/45); DECISIONS.md
is unchanged. The current task explicitly requires the tray to stay put, overriding
D82's older tray hiding behavior for this slice (recorded on #44).

The PWA document is fixed. Terminal touch uses the existing Ghostty renderer's
`scrollLines`, fractional carry and time-based momentum; pinch changes its font,
and horizontal swipes pan an overflowing canvas. Gesture callbacks stop on edges,
cancellation, hidden documents and disposal. There is no new renderer or dependency.

Sign-in has a quiet recovery button. A signed-in browser can also open recovery
from the account palette without first discarding its live cookie. Entry checks
all 24 English BIP-39 words and their checksum, including numbered whole-key paste.
The shared card, stepper, ticks, count-up, word controls and pane motion follow
onboarding. The server supplies the exact ready time. The browser unwraps the old
recovery envelope before registration and wraps the original DEK for the new
passkey and rotated recovery key; it never persists recovery words or capabilities.
The change to auth.ts exports existing helpers/types only, in its own commit,
leaving binary-handling functions for the parallel fix-prf job.

## Evidence

`target/playwright-final.log`: **29 passed (3.4m)** against the production build,
port 4551, Chromium with the iPhone 15 touch profile for terminal gestures.
The 500-key probe reports p99 **16.10 ms** against the existing 20 ms assertion.
The touch result is verbatim:

```text
MOBILE_SCROLL rows=368 drag=16 momentum=40 font=13->24 pan=90 document=0 controls=fixed
```

`target/native-browser.log`: the existing four real-authenticator scenarios and
two new recovery scenarios pass on Chromium 149.0.7827.55. Native PRF,
HKDF-SHA256/AES-GCM and the real Rust verifier/SQLite run through private IPC.
Both immediate and delayed recovery preserve the DEK, consume the capability and
allow login with the replacement passkey. The 24-hour elapse hook belongs only to
the browser test example, not the production router. Registration uses another
virtual authenticator because excludeCredentials correctly rejects the old one.

Failing checks preceded the fixes: matching live recovery returned 86400 instead
of 0; terminal gestures did not move its viewport; sign-in lacked recovery entry;
recovery pane motion had a 0 px delta; a rejected finish could reach welcome;
and the first terminal interaction retained onboarding listeners (3 page errors).
The retained tests cover wrong-account, pending and expired cookies, revocation
while Argon2 runs, active requests that cannot be accelerated, authoritative delay,
invalid words, failed registration/finish retries, original-DEK wraps, pane glide,
44 px steady touch targets and listener cleanup. Red/green logs remain in target.

### Measurements and their limits

Same-toolchain production build comparison against `56bb6f5`: main.js gzip
27911 → 28328 bytes (+417); all JavaScript files gzip 238995 → 243842 bytes
(+4847). Raw totals are 793205 → 805662 bytes. All-file totals include lazy
terminal/recovery chunks and workers, not the first-paint download.
Evidence: `target/evidence/bundle-size.json`, Bun 1.4.2 minification and gzip
level 9 per file. Recovery loads on demand and reuses the already-present BIP-39
and envelope code rather than introducing a second authentication implementation.

The optimized recovery-start diagnostic uses 50 live database session rows and
30 samples per path. With no matching cookie: p50 17436 us, p99 22332 us;
with the matching cookie: p50 17548 us, p99 20062 us
(`target/recovery-scale.log`). This measures Argon2 plus SQLite-memory request
creation, not network or device authentication. No per-session state was added;
50 sessions use 50 existing session rows, and one recovery row per account.

Machine: Linux x86_64, KVM, i9-9900K, 8 cores at 3.60 GHz, 31 GiB RAM.
Three loaded repeats and machine/load metadata are retained in
`target/recovery-scale-repeat.log` and `target/evidence/recovery-scale-machine.json`.
Repeat load averages increased from 6.36/6.24/7.08 to 8.63/6.73/7.23 while other
atomic-gate compilation and tests overlapped. These noisy local samples establish
no regression claim. Full-browser completion load is recorded separately in
`target/evidence/browser-machine.json`. The pinned perf-VM budget run remains
review work; this job's authorization does not extend to modifying that host.

## Review checklist

- B1 / transaction authority: expensive word verification stays outside the
  writer lock. The exact verified hash and same-account unlocked unexpired session
  are rechecked together under that lock. The revocation race test pauses at the
  verification/write boundary. Active requests retain their original deadline.
- S1 / HTTP admission: origin, body bounds and existing rate partitions are
  preserved. Exactly one of legacy user_id and additive username is accepted.
  Unknown usernames use bounded word verification and generic denial. An invalid
  optional cookie cannot grant authority or suppress the 24-hour path.
- S2 / cryptography: existing engines and envelope helpers are reused. Native
  browser tests exercise PRF and the real verifier. PRF outputs are stripped from
  finish proofs; DEK/entropy/PRF byte buffers are cleared in finally blocks.
  Recovery-start emits no cookie, preserving the reviewed concurrent-cookie rule.
- N1 / lifecycle and UI: every new module documents its role and non-obvious
  authority/momentum invariants. Shared UI is reused. Observers, timers and touch
  listeners stop when their flow is disposed. Geometry, motion, idle rendering and
  reduced motion have browser evidence; screenshots require owner review.

### Remaining product and device limits

The following page-loss limitation describes the original `18d5035` slice and
is superseded by the [recovery audit fixes](recovery-audit.md) on #45. Modern
recovery now resumes at the original server deadline and uses browser-only words,
with an explicitly selected one-time migration for older keys.

The original frozen contract rejects a second start while recovery is active. The request
and words remain in memory, so reloading/closing the waiting page loses the
capability; restarting does not reset or accelerate the deadline. The UI says to
keep the page open and start denial points to the recovery page already open.
A resumable recovery endpoint preserving that deadline needs an additive contract
and owner decision; it is proposed on #45 rather than invented by this slice.
A physical iPhone/PWA and Safari passkey check, independent security review,
owner screenshot review and pinned perf-VM budget certification remain required.

## Reproduction

```sh
nix shell nixpkgs#binutils nixpkgs#file nixpkgs#gnumake nixpkgs#perl nixpkgs#zig_0_15 -c scripts/verify fast
TRACER_TEST_PORT=4551 scripts/verify-auth-browser
cd apps/tracer
TRACER_TEST_PORT=4551 bun x playwright test
```

The native gate also needs the native build drivers available from the same Nix
shell. No browser trace or automatic failure screenshots capture secrets.
Explicit recovery screenshots contain public deterministic fixture words only.
Per-commit complete gates/checks/builds and elapsed times are recorded in
`target/atomic-gates/results.jsonl` and `*-fast.log` / `*-app.log`.
The final issue comments supply the final head, unedited gate output attachments
and three-line owner testing notes. Nothing is pushed, merged or deployed.

## Atomic implementation history

| Commit | Logical change |
| --- | --- |
| `7c9fa51` | Specify same-device recovery authorization (D113) |
| `a50cb50` | Route terminal touch gestures through Ghostty scrollback (#44) |
| `710ed9a` | Keep mobile document scroll fixed and wire terminal gestures (#44) |
| `ec66748` | Keep the mobile key tray visible during scrollback (#44) |
| `b42795b` | Waive recovery delay only for a matching live session (D113) |
| `96965fe` | Expose authoritative recovery readiness and username lookup (D113) |
| `ece609f` | Prove recovery session isolation, races and unchanged delays (D113) |
| `4c691ae` | Reuse onboarding recovery-word acknowledgement controls (#45) |
| `0bc902e` | Share existing browser ceremony helpers with recovery (#45) |
| `c64de57` | Recover passkeys by rewrapping the original browser DEK (D113) |
| `0b43b4a` | Open the onboarding-style recovery flow from sign-in and live devices (#45) |
| `3e99342` | Verify recovery crypto and both delays in native Chromium (D113) |
| `63f2460` | Regress iPhone touch scrolling, momentum, pinch and horizontal pan (#44) |
| `7f02473` | Exercise recovery steps and finish rejection with production UI screenshots (#45) |
| `595ae06` | Match recovery pane fitting to onboarding motion (#45) |
| `697587b` | Give recovery actions full mobile touch targets (D80) |
| `de4179b` | Explain recovery start denials and existing-device passkeys (#45) |
| `3b1cde5` | Release onboarding listeners before terminal interaction (#45) |

## Production screenshots for owner review

- [mobile-before.png](https://git.kayg.org/attachments/ba16445e-5c26-4780-bce8-884766d734d7)
- [mobile-after.png](https://git.kayg.org/attachments/36bdc44c-7770-476b-ab99-be7328a0dea0)
- [recovery-immediate-create-passkey-1440x900.png](https://git.kayg.org/attachments/7724e0f2-9061-4b58-acfd-8e2011abad23)
- [recovery-immediate-create-passkey-393x852.png](https://git.kayg.org/attachments/724f6721-45b2-4bb6-aa98-3992be87aed4)
- [recovery-immediate-enter-words-empty-1440x900.png](https://git.kayg.org/attachments/bf75bc48-b31a-44a4-97cb-5ed7e0145f89)
- [recovery-immediate-enter-words-empty-393x852.png](https://git.kayg.org/attachments/d23ed248-fa95-428e-80d0-9b7d1176cf42)
- [recovery-immediate-enter-words-public-fixture-1440x900.png](https://git.kayg.org/attachments/b9ae9968-b937-4266-8ba4-4efdf22c423e)
- [recovery-immediate-enter-words-public-fixture-393x852.png](https://git.kayg.org/attachments/ac87e45f-cf7d-4748-b336-735ef7ae2c88)
- [recovery-immediate-ready-now-1440x900.png](https://git.kayg.org/attachments/fba681d3-4dec-49f4-b7d4-9b1f1b328889)
- [recovery-immediate-ready-now-393x852.png](https://git.kayg.org/attachments/8e20f765-d4fb-4ea7-aa42-635a08126179)
- [recovery-immediate-save-rotated-public-fixture-1440x900.png](https://git.kayg.org/attachments/315f69cb-7def-488f-b556-517207c41697)
- [recovery-immediate-save-rotated-public-fixture-393x852.png](https://git.kayg.org/attachments/a8f49767-18fb-4eac-90a4-aa5a6056e768)
- [recovery-immediate-welcome-1440x900.png](https://git.kayg.org/attachments/4c6f4e02-d63f-41d1-8fa7-4f8428aed403)
- [recovery-immediate-welcome-393x852.png](https://git.kayg.org/attachments/a5bb927c-6af1-48f6-a546-59841fca9b44)
- [recovery-delayed-create-passkey-1440x900.png](https://git.kayg.org/attachments/d0ef189b-653b-4383-8d78-60947af2b7ca)
- [recovery-delayed-create-passkey-393x852.png](https://git.kayg.org/attachments/a681edfd-aba0-4d18-aac7-5ad4409c634e)
- [recovery-delayed-enter-words-empty-1440x900.png](https://git.kayg.org/attachments/cd8c773d-91f6-4fca-8f8e-1edd245322ac)
- [recovery-delayed-enter-words-empty-393x852.png](https://git.kayg.org/attachments/2ca7c3eb-f5b6-4346-8af2-c37c9bc01637)
- [recovery-delayed-enter-words-public-fixture-1440x900.png](https://git.kayg.org/attachments/b6ad36eb-32eb-4d52-ac35-e7919b7c8fe8)
- [recovery-delayed-enter-words-public-fixture-393x852.png](https://git.kayg.org/attachments/04e72adb-4513-4131-906a-ad1b6e6db37f)
- [recovery-delayed-save-rotated-public-fixture-1440x900.png](https://git.kayg.org/attachments/8481fe16-7c0b-429e-80c0-b951e582a1a8)
- [recovery-delayed-save-rotated-public-fixture-393x852.png](https://git.kayg.org/attachments/45ffeb62-5e9f-4812-b4a8-d9ee790b3548)
- [recovery-delayed-wait-24h-1440x900.png](https://git.kayg.org/attachments/92e3be0d-1743-4dee-9ffd-c7975ed18320)
- [recovery-delayed-wait-24h-393x852.png](https://git.kayg.org/attachments/0d18938f-b80b-42f8-ae7c-76fbfddc23a7)
- [recovery-delayed-welcome-1440x900.png](https://git.kayg.org/attachments/7c7473fc-e607-48f7-97ae-34fcd42086bf)
- [recovery-delayed-welcome-393x852.png](https://git.kayg.org/attachments/1ba22ccb-e2c4-46ea-a66c-de5dcc821f23)
