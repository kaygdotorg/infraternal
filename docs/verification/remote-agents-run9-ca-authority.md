<!-- Verification evidence for the real administrator CA authority and HTTP decoder, D168/#78; no key/proof bodies. -->

Shipping status: the authority, HTTP decoder and real CLI regression are committed.
Runtime activation remains pending the ARM budget decision; the configured CLI
proof passes with that recorded patch, not the unmodified shipping runtime.
Phase 1 is incomplete. Copy provisioning, role rewrap, administrator notification
delivery and remaining lifecycle/host-chaos work are still outstanding.

Authority source473c2fb7 and permanent security tests70878389 each pass the full
requested Nix fast gate. Seven real ES256/SQLite/private-encrypted-copy regressions
cover actual cold unlock, single-use/no-extra-session, fresh proof from a stale tap,
revoked role/session, changed generation, expired session, credential deletion,
wrong wrapping key, absent UV, ordinary-login purpose refusal and preservation of
the rightful ceremony after a foreign-browser attempt.

Release diagnostic:100 actual unlocks at1000 SQLite administrator records and1000
private encrypted-copy files; one measured registered credential. Eight cores on
infraternal-dev, CPUWeight10000, load16.06/23.01/22.58, no own compiler/browser overlap
during sampling. Start wall p50/p99 0.648250/4.911657ms; finish wall1.842820/9.246756ms.
Process CPU1.906580/3.109636ms includes independent clock spawn/pipe coordination;
not isolated crypto CPU. RSS16376→16524KiB (+148KiB).999 idle encrypted copy/public
metadata files total481600bytes. HTTP/client signing/initial publication excluded.
The owned fixture cleans up on Drop. This is not a1000-connected-host measurement
or acceptance of configured shipping CLI startup. Existing connection/renewal
measurements are recorded separately.

The first diagnostic compile rejected unsafe direct clock access under existing
unsafe_code=forbid; it was replaced by the existing renewal diagnostic method.
A missing Command import was corrected. No lint or test budget weakened.

HTTP preview:3 real signed-proof/private-copy tests pass2.16s and workspace all-target
Clippy passes12.92s. Exact Origin and secure cookie required; successful response
contains only lock status/no Set-Cookie; static empty400 for malformed scoped key
or unknown fields;32769byte body413. An initial test misexpected403 for malformed
cookie; existing cookie parser returns401. A separate valid-shaped unknown-cookie
case verifies403. Production HTTP/CLI wiring, initial provisioning, role rewrap
and notification delivery remain outstanding at this evidence revision.

Committed HTTP boundary: source98a22b5e, three real HTTP regressions6d3bc708,
and actual unlock decoder fuzz target8f3d37e9. ASAN completed2,528,103 executions
in61s, peak508MiB, zero artifacts. Public-only seeds cover body32768/32769,
ceremony128/129, duplicate/unknown fields, array widths31/32/33 and invalid bytes.

The configured normal release CLI regression is committed atd14a7713. It uses a
physical SQLite database, a real signed registered ES256 passkey, private GCM
administrator copy and pinned peer-name TLS. Original runtime failed on CA status
404 in2.99s. Saved runtime wiring passes in3.04s: valid enrollment refused while
cold-locked, actual passkey unwrap unlocks enrollment, restart cold-locks again.
The test requires exclusive4701/7443 and INFRATERNAL_REMOTE_TEST_BINARY; it is run
explicitly rather than starting listeners in the ordinary parallel test suite.
Its setup uses a fixture wrapping key; it does not prove browser DEK derivation,
first-copy provisioning, role-change rewrapping or notification delivery.

The runtime wiring remains uncommitted pending the ARM budget decision. Shipping
size before/after is18,109,456/18,238,192 bytes x86 and16,141,104/16,251,744 ARM.
ARM's unchanged limit16,196,376 is exceeded by55,368 bytes. Matched ARM crate text
measurements total11,312,992/11,400,800 (+87,808): Axum+33,620, server+19,144,
Tokio+11,092, std+10,796, openssl_sys+52; rustls305,048 and ring131,212 unchanged.
No dependency or provider was added for runtime activation. Three dispatch
experiments did not meet the limit and were reverted. ARM is fixed ET_EXEC with
no dynamic section: applying the existing x86 RELR option does not change size.
Only a read-only strict-pinned o1 probe was made; nothing was installed remotely.
No baseline change, push, deployment or perf-VM access occurred.

A single-final-query authority experiment passed all real regressions but added
272 ARM bytes. Six alternating old/new release runs at1000 records/private copies
(100 unlocks each), eight cores, load38.5–45.8, measured median per-run finish CPU
p50/p99 2.558305/3.839477ms before and1.355632/2.485580ms after; wall
2.574675/13.840041ms before and1.278374/9.200146ms after. One after-run CPU p99
was4.572980ms. Shared-load variability and absence of a size reduction did not
justify retaining this performance change; it was reverted. Measurements include
clock coordination and exclude HTTP/client signing/setup as in the first probe.

Header/admission self-review fixa317a56d: malformed unlock input without an allowed
Origin failed first with400 instead of403 (0PASS/1FAIL0.90s); four real HTTP cases
pass3.90s after moving cheap Origin/cookie and bounded admission before decoding.
Full requested fast gate passes with unchanged18,109,456/16,141,104 static sizes.
The actual unlock decoder is unchanged, so its existing ASAN campaign applies.

Current dev01a6d848 merged cleanly at031c8552, with a full green fast gate.
Merged tracer production build and TypeScript check pass. Real rootless two-process
remote enrollment/session/three-browser-writer proof passes7.16s at sourcea317a56d,
no own compiler overlap while sampling. Join-to-terminal428998us; native wire
keystroke44721us;352 output bytes, lost0/duplicated0. Chromium production renderer
25-key samples: desktop p50/p99 23.50/49.00ms, iPhone15 viewport23.30/49.60ms.
Enter-to-glyph one-shot measurements440.114/180.019ms include polling/coordination.
Machine infraternal-dev8cores, load10.09/18.69/21.30. These are direct local values,
not300ms RTT, a physical iPhone, or proof of the20ms UI budget. Native remote
mTLS validation remains enabled; Chromium accepts only the fixture's test TLS
certificate through the existing harness. No HTTP/WebSocket test double is used
in this proof; mock=1 enables inspection hooks. Browser authority stays on private
stdin and the captures contain only synthetic shell markers.

Production captures for owner review (no author visual-quality judgment):
[desktop](remote-agents/run9-merged-production/desktop.png),
[phone viewport](remote-agents/run9-merged-production/iphone.png).
The 325-case production browser suite ran separately on TRACER_TEST_PORT=4701
with a dedicated output directory; its result is recorded below.

Merged production browser result:325 tests,281PASS/18FAIL/26skipped,51.1min,
CPUWeight10000/TRACER_TEST_PORT4701; no own compiler overlap. Tracer/UI/protocol
TypeScript and the browser latency/mock harness inputs are byte-identical to
merged dev01a6d848. The full result is red, not accepted as a green browser gate.
The18 failed cases were repeated alone under the same scope/port against actual
dev01a6d848 and sourcea317a56d: dev6PASS/12FAIL7.5min; head5PASS/13FAIL7.4min.
Twelve persistent failures reproduce in both: wizard material blur; four DPR3
level3/4 ink/paper ghost checks; motion audit; four sign-in image baselines;
terminal/probe; access first paint. Five full-run failures pass in both isolated
runs: view flight, toolbar focus, Maple Mono DPR1 cursor, onboarding, session
scene sequencing. Mesh access differed (devPASS/headFAIL), then reversed in a
single-case recheck (headPASS6.7s/devFAIL), demonstrating an inconsistent outcome.
No expectation, deadline, image baseline or performance threshold was weakened.
These current-dev comparisons do not claim that the same18 cases exist atac03b19;
the earlier exact Rust expired-handshake comparison onac03b19 is separate.

Useful full-run samples: resize median/p95/max0.70/1.00/1.00ms; DPR2 10MB stream
9.77MB/s, p95 frame16.7ms and redraw5.5ms at load22–23/8cores; droplet average/max
0.094/0.20ms;50MB output2.81/2.85MB/s prediction off/on;50 theme switches JS p99
1.10ms/no long task above50ms. These individual numbers do not cancel failed
budgets. Returning sign-in usability n10 p50/p99 3930.70/4051.20ms (<5000), while
the combined terminal scenario fails later. Isolated setup-screen first paint
upper-bound p99 dev1821.30/head1662.50ms exceeds its1000ms budget at configured
RTT300ms. Phone captures are Chromium viewports, not physical Safari evidence.

Authentication screenshots mask setup capabilities and recovery words through
the existing harness; raw authentication DOM error snapshots were removed.
Temporary baseline worktree/output directories are removed after comparison.
The current verification note/contract/captures are gated as a separate docs
commit; source/header fix and dev merge each already passed their own fast gate.

First documentation fast run was red in the untouched scheduler-canary fixture:
legacy500ms CPU ticks2→3, rather than unchanged, at load12.99/13.64/10.14 on8cores.
Exact head test under CPUWeight10000 passes3.11s (two scheduled slices/2.500s).
The same Rust test on exact devac03b19 under the same scope and required Nix/Zig
shell also passes; wrapper, Python fixture and observer are byte-identical.
Initial baseline attempts lacked Zig, then Nix in the scratch login PATH; those
are build-environment failures, not test comparisons. Absolute Nix/Cargo paths
provide the required environment. No timing/assertion/observer change was made;
the full requested gate is retried before committing this documentation.

The second documentation fast run passed the scheduler canary but failed the
untouched expired-handshake socket assertion at socket_tests.rs:151. Load was
13.46/10.48/10.86 when inspected, not a test-launch measurement. The exact head
case under the required Nix shell and CPUWeight10000 passes in0.72s; the earlier
exact ac03b19 comparison also passes (6.09s). No source, assertion or threshold
was changed. A full gate is retried with its default test concurrency.

Default-concurrency fast is also red: concurrent legacy fixture creation hits
the existing process-global two-slot Argon admission (Throttled at auth/tests.rs:
3094). Both existing auth tests and CA fixtures fail there, before CA authority
execution. The production semaphore remains unchanged. The full gate returns
to RUST_TEST_THREADS=1, as in the preceding green per-step gates.
