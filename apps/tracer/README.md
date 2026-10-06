<!-- Role: build, run, and browser-test guide for the minimal S1 web client. -->
# Tracer

The tracer is a static TypeScript client with one full-viewport terminal. It uses
the shared protocol codec and builds into `dist/` for the server's `--web-root`.

## Build

From this directory, install the locked dependencies and run the strict type
check and production build:

```sh
bun install --frozen-lockfile
bun run check
bun run build
```

Serve `dist/` from the infraternal server. The public `status` action chooses the
screen before session lookup. When setup is required, enter the current one-time
token from `infraternal server setup-token`, choose a username and display name,
create a passkey, and save the recovery words before opening the terminal.
Otherwise, choose **Continue with passkey**. No account UUID or device name is
required; the browser supplies a device label.

Sign-in discovers the resident credential and verifies its signed user handle.
After authentication, a second local passkey prompt evaluates the credential's
stored PRF input to unlock its account key. Existing envelopes retain their
legacy input; new registrations use a per-user input. A failed unwrap logs out.
Prompt cancellation, invalid setup input and server failure have separate guidance.

The optional `host` query parameter selects a lowercase UUID host, for example
`?host=00000000-0000-4000-8000-000000000001`.

## Renderer source pin (#36)

The tracer loads the MIT `ghostty-web` source build pinned to the crash fix in
upstream #180. `RENDERER-VERIFICATION.md` records the exact source and Ghostty
SHAs, reproducible build and checksums, deferred bundle-size delta, Chromium
crash corpus, scrollback/RSS measurements for one and eight sessions, and the
matched 500-key latency comparison with 0.4.0. The renderer remains dynamically
loaded after sign-in.

## Onboarding and account identity (#32)

First enrollment is a four-step flow: setup token, username and display name,
passkey, then the 24-word recovery key. The server's `registration-finish`
request is held until the owner confirms they stored the recovery words. The
session response carries the username and display name. The username is checked
as lowercase ASCII `[a-z0-9_-]{2,32}` by both the client and server; the server
enforces uniqueness and limits display names to 64 Unicode characters.

Returning owners use one primary **Continue with passkey** action with a
discoverable credential. First enrollment shows the centred glitch welcome for
2.6 seconds. The faulty-terminal canvas runs behind auth, then fades and releases
its WebGL context when the terminal takes over. Short waits show no counter; waits
past 400 ms count actual elapsed time. The account key still follows the existing
resident-credential and PRF flow described above.

`packages/ui` is the shared AGPL-3.0-only package for spring, tick, glitch,
count-up, copy feedback, warm tooltips and the faulty-terminal canvas. Its source
modules hold the motion timings and lifecycle rules. The tracer preloads Geist
Mono, waits for `document.fonts.load()` (with the mockup's 800 ms fallback), and
uses `font-display: block` so auth text does not swap from a fallback face.

The production-browser `onboarding.spec.ts` saves dark screenshots for token,
identity, passkey, recovery, welcome and returning sign-in at 393 × 852 and
1440 × 900. It checks the welcome block within 1 px of viewport center, checks
that step transitions add no non-input layout shifts and preserve the reserved
card height, exercises the 400 ms counter threshold and recovery copy/download
tick swap (including a rejected clipboard write), and confirms the canvas is
removed after sign-in. The test uses generated recovery words from the local
test double; do not use it with a real account.

The full browser run passed four tests with one worker because the specs share
one mutable test-double process. On Linux 6.12.111 x86_64 (8 vCPUs; load average
3.56/1.94/1.99 immediately after the run), 30 fresh production surfaces measured
first-contentful-paint setup p50/p99 66.8/279.5 ms and sign-in 66.2/93.7 ms.
The screenshot upper bounds were 151.1/367.2 ms for setup and 123/162 ms for
sign-in; the existing gate requires each p99 to stay below 1,000 ms. Against
the 639ac27 baseline, FCP medians rose by 9.7 ms and 10.2 ms; setup's p99 was
191.7 ms higher. Screenshot time includes capture overhead, and this local run
does not model a phone, network or concurrent users. The existing 500-key
terminal probe measured p50/p99 15.1/16.7 ms and resume 79.5 ms.

Area self-review checklist: status chooses setup or sign-in; enrollment sends
identity labels and waits for recovery acknowledgement; username/display limits
are enforced; resident login and PRF unwrap are unchanged; no recovery phrase is
written to logs or tracked files; icon-only controls have labels/tooltips; fonts
and count-up timing follow the approved module contracts; phone/desktop screenshots
and layout checks are attached to #32. The real Rust router browser check runs
from the server lane against this production `dist/`.

## Latency probe

Append `?probe=1` to show the opt-in probe panel. It defaults to 500 synthetic
keys; `n` may set a count from 1 through 5,000, such as `?probe=1&n=500`. The
probe waits until the terminal is connected and output has been quiet, then
types ASCII keys without pressing Enter. It sends the next key only after the
previous echo reaches Ghostty's render callback, so latency values do not
include a synthetic burst queue. The 100 ms quiet period only enables the probe
after existing output settles; it is outside each sample. The report shows
painted echo count, p50/p95/p99 keydown-to-paint latency, and browser-side hop
timings. **Drop socket** forces a disconnect and records the time until a
marker echo paints after resume. **Copy results** works on a phone or falls back
to selectable report text when clipboard access is unavailable.

## Browser test

```sh
bun run test
```

Playwright builds the production bundle, starts `test/mock-server.ts` on
`localhost:4173`, and uses a virtual authenticator. The server is explicitly a
test double: its passkey endpoints accept test ceremonies and do not verify
WebAuthn signatures. Do not use it as an authentication server. The browser
test sends 500 sequential probe keys, checks for p99 below 20 ms, and saves
terminal and probe screenshots plus the per-key browser/double attribution
under `test-results/`. Playwright disables renderer backgrounding by default so
headless rAF scheduling reflects an active terminal surface. Set
`TRACER_CHROMIUM_FLAGS` to override launch flags when comparing browser
scheduling modes.

## Usernameless sign-in evidence (#21)

Strict TypeScript, the production build and the full repository fast gate pass.
Playwright uses a CTAP2.1 resident, UV, PRF virtual authenticator with cookies
and localStorage cleared before sign-in. It verifies status-first selection,
absence of account/device inputs, cancelled prompt, bad token and server failure.
The test double validates the credential/user-handle association; actual Rust
signature/counter verification is covered by the server lane's software and
real-browser router tests. No arbitrary browser traces/failure screens are saved.

Production screenshots for external review are in
`test-results/terminal-first-run-passkey-29742-esume-and-the-latency-probe/`:
`setup-light.png`, `setup-dark.png`, `signin-light.png`, `signin-dark.png` at
390 × 844 under light and dark system preferences. The inherited tracer CSS is
dark-only, so these are preference captures rather than separate implemented
themes. No visual-quality approval or physical-iPhone result is claimed.

Local host: Linux 6.12.111, x86_64, 8 vCPUs on Intel i9-9900K at 3.60 GHz.
Thirty fresh browser surfaces per state confirm painted pixels by screenshot.
The post-capture timestamp includes screenshot overhead: setup p50 124.4 ms,
p99 171.9 ms; sign-in p50 174.6 ms, p99 376 ms. The final three-test run
measured setup p99 217.1 ms and sign-in p99 169.5 ms. This is a local upper bound
with routed status and a test-double session endpoint, not a phone/network claim.
Zero access-screen polling is added; the terminal remains deferred until sign-in.
Production `main.js` is 49,589 bytes, deferred terminal chunk 662,827 bytes.

The existing 500-key probe painted 500/500 echoes: p50 15.0 ms, p99 16.4 ms,
resume 75.0 ms. Earlier concurrent-build runs exceeded its unchanged 20 ms gate
(25.7–39.1 ms); the successful run remains in
`../../target/passkey-job/browser-foreground.log`. Access/error measurements are
`access-render.log` and `errors-green.log` in that directory. These values do not
prove the pinned perf-VM or physical-phone budgets in decision 41.

Self-review checked Origin/cookie requests, missing/invalid status rejection,
no guessed access form during server failure, resident identity without local
UUID storage, PRF stripping and zeroization, logout after unwrap failure, the
shared UI package, 16px mobile inputs and explicit screenshots without real secret captures.

The server lane also runs `scripts/browser-auth/check-tracer.mjs` against this
production dist directory and the actual Rust router over private IPC. It passes
resident setup, recovery acknowledgement, empty-storage discoverable login and
DEK unwrap on Chromium 149.0.7827.55; terminal sockets are closed locally because
that fixture verifies authentication only. Evidence is the server worktree's
`target/passkey-job/paired-browser.log`.

`check-restart.mjs` in the server lane also SIGKILLs the actual server, retrieves
the newly minted token through the actual CLI, and runs this production browser
flow against its HTTP router. Older and spent tokens fail; a third startup
retains the owner and exposes no new capability. Evidence: the server worktree's
`target/passkey-job/process-restart.log`.
