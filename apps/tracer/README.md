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
token from `infraternal server setup-token`, register a passkey, and save the
recovery words before finishing setup. Otherwise, choose **Continue with passkey**.
No account UUID or device name is required. The browser supplies a device label.

Sign-in discovers the resident credential and verifies its signed user handle.
After authentication, a second local passkey prompt evaluates the credential's
stored PRF input to unlock its account key. Existing envelopes retain their
legacy input; new registrations use a per-user input. A failed unwrap logs out.
Prompt cancellation, invalid setup input and server failure have separate guidance.

The optional `host` query parameter selects a lowercase UUID host, for example
`?host=00000000-0000-4000-8000-000000000001`.

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
390 × 844. No visual-quality approval or physical-iPhone result is claimed.

Local host: Linux 6.12.111, x86_64, 8 vCPUs on Intel i9-9900K at 3.60 GHz.
Thirty fresh browser surfaces per state confirm painted pixels by screenshot.
The post-capture timestamp includes screenshot overhead: setup p50 124.4 ms,
p99 171.9 ms; sign-in p50 174.6 ms, p99 376 ms. The final three-test run
measured setup p99 217.1 ms and sign-in p99 169.5 ms. This is a local upper bound
with routed status and a test-double session endpoint, not a phone/network claim.
Zero access-screen polling is added; the terminal remains deferred until sign-in.
Production `main.js` is 49,465 bytes, deferred terminal chunk 662,827 bytes.

The existing 500-key probe painted 500/500 echoes: p50 15.0 ms, p99 16.4 ms,
resume 75.0 ms. Earlier concurrent-build runs exceeded its unchanged 20 ms gate
(25.7–39.1 ms); the successful run remains in
`../../target/passkey-job/browser-foreground.log`. Access/error measurements are
`access-render.log` and `errors-green.log` in that directory. These values do not
prove the pinned perf-VM or physical-phone budgets in decision 41.

Self-review checked Origin/cookie requests, missing/invalid status rejection,
no guessed access form during server failure, resident identity without local
UUID storage, PRF stripping and zeroization, logout after unwrap failure, shared
UI styles, 16px mobile inputs and explicit screenshots without secret captures.
