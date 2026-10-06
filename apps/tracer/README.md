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

Serve `dist/` from the infraternal server. On first use, choose **Set up the
first owner**, enter the server's one-time setup token, register a passkey, and
save the recovery words before finishing setup. Later visits use the account ID
and passkey login form.

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
