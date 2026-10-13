<!-- Compression and explicit-credit attach evidence and reviewer handoff for #66 part 1. -->
# Sign-in speed phase A, part 1

This lane starts from dev `444b839e45f06ef754c784903fa998e16ac9ada7`.
Auth code and routes are outside its scope. The owner-approved phase A target
belongs to the combined #66 work, including part 2.

## Static delivery

The production build writes gzip level 9 and brotli quality 11 sidecars for
compressible text and WASM. Encodings that do not save bytes are omitted;
WOFF2, raster images, and archives remain identity. The existing tower-http
file service negotiates encodings; no compressor runs on HTTP requests.

Bun emits content-hashed `chunk-xxxxxxxx.js` files. Only those successful
non-HTML responses get `public, max-age=31536000, immutable`. Stable entrypoints,
workers, styles, fonts, index.html and SPA document fallbacks revalidate with
`no-cache`. Every static representation, including identity, varies on
`Accept-Encoding`; API/auth response policy is separate.

The fast gate builds the real tracer and caps the aggregate transfer of all
JavaScript, including the deferred inline Ghostty WASM, at 300 KiB gzip and
250 KiB brotli. Missing sidecars count as identity, so removing compression
cannot silently evade the transfer budget.

| Production bytes at this base | Identity | Gzip | Brotli |
|---|---:|---:|---:|
| Ghostty chunk | 681,295 | 197,537 | 159,604 |
| All JavaScript | 797,989 | 242,462 | 198,892 |

Across 16 simultaneous cold viewers the JS bodies total 12,767,824 bytes
identity, 3,879,392 gzip or 3,182,272 brotli. HTTP/TLS overhead, fonts, styles,
and cache effects are separate. No response compressor or per-session
compression buffer is added.

The final real Chromium cold response carries `Content-Encoding: br` and
159,604 encoded Ghostty body bytes (681,295 decoded); Resource Timing reports
159,904 bytes including its transfer overhead. The WOFF2 response remains
identity. Warm hashed Ghostty and browser-shim requests transfer zero bytes.

The pinned renderer tries a Vite Node-file shim before fetching its inline
WASM. That unresolved dynamic import previously requested SPA HTML. Correct
no-cache headers exposed a 402.9 ms warm-cache revalidation at 200 ms one-way.
A Bun build plugin resolves the optional Node loader to a throwing browser
module, preserving Ghostty's existing fetch fallback. It emits actual hashed
chunks, so returning browsers can reuse them without revalidation. Vendor
checksums and renderer choice remain unchanged. A real Bun build regression
test fails before this resolution and passes afterward. Aggregate gzip grows
149 bytes (2,384 bytes across 16 cold viewers), avoiding a serial RTT.

## Attach investigation

The browser sends AttachTerm then Credit without waiting for Ack. The server
starts the browser and embedded-relay credit counters at zero. The
infraternal agent's `Output::attach` incorrectly began with an implicit
1 MiB. If retained shim output arrived before the server forwarded Credit,
`embedded::process_incoming` rejected it as exceeding granted credit and
restarted the entire leg-B connection. The actor doubled its 200 ms backoff
to 400 ms. The eventual reattach restored retained credit and replayed output.
If Credit won the race, no restart occurred and the implicit grant instead
funded an extra MiB.

The real-PTY failing test observed Output (0x11) after Attach Ack without any
Credit. The debug browser method smoke at 200 ms one-way observed first Ack
at 8191.9 ms and first Output at 8631.8 ms: a 439.9 ms gap, with another Ack
immediately before Output. These are diagnostic samples, not acceptance
percentiles.

The fix starts the infraternal agent at zero and requires explicit Credit,
including after a reconnect. It preserves shim-owned accepted/written input
cursors, the sequenced-input fence, retained-ring-first replay, starvation
recovery and all binary layouts (wire contract §6; decisions 5, 13, 41, 81).
The same constant-size credit state is used; no additional per-session
allocation is introduced (zero additional bytes × 50 sessions).

HTTP TCP sockets already set TCP_NODELAY in runtime.rs; the TLS acceptor does
the same in pinned axum-server 0.8.0. Embedded leg B and shim sockets are Unix
sockets, so Nagle and delayed TCP ACK do not apply. Neither Ping nor a second
Credit is an attach prerequisite.

At 50 simultaneous real PTYs, all unfunded attachments remained silent for
350 ms while control stayed responsive. First funded Output p50/p99 was
12.403/15.906 ms. The infraternal agent RSS was 5,592 KiB; individual shims
were 5,996–6,004 KiB, totaling 300,056 KiB for 50. This local diagnostic ran
on x86_64, 8 available CPUs, load averages 13.41/10.61/12.38; it is not a
pinned perf-VM acceptance benchmark.

Real-engine regressions also check exact one-byte replay funding, retained
2,640,000-byte replay across 12 streams, stalled-terminal control isolation,
wrapped and less snapshots, starvation recovery and legacy replay parking.

## Reverse proxy boundary

A read-only request through the deployed Traefik endpoint returned
`Content-Length: 681268` for `/chunk-6hym6z0e.js` without Content-Encoding,
matching the existing deployment's identity build. No deploy was changed.
Direct monitor01 inspection is blocked: the hostname does not resolve here,
and SSH to `kayg@10.69.69.50` fails host-key verification. A verified connection
is needed to confirm configured header pass-through; the identity request
alone does not prove how a future compressed deployment will behave.

## Returning sign-in waterfall

The baseline uses frozen dev `444b839` and its identity web build. The final
run uses the fixed-credit release binary (source `45d8cb3`) and browser build
`5290a04`; its SHA-256 matches the final fast gate release executable:
`8a3ad16ae7d7922ad57044dab268be8e28487a7a8a5d0411ed1cc604c9724dc3`.
The harness records the checkout revision/dirty paths when it starts; the
final run began before the unchanged browser-build edits were committed.

Both runs use Chromium 149.0.7827.55 on Linux x86_64, an Intel i9-9900K with
8 available CPUs, real Rust/SQLite/PTYs and virtual resident PRF WebAuthn.
HTTP request-response delay is twice the named one-way delay, and each
WebSocket bridge direction delays application frames by that one-way value.
Throughput is unlimited: body-byte reductions are measured separately,
so these runs do not model a slow mobile download. Each group has ten runs,
one cold and nine warm; p50 and p99 use nearest rank, so p99 is the maximum.
Host loads differ and are retained with the traces. These are local diagnosis
and comparison, not controlled pinned-VM performance acceptance.

All values below are milliseconds, p50 / p99:

| One-way delay | Attach Ack → Output before | Final after | Attach → Output before | Final after |
|---|---:|---:|---:|---:|
| 0 ms | 405.5 / 456.1 | 1.3 / 4.9 | 424.7 / 484.9 | 3.6 / 11.0 |
| 100 ms | 414.7 / 448.1 | 1.3 / 2.9 | 616.0 / 656.9 | 202.5 / 208.5 |
| 200 ms | 413.4 / 535.8 | 1.7 / 2.6 | 815.5 / 955.1 | 403.0 / 407.6 |

| One-way delay | Click → paint before | Final after | Post-passkey → paint before | Final after |
|---|---:|---:|---:|---:|
| 0 ms | 888.5 / 1361.6 | 162.3 / 427.2 | 834.6 / 1270.8 | 144.5 / 411.1 |
| 100 ms | 2492.2 / 3775.6 | 1911.7 / 2761.0 | 2241.6 / 3556.4 | 1705.7 / 2553.5 |
| 200 ms | 4283.3 / 5788.3 | 3712.2 / 5329.6 | 3865.4 / 5379.5 | 3306.3 / 4922.4 |

The intermediate pre-shim run remains attached as `after-waterfall.json`.
At 200 ms, trial 4 reconnected between its first Attach and its successful
Attach, adding 707 ms before Ack. Aggregate Attach → Output p99 was 1115.8 ms,
while successful Attach → Output was 408.6 ms and Ack → Output 1.5 ms.
It also exposed the 402.9 ms missing-shim revalidation. The final harness
retains all connections and numeric close codes rather than hiding retries.
All 30 final runs produced Output without reconnecting.

Load averages are 1 / 5 / 15 minutes:

| Run | One-way delay | Before group | After group |
|---|---:|---:|---:|
| before | 0 ms | 12.96 / 15.48 / 15.26 | 17.12 / 16.97 / 15.91 |
| before | 100 ms | 17.12 / 16.97 / 15.91 | 18.98 / 16.61 / 15.88 |
| before | 200 ms | 18.98 / 16.61 / 15.88 | 12.94 / 14.88 / 15.30 |
| final | 0 ms | 4.27 / 4.81 / 7.00 | 1.57 / 3.30 / 6.02 |
| final | 100 ms | 1.57 / 3.30 / 6.02 | 1.71 / 2.53 / 5.20 |
| final | 200 ms | 1.71 / 2.53 / 5.20 | 2.53 / 2.46 / 4.54 |

## Validation and reviewer handoff

The prescribed fast gate uses:

```sh
nix shell nixpkgs#binutils nixpkgs#file nixpkgs#gnumake nixpkgs#perl nixpkgs#zig_0_15 -c scripts/verify fast
cd apps/tracer
TRACER_TEST_PORT=4641 bun x playwright test
```

The final production browser suite passed all 34 tests. Its 500-key probe
reported callback p99 15.0 ms, below its existing 20 ms threshold; local
setup/sign-in first-contentful-paint p99 was 302.4/114.2 ms. These browser
checks use the existing terminal test double, while the waterfall, replay
and 50-session diagnostics use real Rust and real PTYs. They do not replace
the pinned perf-VM gates in decisions 41 and 81.

The motion audit had two sampling failures unrelated to product behavior:
the idle blur endpoint settled at 1.99985 rather than exactly 2, and a CDP
round trip missed the checkbox draw's intermediate state. Separate test
commits apply the existing settling epsilon to the idle endpoint and observe
intermediate animation frames inside the page. Final endpoints and all
latency budgets remain enforced.

The author checked the applicable contract and review invariants:

- `contracts/wire.md` §6 credit remains additive, bounded and explicitly
  granted; no frame layout, parser or foundation dependency changes.
- Snapshot/ring replay, accepted/written offsets and the sequenced-input
  barrier remain covered by existing real-engine reconnect tests.
- Unfunded attachments cannot emit output; control and siblings continue
  while terminal credit is exhausted. No implicit MiB survives a reconnect.
- Compression happens only at build time; identity fallback, q-value
  negotiation, HEAD byte lengths, fonts and SPA document cache behavior are
  tested. A missing-sidecar probe correctly fails the transfer gate.
- Auth, onboarding and auth routes have an empty diff from the base.
  Vendor checksums, licenses and dependencies remain unchanged.
- Production screenshots are attached for independent visual review;
  this lane does not assess its own visual quality.

Reproduce the waterfall from the worktree root after the fast build:

```sh
TRACER_TEST_PORT=4641 bun scripts/browser-auth/measure-returning-signin.mjs
```

Keep `target` in the job's disk-backed scratch directory. The default records
ten runs per latency with a fresh real SQLite database and virtual PRF
passkey, one cold cache per group, and warm caches for the other nine.
Auth reads are paced below the existing limit. The harness records only
sanitized paths, sizes, timing marks and frame types; temporary enrollment
state and credentials are removed on exit. Binary, web-root and results
overrides are available through `SIGNIN_MEASURE_BINARY`,
`SIGNIN_MEASURE_WEB_ROOT` and `SIGNIN_MEASURE_RESULTS`.

The inherited harness left detached shims alive after removing their runtime.
A real one-run regression observed one newly retained shim before the fix and
zero afterward. Teardown now reuses socket-authenticated `agent_fixture.cleanup`
before unlinking the short rendezvous pathname; it also bounds server shutdown.
Run `python3 scripts/browser-auth/verify-waterfall-cleanup.py` after the release
build to check this independently. This teardown change follows measurements
and does not change the final waterfall timing tables.

Historical sanitized receipts and screenshots were removed under D262. Fresh output belongs at `$HOME/.cache/codex-scratch/tracer-<pid>/evidence/playwright/signin-speed-a1/`:
`before-waterfall`
and `final-waterfall` JSON/log pairs, the intermediate `after-waterfall`
pair, `final-fast.log`, `final-browser-2.log`, red/green attach and browser
build findings, and the real-PTY scale/reconnect logs. `attach-scale.py`
reproduces the 50-session diagnostic against a specified release binary.
The final waterfall's `final-waterfall-{0,100,200}ms.png` screenshots show the
real signed-in production terminal. The regular browser screenshot files
remain in the external Playwright scratch directories. Scratch
builds and temporary baseline copies are removed after evidence is retained.
