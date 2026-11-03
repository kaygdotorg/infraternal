# Browser performance budgets

These checks run on `infraternal-perf-01-backup01` through its installed
`perf-run`. They are excluded from the functional Playwright suite (#314).
Build the tracer on a development VM with `INFRATERNAL_CLUSTERS_PREVIEW=1`,
then copy the checkout, dependencies and `apps/tracer/dist/` to the perf VM.
The perf configuration only serves the copied artifact; it never builds it.

From `apps/tracer` on the perf VM, with the existing Bun/Node/Playwright
runtimes on PATH:

```sh
perf-run --out "$HOME/.cache/codex-scratch/browser-budgets/evidence" -- \
  bun x playwright test -c playwright.perf.config.ts
```

The moved thresholds remain unchanged:

- terminal: returning sign-in p99 ≤ 5000 ms, predicted paint p99 ≤ 17 ms,
  resume p99 within the original RTT-derived budget, access render upper
  bound < 1000 ms;
- renderer: prediction-on median 50 MB throughput ≥ 95% of prediction-off;
- frame incident: injected 200 ms stall has worst interval > 190 ms, attributed
  script > 150 ms and heartbeat lateness > 100 ms;
- frame meter: mean/p99 < 50 µs, self time < 0.05 ms, layout overhead ≤ 3,
  style overhead ≤ ceil(control × 1.05) + 3;
- backspace prediction: every measured input cost < 2 ms;
- synchronized output: input send ≤ 16 ms while output is held. This check uses
  the direct fixture backend: its 150 ms paint hold must not expire while a
  300 ms fixture control/observation request is in flight.

The functional suite retains the corresponding access, input, resume,
renderer-canary and incident-recording checks without asserting elapsed speed.

The terminal scenario and paired throughput samples use the default 300 ms
proxy profile. The access first-paint check uses the direct backend (0 ms
injected latency): its existing 1000 ms budget measures local rendering,
including the compositor screenshot, rather than repeated asset round trips.
