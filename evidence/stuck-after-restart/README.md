<!-- Records confirmed restart faults, real-engine regressions, perf-VM evidence and author checks for #199. -->
# Restart continuity, #199

Base: `9ab4329c`, `origin/release-prod-live`. Branch: `stuck-after-restart`.
No production process, session, logs or owner fixtures were accessed. No deployment.

## Confirmed faults and repair

1. `connection.ts` expired its resume capability 120 seconds after **Welcome**. The server starts grace at disconnect/startup recovery. An overnight page therefore opened a fresh writer; `TerminalClient.restartCursors()` discarded its retained keystrokes and reset the screen. Grace now starts at the actual disconnect; unwelcomed retries never extend it.
2. Window cards initialized as live and inventory repaint classified every surviving shim as live. Neither proves that this window can type. Bindings now keep transient readiness; the existing card stays reconnecting until the validated replay fence reaches the painted cursor. Inventory retirement/refusal still overrides it. Confirmation clears only the routine catching-up text, preserving approximation and input-pressure warnings (D110). Sending AttachTerm or receiving the server's synthetic Ack is insufficient.
3. Ordinary reconnect backoff missed D259 at 72 sessions. Confirmed terminals now use jittered 5–10 ms checks for a bounded ten-second recovery window. A greeted refusal cancels that window; prolonged outages retain ordinary backoff. There is no extra work on an established idle connection. Writer rows are counted when AttachTerm is sent even if confirmation never arrives.
4. A page retained its old unlocked CA indicator across restart. Later Welcome events refresh the existing authority control independently of replay; the existing Settings/toast/inbox action handles unlock.

The embedded-host attach path does not consult the CA. Real tests prove that surviving local PTYs remain writable while it is locked. This does not change remote-host certificate admission or CA cold locking.

## Red and green evidence

- [overnight-before.log](overnight-before.log): controlled-clock mux regression fails (`false,false` instead of `false,true`). [overnight-after.log](overnight-after.log) and [final-unit.log](final-unit.log): passing expiry, retry, routing and retirement checks.
- [systemd-before11.log](systemd-before11.log): exact baseline binary, production browser, real passkey/CA/PTy, server-only systemd stop; the queued command never executes after restart.
- [green-dot-before.log](green-dot-before.log): the transport is disconnected but the window remains `data-status=live`.
- [systemd-head2.log](systemd-head2.log): both repaired cases pass with no page reload, real systemd `KillMode=process`, desktop 1440×900 and touch viewport 393×852. Commands are matched as complete output lines to distinguish execution from input echo.
- [browser-regressions.log](browser-regressions.log): wrapped-ring snapshot and locked input/canvas checks, 3 passed. [authority-browser.log](authority-browser.log): existing CA UI cases, 4 passed, desktop and phone.
- `commit-01-gate.log` through `commit-13-gate.log`: per-module formatting/type/test gates. `real-head-ts.log` checks the real fixtures explicitly because the ordinary tracer tsconfig excludes `real/`.

Production-build captures for independent visual review (the job does not judge visual quality):

- [desktop recovering](restart-locked-catching-up.png), [desktop ready](restart-locked-ready.png)
- [phone recovering](restart-unlock-catching-up.png), [phone ready](restart-unlock-ready.png)

## Pinned VM measurement

[perf-final2.log](perf-final2.log): `10.69.69.208`, `infraternal-perf-test`, 4 CPUs, 8,262,782,976 bytes physical memory, starting load `0.59 0.48 0.49`. 72 actual PTYs (one viewed, 71 idle), Chromium desktop and touch phone viewport, fixed 150 ms WebSocket RTT (75 ms each direction; no loss/jitter claim).

| Case | Path recovered → painted/typable | D259 bound | Last screen |
| --- | ---: | ---: | --- |
| Desktop, CA stays locked | 169.312 ms | 200 ms | Same bitmap retained |
| Phone, CA unlocked after cold restart | 163.537 ms | 200 ms | Same bitmap retained |

A cold restart is initially locked in both cases. The second case additionally unlocks through the shared real passkey action and verifies subsequent typing. The screen is never cleared during this resume path (restore cost zero); the next animation-frame observations were 8.5 / 11.8 ms. These are two scenario measurements, not a p99 claim or evidence for indefinite network outages.

The phone run measured 72 shims: mean RSS 4,152,945 bytes × 72 = 299,012,096 bytes (sum of per-process RSS, not unique physical memory); max 4,161,536. Embedded infraternal daemon RSS 5,496,832 bytes; server RSS 20,176,896 bytes. Native code is unchanged.

Earlier failed measurements are preserved: `perf-restart3.log` (219.776 ms), `perf-restart4.log` (204.756 ms). `perf-final.log` exposed measurement perturbation: a full GPU bitmap readback inside the recovery window delayed paint. Bitmap verification now runs while the backend is stopped, before its path recovers; the latency window has only scalar timestamp observations. The RTT+50 ms assertion is unchanged. `perf-driver.sh` mounts job-owned runtime/home/account fixtures privately and holds the original shared lock inode only for the experiment. Builds/install/copies happen outside that lock.

Build-host test durations and gate RTT diagnostics are functional-run output, not performance evidence.

## Static artifacts and gate

Exact x86 baseline build: [baseline-static.log](baseline-static.log), 20,333,104 bytes. Fixed artifact is byte-identical, SHA-256 `7dadb073fdcd4eb0f55ebd4364cfb103eec7cfcf348ffd042edacfcf01f15f48`.

| Target | Baseline/source-equivalent fixed artifact | Delta | Frozen ceiling |
| --- | ---: | ---: | ---: |
| x86_64 musl | 20,333,104 bytes | 0 | 16,404,816 bytes |
| aarch64 musl | 18,112,240 bytes | 0 | 13,817,816 bytes |

No Rust/build/dependency source changed from 9ab4329c. Both static artifacts exceed inherited ceilings; no allowance or decision was changed. [verify-fast-final.log](verify-fast-final.log): 740 native tests passed, 0 failed, 78 inherited configured ignores; fmt, VT fmt, clippy and cargo-deny pass; static builds fail only those caps. The first invocation's temporary pathname exceeded SUN_LEN; [short-path-rerun.log](short-path-rerun.log) passes with a short private TMPDIR, and the complete rerun uses that directory. The implementation/evidence head gate is retained as `verify-fast-head.log`; the final exact-head run is recorded verbatim on #199. The final warning-preservation check is covered by `warning-snapshot.log` and the additional 72-session `perf-head.log`.

## Author checklist and acceptance scope

- Frozen wire/auth/storage contracts retained; no foundational choice or dependency addition.
- Every readiness claim is bound to an ordered, session-validated replay event and painted cursor; unconfirmed streams cannot decrement another stream's ready count.
- Durable writer/input replay retained; transient readiness never enters a saved layout; retirement and per-window isolation remain covered.
- Existing shared window status and CA action reused (D160); no new UI component, styling, permanent poller or focus behavior. TASTE reviewed for implementation consistency; captures are provided for independent judgment.
- Real binary/PTy/systemd/SQLite/passkey cases and separate failing-before logs retained; budgets measured only on the pinned VM at 72 sessions.
- Secrets remain in fixture memory/private pipes; no credential lookup, host-key changes, production access, broad process termination or load generator.
- Atomic module/test commits, per-commit gates and #199 findings recorded; size increase zero; inherited cap failures stated explicitly.

The owner's original production tab remains untouched and unverified. This is a browser-side repair: an already loaded old bundle cannot acquire new behavior from a server binary swap alone. The same-page, no-reload guarantee is proven for a page running this fixed build. Production acceptance and independent review remain with the owner/orchestrator; this lane does not claim that the original persistent production stall was directly inspected or that every cause of it has been excluded.

Owner check after the fixed client is available: keep a terminal open, restart the server through its normal unit, type during and after the stop, leave the CA locked, then unlock and type again. Verify the same session and screen, reconnecting during the stop, and automatic restored typing without a reload during that restart.
