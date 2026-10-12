<!-- Records the production add-host integration and its measured, unwaived gates for #169. -->
# Production add-host integration

Base: `b4ae9e22`. Approved upstream head: `b800019c`, merged by `6ec4aabd`. The four original commits are preserved. `64d4e213` and its size-baseline change are excluded. Integrated code head: `7bb2801e`; the final evidence commit changes only documentation, logs and screenshots. Nothing was deployed.

The daemon retains production uid, input-size and terminal-cell validation, plugin/resource admission and typed refusal. It adds optional private readiness. The shim retains ordinary ownership, output drain, exit deadlines and ended records. Readiness retires without ended records on completion or its absolute 10-second deadline. Polling selects the earliest deadline and retains immediate nonblocking post-exit draining. CLI D217 startup, signal handling and exit retention remain. The old fixed session cap was already on the old base and is superseded by production D214 resource admission.

Required session tests exposed an existing touch manager entry requiring the header button that touch deliberately omits. Separate module commits extend the existing manager with one fallback and retain terminal/no-access/team eligibility. The fixture commit checks visible buttons and uses the existing narrow-header overflow. No component, style, dependency or engine was added. Screenshots are attached for independent review; there is no author visual-quality or physical-iPhone claim.

Fresh static-binary readiness: four startup profiles at 1216.6–1308.7 ms; explicit cleanup 310.8 ms; abandoned cleanup 9893.3 ms; zero artifacts or active private scopes. Local infraternal-dev, i9-9900K, 12 logical CPUs, kernel 6.12.111, CPUWeight=10000, RTT 300 ms, load 68.31/51.06/50.78. These test the readiness boundary, not remote enrollment. See `readiness-static.log`. Failure storage is 120 inline bytes, 122,880 bytes per 1024 events and 1,966,080 bytes for 16 batches, excluding dynamic allocations (`failure-storage.log`).

Targeted clippy passes (`clippy.log`). Corrected native tests pass: agent 55/0/11 ignored; shim 64/0/13 ignored; SSH suites pass (`native-corrected.log`); server bootstrap 29/0/1 ignored (`remote-server-bootstrap.log`); setup 11/0 (`setup-corrected.log`). Normal ephemeral fixture paths avoid AF_UNIX path limits; build targets remain under HOME cache. Parallel setup refusals passed with serial execution. The unchanged workspace setup attach assertion failed once, passed isolated in 1.65 s, then passed in the full workspace rerun. No test assertion was weakened.

Tracer check and source tests pass: 150 tests, 10,921 assertions (`ui-head-check.log`, `ui-head-source.log`). Production build and transfer pass (`ui-head-build.log`, `ui-head-budget.log`): critical gzip 293,452/307,200 bytes and Brotli 243,939/256,000; deferred gzip 48,914/51,200 and Brotli 43,191/45,056; largest on-demand gzip 15,090/20,480 and Brotli 13,399/18,432. All 27 add-host wizard cases pass in `browser.log`. All 20 session cases pass in 4.1 minutes (`sessions-final.log`); the eligibility follow-up passes four focused cases (`eligibility-browser.log`).

The final remaining-browser replay is **3 passed / 5 failed** in 5.7 minutes (`browser-head-corrected.log`). Unwaived failures:

- Retired exit 7 and exit 0: attach count 3 versus expected 2.
- Theme: three tasks over 50 ms, despite switch p99 8.5 ms.
- Terminal: returning sign-in p99 5072.4/5000 ms; predicted glyph 22.9/17 ms.
- Access-screen upper bound, 30 samples at 300 ms RTT: setup 3036.0/1000 ms; sign-in 2194.2/1000 ms.

This replay ran locally alongside the final native gate; observed load was 15.73/19.94/27.50. An earlier quiet replay was 5 passed / 3 failed (`browser-remaining.log`), including saved-status attach count 4/3 and reconnect 1002.2/900 ms. This variation does not establish baseline causality or justify a load waiver. Release readiness remains blocked by these browser failures.

Module preload, stylesheet packing, exact-product fixture and compressed-asset experiments retained the original assertions, RTT and sample counts. First paint remained red, including compressed setup 1727.5 ms and sign-in 1762.3 ms. **All experimental source changes were reverted.** Their logs are diagnostic evidence only. `browser-head.log` is an incomplete, superseded start. Initial running-script editing invalidated its shell read offset; that job alone was stopped and its corrected run retained. No remote host was reached.

Reproduce browser replay with `TRACER_TEST_PORT=4935 bun x playwright test test/dead-session.spec.ts test/terminal-theme.spec.ts test/terminal.spec.ts` under `systemd-run --user --scope -p CPUWeight=10000`. Session file: `test/sessions-canvas.spec.ts`. Full gate: `scripts/verify fast`, normal fixture TMPDIR, `RUST_TEST_THREADS=1`, build target under HOME cache. The `final-gate.sh` helper records exact local settings. GNU gates reuse this job's own locked OpenSSL 3.6.3 archives (`native-archive-checksums.txt`); RUSTC_WRAPPER and the musl build remain unchanged. Temporary targets and test state are removed after retaining evidence.

`fast-final.log` is the earlier completed full gate. `fast-head.log` is the final rerun on the integrated code. Static x86 is 20,093,776 bytes, stripped PIE without PT_INTERP, versus the unchanged 16,404,816-byte maximum. ARM is not reached after this failure. No restart-test stalls or waivers occurred. No browser waiver or size-baseline update.

Final `scripts/verify fast` output (verbatim):

```text
+---------------------------+--------------+
| Rust gate                 | Result       |
+---------------------------+--------------+
| fmt                       | PASS         |
| VT native fmt             | PASS         |
| clippy                    | PASS         |
| test                      | PASS         |
| cargo-deny                | PASS         |
| static builds             | FAIL (1)     |
+---------------------------+--------------+
```
