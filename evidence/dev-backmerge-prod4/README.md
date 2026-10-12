<!-- Records production backmerge integration and unwaived verification for #169. -->
# Production backmerge

Dev base `d93056ef6f0e16e47b50583cfb781ee15bf09850`; production parent `61bdbd9f7fe034f5d9261aea8b480d01d626d3ba`. Only `dev-backmerge-prod4` is in scope; no deployment or update to dev/main. Production ancestry includes add-host round one, terminal fidelity, ended sessions and the touch session manager. Later add-host rounds are excluded.

The seven expected conflicts preserve dev's asynchronous plugin admission, generated CLI actions, signed architecture payload resolution and CA handoff, alongside production readiness and classified diagnostics. Capability invalidation and shim census use separate watches. The control decoder now retains the exact plugin notice kinds; `plugin-notice-before.log` fails before the repair and `plugin-notice-after.log` passes afterward.

Dev and production independently assigned migration version 20. The production exit-index SQL is moved unchanged to 22. Startup transactionally retags only the exact successful shipped checksum, then ordinary SQLx migration validation applies. Dev 20/21 remain unchanged. Tests cover fresh/dev/production histories, owner data, idempotence, dirty/unknown ledgers, occupied 22 and concurrent/interrupted retagging. Proper before evidence is `migrations-before.log`; `migrations-invalid-fixture.log` used an invalid owner fixture and is not proof. Normalization uses the one compiled migrator and its checksum, with no additional runtime hashing.

Independent read-only review caught an accidental reset of production reconnect backoff after greeting. A paused-clock test exercises the real embedded actor and fails before removing that reset (`backoff-before.log`). Virtual-clock scheduling checks are functional policy tests, not performance measurements. The review verdict is in `independent-review.txt`.

The existing daemon oracle's functional mode initially sampled CPU/RSS despite promising to omit performance checks. Those samples now run only in performance mode; thresholds remain unchanged. Functional mode retains all 24 abrupt-stop data, acknowledgement, exit and restart assertions. One unchanged replay failed at iteration 24 and is retained; the next replay passed 24/24. No load exemption is claimed.

The full tracer compiler caught a further merge gap: production failure Details omitted dev's two binary-download steps. The existing label map now covers both. The existing signed-payload case checks both architectures on desktop and phone, opening Details and checking the failed-step label. Browser plugin is unavailable; repository Playwright is the authorized fallback.

Browser functional coverage: 59/62 passed initially, with three overall 30-second harness watchdog failures. All three passed unchanged on a 120-second replay (`browser-functional.log`, `browser-retry.log`). Cursor and phone-width coverage passed 8/8 (`browser-live-web.log`). The initial overlapping product/preview build invalidated its run; `browser-invalid-overlapping-build.log` is diagnostic only. Fresh production-build screenshots are under `captures/`, for independent/owner review; no author visual-quality judgment. Unique browser port: 4987.

Performance and latency gates require the perf VM. The authorized NetBird SSH probe returned exit 1 with empty stdout/stderr (`perf-access.log`); no keys or credentials were inspected or changed. Timing browser cases were not run on the shared build host. No build-host timing, CPU or RSS result is performance evidence.

The D243 script is byte-identical to dev: SHA256 `14a782d5b95b972a39df1a3899ccb9f71190622da4d9b3808038ca5061dd6430`. Limits remain 16,404,816 bytes x86 and 13,817,816 bytes ARM. Initial static builds were executable, stripped static PIE without PT_INTERP, but exceeded both limits. Those earlier build logs predate the final migration compatibility repair; final verification supersedes them. No gate was relaxed.

Native targets and fixture state are isolated under HOME cache, with locked native OpenSSL archives reused only for GNU builds. `native-env.sh` records the environment. The first final native replay failed only because the mouse probe lacked Zig on PATH; retained as `native-final.log`. The corrected environment adds the same pinned Zig path as `scripts/verify`. Source checks exclude imported evidence whitespace to preserve verbatim historical logs.

Corrected final native verification passed fmt, strict all-target workspace Clippy and workspace tests: 805 passed, 0 failed, 104 ignored across 94 result rows (`native-final2.log`). Full TypeScript verification passed: vendored checksums, protocol compiler, tracer check, 168 source tests, production build/transfer, Rust differential oracle and 36 protocol tests (`ts-full2.log`). Final JavaScript transfer: critical gzip 294,908/307,200 and Brotli 245,192/256,000 bytes; deferred 49,746/51,200 and 43,870/45,056; largest on-demand 15,179/20,480 and 13,500/18,432. Wizard architecture/Details coverage passed 4/4 (`browser-wizard-labels.log`), with four fresh captures.

Final ARM build succeeds and is stripped/static without PT_INTERP, but is **19,355,472 bytes against 13,817,816 allowed** (`static-arm-final.log`). This is an unwaived D243 failure. Final x86 build also succeeds as stripped static PIE without PT_INTERP, but is **21,857,264 bytes against 16,404,816 allowed**. `scripts/verify fast` exits 1 with static builds as its only failed row (`verify-fast.log`); the fast script skips TypeScript after a Rust failure, so the separately completed full TypeScript gate supplies that coverage.

The resolved merge remains staged, **not committed or pushed**, because the brief permits push after passing gates and every commit must pass its gate. HEAD remains the dev base; MERGE_HEAD remains the production parent above. Neither the size failure nor unavailable perf timing is waived. The orchestrator needs a size repair retaining D243 and permitted perf-VM access before the single merge commit can be completed. Issue #169 records the blocked state and final gate output.

Final `scripts/verify fast` summary (verbatim):

```text
+---------------------------+--------------+
| Rust gate                 | Result       |
+---------------------------+--------------+
| fmt                       | PASS         |
| VT native fmt             | PASS         |
| CLI plugin compile-out    | PASS         |
| clippy                    | PASS         |
| test                      | PASS         |
| cargo-deny                | PASS         |
| static builds             | FAIL (1)     |
+---------------------------+--------------+
```
