<!-- Release-channel correctness, build, scale and review receipts for D198/D202/D224/D225/D226 and #157. -->
# Release channels: verification evidence

Base: `794ef45fea5b07012af33ad720bb47483822786d`. Source/documentation head and the atomic, individually pushed commits are in [commits.txt](commits.txt). The evidence-only commit follows that head. [source-sha256.txt](source-sha256.txt) records the final gate inputs; [SHA256SUMS](SHA256SUMS) covers the archived receipts. Compiler log whitespace is preserved verbatim; whitespace checks apply to the authored prose and reproduction wrapper. No live bucket or Worker was contacted, no build was published, and no server was initialized by the channel CLI.

Server settings default to stable independently of the running binary's identity. Switching to edge requires acknowledgement that builds are published as made and are unreviewed; switching back is plain. The release plugin is removable at build time and switchable at runtime. Latest lookup authenticates the signed manifest and exact VERSION through the same descriptor; a missing stable release never falls back to edge. Add-host retains the server's exact binary identity.

## Required checks

[final-fast.log](final-fast.log) contains the final `scripts/verify fast` output. All non-size Rust rows pass. The known stripped x86_64 static PIE size failure remains: **20,295,232 bytes**, versus **20,042,272 bytes** recorded at `794ef45f` in [the original receipt](../release-pipeline-round2/static-size.log), a **252,960-byte increase** (1.262%). The configured ceiling is 16,404,816 bytes. This is recorded as a failure, not waived as a green gate. Both compared binaries are x86_64-musl stripped static PIE with no PT_INTERP; no matched ARM baseline delta is claimed.

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

The size failure exits the normal dispatcher before TypeScript; [ts-fast-final.log](ts-fast-final.log) records the separate existing TypeScript dispatcher: 145 tracer tests / 11,246 assertions and 36 protocol tests / 34,462 assertions, compiler checks, production build, vendored checksums and transfer budgets pass. [release-scripts-final.log](release-scripts-final.log): Python release suite, 5 passed. [worker-final.log](worker-final.log): 3 passed, 16 assertions. [publication-review-final.log](publication-review-final.log): 2 passed, 5 assertions, including single-writer publication and refusal of ambiguous duplicates. [channel-cli-final.log](channel-cli-final.log) and [channel-cli-edge-final.log](channel-cli-edge-final.log) exercise the compiled CLI with a real PTY and private SQLite fixture: default stable, refused silent edge switch, yes/no persistence, plain stable switch, pretty output, shared skill instructions, and reported channel identity.

Named real-engine receipts: release_verify **2 passed / 1 ignored**, release_payload **9 passed / 2 ignored** including edge add-host, release_latest **3 passed / 2 ignored**, release plugin **6 passed / 1 ignored**, shared version grammar **1 passed** (table cases). Ignored scale fixtures were executed explicitly below. [feature-core-only.log](feature-core-only.log), [feature-release-only.log](feature-release-only.log) and [core-feature-tree.log](core-feature-tree.log) verify the build-time removal path and absence of the release plugin from core-only dependencies.

[edge-pipeline-final.log](edge-pipeline-final.log) records the actual `scripts/release/build --channel edge` dual-musl pipeline. [edge-bundle-receipt.txt](edge-bundle-receipt.txt) records the UTC VERSION, exact sizes and SHA256 values. Both architecture payloads contain that stamp and have no PT_INTERP. x86_64 `--version` and the edge CLI workflow were executed; aarch64 was inspected, not executed. The edge binary still starts with stable server settings. Signing and publishing were not requested.

## Optimized measurements at 50 callers

Machine: infraternal-dev, 8 cores. Each benchmark ran locally under `systemd-run --user --scope -p CPUWeight=10000`, production `cargo test --release`, without a load generator. Raw logs include machine/load and fixtures. [run-measurements.py](run-measurements.py) reruns the three explicit ignored fixtures with required scratch target/output paths and refuses a zero-test result.

Real OpenSSH/Ed25519 signed metadata, 200 samples per mode, 50 callers, 4 workers; load average 30.16 / 24.93 / 22.61:

| Manifest | Verifier mode | p50 (µs) | p99 (µs) | Max (µs) | 50-call batch (µs) |
|---|---|---:|---:|---:|---:|
| 165 bytes | inline | 122 | 4,228 | 4,262 | 10,174 |
| 165 bytes | blocking | 140 | 2,857 | 3,968 | 18,740 |
| 65,340 bytes | inline | 465 | 32,971 | 37,096 | 30,064 |
| 65,340 bytes | blocking | 664 | 6,096 | 7,173 | 11,069 |

[measurement-bench_bounded_metadata_verification.log](measurement-bench_bounded_metadata_verification.log) records this comparison. Inline has the lower median and the larger near-limit tail/batch cost. Verification remains inline because the bounded verifier must belong to the cancellable future: a detached blocking task could survive runtime disable and race staging cleanup. The read-only reviewer supports this correctness tradeoff; see [review.md](review.md). Tails include shared-host scheduling; this does not attribute CPU occupancy or certify D41 frame/terminal budgets.

[measurement-bench_latest_fifty_callers.log](measurement-bench_latest_fifty_callers.log): 50 simultaneous authenticated loopback latest lookups, 200 requests plus 4 warmup, all 50 results verified, **zero staging directories** remain. p50 **170.814 ms**, p99 **215.482 ms**, batch **218.710 ms**. RSS **12,192 → 15,852 KiB**, process HWM **12,192 → 16,648 KiB**, delta **4,456 KiB** (4.35 MiB). Normalizing that peak over 50 gives **91,258 bytes/caller**; this includes fixture/transport, not isolated per-lookup allocation or a full production daemon/TLS measurement. Lookup structure is 64 bytes. Load 29.18 / 24.82 / 22.59.

[measurement-channel_reads_at_fifty_concurrent_callers.log](measurement-channel_reads_at_fifty_concurrent_callers.log): 50 sequential channel reads p50 **0.064 ms**; 50 simultaneous callers with SQLite pool size 1 finish in **1.710 ms**. Service handle is 24 bytes, so 50 handles use 1,200 bytes excluding pointed-to state. Load 19.82 / 22.75 / 22.04. The signed near-limit fixture is asserted to be 65,000–65,536 bytes, avoiding accidentally benchmarking an over-limit refusal.

## Exact-source parser sanitizer run

[fuzz-exact-final.log](fuzz-exact-final.log): **12,486,906 executions in 301 seconds, no crash**. `nightly-2026-10-01`, ASan, CPUWeight=30, max input 70,000 bytes, RSS cap 2,048 MiB, release LTO disabled, stripping disabled, `ASAN_OPTIONS=detect_odr_violation=0`. [fuzz-exact-sources.txt](fuzz-exact-sources.txt) identifies the actual committed grammar, pointer parser and registered harness. The isolated manifest excludes unrelated server/VT sanitizer engines; it invokes these repository sources with release plugin default features off. [fuzz-isolated-Cargo.toml](fuzz-isolated-Cargo.toml) preserves the actual absolute paths for provenance; adjust paths for another checkout. [fuzz-isolated-Cargo.lock](fuzz-isolated-Cargo.lock) and [fuzz-dependency-match-fixed.txt](fuzz-dependency-match-fixed.txt) show all **176 registry packages match the repository lock** by name/version/source/checksum. [fuzz-corpus.tar.gz](fuzz-corpus.tar.gz) preserves the evolved corpus, including oversized inputs. The repository's normal fuzz target is also registered in `fuzz/Cargo.toml`.

An earlier isolated attempt used arbitrary 1.5.0 rather than the repository's 1.4.2; it was stopped, the isolated lock was corrected offline, and the full 300-second run was restarted. Only the matching final run is claimed here; the repository lock was not changed for that correction.

## Review and failed-gate history

The author checked the release reviewer checklist in `docs/operations/release.md`: reused HTTP/signature engines and trust roots, strict bounded parsing, same-descriptor VERSION authentication, exact add-host transaction identity, private existing-server storage, explicit confirmation and fresh authority immediately before commit, action-derived CLI/API/skills, plugin feature/runtime removal with owned cancellation, and absence of UI or publication side effects. [review.md](review.md) records independent read-only security/correctness/lifecycle review and its performance assessment.

[cancellation-red.log](cancellation-red.log) reproduces the detached verifier ownership defect before the fix; [cancellation-green.log](cancellation-green.log) proves the inline correction. [authority-boundary-red.log](authority-boundary-red.log) reproduces authority changed by a write trigger; [authority-boundary-green.log](authority-boundary-green.log) proves the fresh check immediately before commit rejects it.

Initial gate failures are preserved with successful retries; no assertions, deadlines or unrelated auth source were weakened. The eager schema row broke an existing count invariant and was removed rather than changing that test. Socket headroom and review liveness each failed once in full gates; the identical detached dev fixtures **passed** in the same general load window (85.87 s and 8.79 s), so those comparisons do not prove a load cause. The complete worktree retries then passed every non-size row. CLI dispatch exceeded its function-length lint; routing moved into the release module without suppression. The fuzz slice initially hit a collapsible-if lint; the partial gate was stopped, guards were collapsed, workspace clippy and the complete retry passed. Per-slice receipts identify these failures and retries; none is presented as green.

The initial final gate was stopped after two `agent_review` tests refused terminal creation before their timing assertions; [final-agent-partial-fast.log](final-agent-partial-fast.log) preserves it. Both tiny-credit and isolation tests passed on detached dev in [final-agent-dev-baseline-tools.log](final-agent-dev-baseline-tools.log). That six-test comparison has 5 passed and 1 unrelated setup failure: the older initial-attach fixture expected its local `target/` directory. Initial Nix/Zig PATH failures are separate environment receipts. [final-agent-baseline-source.txt](final-agent-baseline-source.txt) shows the test module/snapshot script match dev, while isolation/fixture scripts differ there; all four are unchanged by this job versus the supplied base. This comparison does not establish a cause or waive any row. The final full worktree retry must pass all non-size rows.

The next full worktree run passed all 6 agent_review tests, then `ring_wrap_snapshot_repaints_real_vim` failed with socket `WouldBlock/EAGAIN` at its existing 5-second read deadline. [final-shim-partial-fast.log](final-shim-partial-fast.log) preserves that run. The identical detached dev test passed in 3.31 seconds; [final-shim-dev-baseline.log](final-shim-dev-baseline.log) and [final-shim-baseline-source.txt](final-shim-baseline-source.txt) record the comparison and load 26.72 / 27.98 / 28.28. No shim/VT/test source or deadline changed, no cause is inferred and no row is waived. The complete final retry is the required receipt.

A subsequent full run passed terminal/shim tests, then server had 284 passed / 1 failed / 35 ignored: `reviewer_disk_restart_and_concurrent_resume` returned SQLite `database is locked` (code 5) from `recovery_start_clock`, unwrapped at reviewer_tests.rs:67. [final-auth-partial-fast.log](final-auth-partial-fast.log) preserves it. The identical test passed on detached dev in 24.29 seconds; [final-auth-dev-baseline.log](final-auth-dev-baseline.log) and [final-auth-baseline-source.txt](final-auth-baseline-source.txt) record the comparison/load 20.52 / 24.62 / 26.23. The initial call-site description incorrectly named open_disk and was corrected on the issue. No recovery/lock-timeout/test source changed, no cause is established and no row is waived.

Another full run passed terminal/shim/reviewer restart tests, then had 284 server tests passed / 1 failed / 35 ignored: the socket liveness fixture received an initial watch `error` instead of `snapshot` at line 49. [final-liveness-partial-fast.log](final-liveness-partial-fast.log) preserves it; this differs from the earlier CLI-slice expiry assertion. The identical test passed on dev in 9.05 seconds in the same load window, so no exception applies; [final-liveness-dev-baseline.log](final-liveness-dev-baseline.log) and [final-liveness-baseline-source.txt](final-liveness-baseline-source.txt) record it. Assertions/deadlines remain unchanged.
