<!-- Records the #78 repair evidence, scope, size accounting and reproducible checks. -->
# Remote infraternal agent repair round

The repair merged dev 42e50d42 first, cherry-picked all four independent review regressions, reproduced them, then fixed CA route activation, pre-body admission, transport removal and operator output. R3's saved runtime CA wiring is active: one cold source is shared by administration and enrollment; configured encrypted copy storage is validated before listeners start. No signing key is supplied through argv or generated implicitly.

## Regression evidence

| Finding | Original review commit | Failing evidence | Repair |
|---|---|---|---|
| RA1 | 8953e45b | 0/1; [404,404,404] instead of [401,401,401], 0.09s | a81d9dae |
| RA2 | bebdec4c | 0/2, 2.48s; unfinished body delays headers; ninth request 200 instead of 429 | 38222045 |
| RA4 | 347ce302 | 0/1, 0.52s; both offline normal core graphs retain Quinn | b76c05ec |
| RA3 | a3a7c231 | 0/1, 0.00s; all three real Clap cases reject --json | 3c29f8c3 |

RA2's added deadline regression also failed before the fix. Seven actual HTTP router tests pass: headers precede extraction, eight unfinished bodies exhaust admission, a five-second deadline returns its slot, and existing body/proof refusals hold. Cryptographic worker admission is independently bounded; final authority is re-read with live time under the database writer lock immediately before installing material.

RA4's unchanged standard-library-only test was also run directly with `rustc --test` (CARGO_MANIFEST_DIR set to the server crate); it invokes actual offline locked Cargo graphs. It passes after extraction. All-target core-only Clippy passes for host, server and CLI. The disabled CLI preserves every input/output byte across 24 abrupt daemon stops: 1/1 passed in 39.23s. Normal graphs for all three packages contain zero Quinn, Rustls or remote-plugin entries. Transport implementations live once in crates/plugins/remote and reuse plugin-api's Channel and bounds. Remote router/actor/host-selection/native-dispatch adapters are feature guarded. Core defaults are off, CLI default remote forwards features explicitly, and unconfigured runtime starts no remote listeners. Static plugin metadata declares actions, instructions, settings, defaults and role dependencies; #10's full generated-adapter registry is separate work.

RA3 adds genuine JSON result records, organized human refusal sections and next steps, NO_COLOR behavior, and JSON or human server logs. Descriptions, ordered remote help and enabled action IDs come from the plugin action definitions. Two real-command tests fail before the fix; all three output assertions also fail against the previous stripped shipping executable. They pass 3/3 in both enabled and disabled debug builds, without creating storage or reflecting missing identity/CA paths. The synchronous inherited-fd/shim fast path remains before parsing and runtime initialization.

## Scale and machine

All measurements ran locally on infraternal-dev (Debian 13, Linux 6.12.111+deb13-amd64, eight vCPUs, Intel i9-9900K reported by the guest), under systemd-run --user --scope -p CPUWeight=10000, without a load generator or concurrent build from this job.

CA router benchmark: 1000 serial valid-header/invalid-JSON-proof requests, real Axum/SQLite fixture, debug profile, network and passkey work excluded. Before: median 33606 ns, p99 116360 ns, load 9.16/14.23/17.74. After: median 35716 ns, p99 100524 ns, load 10.84/11.25/15.55. Median difference 2110 ns/request or 2.11 ms at 1000 requests; the actual shared body bound is eight x 32768 = 262144 bytes. Shared host load limits causal precision. The bounded reads justify this small admission cost.

## Reviewer check

Origin/cookie checks precede body reads. Body size, admission, deadline and cancellation remain bounded. Proofs/paths/wrapping material are not reflected. Cold startup and real registered signed-passkey unlock/restart are checked through the stripped configured CLI. Final live session, credential, membership and ceremony authority remains checked under the writer lock. Remote selection never falls back locally. Parser/fuzz targets retain their public entry points with explicit remote features. No new registry package/version or foundational engine was chosen; normal shipping graphs have no duplicate TLS/QUIC engines. Modules document their role and non-obvious ownership/cancellation invariants. Issues remain open; no push or deploy occurred.

First-copy browser provisioning, role rewrap, notifications and update IPC remain the separate phase-1 work already recorded on #78; this repair does not claim that phase complete.

## Stripped static size (D205)

Release uses opt-level 3, full LTO, one codegen unit and stripping. Unwinding is retained for session/process isolation [5]. All measured shipping binaries have no PT_INTERP. Values are bytes; positive rows add generated feature code, not new registry engines.

| Commit set | x86_64 musl | Change | aarch64 musl | Change |
|---|---:|---:|---:|---:|
| Merged dev baseline 7c179302 | 18105104 | — | 16141104 | — |
| CA activation a81d9dae | 18233840 | +128736 | 16250592 | +109488 |
| Body admission 38222045 | 18235344 | +1504 | 16253424 | +2832 |
| Plugin extraction b76c05ec | 18256656 | +21312 | 16275584 | +22160 |
| CLI output 3c29f8c3 | 18354736 | +98080 | 16347440 | +71856 |
| Total repair growth | | +249632 | | +206336 |

The ARM shipping executable is 151064 bytes over the old 16196376-byte limit. D205 explicitly accepts justified feature growth; the budget and profile were not raised or weakened.

Every added file byte is accounted for below by physical ELF sections (NOBITS excluded). Code means .text; constants means .rodata; unwind means .eh_frame, .eh_frame_hdr and .gcc_except_table; other allocated metadata includes .got/.data.rel.ro/.relr.dyn. The residual is exact section/header alignment. This is section accounting, not a claim of per-function attribution from stripped binaries. CA activation makes the administration route/authentication/copy/decode machinery reachable; admission adds bounded extraction/deadline code; extraction changes cross-crate generated transport code; output retains human/JSON formatting and shared help.

| Step / architecture | Code | Constants | Unwind | Other metadata | Alignment/headers | Total |
|---|---:|---:|---:|---:|---:|---:|
| CA / x86 | +106432 | +4096 | +15840 | +1848 | +520 | +128736 |
| CA / arm | +86784 | +4096 | +16864 | +1712 | +32 | +109488 |
| Admission / x86 | +896 | +0 | +444 | +288 | -124 | +1504 |
| Admission / arm | +2048 | +0 | +512 | +272 | +0 | +2832 |
| Plugin / x86 | +18496 | +0 | +3596 | +0 | -780 | +21312 |
| Plugin / arm | +17920 | +0 | +4312 | +16 | -88 | +22160 |
| CLI / x86 | +77440 | +4096 | +14292 | +944 | +1308 | +98080 |
| CLI / arm | +59392 | +0 | +11532 | +944 | -12 | +71856 |

Cargo.lock adds only the local plugin package and path edges, with no new registry versions. `cargo tree --locked -p infraternal --duplicates --edges normal,no-proc-macro` has no duplicate TLS/QUIC engine roots. Workspace `cargo tree -d` additionally separates the same Either 1.18.0 build/macro and normal contexts; that is not a second shipping library/version. Existing unrelated version duplicates remain.

The final x86 core-only musl executable is 15113744 bytes, stripped/static with no PT_INTERP: 3240992 bytes smaller than the enabled shipping build. Its same real output/refusal assertions pass 3/3. ARM core-only size was not measured; ARM shipping size is measured above.

## Final release proofs and startup cost

The stripped release output suite passes 3/3 in 0.01s. The configured stripped CLI proof passes 1/1 in 1.77s: rootless, cold refusal, real registered signed passkey, encrypted private copy, no fixture signer injected into the serving process, same-source enrollment unlock, then cold restart locked again. The existing opt-in test supplies the actual shipping executable through INFRATERNAL_REMOTE_TEST_BINARY; output assertions likewise accept INFRATERNAL_REMOTE_OUTPUT_TEST_BINARY.

1000 alternating paired stripped x86 CLI startup/refusal processes (NO_COLOR, missing private identity, no connection or storage creation): before median 1981779 ns/p99 6259302 ns; after median 2122798 ns/p99 6261441 ns. Median cost +141019 ns, projected +141.019 ms at 1000 process starts. Load 5.19/8.41/9.52 to 5.02/8.32/9.49. This includes fork/exec and process teardown under shared load; it is not an enrollment/network latency measurement. D202's machine-readable and human output justifies the 0.141 ms startup cost. The inherited-fd/shim fast path bypasses parsing/presentation.

The final restored shipping executable was checked again after the core-only build: the same configured CA proof passed 1/1 in 2.90s, and both bare CLI smoke checks passed.

## Reproduction and gate

Use the pinned repo toolchains and a private CARGO_TARGET_DIR under $HOME/.cache/codex-scratch. Set TRACER_TEST_PORT=4781 and RUST_TEST_THREADS=1. Run benchmarks locally inside systemd-run --user --scope -p CPUWeight=10000 and record /proc/loadavg. Relevant checks:

```sh
cargo test --workspace --locked
cargo clippy -p infraternal-agent -p infraternal-server -p infraternal --all-targets --no-default-features --locked -- -D warnings
cargo test -p infraternal --no-default-features --locked --test agent_daemon
cargo test --workspace --locked --test remote_output
cargo test --workspace --locked configured_release_cli_cold_lock_real_passkey_unlock_and_cold_restart -- --ignored --nocapture
cargo test --workspace --locked ca_body_admission_at_1000_requests -- --ignored --nocapture
scripts/verify fast
```

Each fix ran fast. Every non-size row passed; the ARM old size budget stops fast before its TS stage, so the unchanged `ts_verify_fast` stage was also run explicitly and passed. No qualifying load-sensitive failures required a detached dev comparison. Bare CLI smoke checks were also run explicitly: server and infraternal-agent modes each return exit 2 with `not implemented`.

Final gate load: 2.89 6.14 8.36 2/5439 3819836; 12.90 8.62 8.48 7/5514 3842918;

Verbatim final fast summary and supplemental TS result:

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


 7 pass
 0 fail
 34390 expect() calls
Ran 7 tests across 2 files. [2.13s]
```
