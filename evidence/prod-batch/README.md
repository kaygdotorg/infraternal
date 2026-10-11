<!-- Records the production batch launch audit, kernel regression and merged-tree verification for #154/#151/#149/#158 [13][40][188][205][217]. -->
# Production batch verification

Base: `ebcc73a0ec22f8498a0466b2d8641ac569f87e77`, branch `prod-batch`.
Validated code head: `431ec8a743427a40b7509cd32d7fe712be6eca80`.
Commits: `b67d0345` protected lifetimes/observers; `431ec8a7` child signals.
Exact TLS production comparison: `5d02b8d6b9f882695d92e1d17f80abb8f6af2e06`
(`origin/tls-session-prod`). No deployment.

The merge conflicts retain both fuzz binaries (`terminal_admission` and
`remote_ca_handoff_decode`) and both shim exports (`run_with_retention` and
feature-gated `locked_bytes`). No conflict-resolution code was lost.

## Child-launch audit

| Production boundary | Shared signal policy |
| --- | --- |
| Embedded infraternal agent, `server/src/embedded.rs` | `prepare_spawn` before POSIX spawn |
| Detection, init scope, detached shim, `agent/src/sessions.rs` | `isolated` calls `prepare_child` before shell exec/fd3 closure |
| PTY shell, `shim/src/pty.rs` | `prepare_child` before PTY/privilege setup |
| Double fork, `shim/src/pty.rs` | Fixed: existing `reset_child_signals` at each child branch |
| SSH bounded execution, `plugins/ssh/src/process.rs` | `prepare_child` in `execute_inner` |
| SSH connection and key helpers, `master.rs` / `credentials.rs` | `prepare_child` on direct spawns; remaining commands use bounded execution |
| Installation, `infraternal/src/install.rs` | `prepare_child` on both systemctl calls |
| Remote removal, `plugins/remote/src/uninstall.rs` | `prepare_child` on removal and systemctl launchers |

Retention, ended-record recovery and dead-session relay paths launch no extra
processes. `restart.rs` uses same-PID `fexecve`, deliberately preserving the
queued reload policy under D217; it does not launch a child. Build drivers and
disposable test fixtures are separate from production launch policy.

The raw-fork boundary previously retained blocked and ignored SIGHUP. The
single-threaded probe inherits SIG_IGN through a shell, blocks SIGHUP before
calling public detach, checks the original caller mask, and executes an
unprepared shell from the detached child. Before repair: mask not empty and
shell survived SIGHUP. After: empty mask and shell terminated by SIGHUP.
The kernel regression and all seven closed-stdio combinations pass (2/0).
The shared Command/POSIX test also checks ignored dispositions and parent mask.

The fix reuses the existing audited syscall policy, resetting dispositions
before unblocking, with no allocation, captured state or lock on the successful
reset path. Descriptor ownership, setsid/double-fork behavior, PTY privilege
order and signal policy in the original caller remain intact. No dependency,
parser, auth policy, budget or release profile changes.

## Non-dumpable session lifetime

The initial merged-tree gate and its isolated lifecycle retry failed at
`verify-session-bounds.py:82`: after opening a live session, counts were 0/0
rather than 1/1. The real owned shim was sleeping with its socket present;
following `/proc/<pid>/exe` returned EACCES while executable-link metadata
remained readable. CA first-entry dump protection and the #151 registry had
incompatible assumptions.

`Live::alive` now checks symlink metadata without following the ptrace-gated
executable link. It retains authenticated rendezvous presence, the bounded
process-birth tick check, dead-state exclusion and PID-reuse protection. The
alternative of restoring dumpability was rejected because it weakens CA
protection; dropping lifetime validation was also rejected. No extra field,
descriptor, allocation policy or idle task is added.

The disposable non-dumpable-process regression failed before repair in 0.02s
(count 0 instead of 1), then all four lifecycle tests passed. It reaps its child
before assertions and supports privileged runners with different ptrace policy.
The original real-shim lifecycle test also passes in the corrected full gate.

The protected process also denies `/proc/<pid>/fd` enumeration. SB-01 and
retention observers now share `shim_socket_count`: the readable kernel Unix
socket table counts the exact unique private rendezvous pathname, including
accepted connections. Their original endpoint counts, deadlines and protocol
assertions remain intact. SB-01 failed with EACCES before repair; retention
contained the same FD enumeration. SB-01 then passed in 0.98s and retention
in 1.92s. Using sudo, weakening dump protection and replacing detach observation with a sleep were rejected.

## Startup measurement

Local infraternal-dev, 8 CPUs, CPUWeight=10000, no own compilation overlap.
Seven alternating batches of **200 real double-fork launches**, same GNU debug
profile and probe workload before/after. Batch medians 446.576 / 490.347 ms:
observed +218.854 us per launch, +43.771 ms over 200 launches. Load before
22.72/25.53/24.54, after 20.07/24.87/24.34. Shared-host variation prevents an
isolated causal estimate; this is a startup diagnostic, not a shipping p99 or
200 simultaneous live sessions. The launch-only cost restores required child
signal correctness. No new persistent reset state or idle work; total child RSS
was not measured. Raw rows: `detach-cost.log`.

## Protected registry at scale

Static shipping profile, 200 simultaneous real 80x24 shims on infraternal-dev,
8 CPUs, CPUWeight=10000, local RTT=0. Recovery counted 200, admission counted
201, and reaping the extra returned to 200. Across 101 facts reads, p50 was
3.407 ms and maximum 12.664 ms. Load 14.95/20.68/25.35 ->16.80/20.96/25.41;
the own TLS baseline build overlapped, so timing is a loaded-host diagnostic,
not an isolated causal delta. No new persistent registry state; total RSS/PSS
was not measured because facts-only avoids protected smaps. All fixture-owned
processes were cleaned up. Binary identity and rows: `protected-scale.log`.

Final shipping binary (both fixes), no own build/test overlap: again recovered
200, admitted 201, after reap 200; 101 facts reads p50 **4.706 ms**, maximum
**14.941 ms**. Load 14.20/22.66/21.65 ->16.03/22.90/21.73. Local RTT=0,
same CPUWeight and dimensions. This is not a before/after causal comparison
with the earlier loaded run. Identity/rows: `final-scale.log`, `binary-final.txt`.

## Frontend evidence

Browser plugin unavailable; existing Playwright harness used on port 5799 with
the default 300ms profile. Production build, check and source tests pass:
142 tests / 10,901 assertions. Seven selected browser tests pass in 1.8m:
dead-session (four), detached-output, transient-session-review and
transient-session-input. These exercise ended status 0/7, one final attach,
saved-status disconnect, detached output, bounded shared-stream retry and exact
nonzero input continuity. The test double supplies protocol cases; Rust tests
provide real PTY/native QUIC/auth/TLS evidence separately.

D188 refreshed production build at code head `431ec8a7`: critical
gzip 290,397/307,200 bytes, Brotli 241,123/256,000; deferred
gzip 50,719/51,200, Brotli 44,797/45,056; largest on-demand chunk
gzip 15,002/20,480, Brotli 13,328/18,432. Every font budget also passes.
Initial browser-build figures remain in `tracer-retry.log`; refreshed build
and size rows are in `tracer-final-build.log` / `tracer-final-budget.log`. The independent DS-02 transfer test passes.
Standard supplemental TS fast also passes: 36 protocol tests / 34,462 assertions.
Screenshots in `screenshots/` come from the production build. This job makes no
visual-quality judgment and changes no frontend source.

## Final verification

`scripts/verify fast` completed on the exact code of `431ec8a7`. Every test
and non-size row passed, including SB-01, retention, all five DS-03 native
cases, ordinary CA handoff, auth and native/proxy TLS. Server: 291 passed,
0 failed, 32 existing ignored diagnostics; shim: 65/0/13 ignored; detach: 2/0
in 1.04s. The unchanged D205 size ceiling is the sole gate exception.

The x86 binary is static PIE without PT_INTERP, **20,064,944 bytes**:
**+73,488 bytes** versus fresh exact TLS baseline 19,991,456; **+64 bytes**
for the double-fork repair. It exceeds the unchanged 16,404,816 ceiling by
3,660,128 bytes. Both hashes and source identity are in `binary-final.txt`.

Raw transcripts preserve tool-emitted whitespace; documentation and Python
harnesses pass their whitespace/syntax checks.

Gate output, verbatim (`fast-complete.log`):

```
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

The x86 size check stops the ordinary dispatcher before ARM and TS checks.
ARM was not built in this job. Supplemental standard TS fast passed, as did
the requested tracer build, check, source tests, transfer review and browser
specs. Real-browser auth passed four isolated passkey scenarios and two
real-verifier recovery scenarios on Chromium 149.0.7827.55 (`auth-browser.log`).

The preliminary cold fast run was interrupted during Clippy (exit 130) to
prioritize failing-before evidence; it is not a completed gate. Baseline setup
initially reused a newer build-script executable from the shared target and
failed on the absent TLS handoff linker script. That artifact was rejected.
Refreshing source timestamps rebuilt the exact TLS baseline, then refreshing
the merged build script restored its own linker flags. The failed cache run
(`baseline-cache-failure.log`, `fast-protected.log`) is not a size-only gate.
The corrected protected-step gate is `fast-protected-clean.log`.

Two subsequent full runs failed different socket tests: initial liveness
snapshot type error (`fast-detach.log`), then unexpected headroom socket close
(`fast-final-clean.log`). Isolated liveness retry passed. A detached dev
baseline at `5bc58323ab14a99613df16c1dbe254e99bda3d28` and the merged binary then
ran both unchanged tests together under one weighted scope/default 300ms RTT.
Both passed: liveness 9.54s each; headroom 77.75/79.50s, 10,000 nodes/30,000
grants, 88 pages, maximum frame 64,612 bytes, liveness resync then Pong. Load
21.22/17.12/15.96 ->24.03/20.18/17.21, overlapping non-server compilation.
No matching baseline failure, so **no #118 waiver**. Pair transcripts and
reproduction harness: `compare-*.log`, `socket-comparison.log`,
`compare-sockets.py`. Harness elapsed fields are wait-observed; use native
test result durations for exact runtimes.

The separate exclude-server attempt failed terminal.open with
resource_unavailable after the initial session exited. Same binary isolated
retry passed all 24 abrupt stops/4,710,396 exact payload bytes in 41.44s
(`workspace-except-server.log`, `daemon-retry.log`). No timeout or production
workaround was added. The final complete gate passed all these cases and all
remaining workspace tests with no other own build/test suite active.

CA test boundary: ordinary handoff tests include real exec, peer identity,
protected mappings, malformed frames and parser properties. The explicit
ignored warm shipping-restart/128-PTY benchmark was not rerun: its harness
hardcodes the separate ca-handoff job scratch directory, outside this job
write scope. Existing reviewed CA evidence remains in `evidence/ca-handoff/`.
This report does not claim that ignored benchmark passed anew.

Author review: [reviewer checklist](reviewer-checklist.md). Issues remain open;
no deployment. The final evidence commit follows the validated code head and
changes only these records. Final issue comment records the complete head SHA.
