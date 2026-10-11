<!-- Records independent review fixes, real shipping continuity, parser fuzzing and measured distribution evidence for #154 [168][184][217][224]. -->
# CA handoff verification — review round 2

Runtime/test head: `1b494d4b58560d818db6b532946d15af4af81f42`; production alignment: `6e08065b` (unchanged Rust
baseline `06857458`). Fixes and evidence are recorded on
[#154](https://git.kayg.org/kayg/infraternal/issues/154). No deployment.
The [round 1 evidence](README-round1.md) is historical; its user-mode warm policy
was replaced by the owner-directed root-only policy below.

## Real replacements and latency

A debug Rust harness drives the stripped static musl **release** server/CLI from
a protected root-owned install. It measures 25 same-PID replacements, including
staged update/rollback, default-path restart and SIGHUP. Completion requires a
new control socket generation and authenticated unlocked CA status.

| Measurement | Round 1 p50/max | Round 2 p50/max | Change |
| --- | ---: | ---: | ---: |
| Request to new unlocked CA | 30.736 / 39.541 ms | 26.856 / 36.962 ms | -3.880 / -2.579 ms |
| HTTP connection refusal upper bracket | 23.795 / 29.478 ms | 21.023 / 26.725 ms | sampled, 1 ms configured probe |

205 refused connection samples. These are sampled upper
brackets, with scheduler/load uncertainty, rather than exact outage edges.
Round 1 ran as the user UID under the previous policy; round 2 runs as root under
the required policy and a different host load. The delta describes the observed
runs; it does not isolate the cost of a single fix. No artificial CPU load was
started. QUIC/WAN reconnect latency is outside this local measurement.

Scale: 50 users, 10000 **retained records**, 128 real live PTYs (single-host limit).
All original shim PIDs survive; every PTY reattaches and accepts new input after
replacement. Retained rows are not claimed as live remote connections.
Machine: infraternal-dev, Linux 6.12.111+deb13-amd64, Intel Core i9-9900K 3.60 GHz,
8 available CPUs. Every benchmark runs locally in CPUWeight=10000 scope. Root shipping uses a
private mount namespace, binding its scratch runtime directory onto `/run`;
PID/network namespaces and production runtime policy are unchanged. The first
root harness run looked under XDG instead of the fixed root runtime path; its
128 owned shims were cleaned with pidfds before the isolated rerun.
`load_before=12.92 17.07 25.40 5/2863 1073164; load_after=16.90 17.75 25.53 13/2912 1075091`. [Root transcript](round2/shipping-root.log),
[user-mode cold transcript](round2/shipping-rootless.log).

Both runs make the real reply fail with EPIPE and prove health, CA state, service
PID and endpoint generation survive. User mode then proves explicit cold reply,
same-PID exec, locked CA and `/dev/null` stdin. Root mode also rolls back to the
same real binary with its note version invalidated: no key is offered, the reply
is cold, the CA is locked and fd 0 is `/dev/null`. Startup audit records confirm
the actual warm/cold import result using the unchanged service PID.

## Review fixes and failing-first evidence

| Finding | Repair and evidence |
| --- | --- |
| P1 executable authorization | Root-only export; opened root-owned protected inode and every parent, exact versioned ELF note; `fexecve` of the same fd. General binary/rootless paths are cold. [Before](round2/p1-before.log), [after](round2/p1-after.log), [root unmarked](round2/p1-root-unmarked.log). |
| P2 child inheritance | Explicit null stdin for embedded infraternal agent, shim and systemctl launches; existing SSH pipes/null and explicit PTY slave retained. [Before](round2/p2-before.log), [after](round2/p2-after.log). |
| P3 restart errors | EPIPE/invalid reload retain the pinned serving future; deleted running inode reopens invocation path. [Before](round2/p3-before.log), [after](round2/p3-after.log), plus shipping EPIPE. |
| P4 startup exposure | Dumpability disabled as first main action; receive/detach before cold configuration. SSH prompt helper preserves its existing proc authentication after detaching stdin. [Before](round2/p4-before.log), [after](round2/p4-after.log), [SSH regression](round2/p4-ssh-before.log), [SSH repair](round2/p4-ssh-after.log). |
| P5 stdin cleanup | Injected null-open/dup errors close fd 0. [Before](round2/p5-before.log), [after](round2/p5-after.log). |
| P6 secret buffers | Dedicated `mlock` + `MADV_DONTDUMP` mappings, checked through kernel smaps; whole-page wipe on drop. [Mapping before](round2/p6module-before.log), [after](round2/p6module-after.log), [actual frame before](round2/p6-before.log), [after](round2/p6-after.log). |
| P7 shutdown | Runtime shutdown bounded at 4 s; resistant child TERM/KILL/reap deadlines 2/3 s. Real resistant-child and blocked-runtime tests fail before, pass in approximately 2.03/4.03 s afterward. [Child before](round2/p7-before-0.log), [after](round2/p7-after-0.log), [runtime before](round2/p7-before-1.log), [after](round2/p7-after-1.log). |
| P8 early SIGHUP | Queue through exec/startup; register handler before unblocking; reset child mask. [Signal before](round2/p8-before.log), [after](round2/p8-after.log), [child mask before](round2/p8-mask-before.log), [after](round2/p8-mask-after.log). |
| P9 optional control | Failed control setup still serves HTTP 200. [Before](round2/p9-before.log), [after](round2/p9-after.log). |
| P10 audit | Kernel peer PID/UID, escaped target, warm/cold/refused/reply-failed records, actual successor outcome; no private bytes/lengths. [Before](round2/p10-before.log), [after](round2/p10-after.log). |
| Closed stdin edge | Keep opened code above fd2, retain owned null input through exec, explicitly clear stdin CLOEXEC. Both native-probe exec stages fail first; the probe avoids Rust startup repairing fd0 and masking the failure. [Before](round2/stdin-before.log), [after](round2/stdin-after.log). |

The capability note establishes compatibility, **not a release signature**.
D184/D224 verification remains one explicitly deferred opened-fd hook;
`release/allowed_signers`, SSHSIG namespace `infraternal-release`, supplies the
future policy. No foundational library was selected: syscall work reuses the
existing D40 shim boundary and audit uses existing workspace tracing. Each
dependency declaration and module change has its own gated commit.

Protected serialization peaks at two 4 KiB pages (8 KiB/server × one concurrent
transfer), receive at one page, independent of 10000 hosts/128 PTYs. Protection
failure makes handoff cold. OpenSSL retains its persistent key and briefly
returns an allocator export copy that is immediately zeroized. Kernel socket
buffers contain the bounded frame (at most 2090 bytes); userspace cannot wipe
or apply mapping dump advice to those buffers. These residual copies remain.

## Fuzzing and final suites

Actual `cargo fuzz run remote_ca_handoff_decode` ran **311 seconds**, CPUWeight=30,
ASan and sanitizer coverage enabled: **12051706 executions**, cov 108, ft 231,
peak RSS 505 MB, no crash/sanitizer finding. It covers bounded CA decoding and
exact aligned compatibility notes. No valid private frame corpus is persisted.
[Full output](round2/fuzz-final.log), [machine/load/command settings](round2/fuzz-environment.txt).
The nightly sanitizer link needed command-only LTO=false/STRIP=none; production
profiles are unchanged. Observed fuzz load: 19.62/35.74/37.53.

| Final suite | Passed | Explicitly ignored diagnostics |
| --- | ---: | ---: |
| CA lifecycle/administration/handoff | 45 | 7 |
| Remote server | 49 | 10 |
| Infraternal agent remote | 22 | 2 |
| CLI/restart/startup | 35 | 0 |
| Core CA cryptography | 8 | 2 |

[Final suite transcript](round2/final-suites.log), [core CA](round2/final-ca-core.log). Ignored shipping coverage runs
separately above. Every non-size fast row passes, including auth/socket/review
and credit tests; no #118 baseline waiver was used. An intermediate shutdown gate
caught two Clippy findings; the audit gate caught expression/doc lints. All
were repaired without suppressions before successful full regates.
The first shipping gate also hit the unchanged shim backpressure test
(head1515/minimum1847); the exact isolated rerun passed in 0.26 s, followed by a
fresh passing full test row. No assertion or waiver was used. Failed and passing
transcripts are retained with every per-step full gate in `round2/`.
The first deployment-doc gate hit an unchanged SSH helper fixture with
`ETXTBSY` before helper code ran; its exact isolated rerun passed in 0.01 s.
Its next gate hit two unchanged mesh fixture setup `PoolTimedOut` failures;
exact isolated reruns passed in 2.17/1.24 s. Final full gates serialize harness
execution (`RUST_TEST_THREADS=1`) to reduce between-fixture contention; each
test’s internal concurrent scenarios and assertions remain unchanged. No #118
waiver or production/test assertion change is used. Failed gates and isolated
reruns are archived, and a fresh passing full test row is required.
The first job-local fixture root exceeded the AF_UNIX bound before daemon
startup; the verification-only root was shortened to the job’s `/s` directory
and preflighted against the unchanged 108-byte bound.
The fourth documentation gate hit the existing auth-socket continuation assertion
under load. The exact test passed on detached `dev` baseline
`f91517019a83e6d66226841267f72b82f907ae46` (106.24 s, load 36.09/32.93/29.57);
therefore no #118 exception was established. A fresh full gate passed every
non-size row, including that exact scale test; no waiver was used.
[Failed full gate](round2/docs-fast-fourth.log),
[baseline comparison](round2/auth-socket-baseline.log).
[Author reviewer checklist](round2/reviewer-checklist.md); independent review is
still required by PROCESS §2.

## Distribution and gates

| Static target | Unchanged production baseline | Final | Growth from baseline | Growth from round 1 |
| --- | ---: | ---: | ---: | ---: |
| x86_64 musl | 19896992 | 19974896 | +77904 bytes | +36176 bytes |
| aarch64 musl | 17729832 | 17796824 | +66992 bytes | +27648 bytes |

Both binaries are static, have no PT_INTERP, and carry the note; see
[artifact checks](round2/static-artifacts.log). Historical ceilings (16404816 /
13817816 bytes) already fail on production. They were not raised. Only that
pre-existing x86 size row fails `scripts/verify fast`; the dispatcher stops before
ARM/TS, so those are checked separately. [Final fast output](round2/gate-fast.log),
[ARM build](round2/arm-static-build.log), [TypeScript](round2/ts-fast.log) (36 tests,
34462 assertions), [remote-disabled build/dependency tree](round2/feature-off.log).
The remote cargo feature removes handoff and protected-buffer activation.

To reproduce warm shipping coverage, install the built release server and debug
server test executable in an isolated root-owned path whose every parent is
root-owned and not group/world-writable, then run the test as root inside a local
CPUWeight=10000 scope, with `INFRATERNAL_TEST_BINARY` set to that release path:
`ca_handoff::shipping_tests::shipping_restart_reload_rollback_and_cold_start`
with `--ignored --exact --nocapture`. Running as a user exercises the cold branch.
Use `$HOME/.cache/codex-scratch/ca-handoff` for all build targets, never `/tmp`.
For the root fixture, use the retained [mount wrapper](round2/root-shipping-scope.sh)
inside `unshare --mount --propagation private`, binding the isolated scratch
runtime onto `/run`; root production paths intentionally ignore XDG.
The fixtures clean up their owned servers/shims/data. The operational sequence is
[deploy.md](../../docs/operations/deploy.md).
