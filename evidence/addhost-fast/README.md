<!-- Records reproducible add-host speed work, acceptance limits and preserved safety for #190/#169. -->
# Host provisioning speed

Branch `addhost-fast` starts at supplied production/start-fresh base
`b14a7146003a0d81399b55ef0972e970c258f882`; no deployment is performed.
Issue #190 records implementation and gates; #169 is the parent safety record.

All latency acceptance samples run on the named perf VM through NetBird SSH,
under `/var/lock/perf-bench.lock`, in `/root/infraternal-bench/addhost-fast/`.
Each phase uses ten fresh disposable targets per LAN/150 ms RTT profile,
75 ms egress and ingress delay in the target network namespace. Payloads are
release static executables; release controllers and SHA256 manifests are frozen
before another build replaces their paths. Each raw log records machine and load.
No build-host browser or test duration is performance evidence.

`report.py` requires ten successful Done proofs per profile and reports median
and nearest-rank p95 (the maximum of ten). `perf-run.sh` reproduces a phase.
The original `baseline` and `hash-cache` listener used a test acceptor with
Nagle enabled; those numbers are diagnostic. `production-baseline` corrects
the fixture by calling the actual production acceptor. That window has large
load outliers and is not a controlled speedup ratio against later windows.

**Acceptance remains open.** The current `quote-safe` pair reaches Check→Done
p50/p95 **575/645 ms on LAN** and **4977.5/5002 ms at 150 ms RTT**, ten fresh
targets each. LAN meets 1500 ms; RTT does not meet 4000 ms.
`quote-safe-table.md` and `quote-safe/` contain the current complete table and
twenty raw logs. The earlier phase named `final` predates the quoting repair.

| Implementation phase | LAN p50 / p95 ms | 150 ms RTT p50 / p95 ms |
| --- | ---: | ---: |
| Production acceptor baseline | 2001 / 12411 | 10721.5 / 20881 |
| Direct local login + early TCP_NODELAY | 1030.5 / 1122 | 7927.5 / 8054 |
| Prepared gzip, same full payload | 762 / 849 | 6949.5 / 8584 |
| Combined setup steps | 680.5 / 913 | 6177 / 6210 |
| Proof-gated concurrent commit admission | 682.5 / 706 | 6024 / 6051 |
| Node component payload | 565 / 717 | 5759 / 5929 |
| Framed upload + setup | 601.5 / 636 | 5266.5 / 5291 |
| In-channel verified cache negotiation | 571 / 590 | 4969 / 4983 |
| Rebuilt pair before quoting repair | 567 / 608 | 4961.5 / 4982 |
| Quoting repair, current runtime | 575 / 645 | 4977.5 / 5002 |

The later matched remote-step profile uses ten fresh targets per version/link
with fixed-name target instrumentation: before 885/977 ms LAN and
9107/9134 ms RTT, after 599/628 ms LAN and 4969/4994 ms RTT.
`remote-step-table.md` gives upload, join, activation, start and linger p50/p95;
`steps/` holds all forty logs. `step-shell.sh` logs fixed names, status and
durations, never argv or stdin. These instrumented totals are a separate
profile; uninstrumented `quote-safe` determines acceptance. Combined channel
times include SSH overhead. Commit overlaps facts/proof and is not additive.

The opened-file hash cache benchmark covers ten cold misses and 1600 warm
lookups. `hash-cache-scale.log` records the locked VM and load: miss p50/p95
137.571/170.799 ms, warm-hit p50/p95 0.055/0.175 ms. This is cache lookup scale,
not 1600 simultaneously installed infraternal daemons. At most two 64-byte
digests and fixed entry slots are shared across attempts; no per-host timer or
hashing task is retained. Compression stores at most four public entries, each
bounded to 64 MiB. The measured full payload is 20,355,632 raw / 8,987,325 gzip
bytes, the x86_64 node payload 11,045,696 raw / 4,754,025 gzip bytes. Payload
preparation precedes Check once per server startup; each raw log records it.
Cache bounds are not whole-server RSS evidence. Admission remains eight
active targets globally across sixteen batches; the single-target acceptance
samples do not establish network/whole-server behavior at that concurrency.

The implementation retains strict host trust, lazy in-memory credentials,
mode/uid checks, checked decompressed SHA256, verified retry reuse, ownership
journals, named failure steps, reversible service activation and terminal
marker plus matching authenticated zero exit before commit. Compound steps use
fresh child shells so shell status observation cannot disable errexit. Commit
admission blocks on a one-use empty-line release and rechecks ownership before
retiring the lease or deleting previous artifacts.

Known network login remains first. Unknown/manual targets with local material
try it directly and retain network-only fallback; local method receipts avoid
inventing provider metadata. A native descriptor handoff sets TCP_NODELAY
before SSH while retaining native trust and one owned foreground connection.
Upload/setup negotiates verified reuse or an available improving encoding in
one channel; malformed receipts receive no private invitation. The default
release server retains both modes. Both matching node payloads omit server
creation/storage through component features; release packaging validates all
three static artifacts and checksums before publishing the directory.

Nested quoting exposed a fish regression. The original helper fails a real
byte-preservation oracle; the repair passes four shells × four nesting levels
with quotes, backslashes, literal expansion syntax and newlines. See
`shell-quote-before2.log` and `shell-quote-after.log` for red/green proof.
All 59 installer tests and strict SSH clippy pass. Negotiated retry tests use
real shell/filesystem steps for intact-cache reuse and corrupt-cache re-upload
after activation refusal.

`regressions/` contains thirteen successful real-SSH cases: four login shells,
direct root setup, tiny disk, read-only home, foreign data, missing user
manager, noexec temporary storage, linger, verified retry and upload
cancellation. Each executes exactly one live test. An early wrong-feature
controller executed zero tests; `regressions-zero-tests/` is excluded. The
harness now refuses such a binary before creating a target. The existing
round-3/start-fresh Rust cases also remain in the workspace gate.

Pinned HTTPS delivery and explicit send buffers were slower in the measured
diagnostic cases. Per-socket CUBIC improved the three-target median by about
0.23 s but still missed four seconds. Production retains the existing
congestion setting and engines. Candidate code is in evidence, not the app.
`tcp-profile.log` shows BBR startup ramp during bulk transfer. No shared host
setting, live owner fixture, host key or unrelated host was changed.

Functional browser checks use a production build and unique port4480:
32 pass, four intentionally skipped captures, including add-host/start-fresh
regressions. `browser-functional2.log` is the record; `captures/` contains phone
and desktop production screenshots for independent review. The author does not
judge their visual quality. No physical-iPhone/Safari claim is made.

The separate TypeScript gates pass 175 tracer/UI and 36 protocol tests,
compiler checks, production build and transfer budgets.

The milestone full gate passes Rust tests, clippy, formatting and dependency
checks but fails the existing static-size caps: x86_64 20,474,992 bytes versus
16,404,816, ARM 18,240,032 versus 13,817,816. The supplied production x86_64
binary was already 20,329,584 bytes; this milestone's delta is 145,408 bytes.
The caps remain unchanged. Static linkage and x86_64 key-memory initialization
under an 8 MiB memlock limit pass; ARM key-memory runtime is not claimed.
Final-head gate output and outstanding acceptance are recorded on #190.

The reviewer checklist in `docs/reviews/ssh-bootstrap-87-repair.md` was
applied: batch/authority admission, native dynamic trust, exact ownership and
restart recovery, cancellation/process retirement, feature removal, private
terminal proof and licenses have functional evidence. Parser fuzz targets
cover transfer/setup receipts and streaming method evidence and compile
under strict clippy; no new coverage-enabled campaign is claimed.
The RTT limit, static-size gate and whole-server concurrency/RSS evidence
remain open. Payload transfer has not been moved ahead of the read-only
check/CA admission boundary. This is a partial record, not a completed-budget
claim.
