<!-- D250 implementation evidence, review boundaries and outstanding staging acceptance, issue #188. -->
# Deploy pipeline evidence

Issue: [#188](https://git.kayg.org/kayg/infraternal/issues/188). Parents #154 and
#157. Decisions D186, D217, D226, D244, D250 and D251; owner D1 on #188.

Implemented: serialized capacity-aware exact-dev-head builder, immutable hashed
static/tracer bundles with ten-release retention, signed root-owned transport,
warm replacement with live image/health/CA confirmation, retained online
database backup and verified previous-image rollback, live web-only swap,
production tag/main recording after acceptance, and separate staging mode.
No service was installed or enabled. No production deployment, provider
publication, signer access, credential-store access or main change occurred.

Functional evidence:

- `merge-tests-final2.log`: 26 native restart cases pass, one explicit optimized
  measurement remains ignored; three restart-filtered integration cases pass.
  This is a rootless build-host gate, not unlocked-root-CA staging evidence.
- `merge-clippy-final.log`, `tracer-check.log`: CLI all-target Clippy and tracer
  TypeScript check pass. Formatting and systemd unit validation pass.
- `scripts-tests-latest.log`: fourteen cases pass, including real SQLite committed-WAL
  backup, Unix socket framing, cold-reply refusal, live HTTP redirect refusal,
  exact streaming archive contents and metadata bounds. Controlled restart/web
  rollback cases use explicit doubles; they are not real deployment proof.
- `builder-lock-red.log`: actual subprocess loses the supervising flock before
  the fix. Worker subprocesses now inherit the same held descriptor explicitly.
- `redirect-red.log`: real redirect regression fails before the fix. The fixed
  local HTTP opener refuses redirect/proxy forwarding and closes error bodies.
- `merge-tests.log`, `merge-tests-serial.log`, `merge-tests-final.log`: failed
  bounded-debug-image fixture attempts, retained without a #118 waiver. The
  final fixture launches the private stripped signed image, preserving its
  deadline and inode/stdin checks.

The initial milestone fast gate reports an SSH synthetic-key private-pipe
authentication failure at `crates/infraternal/tests/ssh_askpass.rs:94`; no real
credential investigation or waiver was applied. The unchanged exact test
passes on dev baseline c0d01d22 (`ssh-baseline.log`). Current-workspace proof
with the existing SHA256 dependency optimized in dev/test passes both private
key/unknown-parent cases (`ssh-original-fixture-optimized.log`), retaining the
original fixture, deadlines and full-image verification. No crypto engine or
release profile changed. Complete final-head fast output is recorded on
#188 and retained separately as `verify-final.log`; no passing full-gate claim
is made until every required row passes.

The 00344cd0 milestone passes every native Rust row except the pre-existing
static size ceiling: x86 ELF is 21,882,448 bytes against 16,404,816. No ceiling
was changed. Final-head verification also includes the child-lock fix; its
receipt on #188 supersedes earlier milestone/interim output.

Historical prerequisite blockers before owner D1:

Perf VM reachability was confirmed through the named NetBird SSH entry. A later
nonblocking lock probe returned `LOCK_BUSY`; the attempted functional fixture
upload did not acquire the lock or create remote files. No performance numbers
were collected. Signed A/B artifacts matching the production trust anchors are
also absent. No signature bypass or local signing key was introduced to work
around that prerequisite.

# Reviewer checklist

- New scripts use existing toolchains, release packaging, public trust anchors,
  HTTP authority route and restart protocol. No engine/dependency was selected.
- Exact-head gates precede completed-cache publication. Capacity admission,
  quota, lifetime lock, failure backoff and durable prune receipts are present.
- Signed images and metadata are checked locally and remotely; in-process
  signature/seal/probe admission remains authoritative. Source UID is not
  preserved by root extraction. A retained previous image has signed metadata.
- Administrator sessions stay in caller/SSH/helper memory. No redirects,
  ambient proxies, credential-store reads, credential files or secret arguments.
  Provider/auth/journal diagnostics are not echoed.
- Backup uses SQLite's online API, excludes WAL sidecars/live sockets and does
  not follow state symlinks. It is not a quiescent filesystem snapshot. Warm
  rollback never overwrites a running database.
- Changed endpoint plus live executable identity distinguishes new execution
  from old-server health or round4 late recovery. Both health and CA must pass.
- Failure restores web and installed aliases before verified previous-image
  replacement. Lost CA custody/dead successor requires explicit recovery; the
  script never claims a healthy unlocked rollback in that case.
- Production refs move only after remote acceptance, through an atomic normal
  push; concurrent main changes fail rather than force history. Staging does
  not move refs and uses only the brief's perf-VM directory.
- Real signed root/server deployment now passes in the throwaway perf-VM unit:
  [raw acceptance](staging-proof.txt). The first two failed fixtures are retained
  in [startup failure](staging-startup-failure.txt) and
  [runtime-path failure](staging-runtime-path-failure.txt). Neither is a successful
  acceptance or product-performance result.

# Completed staging acceptance — owner D1

Machine `infraternal-perf-test`, kernel `6.12.69+deb13-amd64`; exclusive
`/var/lock/perf-bench.lock`. Load before `0.21 0.64 0.84`, after
`0.44 0.67 0.84`. The entire run used its own directory, ephemeral loopback
ports, retained CA, database, transient systemd unit and private runtime mount.
The normal passkey verifier unlocked the cold server once; no signer was
injected into the running server and no further unlock ceremony was needed.

| Evidence | Observed result |
| --- | --- |
| Signed A/B handoffs | 12 alternating replacements; live hashes and unlocked CA confirmed |
| Listener-gap bracket p50 / p99 | 24.432 / 204.674 ms (nearest rank, n=12) |
| Worst actual probe spacing | 101.625 ms; nominal sleep 1 ms, connect timeout 100 ms |
| Retained scale | 50 users, 10000 node records, 128 real PTYs |
| Session continuity | All 128 original shim PIDs survived; all 128 resumed new input/output |
| Signed unusable C | Refused before shutdown; restart endpoint and serving image unchanged |
| Actual deploy rollback | Retained signed B serving, CA unlocked, database never overwritten |
| Backup | SQLite integrity OK; 10000 nodes/50 users retained; previous image signature verified |
| Teardown | Transient unit/process group removed; run directory absent before lock release |

Gap values conservatively bracket availability between the last successful
connect before refusal and first success afterward. The100ms connect bound
made the worst sampling interval 101.625 ms. Thus the p99 is an **upper bound**,
not a precise 204.674 ms physical blackout. It is not browser reconnect latency,
and this run does not claim a reconnect-budget pass. A/B share the actual
compiled staging program with distinct signed versions/hashes (B has an inert
ELF trailer); the ARM placeholder is never executed or a production artifact.
These limitations are part of the claim, not omitted samples.

The non-default `staging-trust` feature requires a fresh public key at build
time. The private signer is generated only in job scratch and deleted before
transport; it is never committed, logged or placed in argv. A normal build
rejects its SSHSIG; the staging build accepts it. Production's static ELF gate
rejects the actual stripped staging image, before the existing size gate.
No production endpoint, production signer, production CA, tag or main ref was
changed. The cut-over instructions are in
[the operator procedure](../../docs/operations/deploy-pipeline.md).

Author review checked: compiled default trust isolation; no runtime trust
mutation; unchanged strict SSHSIG/parser/sealed-image admission; no plaintext
CA key transfer through files/argv/logs; stdin-only administrator session;
root-owned protected image parents; same-PID/live-image/endpoint/health/CA
acceptance; physical Unix-socket bound; verified backup/rollback without live
DB restore; own transient unit/runtime/data and cleanup under the lock; no
production deployment/ref changes; honest sampler and scale qualifications.
No foundational dependency or production release profile changed.

A full milestone gate passes the native Rust rows and dependency checks. The
pre-existing static size ceiling remains unchanged. The final-head gate is
required before handoff; its raw output belongs verbatim on #188 and locally
in `verify-staging-final.log`.
Production cut-over still requires that gate and an independent break-it review
with no P0/P1. D251 quiet-window automatic application is a separate integration
prerequisite; the existing channel setting alone does not implement it.

# Round-three review fixes and reproof

The exact four independent review regressions and the R1/P1 plus R2–R4/P2
repairs are recorded in [round-three evidence](round3/README.md). The fresh
[locked staging rerun](round3/staging-proof.txt) after the recovery-path fix
passes 12 handoffs, 128 preserved shim PIDs/resumed sessions, single-unlock CA
custody, C refusal, verified warm rollback, backup and teardown. Its listener
brackets are p50/p99 18.576/102.768 ms with 101.438 ms worst probe spacing.
The earlier acceptance table and raw receipt above remain the original run.
Final branch-head gate output is recorded verbatim on #188.
