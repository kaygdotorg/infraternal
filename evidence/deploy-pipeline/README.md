<!-- D250 implementation evidence, review boundaries and outstanding staging acceptance, issue #188. -->
# Deploy pipeline evidence

Issue: [#188](https://git.kayg.org/kayg/infraternal/issues/188). Parents #154 and
#157. Decisions D186, D217, D244 and D250.

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
- `scripts-tests.log`: thirteen cases pass, including real SQLite committed-WAL
  backup, Unix socket framing, cold-reply refusal, live HTTP redirect refusal,
  exact streaming archive contents and metadata bounds. Controlled restart/web
  rollback cases use explicit doubles; they are not real deployment proof.
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
- Real A → B root/server deployment, listener-gap measurement, unlocked CA,
  real retained sessions and bad-image rollback acceptance remain **pending**.
  No mock/unit duration or inherited receipt substitutes for that proof.
