<!-- Operator setup, trust boundaries and acceptance requirements for prebuilt dev deployment [186,217,244,250]. -->
# Prebuilt dev deployment

`scripts/release/dev_builder.py` produces private, complete bundles under
`$HOME/.cache/infraternal-releases/<full-sha>/`. It follows the first-parent
history of `origin/dev` after a fixed installation base. Production remains a
tagged dev commit; this service never publishes, signs, deploys or changes main.

The supplied `scripts/release/infraternal-release-builder.service` is an
operator-installed systemd **user** service. Set its repository path and fixed
`--start-sha` to the dev ancestor immediately before the first desired build.
Install the pinned Rust toolchain, both musl targets, Bun, native build tools and
cargo-deny before enabling it. Installation is a separate operator action;
this job does not install or enable the service.

One cache-wide flock serializes builders, including children after an abrupt
stop. `CPUWeight=10000`, `CPUQuota=200%` and two Cargo build jobs reserve a share
while capping the service at two CPUs. Admission stops when either the one- or
five-minute load average reaches 8 on this eight-core host. D250 does not state
a numeric load limit; 8 is a conservative admission choice consistent with
PROCESS §5. The operator may lower `--load-limit`; the script refuses a value
above the machine's CPU count. An admitted build remains bounded by the service
CPU quota if other work starts afterward. No artificial load is generated.

The default runs `scripts/verify fast` against each exact detached dev head,
then reuses its two static binaries through `scripts/package-release --built`.
It uses `scripts/auth-toolchain` and checksum-pinned Zig 0.15.2, and builds the
tracer production bundle with the frozen dependency lock. A gate failure never
publishes a complete cache directory. Per-head gate logs remain under
`$HOME/.cache/codex-scratch/dev-release-builder/gates/`; failures retry no sooner
than 15 minutes and do not block newer heads. One completed-head receipt per
commit prevents pruning from causing old builds to run again. Source worktrees
and incomplete bundles are removed after each attempt; the reusable build
target remains while the service is installed.

`--gate-mode status --gate-context <exact-context>` can reuse an existing full
Forgejo gate instead. It reads only the public commit-status API and requires
the newest matching context to be successful. Configure the exact full-gate
context, never a partial check or aggregate status. The base commit's status
list was empty during this job; no guessed CI context is enabled by default.

Completed bundles contain both host payloads, the x86 server copy, `VERSION`,
`SOURCE`, `GATE`, the web directory and exhaustive `SHA256SUMS`. Directory
publication is atomic; the last ten complete bundles are kept. Deploy's flock
pins its selected local bundle against pruning. Build hashes attest local
integrity; they do not replace release signatures.

# Signing and deployment

Signing is external to this pipeline. The operator publishes the exact built
`VERSION` and binary bytes using the existing release procedure, then supplies
its public `MANIFEST` and `MANIFEST.sig` beside the cached artifacts. These two
late public metadata files are excluded from the builder's integrity list.
The bundle's identity must match the signed manifest and pinned public trust
anchors; signing a different rebuild cannot admit the cached bytes. Neither
script contacts a provider management API or a credential store.

The current production image also needs matching signed metadata beside its
installed image before the first binary handoff. This is a prerequisite for
verified warm rollback. Deployment refuses an unsigned current image; it does
not bootstrap trust by restarting it or by signing locally.

An operator pipes an already-authorized administrator session into
`scripts/release/deploy <full-sha> --review-clear`. Supply the session from an
existing in-memory caller, never a file, argument or logged command. The flag
attests that break-it review has no unresolved P0/P1; it is not inferred from
the gate. The CLI checks dev ancestry, main fast-forwardability, the build's
exact-head gate receipt, every local checksum and signed binary digest. No
build occurs during deployment.

Payloads travel through NetBird SSH to monitor01. Archive extraction creates
root-owned private files, independently of the builder's UID and umask. Remote
preflight verifies both the candidate and retained rollback signature, requires
health and an unlocked CA, and checks the installed bytes against the live
PID's executable. The server must run as root: round 4 intentionally retains
cold semantics for rootless replacement. The host needs Python 3, ssh-keygen
and readable `/proc/<pid>/exe` for identity confirmation.
Complete remote admission authenticates the server copy and each separately
installed architecture payload against the signed manifest. The unsigned
integrity list alone cannot authenticate a reused remote directory.

Before replacement, the SQLite online-backup API saves a consistent committed
database, including WAL pages. Other persisted state is copied without live
sockets or following symlinks. The complete old executable, payloads and public
signature metadata remain in a private timestamped backup. Other files may
change while serving continues; this is a consistent **database** snapshot,
not a quiescent snapshot of every concurrent filesystem mutation.

The local restart socket requests the new absolute binary pathname. Round 4
authenticates and seals the image, probes it, transfers the CA in memory and
execs with the same PID. Acceptance waits for a changed control endpoint,
matching live executable hash, health and unlocked CA. A late kernel recovery
to the old image does not satisfy the successor identity check. Successful
deploys point the installed server and both bootstrap payloads at the same
release. Web-only deployment uses `--web-only` and swaps the staged directory
live without requesting any restart.
Web-only deployment preserves the existing production tag and main identity:
its candidate commit has not replaced the running executable.

Failure restores the previous web and installed links and requests the retained
signed previous image through the same verified handoff. A database is never
overwritten while the server is running. The retained snapshot supports a
separate, explicit cold data recovery. If the successor loses CA custody or
exits, automatic rollback cannot recreate the unlocked key; the deploy reports
failure and requires operator recovery. It never reports a locked rollback as
successful. No journal or authentication response is printed.
Alias or web restoration errors do not skip the retained process rollback.
If those filesystem repairs fail, the script reports operator recovery even
when the previous executable is serving with an unlocked CA; inspect the
installed links and retained web directory before the next deployment.

Only after remote acceptance of a binary deployment does production get an annotated
`prod-<UTC-date>-<short-sha>` tag and an atomic push of that tag plus a
fast-forward of remote main. No force push is used. A concurrent main change
may refuse the push: the CLI reports `deployed-unrecorded` with the SHA and tag
for reconciliation. Staging never creates tags or moves main.

# Staging acceptance

Use only the perf VM through NetBird SSH, hold
`/var/lock/perf-bench.lock`, and keep the entire instance under
`/root/infraternal-bench/deploy/`. Prepare the server's private `data`, signed A
release, `bin/infraternal` and matching payloads, and live `web` there. It must
be running with an unlocked CA and an administrator session in process memory.
The client accepts `--staging --staging-pid <pid> --staging-port <port>` and
addresses that instance using `https://localhost` as its public origin.

Before a production deployment, measure A → B with the unlocked CA, concurrent
listener sampling and real retained sessions; confirm PID/image/CA identity and
measure listener gap. Exercise a signature-invalid image (preflight refusal),
then an authenticated unusable image or induced late exec refusal to demonstrate
verified rollback and retained CA. Record VM load, sample count and sampling
interval with the raw results. Run all timing work on the perf VM. The build
host's unit-test durations and mandatory gate diagnostics are not performance
evidence.

Owner D1 on #188 authorizes `staging-trust`, a **non-default** Cargo feature.
It requires `INFRATERNAL_STAGING_PUBLIC_KEY` to name a fresh public key at build
time. Production builds ignore that variable. No private key or permanent test
public key is committed. The normal static gate scans the final ELF before its
size check and refuses the staging authority marker, including stripped images.

Run `scripts/release/staging-proof` from this worktree on the build host. It
creates an ephemeral Ed25519 key under the job scratch directory, builds the
static staging image, signs A/B/C with the real v1 identity-bearing manifest
and SSHSIG format, and deletes the private key before transport. A and B execute
the same compiled program; B has an inert ELF trailer and a different signed
version/hash, so live-image confirmation cannot mistake A for B. C is a signed,
deliberately unusable ELF. The ARM file is a signed placeholder in this x86-only
fixture; it is never executed or a production release artifact.

The script waits up to 3600 seconds for the shared perf-VM lock (`flock -w
3600`, D256). Upload and extraction use the unique run directory before taking
the lock; only the native acceptance run holds it. Directory teardown follows
lock release. Every run gets its own directory, ephemeral loopback ports, CA,
data and transient systemd unit. Use `--scratch` to select the current job's
HOME-cache build directory and `--evidence` to retain a separate receipt without
overwriting an earlier run. `TRACER_TEST_PORT` selects that job's test port. A private `/run` mount
keeps shims out of the VM's global runtime directory. Setup reuses the real
software passkey fixture and encrypted CA copies; only one unlock ceremony is
performed. The administrator session remains in memory and private pipes.
The native test executable's existing runtime libraries travel beside it and
are deleted with the run; nothing is installed on the VM.

At 50 users, 10000 retained node records and 128 real PTYs, the fixture performs
12 alternating handoffs, confirms all surviving shim PIDs, checks unlocked CA
and exact executable hashes, then leaves B serving. It tests C refusal with
unchanged restart endpoint before shutdown and exercises the actual deploy
transaction's verified warm rollback. It checks the retained database's
integrity and row counts and verifies the retained rollback signature. All128
sessions must accept new input and return the expected output afterward.

Listener sampling uses nominal 1 ms intervals and records actual maximum sample
spacing. Each gap is a conservative bracket from the last successful connect
before refusal to the first success afterward; no observed refusal is reported
as zero at that resolution. p50/p99 use nearest rank over 12 brackets; p99 is
the maximum sample. This is listener availability, not end-to-end terminal
reconnect time. Raw VM output and machine/load context are written to
`$HOME/.cache/codex-scratch/deploy-pipeline/evidence/staging-proof.txt` by default;
`INFRATERNAL_EVIDENCE_DIR` overrides the evidence directory. The historical
committed staging receipt was removed under D262. The native fixture stops its
own transient unit and process group before
returning. After lock release, the runner removes its data, CA, executables and
runtime libraries and confirms the run directory is absent.

Functional packaging tests are `python3 scripts/release/staging_artifacts_test.py`.
The ordinary deployment suite covers WAL backup, framing, rollback, web-only
failure, capacity and pruning; those tests do not replace perf-VM acceptance.


# Production cut-over: orchestrator procedure, not executed by this job

1. Integrate reviewed changes onto `dev` and resolve every blocking gate,
   including the existing static-size ceiling. Run `scripts/verify fast` on
   the exact production candidate, require a production-trust PASS for both
   static architectures, and require break-it review with no P0/P1. A staging
   image or a size-failing gate receipt cannot be used for production.
2. Install the user builder unit on the build host only as an explicit
   orchestrator operation. Set the real repository path and the fixed starting
   dev ancestor, then run `systemctl --user daemon-reload` and
   `systemctl --user enable --now infraternal-release-builder.service`.
   Check its exact-head GATE/SOURCE receipts and both actual static payloads.
   This job has not installed that service.
3. Publish only the reviewed, gated dev candidate through the production
   release procedure in `docs/operations/release.md`. Place the returned public
   `MANIFEST` and `MANIFEST.sig` beside the **same bytes** in its local build
   cache. Production signing remains external. Never carry the staging feature,
   marker, test key or fixture artifacts into that cache.
4. Before the first administrative cut-over, confirm the production service
   has the reviewed round4 restart protocol, runs as root, has an unlocked CA,
   and has signed matching metadata for its current image. Confirm its data,
   binary/payload and web paths match the deploy entry point. If these
   prerequisites are absent, prepare a separate reviewed migration; stop/start
   cannot demonstrate D217 continuity.
5. Pipe the existing authorized administrator session from an in-memory caller
   into `scripts/release/deploy <full-dev-sha> --review-clear`. The orchestrator
   runs that command; this job does not. It performs the online backup and
   verified handoff, verifies live hash/health/unlocked CA, then atomically
   pushes the annotated production tag and fast-forwarded main. Keep its safe
   receipt, backup location and deployed SHA as the production record.
6. Check production health, unlocked CA, version, retained sessions and the
   production tag. On `deployed-unrecorded`, reconcile the existing running SHA
   and concurrent main update before recording refs; do not force-push. On a
   failed deploy, confirm the retained signed previous image serves with its
   CA unlocked. A dead/locked successor requires explicit cold recovery and a
   passkey unlock; never overwrite a live database.
7. D251 makes production follow edge. The existing declaration-backed setting
   is `infraternal server --data /var/lib/infraternal channel edge --yes`;
   confirm the selection with `infraternal server --data /var/lib/infraternal
   channel --json`. Only reviewed, gated builds may be published to that
   channel. Channel selection/download alone does **not** implement D251's
   quiet-window automatic application: enable that behavior only when its
   separate reviewed implementation is integrated. Thereafter administrative
   deploy is for initial cut-over or recovery; routine updates use the same
   verified CA-preserving handoff.
