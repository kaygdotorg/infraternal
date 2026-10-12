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

Failure restores the previous web and installed links and requests the retained
signed previous image through the same verified handoff. A database is never
overwritten while the server is running. The retained snapshot supports a
separate, explicit cold data recovery. If the successor loses CA custody or
exits, automatic rollback cannot recreate the unlocked key; the deploy reports
failure and requires operator recovery. It never reports a locked rollback as
successful. No journal or authentication response is printed.

Only after remote acceptance does production get an annotated
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

This job's acceptance is pending the signed A/B artifacts. Its functional suite
exercises real WAL backup and Unix framing plus controlled rollback, web-only
failure, status ordering, capacity admission and pruning. These checks do not
substitute for the real staging deployment.
