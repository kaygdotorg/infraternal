<!-- Design and reproducible experiments for a non-default per-person session host [D268, #205]. -->
# One process per person login: research prototype

Status: opt-in research, not adoption. D13's default process per terminal remains
unchanged. D268 Q20 authorizes measurement; only the owner decides adoption or
changes D7/D13/D128/D240/D247. No new terminal engine or dependency was selected.

## Boundary and identity

`cargo build -p infraternal --features process-per-user` adds the hidden
`__shim --host-sessions N` option, with N from 1 through 1,000. The same binary
hosts the batch; normal `__shim` calls still create one process per session.
Every session retains its own mode-0600 socket under the mode-0700 runtime
sessions directory. The production decoder, SO_PEERCRED check, wire layouts,
capabilities, input cursors, writer handling, and PTY launcher are reused.
The existing `shim_frame_decode` fuzz target covers the unchanged parser.
SO_PEERCRED proves a local UID, not a person identity. People sharing an account
already share that account's Unix authority; the control plane must still bind
session IDs and revocation to the person, and never treat the UID as that binding.

The experiment accepts only the host's effective UID. It has no login
authority and does not alter the infraternal agent's launcher. An adoption
must key hosts by **(person ID, Unix account, host)**, never Unix UID alone.
Alice and Bob using the same account require two hosts and two real login
units (D240). Each host runs in the login's `PAMName=` systemd unit (D247),
with the host account's groups, limits and environment. Non-systemd hosts
must use the already-decided host `su`/`login` path. Merely dropping UID in
this measurement is not a PAM-login integration test.

A rootful integration also needs an explicit peer-authentication seam:
`infraternal-agent/src/sessions.rs::connect_with` currently accepts a shim peer
only if its UID is root or the infraternal agent's own UID. A host inside a
non-root account's PAM unit would be refused by a rootful infraternal agent.
Do not solve this by accepting arbitrary UIDs or trusting Hello. Bind the
expected host UID to authenticated person/account launch metadata, validate
that UID against SO_PEERCRED, and keep the root-owned discovery index separate
from the person's private socket/state directory. This is an adoption
integration requirement; frozen frame layouts need no change. Rootless
same-UID connections remain covered by the prototype.

The feature lives in the existing shim crate as a research implementation,
not a new shipping node component. Adoption must expose launch/lifecycle
through the SSH plugin and its shared action definitions (D198/D202), not
add a core role. No work starts when this feature is compiled out.

## State and idle behavior

One thread waits on indexed readiness for listeners, PTY masters and peer sockets. A session gets
at most one 16-KiB PTY read per reactor round. All ready input/control
requests precede bulk work; a global 16-read quantum rotates through sessions
so 1,000 flooding PTYs cannot monopolize one round.
Blocked/drained PTYs are omitted to prevent level-triggered HUP spin. Live
idle sessions have no timers: the readiness wait sleeps indefinitely until socket, PTY or
child-exit readiness. Exited sessions alone use the existing ten-minute
retention ceiling. Only coalesced child-exit readiness reconciles all owned children. Other events
visit ready sessions; unique registration keys prevent a reused descriptor from
inheriting a closed peer's readiness. Retired exit timers are discarded before
waiting, so live idle sessions do not inherit stale deadlines.

VT is initially absent. A complete origin prefix up to 4 KiB is retained.
Before its limit is exceeded, before snapshot, and before resize, the selected
production engine is allocated and fed the prefix at its historical geometry.
Materialization releases the prefix. Snapshot still retains unfinished parser
sequences. State never becomes an evicting raw-byte approximation. VT remains
allocated once materialized; dropping it would require exact state export.

The prototype divides **64 MiB of output-ring retention** and **64 MiB of VT
scrollback retention** over the initial batch. Each session gets the smaller
of its requested ring capacity and the host share; VT history is capped at
17 MiB per session. Screen pages, parser carry, writer queues, peers, snapshots,
allocator overhead and shell/kernel memory are additional. These limits bound
steady detached history, not total host RSS or repeated native allocation
failures. At 1,000 sessions each history share is 67,108 bytes. This is a
retention trade-off, not a free process-sharing win; a smaller ring triggers
more snapshots and provides less replay history. A production adoption needs
a dynamic byte pool and admission limits for aggregate peers/input too.

## Crash containment and revocation

Each session's reactor work is inside `catch_unwind`. A Rust panic or session
I/O failure removes that session, closes its peers/master/listener and retires
its owned shell. The partially mutated session is never reused. Other sessions
continue under ordinary child retirement. The prototype synchronously reaps
its own killed shell; an uninterruptible child exit can stall that reactor.
Adoption needs a nonblocking child reaper. A panic hook must never include PTY output or input in diagnostics.

One existing failure invariant becomes more expensive in a shared PID:
`terminal_native.rs` intentionally tombstones a native handle after any resize
error because native ownership may be partially mutated. Its abandoned native
allocations remain until process exit. Removing a Rust session from the pool
does not reclaim those abandoned allocations while sibling sessions keep the
host alive. Repeated native resize failures therefore invalidate a strict
whole-host memory bound. Adoption needs transactional native resize/ownership
or an isolated fallback/guardian design; the history caps alone do not fix it.

This does not isolate the native VT engine: a segmentation fault, abort,
allocator OOM or shared-process bug affects every session in that person's
login. A per-session-process fallback retains today's isolation but gives up
some shared memory. A monitored VT worker is another option, adding IPC and
state copies; no engine/process fallback was selected. The independent reviewer
must audit the native boundary and fallback criteria before adoption.

Revocation must target the **person login**, not every process with an account's
UID. The control plane first refuses new opens and cuts all of that person's
streams (including direct paths/leases), then stops only the person's login
unit/cgroup and retires its runtime sockets. Another person's login using the
same UID stays intact. The measurement host has no new authenticated management
channel or revocation integration; these stay with the existing authority.

## Restart and upgrade survival

Infraternal agent restarts need no PTY transfer: the session host stays alive
outside the restarting daemon's termination group, and the new infraternal
agent reconnects to the existing per-session sockets and durable input cursors.
Like today's shims, old hosts can retain their image until their sessions end;
new logins use the new image. Never stop the old host simply because a newer
infraternal agent arrives.

Replacing the **session host itself** requires an all-or-nothing handoff:

1. Authenticate a private inherited socketpair. Freeze the old reactor at a
   completed syscall boundary, including accepted input and output offsets.
2. Transfer every PTY master and listener, child identity/lifetime descriptor,
   accepted input/ownership segments, writer cursors/geometries, ring bytes,
   exit/retention state, and terminal/parser state with a versioned manifest.
   Large descriptor lists use numbered batches of at most 64; Linux's maximum
   is 253 descriptors per message ([unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html)).
3. Validate the complete manifest, unique session IDs, byte/resource bounds,
   ownership, descriptor types and exact state import in the replacement.
   A partial batch never authorizes dropping any original descriptor.
4. Acknowledge preparation for the whole host, transfer reactor authority once,
   then acknowledge commit before the old host releases originals. On refusal,
   timeout or pre-commit replacement crash, the old host resumes all sessions.
   Only one reactor may read/write any PTY at a time.
5. Reconnect viewers with their existing output/input cursors. Define child-exit
   status ownership explicitly: a replacement is not the shells' waitpid parent.

`send_masters`/`receive_masters` implement and test descriptor-lifetime transfer
with CLOEXEC through private datagrams, across multiple batches. They do not
implement the transaction or native state import. **FD transfer alone is not
upgrade survival.** The bounded repaint is not exact native state export (D110),
and retained raw bytes cannot reconstruct state after ring eviction or historic
resizes. Until exact import and exit-status handoff are available, keep old
hosts running; do not hot-replace them. A process crash still lacks an external
PTY guardian and cannot be represented as restart-safe. A guardian per person
would preserve descriptors but add one process/login and require independent
state/accepted-input ownership; this trade-off needs owner review.

## Reproducing measurements

Build on infraternal-dev into a job-specific cache target using the production
static-PIE recipe, then copy just the binary and `measure.py` through NetBird SSH
to `/root/infraternal-bench/process-per-user/`. Never build on the perf VM.
For each N in 1/10/100/1,000 and mode in baseline/host, run:

```sh
flock -w 3600 /var/lock/perf-bench.lock \
  python3 measure.py --binary ./infraternal --mode host --sessions 100 \
  --state ./s --samples 1000
```

Use a short unique absolute state path. The harness records binary digest,
machine/kernel/CPU count and load with every sample. It separately reports
host PSS/RSS/anonymous memory, shell PSS, thread count, and per-session host
values. Kernel PTY cost is additional; prior #205 measurements put it near
27.9 KiB/session. Idle sampling records CPU ticks and context switches over
five seconds. Light output emits one line/session/second for five rounds.
All sessions receive ten seconds of sustained background output at N=1/10/100
and in the pooled N=1,000 case. The default N=1,000 baseline instead emits a
finite 32-KiB burst per session; it is explicitly marked non-sustained, not a
worst-case equivalent. `--sustained-baseline` enables a separate memory-contained
capacity run. Each run uses a unique private scope capped at 5 GiB with no swap
and whole-group OOM termination, leaving room on the 7-GiB target. The scope's
outer interrupt timeout bounds each flood below two minutes. Output-byte
counters accompany CPU samples so lower CPU is not confused with throughput. Echo timing recognizes
a marker generated by the shell's printf, not the input's terminal echo.
Hello/snapshot/input-to-output latency is local shim overhead, not browser
input-to-photon or a full direct/relayed network measurement.

Memory and latency profiles run in separate fresh fixtures: snapshot/echo
sampling materializes VT and must not contaminate idle/light memory rows.
`test_measure.py` tests markers inside large output frames and across frame
boundaries; the detector searches the whole frame before retaining its suffix.
Snapshot timings negotiate approximation and count flagged replies; errors
never count as snapshots. Shell and output-generator PSS are additional rows.

Raw receipts, measured numbers, trade-offs and final gates live on
[issue #205](https://git.kayg.org/kayg/infraternal/issues/205), outside this
checkout (D262). Run the copy/locked matrix wrapper with the opt-in static image,
a job evidence directory, and a distinct default-feature static image:

```sh
bash research/process-per-user/run-matrix.sh \
  "$HOME/.cache/codex-scratch/process-per-user/evidence/infraternal-prototype" \
  "$HOME/.cache/codex-scratch/process-per-user/evidence" \
  "$HOME/.cache/codex-scratch/process-per-user/evidence/infraternal-baseline"
```

## Adoption checklist

- Preserve D240 person/account isolation and prove the real PAM unit path.
- Test real infraternal agent restart and all launch/discovery paths, including
  multiple session identities sharing one Hello PID.
- Test Rust panic containment and document native faults/OOM honestly.
- Prove revocation cuts only the intended person login and all its routes.
- Complete exact whole-host state/FD transaction and child status ownership
  before claiming host replacement survives upgrades.
- Measure idle/light/sustained-flood PSS, aggregate peer/input bounds and typing
  p99 at 1/10/100/1,000 on the perf VM; compare like retention as an ablation.
- Audit unsafe descriptor ownership, malformed ancillary data, failed startup,
  peer replacement/deferred inputs, ring eviction, resize and final exit.
- Keep ASLR and production defaults; independent review precedes adoption.
