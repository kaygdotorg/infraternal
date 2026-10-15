<!-- Design and reproducible experiments for a non-default per-person session host [D268, #205]. -->
# One process per person login: research prototype

Status: D270 selects this design for hardening. The prototype remains opt-in;
D13's default process per terminal is unchanged. D268 Q20 and D270 authorize
measurement and hardening, without changing D7/D13/D128/D240/D247. No new
terminal engine or foundational dependency was selected.
The r4 measurements have not admitted the mixed-soak latency or whole-host
upgrade path. Passing focused tests and the cold-history footprint does not
authorize adoption. Current results and failures are recorded on issue #205.

## Boundary and identity

`cargo build -p infraternal --features process-per-user` adds the hidden
`__shim --host-sessions N` option, with N from 1 through 1,000. The same binary
hosts the batch; normal `__shim` calls still create one process per session.
Launch must occur in a single-threaded process. The research entry checks
`/proc/self/task` before changing signal masks, binding sockets or creating
PTYs: an unblocked sibling thread could consume process-directed SIGCHLD
instead of the reactor's signalfd. Reliability tests launch the real host through
a standalone feature-gated example, outside the threaded test harness.
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
one bounded PTY read budget per reactor round. Incoming input and promoted
short replies use at most 4 KiB; a rotating bulk turn reads at most 16 KiB across
four nonblocking attempts, then feeds the parser and ring once. Ready input/control
requests precede that queue; a global one-bulk-session quantum rotates through
sessions so 1,000 flooding PTYs cannot monopolize one round.
Attached PTYs with at most 1 KiB waiting are promoted ahead of that queue using
a non-consuming readiness hint. Detached producers avoid that classification
syscall. Read-attempt deduplication prevents a promoted session from spending
another budget through an older bulk entry. Slot-indexed membership uses one
byte for queued/cancelled bulk work and a four-byte read generation per session.
Generation wrap clears old read marks before reuse. A promoted entry can be
revived in place; cancelled entries are discarded when popped, without scanning
the whole bulk backlog on every turn. PTY and viewer backpressure keep bulk
producers from allocating an unbounded transmit queue.

A session's first two ready descriptors stay inline in its readiness row;
additional descriptors use a bounded spill list whose capacity survives the
next turn.
Rows are indexed by immutable session slots. A current-generation active list
visits only touched rows, and generation wrap invalidates every old row before
reuse. Descriptor registrations keep the fd only in their generation key and
use a checked 16-bit session index under the 1,000-session admission ceiling.
Registration updates and peer readiness borrow arrays sized by the existing
32-peer admission cap. Healthy peer sockets flush immediately:
each housekeeping visit shares a 32-KiB/four-write budget across pending, state
and output frames. Partial frames retain their byte cursor and ordering; logical
replay work keeps writable interest after an inline frame has drained. Large
completed repaint buffers release storage before an indefinite idle wait.
Retained output is borrowed across physical ring wrap and encoded directly
into that peer's reusable wire buffer. A partial frame keeps stable bytes while
the ring changes; no borrowed ring pointer survives the housekeeping visit.
Ready rows and work lists reuse bounded host-wide capacity between turns.
Ordinary PTY-plus-viewer readiness requires no transient allocation, and the
indexed rows plus active indices reserve at most 64 requested bytes per slot.
This host-wide ownership is included in the independent PSS slope, separately
from the per-session terminal ledger.
Blocked/drained PTYs are omitted to prevent level-triggered HUP spin. Live
idle sessions have no timers: the readiness wait sleeps indefinitely until socket, PTY or
child-exit readiness. Exited sessions alone use the existing ten-minute
retention ceiling. Only coalesced child-exit readiness reconciles all owned children. Other events
visit ready sessions; live child status is polled only on exit readiness or a
drained PTY. One descriptor index carries generation-checked registration keys,
preventing a reused descriptor from inheriting a closed peer's readiness. Retired exit timers are discarded before
waiting, so live idle sessions do not inherit stale deadlines.

VT is initially absent. A complete origin prefix up to 4 KiB and at most 32
ordered resize events are retained. Reaching either bound or requesting a
snapshot allocates the selected production engine at the original geometry,
then replays each byte range and resize in order. A quiet terminal can therefore
change geometry without allocating native screen pools. Materialization releases
both transcript buffers. Their capacities are charged to the session budget;
numeric receipts expose resize-event capacity as `geometry_bytes`.
Snapshot still retains unfinished parser
sequences. State never becomes an evicting raw-byte approximation. VT remains
allocated once materialized; dropping it would require exact state export.

The prototype divides **64 MiB of output-ring retention** and **64 MiB of VT
scrollback retention** over the initial batch. Each session gets the smaller
of its requested ring capacity and the host share; VT history is capped at
17 MiB per session. Screen pages, parser carry, writer queues, peers, snapshots,
allocator overhead and shell/kernel memory are additional. These history
shares are retention limits, not a total host RSS budget. At 1,000 sessions each history share is 67,108 bytes. This is a
retention trade-off, not a free process-sharing win; a smaller ring triggers
more snapshots and provides less replay history. A production adoption still needs a dynamic whole-host byte pool and admission
limits against the machine budget, including shell and kernel PTY memory.

The opt-in native page quantum is 80 columns by 32 rows, with one preheated
pool item. Larger geometries still use the existing capacity/reflow algorithm.
This removes the large minimum pool that otherwise multiplies small retention
shares. Rings never round a non-power-of-two host share beyond its byte limit.
Small shares reserve their full bounded capacity after the first 4 KiB of
output; this settles residency during activity rather than touching more ring
pages gradually over hours. Larger rings grow lazily within the same limit.
Empty appends allocate nothing, and the last viewer's removal releases vacant
peer slots. First attachment reserves only the next peer record. After binding,
the socket owns its full pathname; the session releases its separate startup
directory copy.

## Ownership diagnosis and idle bookkeeping

`__shim --host-sessions N --host-accounting PATH` optionally creates a new
mode-0600 numeric receipt file. An explicit SIGUSR2 request records each
session's native ordinary, mapped, resident and encoded bytes, carry/prefix,
ring, input/writer and peer capacities. Mapping residency uses `mincore`
without faulting in payload pages. No terminal content is recorded. Existing
files are refused before PTY creation; a write failure disables only the
receipt. Without the option there is no file, profiling timer or signal work.

The `idle_session_ownership_ledger` ignored unit probe runs at 1, 10, 100 and
1,000 sessions on the perf VM. It separately counts the session vector,
constructor paths/cursors, lazy prompt/raw ring, retired viewers, and indexed
descriptor registrations. Its test allocator forwards unchanged allocation
layouts. Requested owned bytes, allocator resident slack, fixed executable
pages, shell processes and kernel PTYs are distinct costs; total host PSS
divided by session count cannot identify the incremental idle-session floor.
The byte ledger and paired before/after PSS receipts are on issue #205.

## Compact cold history experiment

`compact-history` is a separate build feature that requires `process-per-user`;
both remain disabled by default. Cold pages store bounded UTF-8 blocks and
run-length raw cell attributes. Reversible codepoint deltas between
physical rows and XOR against canonical row offsets expose repetition to the
existing codec while preserving arbitrary row permutations. Codepoint deltas
are used only when every delta is a valid Unicode scalar. A bounded outer
compression pass uses spare caller scratch and never nests on decode. Nontext union bits, wide cells, graphemes,
styles, links, protection and opaque native metadata remain exact. Invalid
text falls back to the existing codec. Allocation-free decoding rejects bad
dimensions, run counts, UTF-8, truncation and trailing bytes; native tests
include a coverage-guided malformed-input target.
The outer envelope is eight bytes and accepts at most 32 KiB of plain codec
data. Larger pages can still use the plain bounded format. Sparse native pool
mappings request `MADV_NOHUGEPAGE` before publication: touching one live page
must not promote an otherwise cold reservation into a huge resident page.
This hint changes neither allocation addresses nor their charged reservation;
failure leaves correctness intact. Ordinary heap allocations are unaffected.

Encoded copies have a separate charged history share. An opportunistic
encoding refusal keeps the original page and its exact-state certificate.
Virtual page reservations remain for infallible restore; their ownership and
resident backing are reported separately. One candidate is compacted after
each nonempty write. The direct-terminal resident probe explicitly requests
full compaction, whereas the reactor currently has no idle continuation.
Snapshot/search/reflow can restore cold pages; a full-compacted measurement
does not prove the same retained footprint after those operations.

The fidelity fixture verifies every numbered 72-column line in 10,000-line
history, full replay, reconstructed search/selection spans and reflow. Another
fixture checks Unicode, styles and links before and after future input. The
paired resident increment excludes the raw wire ring. Its comparison with
the published reference, allocator/header breakdown and limitations are on
issue #205; no reference-memory parity is assumed.
These direct-terminal fixtures use a 17-MiB history share for each terminal.
They do not use the shared host's divided 64-MiB pool; that smaller per-session
share must be disclosed when interpreting real-host retention and viewer costs.
The standalone `scripts/bench/ppu-fuzz-build --compact-history` option enables
the codec in the existing bounded real-terminal parser fuzz harness. Build it
through the build slot into job scratch, then run its campaign on the perf VM.

`scripts/bench/ppu_idle.py` independently measures host PSS at 1/10/100/1,000
sessions and separates fixed image residency from the session slope. It records
native ownership, zero-work idle windows and a separately fenced raw-kernel PTY
probe. Requested bytes and allocator resident pages are distinct measurements.
`scripts/bench/ppu_trace.py` records only numeric scheduler transitions and
syscall names/timestamps in a private trace instance, flags overflow, and labels
its runs diagnostic. Tracing changes the workload's timing and cannot be used
for admission. `ppu_delivery.py` correlates successful sends to the fixture's
own sockets with those same probes. It decodes decimal event fields and the
syscall printer's hexadecimal fields separately, discards raw arguments, and
refuses a run with no correlated writes. Its conservative reader-delay bounds
cannot be subtracted from admission latency.
`ppu_raw_echo.py` compares the same synthetic shell markers over
direct masters; its different reader prevents treating that result as a hard
latency lower bound. The unchanged two-hour `ppu-run --phase soak` remains the
admission workload. Before/after tables and raw receipts live on #205.

The native `ppu_wire_probe` example is a diagnostic observer. It opens additional
viewer sockets with a distinct durable writer, finishes setup before timing,
and checks output offsets and shell-generated markers. Those extra connections
change the workload, so it cannot replace the original soak's admission result.

The long soak runner now retains the same fixture across short locked segments.
An external coordinator confirms that its private cgroup is fully frozen,
releases the perf lock, then reacquires it before thawing. A shared numeric clock
subtracts only the certified frozen interval from fixture deadlines and probes.
The receipt preserves wall times and every freeze/thaw; the active duration is
not uninterrupted wall time. No workload runs while another job owns the lock.
Resume transitions remain visible when interpreting latency. A failed
coordinator thaws and retires only its own named scope, never another job's.

`scripts/bench/ppu_viewers.py` measures additional native viewers with 50
filled terminals. Each viewer has one distinct writer/socket on every
terminal, drains continuously and must observe every typed marker. Receipts
separate attach/repaint fences, idle CPU ticks, resident increments and echo
delivery. This is host-side socket cost: it excludes browser, shell and kernel
memory. The fixture validates all fill output but discloses bounded retained
history rather than claiming that each terminal still holds every fill line.

## Crash containment and revocation

Each session's reactor work is inside `catch_unwind`. A Rust panic or session
I/O failure removes that session, closes its peers/master/listener and retires
its owned shell. The partially mutated session is never reused. Other sessions
continue under ordinary child retirement. The prototype synchronously reaps
its own killed shell; an uninterruptible child exit can stall that reactor.
Adoption needs a nonblocking child reaper. A panic hook must never include PTY output or input in diagnostics.

Shared terminals own every native allocation through a stable boxed allocator.
The ordinary hard per-terminal reservation ceiling is **8 MiB**, including transient
allocations, intrusive ownership headers and mapping prefixes. Ordinary native
payload/metadata allocations share a **256 KiB** ceiling; explicitly tagged
page-pool allocations use the remaining reservation. Size/alignment alone
cannot identify a page request. Native page backing is zero-filled anonymous
memory, and its complete mapping is charged before allocation.
With `compact-history`, the reservation ceiling additionally permits twice the
configured history share for cold-page virtual mappings and exact restore.
Encoded bytes still have their separate charged history share. This larger
virtual reservation is bounded and is not resident-memory savings by itself.

OSC, DCS, APC, PM and SOS strings forward at most **4 KiB** to the native
parser. Excess payload is discarded until the true terminator. The limiter
retains syntax across fragmentation, UTF-8/C1 controls and an ST split between
ESC and backslash; early cancellation would render the discarded suffix as
text when a viewer continued a snapshot. Allocation refusal makes snapshots
explicitly approximate. A native resize error releases the terminal's owned
allocation list without traversing a potentially damaged native graph. The
default per-session implementation keeps its existing native behavior.

Shared-session pending input remains capped at **1 MiB**, with at most
**1,024 ownership segments**; a refused new segment cannot advance an input
cursor. Aggregate decoder, trailing and queued-transmit buffers across one
session's peers are capped at **4 MiB**. Completed oversized transmit buffers
release their capacity. The reactor accounts native ownership, lazy prefix,
parser carry, ring capacity, input capacity/cursors/segments and peers against
**16 MiB plus the configured retention shares** per session. This accounting
bounds in-process ownership; it does not include the person's shell processes,
kernel PTYs or allocator-wide resident fragmentation.

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
