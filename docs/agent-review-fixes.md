<!-- Local regression, benchmark and gate evidence for the infraternal agent review fixes [5][13][40][41][75][81], issue #20. -->
# Infraternal agent review fixes — #20

Review baseline: `947d68f02d787fea54dec33898418651d65fdf74`.
Implementation, regression and benchmark head: `5ee58480e5face8cfaf368bae0a2cdf2a77f3fe8`
on `t-agent`. The report is committed separately. The issue records the final
head and verbatim fast-gate output. Evidence paths below are relative to this
worktree, retained under `target/review-fixes/` rather than tracked binary artifacts.

R1–R3 and R4's secondary copies, buffers, reads and credit grants are addressed.
The VT engine and row clearing belong to the separate `spike-vt` work. Decisions
and performance thresholds have not changed. The local LF throughput check and
existing standalone shim memory guard still fail; this report does not establish
merge readiness or the pinned performance-VM budget.

| Finding | Implemented rule and deterministic evidence |
| --- | --- |
| R1: full terminal queue blocks shared dispatch | Eight-slot command admission never waits in shared dispatch. Overload sends a stream-local Close and cancels that shim attachment, including a stalled handshake. The viewer reattaches and replays unacknowledged input from shim-owned cursors. A held real State reply plus nine commands now permits sibling output and Pong before release in **3.647 ms**. Twelve saturated attachments replay **2,640,000 bytes exactly once**, with a stopped shim isolated. |
| R2: insufficient Snapshot credit stalls the PTY | `contracts/wire.md` §6 defines one bounded repaint debt with positive usable credit. Grants repay debt before raw Output or another Snapshot. Zero usable credit arms the same 250 ms pending-output detach deadline; partial repayment cannot extend it. Four **12 MiB** shell floods complete, with three **27,580-byte** catch-up Snapshots funded by one usable byte each, followed by an initial ring-wrap attachment at **seq 50,333,127**. Unit cases cover zero credit, insufficient initial repaint credit, exact repayment, oversized repaints and the unchanged deadline. |
| R3: retained unwritten input breaks restart attachment | The State exchange consumes monotonic Acks until State and validates `Ack <= written <= accepted`, with a two-second total deadline. A FIFO blocks the shell from reading; the proxy observes **accepted=524,614, written=12,102**, proving **512,512 surviving unwritten bytes** before the abrupt stop. After restart it holds StateRequest until a real PTY-write Ack interleaves. The **524,288-byte** payload and replay fence arrive exactly once. |

Test-first failures are retained in `r1-before.log`, `r2-before.log`,
`r2-unit-before.log` and `r3-before.log`. The corrected production-binary results
are `r1-release.log`, `r2-release.log` and `r3-release.log`; saturation/replay is
`r1-queues.log`. Rust's normal fast gate invokes the new real-process probes
through `crates/infraternal/tests/agent_review.rs`. Process-termination results
use neutral abrupt-stop/restart wording.

The independent writer remains an eight-slot ownership boundary. Full owned
Output payloads transfer to it; overlap or partial credit still copies the
required suffix. Borrowed Reader payloads remain valid until the next read;
owned compatibility callers explicitly convert before crossing a task boundary.
The shim consumes borrowed input immediately into its surviving bounded queue.
Its pending encoder reuses validated capacity, and its poll descriptors occupy
at most four stack slots whose borrows end before peer replacement. PTY draining
stops at 16 KiB, ring capacity, 16 read attempts, or WouldBlock; it never waits to
fill a batch. No buffer pool, new periodic timer or unbounded channel was added.

| Secondary measurement | Before | Retained path | Evidence |
| --- | ---: | ---: | --- |
| Owned 16 KiB relay allocation/forward path, 100,000 iterations | clone 3,899.5 ns/frame | move 2,078.5 ns/frame | `move-bench.log` |
| 16 KiB decode, seven samples × 100,000 frames, median | owned 302.1 ns/frame | borrowed 3.9 ns/frame | `codec-after-repeated.log` |
| Incremental 16 KiB feed | reviewed bytewise owned 42,051.7 ns/frame | contiguous owned median 906.3; borrowed 209.1 ns/frame | `codec-before.log`, `codec-after-repeated.log` |
| Encoder, seven samples × 100,000 frames, median | fresh 470.4 ns/frame | reused 326.3 ns/frame | `codec-after-repeated.log` |
| Async socket write/receive, five samples × 10,000 frames, median | owned 5,230.0 ns/frame | borrowed 4,584.0 ns/frame | `reader-bench.log` |
| Four poll-descriptor constructions, 1,000,000 iterations | heap 30.8 ns/turn | stack 1.5 ns/turn | `poll-bench.log` |
| Credit frames for 50 MiB CRLF | per-fragment 12,895 | 64 KiB batches 757 | `credit-count-per-frame.log`, `credit-count-64k.log` |
| 50 MiB CRLF calls traced on daemon/shim only | pre-drain pump 164,910 | 54,292 (**67.1% fewer**) | `syscalls-pump.log`, `syscalls-after.log` |
| Same trace: poll / sendto / PTY read calls | 25,623 / 25,625 / 12,811 | 6,445 / 6,447 / 15,686 | same logs |

Read attempts increase because Linux returns smaller pieces, while multiplexed
output chunks approach 16 KiB and require fewer poll/send/receive turns. Traced
throughput is perturbed: 5.678 to 7.001 MiB/s. Credit batching has inconsistent
throughput comparisons under contention, so the evidence establishes fewer
credit frames, not a stable throughput gain. The asynchronous Reader benchmark
measures the optional borrowed path; queued writer messages still require ownership.

Owned/borrowed differential ASan fuzz completed **100,000 runs** without a finding
(`codec-fuzz-no-lto.log`). The default fat-LTO fuzz build failed to link sanitizer
coverage symbols (`codec-fuzz.log`). The successful command disables LTO only for
the fuzz harness, preserving production optimization:

```sh
CARGO_PROFILE_RELEASE_LTO=false cargo +nightly fuzz run shim_frame_decode -- -runs=100000
```

Fragmentation, coalescing, malformed/oversized frames and receive cancellation
also have deterministic tests. Fuzz coverage here concerns framing and
owned/borrowed agreement; it does not prove queue or PTY delivery semantics.

The full final production fixture (`release-final.log`, seed 21) verifies
**24 abrupt stops/restarts**, four positions × six, and **6,222,717 payload bytes
exactly once**. Its 1,000 input-to-PTY Ack samples have **p50 79.709 µs, p99
197.446 µs**; Ack latency is an upper bound for actual PTY write latency. The
credit-starved 50 MiB test reaches **seq 104,858,502**, produces a **27,579-byte**
Snapshot, and peaks at **4,088 KiB daemon RSS**. These are one-session measurements,
not a populated 50-session queue or flood-latency guarantee.

| Workload, three 50 MiB runs with ample batched credit | Before secondary fixes, median MiB/s | Final median MiB/s |
| --- | ---: | ---: |
| Exact LF flood | 3.352 | **4.426** |
| CRLF diagnostic | 8.317 | 12.076 |
| Printable diagnostic | 21.491 | 30.653 |

`output-before.log` and `output-after.log` contain all samples. The before binary
is the correctness baseline copied after the relay fix; the trace isolates the
read change using the pre-drain pump binary. This eight-core host had concurrent
work and observed load averages from roughly 5 to 15.5. These local samples are
not isolated hardware results and do not attribute the whole throughput difference
to the code. Diagnostic workloads never substitute for LF in the budget check.

The explicit decision-41 LF check fails at **4.295 MiB/s**, exit 1
(`lf-budget.log`); the required 10 MB/s is approximately **9.537 MiB/s**:

```sh
python3 scripts/bench-agent-output.py \
  --binary target/x86_64-unknown-linux-musl/release/infraternal \
  --runs 1 --batched --workload LF --enforce-budget
```

The retained secondary changes have measured copy/allocation/traffic benefits.
The LF deficit still requires the VT spike and the performance gate on its
intended VM. No throughput threshold was loosened.

A settled **30-second** idle check records unchanged daemon and shim CPU ticks
at `[0,0]`, daemon RSS **3,852 KiB**, and shim RSS **5,872 KiB** (`idle-final.log`).
The existing standalone `<4096 KiB` shim guard fails (`shim-idle-final.log`). The
reviewed baseline also measures about **5,736 KiB** in the same open-idle fixture
(`idle-baseline.log`), so the shim's memory deficit is already present. The idle
result establishes zero observed CPU ticks and the daemon's idle budget; it does
not claim the shim memory guard passed or override its scrollback qualification.

Every logical commit has the prescribed fast gate, with per-step logs:
`r3-gate.log`, `r1-gate.log`, `contracts-gate.log`, `r2-relay-gate.log`,
`r2-daemon-gate.log`, `move-gate.log`, `codec-gate.log`, `reader-gate.log`,
`pump-gate.log`, `read-gate.log`, `regressions-gate.log` and `bench-gate.log`.
The final report commit uses `final-gate.log`. Run:

```sh
nix shell nixpkgs#binutils nixpkgs#file nixpkgs#gnumake nixpkgs#perl -c scripts/verify fast
```

No push or deployment was performed; #20 remains open. The final head and full
fast-gate output are posted there after this report's gate and commit.
