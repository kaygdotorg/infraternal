<!-- Role: Reproducible comparative measurement method for #260; no product changes. -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Head-to-head measurement kit

Research only. The owner decides product changes from measurements. Tracking: #260;
mesh path decisions D313/D316. The product source baseline is `a4f15f8f7` plus
the research branch; `SOURCE_COMMIT` and `MANIFEST` identify each kit.

## One copy, from dev

This directory on `dev` is the only versioned copy of the kit (#260). The deployed copy on
backup01 (`~/.cache/codex-scratch/j88c/kit`) must be refreshed from `dev` and never edited by hand.
Its Python tests run in every `scripts/verify fast` ("head-to-head kit tests").

## Build and run

On compute01, enter the `nix-devshell` flake with Go and Bison available, then run
`~/infraternal-ops/build-slot research/head-to-head/build-kit x86_64 OUT`.
Use `CARGO_BUILD_JOBS=4` and a job-specific `CARGO_TARGET_DIR`. The build uses
the product's static musl recipe, its pinned Zig, checked-in Rust/Go locks,
and the official downloads and checksums in `pins.txt`. The legacy standalone
R4b GotaTun and BoringTun reference rows retain their pinned release inputs.
The matrix takes one executable for every GotaTun source variant. Build the
shipped baseline `84b7bb28e385d57dfb80493e78202898fad24d1e`, J88i
`33ca6fe616587db506b16612f2a4b5bbd54997f3`, and each later pushed candidate
from its exact full SHA on compute01. Pass each executable and matching source
SHA as `--gotatun-binary ID=PATH` and `--source ID=SHA`; never substitute the
active fork head for the shipped baseline.
tmux is built from verified official sources because it has no official
static binary.

Copy the archive and its `.sha256` to the perf VM, verify with
`sha256sum -c ARCHIVE.sha256`, and unpack. As `claude`, run
`bash perf-all.sh` in the kit directory. An optional list selects cases:
`bash perf-all.sh mesh-underlay term-local`. Each case has its own
`perf-run --root` hold, including the snapshot, measurement and cleanup.
The outer wrapper pins the run to perf.slice (CPUs 1–3, 6 GiB); the kit
does not take a second lock or create another scope in this mode.

`run.sh --smoke` reduces sample counts and durations. Smoke runs and all build
VM timings are functional evidence only. Never compare them with perf VM results.

## D348 engine and source matrix

The matched matrix compares plain kernel WireGuard and wireguard-go against
source-labeled GotaTun variants at MTU 1420 with common probes and the same
placement audit. The production baseline is GotaTun
`84b7bb28e385d57dfb80493e78202898fad24d1e`, labeled `GotaTun (shipped,
84b7bb2)`. The J88i fairness candidate is
`33ca6fe616587db506b16612f2a4b5bbd54997f3`; it includes J316's GSO negotiation
commit `ebeb8f0071c4103168b570407f9dc555562f4b79`. J316 is pinned at
`b6789348aea23216e0be06e93d44d6f5239318b3`; the pushed J225 stack is
`21a8a1589ab198e0af171aee3e7147a4b38710d0`. J316's checksum fix is pushed separately as
`f3197d046f385d38c39210dec651e0ba8e096b12`; it is not yet in either listed
source tree. The b678934 and 21a8a15 rows are pre-fix historical sources,
not current measurement candidates. Wait for J225's rebase and 1-flow
smoke handoff before measuring the stack. The full alias
`2bb5347a8cddf3c31df64be1f52466e1a02bf75b` changes only an equivalent Rust
return-expression spelling in the GotaTun data path; it is recorded as an
alias and measured once.

Every source variant receives five repetitions. Run one calibration or one
scenario window at a time through `perf-all.sh`; `perf-run --root` takes the
shared `/var/lock/infraternal-perf.lock`. Announce each window on #260 first
and keep it under 20 minutes.

Start once with `python3 -I lib/matrix.py run --kit "$PWD" --scenario
best-lan --gotatun-binary gotatun-shipped-84b7bb2=PATH
--gotatun-binary gotatun-j88i-33ca6fe=PATH --source
gotatun-shipped-84b7bb2=84b7bb28e385d57dfb80493e78202898fad24d1e --source
gotatun-j88i-33ca6fe=33ca6fe616587db506b16612f2a4b5bbd54997f3 --wg-bin PATH
--wireguard-go-bin PATH --out RESULTS --calibration-only`. This calibrates on
the shipped executable. Then run batches 1–5 for each scenario with the same
paths and output directory, adding `--no-calibrate --batch N`.
`python3 -I lib/matrix.py list` prints the scenario catalog. A failed
calibration remains failed; owner-directed rows use the exact
`uncalibrated, owner-directed` label and show measured and owner-reported
spreads.

### In-app A/B (the product binary)

`perf-all.sh --calibration` and `--ab` measure the GotaTun CLI by default. Set
`H2H_AB_ENGINE=infraternal` and give every row the engine `infraternal`
(`--row control-a=infraternal --binary control-a=PATH --source control-a=SHA`)
to run the in-app `mesh-infraternal` case with each row's own `infraternal`
binary instead. Pinning, probes, the outlived-load guard, the calibration
spread and the pooled analysis are the same, so an in-app A/B has the same
calibrated method as a CLI one. One engine per run: a mixed set of rows is
refused before the lock, and `calibration-spread.json` is read from the
`mesh-infraternal` case directory. Each row's version note records the row
binary and source SHA, not the kit's `SOURCE_COMMIT`. (J610, #260.)

The in-app daemon paces ping more slowly under load than the CLI. With pinned
cores it sends about 110 probes/s at 8 flows, so the 8,000-probe default takes
72.5 s and the fixed 72 s load trips the probes-outlive-load guard (D345). The
`mesh-infraternal` case therefore sizes its load from the probe count:
`ceil(H2H_LAN_PING_COUNT / H2H_LAN_MIN_PROBE_RATE) + H2H_LAN_LOAD_MARGIN`
seconds, defaults 110 probes/s and 10 s, so 8,000 probes get an 83 s load. The
result is never below 72 s, smoke keeps 4 s, and an explicit
`H2H_LAN_TPUT_SECONDS` always wins. If a run still trips the guard, lower
`H2H_LAN_MIN_PROBE_RATE` instead of weakening the guard. GotaTun rows keep the
fixed 72 s.

### Cross-engine head-to-head (J638)

One hold compares different engines: `perf-all.sh --mixed --label HOLD --row
TAG=ENGINE ...` runs two to four different engines, each once, in the given
order. Each row is a calibration-shaped LAN window (8,000 probes, 1 and 8
flows) inside one `perf-run`, followed by the usual restore check. Four rows
fit the 17-minute hold cap (J629's took 13m15s). GotaTun and in-app rows need
`--binary` and `--source`. Row engines are `gotatun`, `kernel-plain` (kernel
WireGuard), `kernel` (NetBird with kernel WireGuard), `netbird-userspace`,
`tailscale`, `infraternal` (in-app), `wireguard-go` and `underlay`.

Give the holds a Williams Latin-square order:
`python3 -I lib/latin_square.py G K N I` prints one order per hold. Every engine
takes every position, and directly follows every other engine, equally often
(n holds for an even n, 2n for an odd n). Pool the holds with `python3 -I
lib/head_to_head.py CALIBRATION/calibration-spread.json HOLD...`. A difference
counts only if every hold agrees in sign and the mean is larger than the GotaTun
calibration spread for that metric. Run `perf-all.sh --calibration` first for
that spread. A missing row is named, never zero.

**Read Gbit/s per busy core first.** Kernel WireGuard queues its encryption and
decryption with `queue_work_on()` on a CPU chosen round-robin from
`cpu_online_mask` (`wg_cpumask_next_online`, drivers/net/wireguard/queueing.h).
That work runs on per-CPU kworkers, which cpusets, the workqueue cpumask, RPS/XPS
and IRQ affinity cannot move. So kernel WireGuard and NetBird's kernel mode also
use the housekeeping CPUs 0 and 5: J629 measured them at 46–95% busy there,
against 0–5% for userspace engines. Only offlining CPUs or isolcpus could stop
that, and both are host changes. The kit measures instead. Every audited window
writes `cpuset-*/cpu-split.json` (`lib/cpu_split.py`): busy % per CPU and busy
cores on side A, side B and housekeeping (user+nice+system+irq+softirq; steal
is reported separately). The pooled report divides Gbit/s by the whole machine's
busy cores, and prints the split beside every row. Raw Gbit/s and loaded p99
for the kernel engines therefore come with up to six cores behind them; the
per-core figure is the fair comparison.

Placement of each engine:
- **In-app:** `lib/mesh_ix.py` runs in side A and starts both infraternal
  nodes. Once the pair is up, `cases/mesh.sh` moves node B's process tree into
  a new side-B scope (`h2h_scope_adopt`), verifies its CPU list and records it
  in `cpuset-pids.tsv`. Before J638 node B stayed on side A's CPUs. J610's and
  J618's in-app absolute numbers therefore had half the CPU budget; their A/B
  deltas compared like with like and still stand.
- **Tailscale and NetBird userspace:** each side's daemon runs in that side's
  scope. Their coordination processes (test control and DERP, NetBird server)
  run in `h2h-c`, which maps to side A, as for NetBird's kernel row. They are
  idle once the path is direct.
- **Load length:** these two rows, like in-app, size their load from the probe
  count (`H2H_LAN_MIN_PROBE_RATE`, default 110/s). A daemon that slows ping
  under load must not fail the outlived-load guard by design. GotaTun and the
  kernel engines keep the fixed 72 s.

### Bufferbloat profile (D381)

`perf-all.sh --bufferbloat --profile fifo|fq_codel --label HOLD --row bare=underlay
--row g=gotatun --binary g=PATH --source g=SHA --row k=kernel-plain --row w=wireguard-go`
runs the home-router profile (`lib/bufferbloat.py`, first built by J512) in the
D348 pinned runner, one profile per hold, in about six minutes. The topology is:
endpoint A (home) → router namespace → endpoint B.
- **Delay and shaping:** each endpoint egress adds 6 ms of netem delay. The
  router shapes egress to A at 481.5 Mbit/s (download) and to B at
  778.9 Mbit/s (upload): HTB, 32 KiB burst/cburst, 1,514-byte quantum.
- **FIFO:** a 3,500,000-byte bfifo on each class, with no AQM (about 58 and
  36 ms of queue at those rates).
- **fq_codel:** target 5 ms, interval 100 ms, limit 10,000, ECN off. A
  `flow hash` filter on the outer src, dst, proto and ports puts every tunnel
  UDP tuple in one bucket, as on a physical router, instead of using the inner
  hash a veth keeps.
- **Underlay and TCP:** underlay GSO/GRO/TSO are off, the underlay MTU is
  1,500 and tunnels use 1,420. The namespaces use TCP CUBIC, because BBR bounds
  its own queue.
- **Load:** each mode (idle, download, upload, both) runs 8 TCP flows per
  loaded direction for `H2H_HOME_SECONDS` (default 12) plus a 6 s guard, with
  100 Hz ICMP probes starting 2 s into the load. Tunnel rows also probe the
  underlay at the same time.

Results go to `OUT/home/results.json`: loss-aware p50 and p99 (losses rank as
infinite RTT), goodput, and each mode's `cores_busy`. Every case also keeps
`tc -s` qdisc and filter dumps. Compare each engine with `bare` in the same
hold. With fq_codel, the inner probe shares the tunnel's outer flow with the
bulk traffic, while the underlay probe has its own flow, so inner minus
underlay is not only the engine's queue. This profile does not yet run
Tailscale, NetBird or the in-app engine, and the matrix does not run it
automatically.

For each later candidate, repeat `--gotatun-binary ID=PATH` and
`--source ID=FULL_SHA` on every command; add `--engine-label ID=LABEL` when
the default label is not descriptive enough. The candidate receives the same
probes and joins every counterbalanced window with both controls and the other
GotaTun variants.

Each scenario receives one comparable Markdown table and machine-readable
JSON. Raw probes, per-row JSON, audit records, machine diffs, and `perf-run`
receipts remain under the output directory. Rows retain throughput,
loss-aware idle and loaded p50/p99/p99.9 latency, CPU seconds/Gbit, idle
CPU/minute, userspace RSS and kernel peer-memory evidence at 1/100/1,000 peers,
binary and allocated disk size, and syscalls/Gbit. Userspace RSS uses
`/proc/<pid>/status` `VmRSS`; PSS uses `/proc/<pid>/smaps_rollup` `Pss`. The
same selected endpoint process trees are summed for every userspace engine,
and raw status and `smaps_rollup` files stay beside each row JSON.
`/proc/slabinfo` peer deltas and system-wide `/proc/meminfo` Slab deltas are
labeled by their actual basis.

## What is measured

The mesh cases are an underlay reference, infraternal, GotaTun v0.10.2,
BoringTun CLI v0.5.2, Tailscale, NetBird's kernel mode, and NetBird's userspace
mode. They use two endpoint namespaces and a separate coordination namespace
on the same VM. Control is local and disposable; no external account or
production mesh state is used. Results
describe this namespace data plane, not real Internet rendezvous or NAT traversal.
The infraternal fixture exercises the product's existing mesh, not unbuilt D313
direct-path or relay changes. Tailscale/NetBird path observations are retained.
The Linux GotaTun candidate is the pinned v0.10.2 CLI unchanged: it already
uses sendmmsg/recvmmsg and enables UDP GRO, while this revision has no UDP send
GSO or TUN virtual-header offloads. BoringTun CLI runs at its defaults: four
workers and a multi-queue TUN.

Each mesh case measures first reachable TCP packet, idle 64/512/1400-byte UDP
one-way and round-trip p50/p99, 64-byte RTT under concurrent 1- and 8-flow
TCP load, TCP throughput at 1/8 flows, CPU seconds per Gbit, and daemon RSS/PSS
idle and under load. Memory sums both endpoint
daemons and their descendants, excluding the coordination process. CPU
seconds per Gbit use whole-machine busy time, including the traffic tools.
Profiles are LAN, 198 ms RTT (99 ms egress delay each way), and that RTT with
independent 2% loss on each egress. An unfragmented round trip crosses both loss points, for 3.96%
exposure before retransmission; fragmented tunneled datagrams can encounter
more drop opportunities. The table reports whole-probe loss. Shared-VM monotonic timestamps make one-way samples possible;
there is no cross-machine clock synchronization assumption.

Terminal viewers share the same measurement procedures. Infraternal's native
leg-A client uses the shipping protocol codec and real server, embedded
infraternal agent, shim and PTY. tmux and Zellij are attached through a PTY;
network cases also attach through a private SSH server. The measurement stops
at bytes received by the viewer and the completion marker, not browser paint.
Multiplexers may coalesce screen updates, so delivered bytes can differ.
The native timing fixture uses cleartext WebSocket behind its private proxy
boundary; TLS termination and browser rendering are excluded. SSH legs include
SSH encryption and authentication. These are backend/viewer-path observations,
not an encrypted end-to-end production ranking. Browser flood triage separately
uses the production renderer and a TLS front. Native terminal
screen updates can also replace earlier screen state, so a marker and byte
count do not establish a lossless shell transcript.

Terminal profiles are local, 300 ms RTT, and 300 ms RTT with 2% packet loss
per direction. Flood waits are bounded at 180 s and each reattach at 30 s;
timeouts are failed measurements. They measure echo p50/p99, a base64 text `cat` workload
(75,000,000 random bytes encoded with 120-column wrapping, approximately
100.83 MB), `yes` for 10 seconds locally, and reattach. The scale case uses
1/10/50 sessions, attaches each once at 120×40 to normalize terminal geometry,
reports shells separately, and measures idle CPU detached and with one attached
viewer. Per-session PSS is the 1→50 slope, not a single
process's RSS divided by an assumed count.

## Evidence and interpretation

Results are `results/TIMESTAMP/summary.md`, per-measurement JSON and `.err` /
`.failed` files, environment and manifest records, per-case status and machine
diff, and outer `perf-run` receipts. A missing result is a failed or absent
measurement, never zero. Any measurement failure or non-empty machine diff
must be inspected before calling a run complete.

Snapshots compare modules, network state, sysctls, mounts, relevant processes,
units, account records and file trees. They exclude volatile counters, logs,
journals, caches named in `snapshot.sh`, and the kit directory. Each case
removes its namespaces, qdiscs, processes, private tmpfs state and newly
loaded modules. The perf VM is never used to build the kit.

`browser-flood.ts` runs three 100 MB floods using Chromium and the production
renderer behind the real-server fixture's lean TLS/WebSocket front. It records
protocol close codes, reconnects, completion, and screenshots outside the
checkout. Run it through `build-slot` with `INFRATERNAL_BIN`, `TRACER_DIST`, and
`J20_EVIDENCE` set; no authentication material enters the evidence.

## J20 results

Full tables, selected-run provenance, raw measurements, failure records and
cleanup receipts are on
[#260](https://git.kayg.org/kayg/infraternal/issues/260#issuecomment-71257).

Production Chromium reproduced the flood retirement on the real server and
renderer. A temporary diagnostic build confirmed the 256-message embedded
output queue fills while its receiver remains open; the server then retires
that attachment and the browser receives stream close 1013. Recovery can
reach the final screen marker with missing output bytes. The separate
control-stream 1001 liveness close also reproduced, but its cause remains
unconfirmed. Evidence and a minimal follow-up proposal are in
[#270](https://git.kayg.org/kayg/infraternal/issues/270). No product fix or
diagnostic instrumentation is included here.

The full x86 namespace workloads ran through `perf-run --root` on the perf VM.
These are single samples, with no claim of Internet NAT traversal or throughput
beyond this three-CPU allocation. The WAN profile adds 198 ms RTT; the loss
profile independently drops 2% in each direction.

| System | LAN 64 B RTT p50 / p99 ms | LAN 1 / 8 flows Gbit/s | WAN 1 / 8 flows Gbit/s | WAN + loss 1 / 8 flows Gbit/s | Idle RSS MiB |
|---|---|---|---|---|---|
| infraternal | 0.106 / 0.238 | 3.22 / 2.88 | 0.098 / 0.781 | 0.038 / 0.315 | 18.1 |
| Tailscale | 0.176 / 0.228 | 6.15 / 5.87 | 0.098 / 0.778 | 0.054 / 0.382 | 92.3 |
| NetBird kernel | 0.100 / 0.160 | 2.48 / 2.30 | 0.098 / 0.779 | 0.038 / 0.259 | 130.4 |
| NetBird userspace | 0.163 / 0.252 | 4.87 / 4.86 | 0.098 / 0.779 | 0.054 / 0.406 | 138.7 |

NetBird userspace reached 1,151.3 MiB peak RSS in the LAN load. The original
underlay snapshot caught an unrelated short-lived SSH process exit; its
corrected reference rerun passed with an empty cleanup diff.
Original raw runs remain available, including every non-empty cleanup diff.

The corrected underlay reached 32.97 / 70.61 Gbit/s with 1 / 8 LAN flows.
At normalized 120×40 geometry, the following totals exclude login shells:

| System | PSS MiB at 1 / 10 / 50 sessions | PSS MiB per extra session (1→50) | Shell PSS MiB at 50 | Idle CPU % detached / one viewer |
|---|---|---|---|---|
| infraternal | 18.8 / 29.4 / 74.9 | 1.14 | 118.2 | 0.050 / 0.767 |
| tmux | 2.5 / 2.6 / 3.0 | 0.01 | 118.2 | 0.000 / 0.000 |
| Zellij | 75.4 / 457.0 / 2139.3 | 42.12 | 114.8 | 1.400 / 1.267 |

Local echo p50 / p99 was 0.64 / 0.96 ms for infraternal, 0.17 / 0.30 ms
for tmux and 11.61 / 11.91 ms for Zellij. Native local floods and the WAN
cat closed 1013. The following local native reattach shares the retired flood
session and is not an independent idle-attach result. Under 300 ms RTT plus
2% loss per direction, the tmux-over-SSH cat timed out at 180 s, followed
by a failed reattach on that session; Zellij reached the marker in 8.20 s.
These are time-to-marker observations, not lossless transcript checks.

Final root cleanup found only the root network namespace, no private work
directories, and no test netem qdiscs. All three initially busy modules
unloaded successfully at final cleanup. The corrected local, loss, scale
and underlay diffs are empty; the WAN diff records another job creating
`/tmp/j7-dns-perf.sh`. Raw diffs and outer receipts remain attached to #260.
