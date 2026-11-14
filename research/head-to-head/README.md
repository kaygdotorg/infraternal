<!-- Role: Reproducible comparative measurement method for #260; no product changes. -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Head-to-head measurement kit

Research only. The owner decides product changes from measurements. Tracking: #260;
mesh path decisions D313/D316. `SOURCE_COMMIT` and `MANIFEST` identify the exact
product source and harness used to build each kit.

## Build and run

On compute01, enter the `nix-devshell` flake with Go and Bison available, then run
`~/infraternal-ops/build-slot research/head-to-head/build-kit x86_64 OUT`.
Use `CARGO_BUILD_JOBS=4` and a job-specific `CARGO_TARGET_DIR`. The build uses
the product's static musl recipe, its pinned Zig, checked-in Rust/Go locks,
and the official downloads and checksums in `pins.txt`. tmux is built from
verified official sources because it has no official static binary.

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
source-labeled GotaTun variants, with MTU 1420, shared probes, and the same
per-row CPU placement audit. The production baseline is the GotaTun revision
shipped by `origin/dev`, `84b7bb28e385d57dfb80493e78202898fad24d1e`; it is
reported as `GotaTun (shipped, 84b7bb2)`. The J88i fairness candidate is
`33ca6fe616587db506b16612f2a4b5bbd54997f3`; it includes J316's GSO negotiation
commit `ebeb8f0071c4103168b570407f9dc555562f4b79`. The remaining candidates in
this comparison are J316 `b6789348aea23216e0be06e93d44d6f5239318b3`, J225's
pushed stack `21a8a1589ab198e0af171aee3e7147a4b38710d0`, and J324 branch
`j324-mem-pools` at `b36d575a20e1f8747ca9e883afdd9aab4c9cd0c5`. J225's stack
contains J316's coalescer and J225's producer batching. The checksum fix is pushed separately at `f3197d046f385d38c39210dec651e0ba8e096b12`;
it is not yet in the listed J316 `b678934` or J225 `21a8a15` source trees.
Those two are pre-fix historical rows, not current measurement candidates.
Wait for J225's rebase and 1-flow smoke handoff before measuring the stack.
The memory candidate is `GotaTun (J324 memory pools, b36d575)`. Each
row carries its full source SHA in
the run JSON and scenario table. The `2bb5347a8cddf3c31df64be1f52466e1a02bf75b`
alias differs from the shipped data path only by an equivalent return-expression
spelling, so the matrix records it as an alias and runs that data path once.

Build all GotaTun rows from clean detached source trees with the same CLI target,
toolchain, and flags. For this owner-directed matrix, build each source on the
x86 perf VM while holding `/var/lock/infraternal-perf.lock`; do not measure
during that build hold. First check the shell with
`nix develop <worktree> -c cargo --version`. Match the production `ring` backend
by disabling CLI defaults and enabling only `ring`; leave optional allocator
features disabled so each binary uses Rust's system allocator. Give each source
a distinct `CARGO_TARGET_DIR` under
`/home/claude/.cache/codex-scratch/gotatun-j317`:

```sh
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=/home/claude/.cache/codex-scratch/gotatun-j317/target-shipped-84b7bb2 \
  cargo build --locked --release \
  --package gotatun-cli --bin gotatun --target x86_64-unknown-linux-musl \
  --no-default-features --features ring
```

Each source variant receives five repetitions in counterbalanced windows. Each
window runs in its own `perf-run --root` hold on the shared
`/var/lock/infraternal-perf.lock`; announce it on #260 before starting and keep
it under 20 minutes.

For a focused priority series, `--select-gotatun` names the GotaTun rows in the
measurement; both reference engines stay in every window. Repeating
`--engine-order` sets the first-window order, and later windows rotate it. The
J225 priority order is shipped, J225+J316, wireguard-go, then kernel:

```sh
--select-gotatun gotatun-shipped-84b7bb2 \
--select-gotatun gotatun-j225-j316-21a8a15 \
--engine-order gotatun-shipped-84b7bb2 \
--engine-order gotatun-j225-j316-21a8a15 \
--engine-order wireguard-go \
--engine-order kernel-plain
```

From the unpacked kit on the perf VM, run:

```sh
OUT="results/$(date -u +%Y%m%dT%H%M%SZ)"
GOTATUN_ARGS=(
  --gotatun-binary gotatun-shipped-84b7bb2=/path/to/gotatun-shipped
  --gotatun-binary gotatun-j88i-33ca6fe=/path/to/gotatun-j88i
  --gotatun-binary gotatun-j316-b678934=/path/to/gotatun-j316
  --gotatun-binary gotatun-j225-j316-21a8a15=/path/to/gotatun-j225-j316
  --gotatun-binary gotatun-j324-b36d575=/path/to/gotatun-j324
  --source gotatun-shipped-84b7bb2=84b7bb28e385d57dfb80493e78202898fad24d1e
  --source gotatun-j88i-33ca6fe=33ca6fe616587db506b16612f2a4b5bbd54997f3
  --source gotatun-j316-b678934=b6789348aea23216e0be06e93d44d6f5239318b3
  --source gotatun-j225-j316-21a8a15=21a8a1589ab198e0af171aee3e7147a4b38710d0
  --source gotatun-j324-b36d575=b36d575a20e1f8747ca9e883afdd9aab4c9cd0c5
  --engine-label 'gotatun-j316-b678934=GotaTun (J316 coalescing, pre-checksum-fix, b678934)'
  --engine-label 'gotatun-j225-j316-21a8a15=GotaTun (J225 batching + J316 GSO, pre-checksum-fix, 21a8a15)'
  --engine-label 'gotatun-j324-b36d575=GotaTun (J324 memory pools, b36d575)'
)
python3 -I lib/matrix.py run \
  --kit "$PWD" \
  --scenario best-lan \
  "${GOTATUN_ARGS[@]}" \
  --wg-bin /path/to/wg \
  --wireguard-go-bin /path/to/wireguard-go \
  --out "$OUT" \
  --calibration-only
```

That command uses the shipped baseline for three-control calibration and
records its spread. Build each executable from the full source SHA; do not
substitute the active fork head for the shipped baseline. Then run
batches 1 through 5 for each scenario, using the same binaries, source SHAs,
labels, and output directory:

```sh
python3 -I lib/matrix.py run \
  --kit "$PWD" --scenario best-lan \
  "${GOTATUN_ARGS[@]}" \
  --wg-bin /path/to/wg --wireguard-go-bin /path/to/wireguard-go \
  --out "$OUT" --no-calibrate --batch 1
```

For a later candidate, add one `--gotatun-binary ID=PATH`, one
`--source ID=FULL_SHA`, and optionally one `--engine-label ID=LABEL` to every
calibration and scenario command. Its row participates in each balanced
window with the same controls and probes.

Repeat with `--batch 2` through `--batch 5`, then select each remaining
scenario from `python3 -I lib/matrix.py list`. One invocation runs one lock
window. Failed calibration remains failed; owner-directed rows keep the exact
`uncalibrated, owner-directed` label and show both current and owner-reported
spread values beside it.

Each run writes a top-level `matrix.json`, a JSON matrix and Markdown table per
scenario, five repeated rows per engine, calibration evidence, `perf-run`
receipts, CPU audit records, machine-diff records, and the raw probe logs.
Throughput, loss-aware p50/p99/p99.9 latency (idle and loaded), CPU/Gbit, idle
CPU/minute, syscalls/Gbit, idle and loaded RSS at 1/100/1,000 peers, kernel peer
memory at those counts, binary size, and allocated disk blocks are retained.
Userspace RSS comes from `/proc/<pid>/status` `VmRSS` and PSS from
`/proc/<pid>/smaps_rollup` `Pss`. The same selected endpoint process trees are
summed for every userspace engine, with raw status and `smaps_rollup` files
retained beside each row JSON. The peer-scale scenario samples loaded RSS
during the same one-flow TCP and latency workload for every engine and GotaTun
source at each peer count; other
scenario rows retain idle peer-count RSS. Both endpoint processes are summed,
and per-peer values divide by the configured peer count per endpoint. Kernel
memory basis is recorded for both states: the `wg_peer` slab delta when
available, otherwise the explicitly system-wide `/proc/meminfo` Slab delta.
Small-UDP rows also retain whole-machine CPU seconds per received payload Gbit,
packet rate, and every lost probe.

## What is measured

The mesh cases are an underlay reference, infraternal, Tailscale, NetBird's
kernel mode, and NetBird's userspace mode. They use two endpoint namespaces
and a separate coordination namespace on the same VM. Control is local and
disposable; no external account or production mesh state is used. Results
describe this namespace data plane, not real Internet rendezvous or NAT traversal.
The infraternal fixture exercises the product's existing mesh, not unbuilt D313
direct-path or relay changes. Tailscale/NetBird path observations are retained.

Each mesh case measures first reachable TCP packet, 64/512/1400-byte UDP
one-way and round-trip p50/p99, TCP throughput at 1/8 flows, CPU seconds per
Gbit, and daemon RSS/PSS idle and under load. Memory sums both endpoint
daemons and their descendants, excluding the coordination process. CPU
seconds per Gbit use whole-machine busy time, including the traffic tools. Profiles are LAN, 198 ms RTT
(99 ms egress delay each way), and that RTT with independent 2% loss on each
egress. An unfragmented round trip crosses both loss points, for 3.96%
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
