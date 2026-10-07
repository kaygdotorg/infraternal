<!-- Pure mesh integration contract and reproducible scale measurements for slice 1. -->
# Mesh core

`infraternal-mesh` coordinates public inventory and arrow grants (D163–D167).
It performs no I/O and selects no crypto, tunnel, transport or netlink engine.
The server and infraternal agent integrate through plain serde data types.
`NodeId` is a stable coordinator-local `u64`; slice 2 persists its binding to
enrollment/inventory identities and never derives it from host names or keys.

## Integration contract

- Create `MeshSettings` once with a caller-generated random 40-bit deployment
  ULA ID. Persist it; recreating the ID on restart changes IPv6 addresses.
  Pass discovered canonical routes to `address::conflicts`. Conflicts include
  default routes and both IP families. They are reported; setup decides whether
  the deployment range needs changing, never the coordinator.
- The coordinator assigns /32 and /128 host routes. Allocation is monotonic;
  no address is recycled in a deployment, including removed nodes. Persist
  `Coordinator::checkpoint()` along with inventory in slice 2, atomically before
  delivery. `Coordinator::restore()` validates checkpoints and rebuilds indices;
  it retains allocation history and key overlap, and resets delivery acknowledgements.
- Only trusted server inventory supplies node IDs and tags; node-controlled
  enrollment data must not assign its own grant tags. Slice 2 authenticates and
  authorizes every membership/rule mutation before calling the coordinator.
- Join automatically. A node always initiates to the server; the server may
  respond but cannot initiate to other nodes without a grant. An arrow installs
  routing on both endpoints, new-connection outbound permission at the source,
  and new-connection inbound permission at the destination. Established replies
  are allowed. Backend enforcement MUST include both directions so a one-way
  arrow cannot become a two-way grant.
- Each `Change.peers` entry is delivered only to its addressed node. A diff
  changes only the listed peers. `PeerView::apply` checks node and prior
  version before mutation; missed or reordered messages require a full
  snapshot. Slice 2 must authenticate messages and serialize changes per node.
  Each node's desired version advances only when its view changes. Compare its
  applied acknowledgement against that target, not a deployment-global version.
- `Change.names` is a shared DNS delta, delivered to every resolver. The table
  is exact and only answers the deployment suffix. Suffix changes remove old
  names and insert new ones. Full table snapshots restore missed DNS delivery.
  These deltas have no delivery version; slice 2 needs reliable ordering or a
  snapshot on reconnect. DNS table delivery is separate from peer policy.
- The node installs a replacement private key locally while retaining the old
  one, then presents only its new public key. Both keys appear in peer diffs.
  After at least 120 seconds AND acknowledgement of current views by every
  current neighbour, `finish_rotation` sends public retirement instructions to
  peers and the rotating node in `Change.local_keys`. While acknowledgements are outstanding, another rotation returns
  `RotationInProgress`; slice 2 must retry rather than discard the retained key.
  There is no node-side expiry timer: outages preserve the last rules and both keys indefinitely.
  This is a logical key-overlap contract, not proof that a single kernel tunnel
  can implement it. #81/slice 2 must prove packet continuity and resolve allowed
  IP ownership for overlapping keys before using a real backend.
- Removal returns a key drop to every current peer, including the server, and
  removes DNS records. Offline nodes apply a reconnect snapshot before being
  marked current. Removing the server itself is rejected.
- `LocalPrivateKey` is node-side only: no serde, no clone, Debug is redacted.
  Real device integration is responsible for secure key storage and erasure.
- `MemoryBackend` models atomic view updates and stats, not packets or real
  handshakes. `Backend` requires atomic failure, correct stateful filters,
  key overlap and indefinite retention on coordination loss.

## Planned slice 2 commands

`infraternal mesh status` renders `MeshStatus` (peers, direct/relayed path,
last handshake, transfer bytes, applied and desired rule versions).
`infraternal mesh up|down` changes deployment mesh enablement (mesh optional,
D123/N2); `infraternal mesh rules add|remove|list`, `mesh settings`, and
`mesh rotate` use the same actions as API/MCP. No binary command is added here.

## Measurement

Build `cargo build --release -p infraternal-mesh --example measure`. Run each
shape as a fresh process under `systemd-run --user --scope -p CPUWeight=10000`:
`measure compile <100|1000|10000> <1|5|20>`, `measure incremental 10000 20`,
`measure view 10000`. Record machine, CPU, load and each raw metric.

The fixture uses one-way all-service node arrows around a ring (each node grants
its next 1, 5 or 20 neighbours), plus automatic server reachability. A broad tag
arrow can expand to a quadratic number of directed pairs; these budgets apply
to the measured sparse topology, not an unrestricted all-to-all tag mesh.
The compiler processes all arrows and builds fresh per-node views. Incremental
measurements time only the mutation (JSON encoding is outside
that interval); bytes are the entire JSON `Change`, not a chosen wire encoding.
“Nodes touched” counts peer-view diff recipients. Rotation additionally returns
one public `local_keys` instruction for the rotating node; its private key was
already installed before the call. Each sampled change is repeated 20 times;
full compilation has five samples per shape. p95 uses the nearest-rank
19th sample out of 20; medians use the sorted sample midpoint.
CPU time comes from the existing workspace `nix` clock wrapper (benchmark-only
dependency); wall time is monotonic elapsed time.
RSS includes allocator and ordered-map overhead and is rounded to pages; peak
RSS includes coordinator plus newly compiled views. View memory is the RSS
increase from populating a single node's view with 10,000 peers and all-service
policies; explicit port sets need their additional ordered-set storage. These numbers
are process measurements, not exact heap accounting or pinned-VM CI gates.
No packet latency/throughput claim is made by this pure coordinator slice.

## Validation and review

`cargo test --locked -p infraternal-mesh` runs 16 regression/property tests, including
10,000 generated mutations checked against fresh compilation and 30,000 unique
address pairs. It checks address stability, protocol/port union denial, minimal targeting,
removal/rotation, checkpoint, DNS and status checks. The compile-fail doctest
proves a node-side private key cannot enter serde serialization.

The final ASAN coverage-guided run completed 20,000 executions in 71 seconds
without an invariant or sanitizer failure. Raw evidence is
[fuzz-final.log](evidence/2026-10-07/fuzz-final.log), with
[compiler/instrumentation provenance](evidence/2026-10-07/fuzz-environment.txt).
A [public synthetic corpus snapshot](evidence/2026-10-07/fuzz-corpus.hex)
is retained for continued runs (each line after the role comment is a filename
and hex-encoded bytes). Its completion record was:

```text
#20000	DONE   cov: 6485 ft: 26123 corp: 871/226Kb lim: 824 exec/s: 281 rss: 445Mb
```

The isolated `fuzz/` package fuzzes structured JSON validation and generated
lifecycle operations against fresh compilation. Run with cargo-fuzz from that
folder, using `CARGO_TARGET_DIR` and corpus/artifact paths under the job scratch
root; the instrumented target is `mesh`. It adds no protocol parser or engine.
For direct reproduction without cargo-fuzz, use nightly and set `RUSTFLAGS` to
`-Zsanitizer=address -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares`,
then build the standalone fuzz manifest with `--release --target x86_64-unknown-linux-gnu`.
Run its `mesh` binary with `-runs=20000 -max_len=1024 <corpus>` and a scratch
`-artifact_prefix`. Check that the output reports loaded counters and growing
coverage; an uninstrumented run is not coverage evidence. The coverage-pass
setup follows the [libfuzzer-sys documentation](https://github.com/rust-fuzz/libfuzzer).
Reconstruct the retained corpus from the repository root:

```python
from pathlib import Path
corpus = Path.home() / ".cache/codex-scratch/mesh-core/corpus"
corpus.mkdir(parents=True, exist_ok=True)
for line in Path("crates/infraternal-mesh/evidence/2026-10-07/fuzz-corpus.hex").read_text().splitlines():
    if not line.startswith("#"):
        name, data = line.split()
        (corpus / name).write_bytes(bytes.fromhex(data))
```


Self-review covers PROCESS §2 and D40: input validation, private/public key
separation, directed stateful grant enforcement, overlapping grant removal,
version checks before mutation, stale delivery, offline state retention,
acknowledged key retirement, immediate peer removal, canonical allocation
restore, name uniqueness, dependency licenses and measured 10,000-node costs.
A pure coordinator cannot prove actual packet filtering or zero packet loss:
#81 and slice 2 must verify those obligations against the selected real backend.

## Slice 1 scale evidence (2026-10-07)

Measured production source `15e4e32` on `infraternal-dev`, Intel Core i9-9900K
at 3.60 GHz, eight logical CPUs, with workspace Rust 1.99.0 release optimization
and LTO. Every benchmark ran under a user scope with CPUWeight=10000. The
one-minute load ranged from 25.88 to 26.41. Raw samples and per-process load
records are in [evidence/2026-10-07](evidence/2026-10-07/); compiler/profile
provenance is in [environment.txt](evidence/2026-10-07/environment.txt).

| Nodes | Arrows/node | Full CPU median/max ms | Wall median/max ms | Coordinator RSS MiB | Peak RSS MiB |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 1 | 0.226/0.349 | 0.227/0.349 | 2.74 | 2.97 |
| 100 | 5 | 0.711/0.961 | 0.711/0.961 | 2.86 | 3.13 |
| 100 | 20 | 2.134/2.355 | 2.210/2.355 | 4.45 | 5.93 |
| 1,000 | 1 | 2.578/2.688 | 2.578/6.756 | 6.14 | 8.49 |
| 1,000 | 5 | 6.134/6.532 | 9.675/12.378 | 7.39 | 10.08 |
| 1,000 | 20 | 28.628/38.164 | 28.732/38.331 | 23.54 | 38.42 |
| 10,000 | 1 | 36.777/44.542 | 36.854/44.664 | 40.10 | 63.51 |
| 10,000 | 5 | 66.182/70.570 | 66.286/75.547 | 52.48 | 79.38 |
| 10,000 | 20 | 285.967/348.001 | 286.224/356.051 | 214.40 | 363.33 |

| Mutation | CPU p50/p95 us | Wall p50/p95 us | JSON bytes min/max | Nodes touched |
| --- | ---: | ---: | ---: | ---: |
| Arrow added | 4.361/9.526 | 4.424/9.424 | 685/687 | [2] |
| Node removed | 24.994/45.181 | 25.139/45.069 | 3,945/3,946 | [41] |
| Node key rotated | 33.965/36.517 | 34.088/36.627 | 15,695/15,695 | [41] |
| Server key rotated | 19539.314/22910.695 | 19671.425/22911.296 | 3,633,162/3,667,641 | [9999] |


At 10,000 nodes/20 arrows, the coordinator retains 419,918 cached peer entries.
Its RSS increase is 222,609,408 bytes: about **22,261 bytes/node × 10,000**
(212.3 MiB), plus process baseline. Total coordinator RSS is 214.40 MiB.
A standalone all-service view adds **3,141,632 bytes for 10,000 peers**, about
**314 bytes/peer × 10,000** (3.00 MiB). Peak RSS while retaining the coordinator
and constructing fresh views is 363.33 MiB.
Address allocation measured 113–161 ns CPU per allocation at 10,000 nodes;
hot exact-name lookup measured 127–185 ns CPU in the 20-arrow processes.
Joining 10,000 nodes before adding arrows consumed 46.97 ms CPU (4.70 µs/node).

Proposed budgets on #80, for this measured topology:

| Quantity | Proposed budget | Observed | Meets |
| --- | ---: | ---: | --- |
| Sparse change p95 CPU at 10,000 nodes | <1 ms | ≤45.181 µs | Yes |
| Full compile CPU at 10,000 nodes/20 arrows | <1 s | 348.001 ms maximum | Yes |
| Coordinator process RSS | <256 MiB | 214.40 MiB | Yes |
| Standalone 10,000-peer view RSS increase | <4 MiB | 3.00 MiB | Yes |
| Coordinator plus fresh-compile peak RSS | <512 MiB | 363.33 MiB | Yes |
| Allocation/hot lookup CPU per operation | <1 µs | ≤185 ns in scale processes | Yes |
| Full-fanout server rotation p95 CPU | <50 ms | 22.911 ms | Yes |

A universal “every change under 1 ms” budget is **not met**: server-key rotation
has 9,999 recipients (plus its local instruction) and up to 3,667,641 JSON bytes.
It needs the separate fanout budget. Dense tag expansion, explicit-port-set
heap costs, real backend work and packet/network latency remain outside these
sparse coordinator measurements.
