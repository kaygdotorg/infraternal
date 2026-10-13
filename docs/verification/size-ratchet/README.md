<!-- Binary growth attribution, behavior-preserving cuts and verification evidence for #198/D243. -->
# Static binary size ratchet (#198)

Production `9ab4329c8d85a3387c8972b06fb03888650641bb` is 20,333,104 B
x86_64 and 18,112,240 B aarch64. Dev base
`85368c7fdda186fa46b142be4d0546807357247a` is 22,580,816 B and 19,986,840 B:
growth of **2,247,712 B / 1,874,600 B**. Both production artifacts and both
dev artifacts reproduce the brief's measurements.

The first shared-target sweep reused the cut native archive at later baseline
checkpoints (85368c7f incorrectly became 22,263,504 B). Those rows are discarded.
For the clean replay, touch the unchanged shim build.rs and scripts/build-vt
after each detached checkout to invalidate Cargo's relative native watches.
This restores the baseline archive; fresh 85368c7f reproduces 22,580,816 B.
Do the same on the final head after replay. Source contents remain unchanged.

## Recipe and attribution

The shipping recipe is `scripts/auth-toolchain`, prepend its checksum-pinned
Zig 0.15.2 directory to PATH, then `cargo build --locked --release -p
infraternal --target <target>`. CARGO_TARGET_DIR is
`$HOME/.cache/codex-scratch/size-ratchet/target`. Sizes are `stat -c %s` of the
stripped executable; `file` identifies static linkage and `readelf -l` must
contain no PT_INTERP. Optimization, LTO, codegen units, panic unwinding, CPU
baseline and all default application features remain unchanged.

The direct production-to-dev Cargo.lock diff adds only first-party plugin
packages/edges. Third-party versions are unchanged; existing libraries gain
instantiations and feature use. Diagnostic `cargo bloat --release --crates
--target x86_64-unknown-linux-musl -p infraternal -n 0` output is retained in
`prod-bloat-x86.txt` and `dev-bloat-x86.txt`. Its estimates include attribution
of generic code and rounded MiB values. Retaining symbols changes code layout
slightly; stripped whole-file sizes below are authoritative.

| Crate / feature | Production .text | Dev .text | Growth estimate | Reason |
| --- | ---: | ---: | ---: | --- |
| infraternal-server | 2.4 MiB | 2.8 MiB | ~0.4 MiB | Mesh coordination/path wiring, CLI and admitted-host inventory |
| plugin-mesh | 234.1 KiB | 545.1 KiB | 311.0 KiB | Node runtime, access enforcement and coordinator actions |
| infraternal-agent | 318.1 KiB | 459.9 KiB | 141.8 KiB | Plugin control, preferred/standby paths and primed writers |
| infraternal-mesh | 3.0 KiB | 109.0 KiB | 106.0 KiB | Active kernel data plane and lifecycle |
| CLI infraternal | 276.1 KiB | 368.6 KiB | 92.5 KiB | Declared actions, help/skills and component adaptation |
| plugin-release | absent | 47.3 KiB | 47.3 KiB | Runtime signed update/handoff action implementation |
| plugin-remote | 76.2 KiB | 117.1 KiB | 40.9 KiB | Transport/control capability integration |
| plugin-api | 12.2 KiB | 48.2 KiB | 36.0 KiB | Shared action contracts and host interface |
| serde_json | 120.9 KiB | 204.8 KiB | 83.9 KiB | Additional typed JSON instantiations |
| serde_core | 26.4 KiB | 102.2 KiB | 75.8 KiB | Serialization/deserialization glue |
| sqlx_core | 172.6 KiB | 222.8 KiB | 50.2 KiB | Additional queries/row types |
| tokio | 314.8 KiB | 355.6 KiB | 40.8 KiB | Additional task/future instantiations |
| plugin-ssh | 228.5 KiB | 237.4 KiB | 8.9 KiB | Production repair/probe integration |
| shim | 217.2 KiB | 220.8 KiB | 3.6 KiB | Session lifecycle integration |
| ring / rustls / OpenSSL | 243.9 KiB / 352.6 KiB / 1.9 MiB | same estimates | effectively unchanged | Required providers/transports remain |

The residual includes standard-library/generic future, allocator and drop glue
(std 1.5 -> 1.8 MiB). `*-crate-text.json` independently aggregates `nm -S
--demangle` text symbols by first Rust namespace, counting aliases once by
(address,size); it assigns generic wrappers to core/alloc and therefore differs
from cargo-bloat's inferred attribution. These are diagnostic text costs, not
feature-off whole-file savings, and cannot be added as independent removals.

The exact stripped ELF accounting in `baseline-sections.json` attributes
1,896,437 B to .text, 57,344 B to .rodata, 145,384 B to .eh_frame, 17,504 B to
.eh_frame_hdr and 23,072 B to .data.rel.ro; other sections/alignment account for
107,971 B. Total: 2,247,712 B.

## Retained costs for the owner

Removing mesh coordination/kernel operation loses D198/D215/D228 behavior:
its diagnostic text growth is 311.0 KiB plugin + 106.0 KiB engine, plus server
and generic task glue. Infraternal agent path switching/priming costs 141.8 KiB;
remote integration costs 40.9 KiB. Server inventory/coordination/CLI growth is
~0.4 MiB, CLI adaptation is 92.5 KiB, and signed update actions are 47.3 KiB.
These features remain present; disabling them is a feature-loss decision.

Ring's 243.9 KiB .text and OpenSSL's provider/assembly remain (D173/D176/D257).
The two AVX-512 AES-GCM functions total 675,280 symbol bytes; disabling them
requires D257's separate AVX-512-machine throughput/latency evidence. This job
does not remove them, switch crypto providers or change optimization levels.
No new foundational dependency is selected.

## Author review

- No protocol, auth, secret handling, schema/migration or application feature change.
- No engine/version/CPU/optimization/panic-mode change; native archive API exports remain available.
- Source cache keys include recipe/adapter/ABI/profile; pinned build definition is restored before flags.
- Public metadata signatures, ordered fields, required order and handler defaults are preserved.
- No new unsafe Rust, dependency, background worker, listener or timer.
- Native replay/fidelity/real-PTY tests and CLI/API tests run against real code.
- Runtime numbers come only from the locked 4-vCPU/7-GB perf VM with CPUWeight=10000 and recorded load.
- Timing probes are one-session/cold-start comparisons, not 200-session/1,000-node performance acceptance.
- Static artifact savings at 1,000 nodes are replicated file storage, not RSS or compressed transfer savings.
- Work stays on size-ratchet; no deploy or owner fixture changes. Issues remain open.

## Historical merge checkpoints

Each row is a fresh stripped x86_64 build of that revision. The first ten
rows are historical checkpoints along the development integration line;
they are not successive children of the production revision. In particular,
the mesh integration restores remote/SSH defaults absent from the earlier CLI
branch, so its 4,617,200 B interval is not a mesh-only cost. Those dependencies
already ship in production. `merge-sizes.tsv` records the clean replay.

| Checkpoint | Change | Bytes | Delta from preceding checkpoint |
| --- | --- | ---: | ---: |
| 47f2b31b | CLI integration | 16,698,208 | — |
| 0510bd85 | UI platform integration | 16,698,208 | 0 |
| bf28c10a | Mesh integration / restored shipping defaults | 21,315,408 | +4,617,200 |
| 7db21709 | Signed release integration | 21,715,536 | +400,128 |
| dedcc2a3 | D215 transport integration | 22,308,720 | +593,184 |
| f2a4b36d | Production fixes backmerge | 22,438,672 | +129,952 |
| 73ce87a7 | Handoff deployment integration | 22,464,880 | +26,208 |
| bdf68a6c | Production live integration | 22,469,168 | +4,288 |
| 52f64477 | SSH home-alias repair | 22,473,264 | +4,096 |
| 5e383c3d | Mesh access integration | 22,534,320 | +61,056 |
| 85368c7f | Bounded admitted-host inventory | 22,580,816 | +46,496 |

The direct production-to-dev path is: production 20,333,104 B → production
integration bdf68a6c 22,469,168 B (+2,136,064 B of retained development features)
→ SSH repair (+4,096 B) → mesh access (+61,056 B) → inventory (+46,496 B).
These four increments sum exactly to the 2,247,712 B growth. Historical builds
use their own locked dependencies and feature definitions, with no edits to
source contents. `artifact-manifest.json` identifies the retained endpoint
artifacts; binaries are not committed.

## Behavior-preserving cuts and caps

| Cut / commit | x86_64 before → after | Saved | aarch64 before → after | Saved |
| --- | ---: | ---: | ---: | ---: |
| Native function/data sections, 722af2a3 | 22,580,816 → 22,263,504 | 317,312 B | 19,986,840 → 19,681,112 | 305,728 B |
| Concrete cold metadata helpers, 5ae7cbf2 | 22,263,504 → 22,204,304 | 59,200 B | 19,681,112 → 19,638,744 | 42,368 B |
| Total | 22,580,816 → **22,204,304** | **376,512 B** | 19,986,840 → **19,638,744** | **348,096 B** |

The native archive still exports the same 182 public symbols on each target;
178 public x86_64 functions now have individual text sections. The final
linker can discard unreferenced entry points without removing the archive API.
`archive-sections-proof.json` records symbol and section evidence. The metadata
helpers share concrete construction after caller conversions; they preserve
public signatures, ordering and serialized output. All 54 action skill/help
pairs, root help and the skill index (110 outputs) compare byte-for-byte.
The skill index SHA-256 is
`b8566728561e06f412ba4a2b4aced345b5f2239e0a688284c7e98e7b36cb009e`.

At 1,000 installed nodes the cuts save 376,512,000 B x86_64 or 348,096,000 B
ARM of replicated executable storage. No feature or dependency was removed.
The new gate caps are the exact measured head sizes, with zero allowance;
+1 B growth fails and -1 B requires updating the cap downward.
`size-boundary.log` records these boundaries on genuine shipping artifacts,
including trust/linkage checks. `old-gate-reproduction.log` demonstrates why the
historical caps could not detect incremental growth: an unchanged dev already
failed them. The replacement caps are below both supplied current-dev sizes;
no extra growth allowance is introduced.

## Functional and runtime evidence

Shim validation: 79 unit and 5 integration tests passed; 13 pre-existing
ignored tests remain ignored. Plugin API: 20 unit and 2 integration tests
passed with all features. CLI: 76 tests passed, with one pre-existing ignored
performance diagnostic. Touched crates passed clippy with warnings denied;
workspace formatting passed. Public output equivalence is recorded in
`metadata-equivalence.log`. Final full gate output is recorded verbatim on
issue #198, against the pushed branch head.

Runtime probes run only on `infraternal-perf-test` (4 vCPU, 7 GB), through
NetBird SSH, under `/var/lock/perf-bench.lock` and CPUWeight=10000. Drivers are
`measure_terminal.py` and `measure_cli.py`. Terminal probes use one real PTY,
1,000 echo/Ack samples and three credited 50-MiB floods per artifact. The
portable shell readiness sequence works with the machine's configured shell.
Earlier shell-prompt attempts were discarded; prompt/fence bytes were removed
from the second throughput comparison.

| Native sections probe | Baseline | Sections |
| --- | ---: | ---: |
| First pair echo p99 | 619,941 ns | 471,217 ns |
| First pair median flood | 16.4474 MiB/s | 17.6840 MiB/s |
| Exact-body pair echo p99 | 466,269 ns | 505,726 ns |
| Exact-body pair median flood | 17.1750 MiB/s | 17.6357 MiB/s |

Loads ranged 0.00–1.54 across the two pairs. Echo noise moves in both
directions; credited throughput is higher in both pairs. Raw results are
`perf-vt-first-baseline.log`, `perf-vt-first-sections.log` and
`perf-vt-exact-body.log`.

Cold CLI probes alternate artifact order over 301 samples per command
(load 0.11–0.59). Values below include process creation and output collection.

| Command | Sections p50 → metadata p50 | Sections p95 → metadata p95 |
| --- | ---: | ---: |
| Root help | 2,339,305 → 2,390,487 ns | 2,834,539 → 2,812,536 ns |
| Skill index | 2,779,418 → 2,803,075 ns | 3,974,684 → 3,757,927 ns |
| Mesh up skill | 2,675,700 → 2,723,604 ns | 3,201,822 → 3,190,837 ns |

The measured 24–51 µs median startup cost is accepted for the 59,200 B x86_64
metadata cut (59.2 MB of executable storage at 1,000 nodes); helpers do not run
in terminal I/O. All three p95 values improve in this longer interleaved run.
Raw 61- and 301-sample results are retained as `perf-metadata-cli.log` and
`perf-metadata-cli-301.log`. These probes do not establish fleet-scale runtime
budgets or independent feature-off savings.
