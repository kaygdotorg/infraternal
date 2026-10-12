<!-- Round-three evidence for review findings R4/R5 and release-channel binary sizing [#157]. -->

# Release channels round three

## R4: reclaim metadata after an abrupt stop

`VerifiedLookup::new` sweeps only canonical `release-check-<UUID>` entries. The
state and staging directories must be owned by the service uid; staging mode is
exactly `0700`. Directory opens use `O_NOFOLLOW | O_DIRECTORY`, and a
nonblocking exclusive flock preserves live entries. Cleanup accepts only the
four known regular metadata filenames, owned by the service uid, with one hard
link and no group/world permissions. Unknown, unsafe, linked, symlinked, or
active entries are retained.

The pre-fix regression log
[`metadata-restart-red.log`](metadata-restart-red.log) records 131,072 bytes
retained after two abrupt stops and a failed zero-byte restart assertion. The
fixed regression is
[`restarted_latest_reclaims_metadata_after_process_stop`](../../crates/plugins/release/tests/review_restart.rs).
It observes 65,536 bytes after each of two abrupt stops because each newly
constructed child first reclaims the previous child's abandoned directory;
the next service startup returns the remaining 65,536 bytes to zero. The
shared-path fixture in the server suite now uses a private `0700` directory,
matching the production precondition.

## R5: reserve database capacity for authority reads

The service takes one shared semaphore permit before it acquires a pool
connection or begins `BEGIN IMMEDIATE`. Its clones share the same permit, so
SQLite's serialized writer wait cannot consume all shared pool connections.
The pre-fix regression log
[`pool-red.log`](pool-red.log) records all eight pool slots occupied and the
authority read blocked for 2,001 ms. The fixed regression is
[`pending_channel_writers_preserve_authority_read_capacity`](../../crates/plugins/release/tests/review_pool.rs).
With an external `BEGIN IMMEDIATE` held, eight release callers against eight
pool slots admitted one writer and left seven slots available; control and
authority reads completed while the write remained blocked. The authority read
measured 0 ms in that run. The test completed in 2.59 s including its bounded
wait and cleanup.

## Tests, fuzzing, and local performance

On the current release source, `cargo test -p infraternal-plugin-release`
reported 7 passed and 1 ignored; the R5 integration test reported 1 passed;
the R4 subprocess test reported 1 passed with its child helper ignored. The
focused server `release_latest::tests` suite reported 3 passed and 2 ignored.
There were no failures.

The `release_verify` fuzz target ran 2,376,397 cases in 31 seconds, reaching
631 coverage edges and 1,304 features with a 188-input / 38 KiB corpus and
527 MiB peak RSS. It reported no crash. The short `release_channel` run
completed 2,216,627 cases in 31 seconds (915 coverage edges, 2,147 features,
no crash).

The parser-sharing change was measured with 50 concurrent channel reads on the
12-vCPU `infraternal-dev` host under a weighted user scope. Before/after p50 was
0.079/0.075 ms, batch time was 4.409/4.772 ms, and the lookup handle remained
32 bytes. Load averages were 39.57/35.47/33.52 and 37.74/35.20/33.46. These
single runs show no p50 regression; the batch difference is small and noisy
under shared host load, so it is not treated as a throughput improvement.

## Binary size and attribution

`cargo bloat 0.12.1` used Rust 1.99.0, the release profile, and
`x86_64-unknown-linux-musl` on the baseline commit `794ef45f` and the final
release source before this evidence-only change. The `.text` section grew from
15,248,428 to 15,461,420 bytes (+212,992); cargo-bloat's ELF file measure grew
from 57,571,672 to 57,894,888 bytes (+323,216). The separate stripped static
artifact sizes were:

| Target | `794ef45f` | Current source | Growth | Existing allowance |
| --- | ---: | ---: | ---: | ---: |
| `x86_64-unknown-linux-musl` | 20,042,272 B | 20,303,232 B | +260,960 B | 262,144 B |
| `aarch64-unknown-linux-musl` | 17,862,968 B | 18,078,296 B | +215,328 B | 262,144 B |

Both baseline artifacts were rebuilt with the same toolchain and release
profile as the current source. The x86 artifact is a stripped static PIE; the
ARM artifact is a stripped static ELF. The verifier now uses these measured
`794ef45f` baselines and retains the existing 256 KiB allowance on both
targets.

The largest positive crate deltas in the final x86 cargo-bloat attribution
were: release plugin +58,898 B (new verified lookup and channel service),
`sqlx_core` +46,303 B and `sqlx_sqlite` +728 B (writer transaction, pool and
authority recheck paths), server +32,738 B (plugin/action registration),
`std` +32,657 B (optimized future/runtime code for the new paths), CLI
`infraternal` +22,780 B and `clap_builder` +3,978 B (operator command),
`serde_json` +7,115 B and `serde_core` +1,822 B (strict action schemas), remote
plugin +2,143 B, plugin API +1,536 B, SSH plugin +128 B, and `flume` +11 B.
Smaller gains and removals account for the remaining net +2,155 B beyond those
positive deltas.

The largest release-specific functions were `VerifiedLookup::latest` (17.5
KiB), the two `ReleaseService::call` future paths (16.2 and 14.7 KiB), and
`ReleasePlugin::run` (3.5 and 1.8 KiB). The first bloat comparison found two
identical `serde_json::from_slice` schema parser instantiations. A shared,
non-inlined helper reduced `.text` by 3,008 B and cargo-bloat's ELF measure by
3,632 B; `serde_json`'s positive delta fell from 13,145 to 7,115 B. The
behavior and strict schema checks remain covered by the release tests.

No second HTTP or crypto implementation was added: the feature uses the
server's existing HTTP/signature engines, and the dependency diff adds the
workspace release plugin without adding a third-party HTTP or crypto crate.
The remaining measured growth implements the signed lookup, bounded private
staging, transactional setting, runtime feature and explicit operator command.
