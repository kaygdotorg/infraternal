<!-- Records merge compatibility, shutdown crash safety and measured shipping evidence for #129 (D16, D163, D198, D201, D202, D205, D216). -->
# Mesh integration and shutdown

Code head: `d9ee14267b848c5f458ddcabec7a83809e5ca748`. Evidence and author
review: [evidence/mesh-integrate](../../evidence/mesh-integrate/).
The final branch-head gate and exact head are recorded on issue #129 after
this evidence commit. Only the integration branch is pushed; the orchestrator
owns the fast-forward of `dev`. No deployment or external host was used.

## Merge compatibility

Merge `bf28c10a` joins dev `8e7467c0` and reviewed mesh `feec1988` with two
parents. Its body records each conflicted file's reasoning. Deployed migration
`0019_host_removal.sql` remains unchanged; the undeployed mesh migration is
`0020_mesh_dataplane.sql`. Capability bits remain additive without renumbering.
Cargo.lock changes only five dependency edges, without version churn.

The merged infraternal agent preserves bounded sessions, TLS/QUIC, CA handoff,
dead-session handling, checked uninstall and writer-owned deferred replies.
Mesh lives in its feature-gated plugin, with a process-owned service surviving
control reconnections. A bounded plugin worker shares authoritative settings
between admission and actions and supplies a fresh trusted node context per call.
Admission no longer parks terminal dispatch. Worker tests cover context,
deferred replies and admission after settings changes.

The existing CLI and skill envelope remain authoritative. Mesh declarations
and CLI adaptation live in the mesh plugin; the core dispatches generic node
components. Agent-only, mesh-only and server-only configurations pass Clippy
with warnings denied. No node component creates a server (D201).

## R6 and crash ordering

The unchanged reviewer test from `dd8d970a` is committed as `d49cdf48`.
It failed against the merged shipping binary before the fix: 51,187,537 µs.
The earlier merged baseline measured 45,639,107 µs. The fixed shipping test
passes at **775,555 µs**, below the unchanged 1,000,000 µs ceiling.

Shutdown first durably records disabled intent. After verifying interface
ownership, one existing generic-netlink request replaces the entire peer set
with empty using the kernel's device flag. Clearing peers before link deletion
keeps retirement under the kernel's batched path. One link deletion removes
interface addresses/routes, and existing firewall transactions remove owned
policy. Only after those acknowledgements does the route journal commit an
empty inventory once. An unsuccessful journal write preserves `Stopping`
and enough state for explicit retry. No private key is serialized by cleanup.

Restore finishes disabled intent even when the interface is already absent,
then retires the journal. An empty replay does not rewrite its inode. Actual
SIGKILL tests cover intent, peer removal, link removal and policy removal on
both firewall backends: **8/8 pass**, each with 1,000 peers. The tests verify
foreign IPv4/IPv6 host routes survive and the 2,000-address recovery journal
becomes durably empty. The pre-fix test fails with stale journal state.
A separate refused-write test verifies `Stopping` followed by successful retry.

All **26** ignored real-kernel regressions pass on the code head, including
R1–R5, bulk identity/route preservation and the new recovery cases. R6 adds
the passing shipping test. Each case runs in a disposable user/network
namespace and its own weighted scope. The child helper is excluded from the
case count. Raw per-case logs and `kernel-results.json` identify every case.

## Production scale measurements

All measurements run locally on infraternal-dev under
`systemd-run --user --scope -p CPUWeight=10000`, without induced CPU load.
Shipping binary hashes, machine and logical CPU count are in `provenance.json`.

| Shipping single-daemon measurement | Before | After |
| --- | ---: | ---: |
| Peers | 1,000 | 1,000 |
| Snapshot including fsync/control RPC (µs) | 570,988 | 659,457 |
| Endpoint action including fsync (µs) | 31,182 | 85,654 |
| Component down (µs) | 45,639,107 | 775,555 |
| RSS on/off (bytes) | 11,399,168 / 10,928,128 | 11,206,656 / 10,698,752 |
| On RSS × expected 1,000 nodes (bytes) | 11,399,168,000 | 11,206,656,000 |
| Idle CPU ticks in 10 seconds, on/off | 0 / 0 | 0 / 0 |

After-test load: `40.31 44.71 46.72`; before sample:
`36.20 27.67 26.54`. The independently failing reviewer run and its different
load are retained rather than substituted for the first baseline.

The production-coordinator proof uses two shipping daemons with **1,000 peers
each**, one actual direct pair and 999 extra public fixture members. IPv4 and
IPv6 receive 25/25 packets each. Deny-new ping/TCP, established-flow survival,
port grant/other-port denial and component-off pass.

| Production pair measurement | Before | After |
| --- | ---: | ---: |
| Mesh throughput (Mbit/s, counted 128 MiB) | 753.34 | 728.25 |
| Underlay throughput (Mbit/s) | 12,231.57 | 10,056.81 |
| IPv4 RTT p50/p99 (ms), after | — | 0.302 / 6.06 |
| IPv6 RTT p50/p99 (ms), after | — | 0.317 / 15.3 |
| Join to first packet (µs) | 1,805,563 | 2,708,894 |
| RSS/node (bytes) | 9,347,072 / 9,351,168 | 11,243,520 / 11,243,520 |
| Mean RSS × expected 1,000 nodes (bytes) | 9,349,120,000 | 11,243,520,000 |
| Idle CPU ticks/10 seconds | 0 / 0 | 0 / 0 |

After pair load: `35.29 39.55 44.42`; before:
`42.37 38.63 31.90`. Fleet memory is a projection, not 1,000 measured daemons.
RSS remains below 15 MB per daemon. The worse active-path samples remain in
the record: shared-host 25-packet tails and uncontrolled windows do not establish
latency or throughput budgets, or attribute those changes to shutdown code.
No relay or WAN capacity is claimed.

Seven additional namespace proofs pass on the current-code debug kernel fixture:
IPv4/IPv6 plaintext underlay ingress refusal and unrequested transit refusal
on both backends, plus fallback connectivity/deny/grant/established-flow
survival. These are two-node functional proofs; only the shipping production
proof above uses 1,000 peers per node. `namespace-results.json` records the
fixture hash, cases and raw logs.

## Gates and reproduction

Per-step fmt, touched-crate Clippy and tests precede each logical commit.
The milestone full gate (`merge-fast5.log`) passes every non-size Rust row.
The final head runs the full gate again; its verbatim table goes on #129.
The static x86_64 binary is **21,315,280 bytes**, above the unchanged
16,404,816-byte ceiling (known D205 overrun), with no PT_INTERP. Release
profiles and size thresholds are unchanged. ARM is built separately because
that known x86_64 size failure stops the gate dispatcher; its result is also
recorded on #129.

The workspace debug binary exceeded the unchanged RSS ceiling under default
feature unification. The default-feature shipping fixture independently passes
at 14,056 KiB. The native full gate uses job-local `gate-profile.toml`: only
three project runtime crates have dev opt-level 1; dependency and release
profiles remain unchanged. This qualification is explicit, not a default
profile pass claim. Put the recorded file in the job scratch and wrap cargo:

```sh
exec /home/kayg/.nix-profile/bin/cargo --config "$HOME/.cache/codex-scratch/mesh-integrate/gate-profile.toml" "$@"
```

Use `umask 022`, `CARGO_BUILD_JOBS=4`, `RUST_TEST_THREADS=1`,
`PYTHONDONTWRITEBYTECODE=1`, `TRACER_TEST_PORT=4289`, and
`CARGO_TARGET_DIR=$HOME/.cache/codex-scratch/mesh-integrate/target`.
The state root must be the short job root itself: appending a directory would
exceed the kernel's Unix socket pathname limit in restart fixtures. Put the
cargo wrapper and the gate-installed Zig directory first on PATH.
`run-kernel.py` records separate namespace cases from Cargo JSON artifacts.
Run `review_shutdown_budget` with `INFRATERNAL_BIN` pointing to the static
binary. Use the existing shipping scale/namespace scripts for production proofs.

The explicit tracer gate passes typecheck, **150 source tests**, production
build and transfer budget; the protocol package passes typecheck and **36 tests**.
The oracle uses a separate scratch Cargo target to avoid competing compiler
locks consuming its deadline. No TypeScript or PWA presentation changed.

| Production transfer | gzip | Brotli |
| --- | ---: | ---: |
| Critical | 291,678 / 307,200 | 242,453 / 256,000 |
| Deferred | 49,647 / 51,200 | 43,731 / 45,056 |
| Largest on-demand chunk | 15,015 / 20,480 | 13,346 / 18,432 |

Raw gate, scale, production and regression evidence is retained without
normalizing output. No load-related baseline exemption was needed.
