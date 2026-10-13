<!-- Reproduction, measurements and retained gate evidence for mesh policy round 3, issue #173. -->
# Mesh policy round 3

> Historical raw logs and receipts were removed under D262. Fresh output belongs under
> `$HOME/.cache/codex-scratch/mesh-policy-verify/evidence/` and should be attached to #173 with
> the `issue-attach` helper.

The three retained review findings are repaired: host retirement removes active
membership and grants transactionally and publishes to live coordinators;
authenticated re-enrollment is accepted by the real node; cleanup requires the
exact owned firewall identity. Additional regressions cover retained addresses
at restart and attestation of unchanged legacy snapshots. Atomic commits and
per-step gate records are on [#173](https://git.kayg.org/kayg/infraternal/issues/173).

## Correctness evidence

- Both frontends: **170/170 packet checks**, plus **5/5 migrated enrollment-to-kernel controls** each: **350/350** total.
- **42 distinct real-kernel namespace cases** pass, plus ordinary tests in 22 test executables. The initial aggregate run had one setup failure: the shipping shutdown case requires `INFRATERNAL_BIN`. Its second setup attempt lacked the supplied scratch directory. Both are retained; the correctly configured release run passes with **1000 peers and down_us=504090**, below the unchanged 1000000 us budget.
- The live publication assertion fails before the Mesh callback (5.09 s timeout) and passes after it (0.16 s). Both retained-address and unchanged-legacy-binding assertions fail before their repairs and pass afterward. Original accepted-version/identity fences remain enabled and pass.
- `gates/` contains per-step formatting, strict touched-crate Clippy, tests, expected failures and namespace result records. `local/` retains packet controls, actual peer counts, arrival timestamps and shipping behavior. See [the author checklist](reviewer-checklist.md).

## Retirement measurements

The harness drives the production authority writer and event-driven coordinator
through trusted admitted-channel fixtures. Three real kernel nodes are present:
a retired sender and **two live receiving peers**, each initially containing
**1000 actual kernel peers** (999 afterward on receivers). The remaining public
members are synthetic, with realistic key byte widths. Both IPv4 and IPv6 reach
the controlled service before retirement; packets sent after confirmed key
removal are refused. Control delay is emulated independently, and the VM data
link uses netem with measured underlay RTT.

Times below are **retirement request to the last receiving peer's confirmed
kernel key removal**. They conservatively include transaction/publication and
fixture scheduling; they are not exact SQLite COMMIT timestamps or a claim about
1000 live traffic pairs.

| Machine / link | nft | iptables-nft |
| --- | ---: | ---: |
| infraternal-dev, local | 1174761.639 us | 1790073.983 us |
| authorized perf VM, 150 ms, first calibrated run | 337652.806 us | 618407.042 us |
| authorized perf VM, 150 ms, interleaved campaign repeat | 495955.591 us | 765216.672 us |

Calibrated first-run mean RTTs: nft 150.191/150.163 ms; compatibility
150.226/150.161 ms. The original third-peer samples were 150/200/300 ms because
the first packet included neighbor discovery. `calibration-original/` preserves
that failure; the repair records the neighbor warmup separately before the
unchanged RTT assertion. No RTT threshold was relaxed.

The repeat's mesh-node fixture RSS was 8790016/8994816/8728576 bytes (nft) and
9003008/9146368/9216000 bytes (compatibility): maximum projections of
**8994816000** and **9216000000 bytes across 1000 nodes**, respectively. These are
component fixtures, not whole infraternal-agent RSS budget measurements. The
coordinator observation uses three live workers, not 1000 live workers.

## 1000-peer apply measurements

Local infraternal-dev, real kernel, **[1000,1000]** peers, one live pair, debug
fixture. 48 iterations with two grant changes yield **192 node timings per
frontend**. Full distributions and each sample's load are retained in
`performance/final-measure-*.json`.

| Frontend | Cold node apply samples | Policy update median | Observed range |
| --- | ---: | ---: | ---: |
| nft | 331127 / 438935 us | 269362 us | 179114–468654 us |
| iptables-nft | 1009984 / 969895 us | 933708 us | 740542–1455889 us |

Shared load was roughly 53–55 in these cohorts; owned release/static builds
also overlapped. These are qualified observed numbers, not quiet-host tail
budgets or an interleaved before/after apply-regression claim. The separate
shipping-release shutdown gate above passes its unchanged scale budget.

## Native latency comparison: unwaived failures remain

Base **378b97da** versus repaired source, identical GNU release profiles and
private native runtime libraries. The package step changes only PT_INTERP,
RUNPATH and debug sections; each artifact records matching executable-segment
hashes. The perf VM runs under the shared lock and CPUWeight=10000. Each RTT
cohort uses **base → head → head → base**, 100 echoes per scenario, with machine,
load, run duration and full metrics in `performance/perf-vm/`.

| Configured RTT | Base ordinary PTY echo p99 | Head ordinary PTY echo p99 | Base same-session flood p99 | Head same-session flood p99 |
| --- | ---: | ---: | ---: | ---: |
| 0 ms | 0.69–0.77 ms | 0.49–0.72 ms | 5.99–6.37 ms | 5.83–7.53 ms |
| 150 ms | 133.41–135.98 ms | 140.16–142.01 ms | 151.85–167.32 ms | 179.98–206.17 ms |
| 300 ms | 323.14–324.48 ms | 324.66–326.16 ms | 383.50–422.54 ms | 400.12–416.42 ms |

All four 0 ms profiles pass. All eight delayed profiles **FAIL** the unchanged
same-session flood-growth budget of **16.67 ms** on both candidates. One 150 ms
head run and all 300 ms runs also exceed their unchanged absolute echo budget.
At 150 ms the head cohorts are higher; this comparison includes all integration
changes since 378b97da and does not isolate a policy-repair cause. No latency
waiver, broad no-regression claim, browser-latency pass or threshold change is
made. These failures remain recorded on #173.

## Reproduction

Use the pinned toolchain, umask 022, job-specific targets under
`$HOME/.cache/codex-scratch/`, and a short private state root. Never use `/tmp`
for targets. Native gate qualification follows the existing
`../gates/gate-profile.toml`: dev opt-level 1 only for the infraternal
agent/server/shim; dependencies and release profiles stay unchanged.

```sh
cargo test --locked -p infraternal-plugin-mesh --all-features --all-targets --no-run
cargo build --locked -p infraternal-plugin-mesh --all-features --example kernel_node --example coordinator_fixture
cargo build --locked -p infraternal-server --all-features --example mesh_revocation_fixture
systemd-run --user --scope -p CPUWeight=10000 unshare -Urn python3 scripts/mesh-revocation-proof.py --fixture "$CARGO_TARGET_DIR/debug/examples/kernel_node" --coordinator "$CARGO_TARGET_DIR/debug/examples/mesh_revocation_fixture" --evidence "$CARGO_TARGET_DIR/retirement"
systemd-run --user --scope -p CPUWeight=10000 unshare -Urn python3 scripts/mesh-policy-proof.py --fixture "$CARGO_TARGET_DIR/debug/examples/kernel_node"
```

Repeat with `--nf-tables`. Run the packet harness separately with
`--enrollment-fixture "$CARGO_TARGET_DIR/debug/examples/coordinator_fixture"`
for the five enrollment controls, or with `--measure --apply-rounds 48` for the
counted apply distribution. For delayed retirement, use `--rtt-ms 150` on the
authorized perf VM through NetBird SSH under `/var/lock/perf-bench.lock`.
`performance/perf-run.py` records the interleaved native profile commands.
Always set a unique TRACER_TEST_PORT for browser harnesses.

The final code/evidence head `84133448` passed every `scripts/verify fast` row
except static builds. Its x86_64 static binary is **21740144 bytes** against the
unchanged **16404816-byte** ceiling; the static-build script stops there, so this
run makes no ARM static-build claim. The complete output is retained in
`gates/final-fast-84133448.log`; the summary is recorded verbatim on #173.
Static size ceilings remain unchanged. No
deployment or issue closure. Ordinary range changes still require the existing
overlap barrier; established-flow retention after grant narrowing is unchanged.
Relay, subnet, exit and login paths are outside this data-plane slice.
