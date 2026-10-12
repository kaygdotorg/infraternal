<!-- Defensive packet-policy, control identity, regression and performance evidence for #173, D164/D166/D197/D216/D227/D228/D235. -->
# Mesh policy verification

The continuation and current measurements are recorded in [round 3](round3/README.md). The earlier measurements below describe the pre-review source.

Base: `378b97da41584876c5aed8ba9828700c8511cd7d` (`dev` at job launch).
Work is confined to `mesh-policy-verify` and disposable user/network namespaces
on infraternal-dev. No production or host networking is modified.

## Findings (phase one)

| ID | Priority | Source at base | Test | Result and evidence | Fix note |
| --- | --- | --- | --- | --- | --- |
| MPV-1 | P1 | `crates/plugins/mesh/src/store.rs:84` | `unbound_enrollment_public_key_is_not_host_authority` | FAIL on real migrated SQLite: claimed and rotated node 3 inherits intended node 3's UDP 5540 grant. `enrollment-red.log`. | Require explicit authenticated host binding; a public enrollment key cannot authorize attachment. Kernel path reproduction and repair follow. |
| MPV-2 | P2 | `crates/plugins/mesh/src/node.rs:296` | `nft_equal_version_conflicting_snapshot_is_refused`, `nf_tables_equal_version_conflicting_snapshot_is_refused` | Both FAIL in separate real-kernel namespaces: version 10 deny replaced by version 10 allow. Named logs. | Permit identical replay only; refuse different complete contents at an accepted version. Retained as failing tests. |
| MPV-3 | P2 | `crates/plugins/mesh/src/node.rs:308` | `nft_snapshot_cannot_replace_local_node_identity`, `nf_tables_snapshot_cannot_replace_local_node_identity` | Both FAIL in separate real-kernel namespaces: node 1 replaced with node 3 at version 11, same addresses. Named logs. | Bind staging to the accepted local node identity across snapshots. Retained as failing tests. |

MPV-2/3 require conflicting input from the trusted coordinator. They do not
demonstrate an unauthenticated packet bypass. MPV-1 crosses the authenticated
host-to-inventory authorization boundary and gives an unauthorized host a
grant usable with its own key. No P0 finding has been established.

The regression files precede repairs. Namespace-only and known P2 failures
are explicitly ignored by ordinary Cargo runs, and run separately with
`--ignored --exact <test> --nocapture --test-threads=1`. No assertion is removed
to turn a gate green.

## Packet campaign

`scripts/mesh-policy-proof.py` reuses the existing kernel node and namespace
helpers. The sender's policy is removed during inbound checks; denial must
come from the receiving node. Independent OUTPUT tests use an accepting
receiver. Fresh socket tuples avoid relying on an earlier conntrack entry.

The preferred backend currently passes 102 checks: IPv4/IPv6 UDP (including
raw port 0, port 65535, three consecutive ports and both edges), TCP protocol
separation, ICMP/ICMPv6, whole and fragmented packets under All/None/Ports,
plaintext and translated port publishing, 12 unauthorized inner sources,
independent output denial, unrequested forwarding and removed-peer refusal.
Positive cases prove live services; forwarding also checks encrypted receiver
counters. The iptables-nft backend also passes 102/102 checks in the retained phase-one run.
Both suites will run again after the repairs.

The consecutive ports are compiled as individual grants: the contract has no
range syntax. Port 0 is prohibited in grants; a raw receiver tests the kernel
edge without accidentally binding an ephemeral port.

## Contract and coverage boundaries

- D216 amends D164: community default is allow; explicit per-peer None in
  the internal configuration is exercised. The public grant API rejects None
  and has no explicit deny-grant shape.
- The frozen direct-path contract explicitly preserves established flows
  after grant removal/default changes. No finite cutoff bound exists there.
  The requested finite established-flow cutoff is therefore an unmet brief
  requirement, not silently substituted with a passing retention test.
- D166 membership does not expire. The seven-day mTLS certificate controls
  coordinator transport admission, not retained WireGuard membership or the
  last-known policy. D235 login certificates are separately 1–24 hours.
- This base has no relay data plane, subnet-route component, exit-node
  component, or mesh-login implementation. Forwarding is refused in slice 1.
  No relayed/direct equivalence, relay-injection, exit-node grant or D235
  end-to-end login claim is made for absent code.
- Earlier R1–R6 evidence is in `mesh-dataplane-round2.md`,
  `mesh-dataplane-round3.md` and `mesh-integrate.md`; those regressions are
  reused, not duplicated.

## Reproduction

Build outside the isolated namespace, keeping the compiler cache reachable:

```sh
export CARGO_TARGET_DIR="$HOME/.cache/codex-scratch/mesh-policy-verify/target"
cargo build --locked -p infraternal-plugin-mesh --features agent --example kernel_node
systemd-run --user --scope -p CPUWeight=10000 \
  env PYTHONDONTWRITEBYTECODE=1 unshare -Urn python3 scripts/mesh-policy-proof.py \
  --fixture "$CARGO_TARGET_DIR/debug/examples/kernel_node"
# Repeat with --nf-tables; use --measure for the 1,000-peer packet-path diagnostic.
```

## Repairs and completed coverage

- MPV-1: explicit optional `host_id` enrollment requires global node-management
  authority and an existing unrevoked authenticated remote host. The existing
  writer transaction records binding, clears removal and publishes revision/audit
  together. Attachment selects only that authenticated host binding. A public
  enrollment key never authorizes attachment or clears removal. Existing bound
  hosts keep their identity across rotation. Legacy inventory remains unbound.
  The typed client exposes the same additive field; legacy input is unchanged.
- MPV-2: compare complete staged contents before accepting an equal-version
  snapshot. Identical complete replay passes, including split replay; different
  contents are refused without replacing the accepted kernel policy.
- MPV-3: a snapshot cannot replace the accepted local node identity. Failed
  staging clears pending input and retains accepted configuration.

Original migrated-SQLite MPV-1 test preceded the repair (`24f27282`). The four
original snapshot failures preceded repairs (`57a74b06`); two additional split
replay failures also preceded repair. Explicit-binding tests reproduced two
missing checks before the API change; the typed-client compiler reproduced its
missing input field before the client change. Every regression retains its
assertions. The ordinary server gate now includes MPV-1.

Production-schema-to-kernel MPV-1 replay uses the actual two kernel identities
with the existing coordinator fixture. At original source `24f27282`, each
backend has **2 PASS / 3 FAIL**: the unbound claim is accepted and its UDP 5540
service is usable in both families. After repair, each has **5 PASS / 0 FAIL**:
claim refused, service not permitted, then explicit owner grant reaches that
same live service. Sender filtering is removed for the receiving checks.

The expanded campaign has **170 PASS / 0 FAIL per backend** (340 total), adding
independent All/None/Ports OUTPUT checks, protocol separation, both port edges,
fragmentation and ICMP to the original 102 checks. The enrollment proof adds
10 passing packet/control checks. Separate exact namespace tests cover the
six snapshot cases and existing lifecycle/ownership/recovery regressions.
The 32 substantive namespace cases pass; the internal shutdown child is a
helper, not an additional proof. The shipping static 1,000-peer shutdown
budget also passes separately (33 substantive namespace cases total).

Eight initial direct-executable namespace runs omitted `CARGO_TARGET_DIR` and
failed fixture initialization; all eight pass with the required environment.
No implementation assertion changed. Full gate setup findings and qualification
are recorded below and in `gates/`.

## Policy application at 1,000 peers

The primary policy-change measurement narrows and widens one live directed
pair using small deltas while both nodes retain **1,000 actual kernel peers**.
Each candidate/backend has 12 rounds × 2 changes × 2 nodes = **48 per-node
samples**. The harness verifies kernel counts `[1000,1000]`. Node timings omit
Python serialization; pair timings retain it. Both candidates use the same
unmodified default dev profile (unoptimized with debug information).

| Backend | Before median, µs/node | After median, µs/node | Change |
| --- | ---: | ---: | ---: |
| nft | 287,296 | 284,921 | −0.83% |
| nf_tables | 971,826.5 | 915,199.5 | −5.83% |

No median policy-replacement regression was measured. This is shared-host
measurement evidence, not a pinned-host latency guarantee. All samples, ranges,
load records and exact kernel/CPU metadata remain under `performance/`.
The machine is infraternal-dev, 8 logical CPUs; all workloads run locally in
`systemd-run --user --scope -p CPUWeight=10000`. One live pair plus 999 synthetic
public members per node is not 1,000 simultaneous traffic pairs. The repairs
add no retained per-peer storage, background work or dependency.

Cold full-install pair measurements are retained separately: nft medians
864,812 → 785,252 µs (3 before/after runs); nf_tables 1,988,582 → 2,078,256 µs
(8 before/after runs). The latter varies with peer setup and shared scheduling;
**no cold-start improvement or non-regression claim is made**. Two incomplete
101-ping samples, one per candidate, are retained without relaxing assertions.

The original alternating RTT diagnostic had invalid later policy-on labels:
unchanged configuration replay correctly skips filter rebuilding after the
harness deliberately flushes chains. A new installed-rule-count assertion
failed on both backends before the harness repair. The diagnostic now restores
saved namespace-owned rules directly before each policy-on sample and keeps
that assertion. Initial apply measurements were valid; later old RTT labels
are not used as proof. No production fast path was changed for this diagnostic.

## Reproduce the continuation

```sh
export CARGO_TARGET_DIR="$HOME/.cache/codex-scratch/mesh-policy-verify/target"
cargo build --locked -p infraternal-plugin-mesh --features agent \
  --example kernel_node --example coordinator_fixture
# Receiving and independent output policy (repeat each with --nf-tables):
systemd-run --user --scope -p CPUWeight=10000 \
  env PYTHONDONTWRITEBYTECODE=1 unshare -Urn python3 scripts/mesh-policy-proof.py \
  --fixture "$CARGO_TARGET_DIR/debug/examples/kernel_node"
# Actual migrated enrollment/grant-to-kernel path:
systemd-run --user --scope -p CPUWeight=10000 \
  env PYTHONDONTWRITEBYTECODE=1 unshare -Urn python3 scripts/mesh-policy-proof.py \
  --fixture "$CARGO_TARGET_DIR/debug/examples/kernel_node" \
  --enrollment-fixture "$CARGO_TARGET_DIR/debug/examples/coordinator_fixture"
# Counted policy replacements at 1,000 peers:
systemd-run --user --scope -p CPUWeight=10000 \
  env PYTHONDONTWRITEBYTECODE=1 unshare -Urn python3 scripts/mesh-policy-proof.py \
  --fixture "$CARGO_TARGET_DIR/debug/examples/kernel_node" --measure --apply-rounds 12
```

For the original MPV-1 packet replay, build `coordinator_fixture` from original
source `24f27282` with the current fixture's `unbound-identity` extension in a
disposable scratch checkout, and use the original kernel fixture. It changes
only proof code; the original store/node implementations remain unchanged.
Raw before/after logs in `phase1/` and `phase2/` retain the results.

Namespace tests are built outside isolation; locate executables from Cargo
JSON artifacts. Export `CARGO_TARGET_DIR` when running them, and use a fresh
`unshare -Urn` per exact ignored test. `kernel/` retains the substantive cases.

## Gate execution and qualification

Per-step fmt, all-feature/all-target mesh Clippy, touched tests and configured
TypeScript compiler/client tests pass. The protocol package has no `check`
script; its existing strict tsc gate is used. No UI presentation changed.
Existing production fuzz targets `mesh_api_json` and `mesh_node_json` still
exercise the modified action/strict node parsers; no new parser/engine exists.
No new fuzz-run claim is made.

The first milestone's restart checks refused cached native executables built
with mode 0775. The unchanged isolated test passes after correcting only owned
job-target modes. All further builds use `umask 022`; no trust check or timeout
was weakened. A second run found the job's long state path exceeds AF_UNIX's
limit; the same immutable daemon test passes using the dedicated short job
state root `$HOME/.cache/codex-scratch/mpv-173`.

Follow the base's documented native gate qualification: use the recorded
`gates/gate-profile.toml` through a scratch cargo wrapper. Only
infraternal-agent/server/shim dev opt-level is 1; dependency and release profiles
stay unchanged. This is **not a default native-profile pass claim**. Use
`CARGO_BUILD_JOBS=4`, `RUST_TEST_THREADS=1`, `PYTHONDONTWRITEBYTECODE=1`,
`TRACER_TEST_PORT=4373`, the job-specific target and short state roots. No #118
waiver is claimed for setup failures. The explicit frontend gate passes **157 tracer/shared-component tests and 37
protocol tests**, strict compilation, production build and transfer budgets.
The first qualified run still fails its test row only at the immediate long
fixture path; the same daemon test passes with the short root. Its x86_64
static output is **21,318,864 bytes**, versus the unchanged **16,404,816-byte**
ceiling (base 21,315,280; delta 3,584 bytes). The aarch64 output is **18,879,528 bytes**, versus the unchanged
**13,817,816-byte** ceiling (base 18,877,112; delta 2,416 bytes). Both are
static/stripped ELF with no PT_INTERP. The final full-head run is recorded
on #173 at handoff. Partial/failed gate logs remain separate from
final-head evidence.

## Owner question retained

Should the frozen direct-path contract introduce a finite established-flow
cutoff after grant removal? It currently preserves established flows; there is
no finite bound to prove. This remains on #173. Behavior is unchanged. Absent
relay/subnet/exit/login paths retain the coverage limits listed above.
