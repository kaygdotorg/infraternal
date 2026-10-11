<!-- Defensive packet-policy, control identity, regression and performance evidence for #173, D164/D166/D197/D216/D227/D228/D235. -->
# Mesh policy verification

Base: `378b97da41584876c5aed8ba9828700c8511cd7d` (`origin/mesh-integrate`).
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

Final gate, measured cost, repair chronology, artifact provenance and reviewer
checklist will be appended after the campaign. This is an in-progress record.
