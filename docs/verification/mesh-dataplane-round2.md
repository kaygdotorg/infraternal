<!-- Mesh slice 1 round 2 regression, kernel, scale and gate evidence for #129, D206 and D228. -->
# Mesh slice 1 round 2

> Historical raw logs and receipts were removed under D262. Fresh receipts belong under
> `$HOME/.cache/codex-scratch/mesh-dataplane/evidence/` and should be attached to #129 with the
> `issue-attach` helper.

Base: `a5f744fbc1d5e8966de46982b995d816e91baff5`. Production/test head: `9091e49f`.
The three review commits were imported first, without weakening or deleting their assertions.
The sole test hygiene change removes redundant raw-string delimiters; packet contents are identical.

| Finding | Correction | Evidence |
| --- | --- | --- |
| R2: translated underlay ingress | Check final destination with incoming interface in INPUT and FORWARD, before mesh grants/conntrack, in both backends. Retain the early fence. | Both original translated-ingress tests pass; IPv6 base delivers, both repaired backends refuse. |
| R1: refused endpoint persistence | Validate the whole batch and persist intent before kernel changes; installation errors restore old endpoints and intent. | Original persistence-refusal regression passes with old kernel endpoint and acknowledged version. |
| R3: orphan restart routes | Retire owned static main-table host routes absent from durable inventory during initial/restart adoption, before final policy. | Original restart regression passes; companion removes both families and preserves five foreign/local routes. |
| Deadline test scheduling | Explicit Pending cancellation and paused test time, preserving the real socket, queued suffix, timeout and retirement checks. | Four deadline tests pass; repaired test 100/100; removing production expiry checks causes expired Ping decoding and a test failure. Restored source passes. |

Earlier Mesh tests: 23 ordinary cases, 8 kernel library cases and 5 kernel integration cases pass.
The new ownership case and four original review test functions also pass in isolated user/network namespaces.
TypeScript/client gate passes, including all 36 protocol/client tests; it was run separately because the Rust size row stops the combined dispatcher.

The nft rule-count regression remains constant at 1,000 peers: 10 drops (four added delivery guards) and 18 accepts.
The fallback adds one delivery drop per family, shared by INPUT and FORWARD. Legacy owned filter chains upgrade and clean up successfully in both families.

## Reviewer checklist

- Final-destination fences precede acceptance; both address families and delivery hooks are covered.
- Owned firewall adoption, legacy upgrade and component-off cleanup preserve unrelated host state.
- Endpoint batch validation precedes persistence; persistence refusal performs no kernel endpoint update.
- Restart deletes only owned main-table static unicast host routes; local routes, other interfaces, tables, protocols and subnet routes survive.
- Desired routes remain usable in the two-node production proof with 1,000 peers per node.
- Deadline cancellation uses controlled time, and the mutation check confirms the expiry assertions still detect the bug.
- Existing checked netlink parsing and approved dependencies are reused; no foundational engine was selected.
- No core role special cases, secrets, prices, new background work or server creation paths were added.
- Module role docs and invariant comments are present. No UI changed.

## Reproduction and provenance

Fresh logs and long diffs belong under `$HOME/.cache/codex-scratch/mesh-dataplane/evidence/`; the historical committed receipts were removed under D262.
Benchmark/proof commands run locally under `systemd-run --user --scope -p CPUWeight=10000` and `unshare -Urn`; no induced host load or other host was used.
Build outside the isolated network namespace so the compiler cache remains reachable. Save executable copies before comparing revisions.

The baseline fixture is built from archived a5f744fb Mesh source using a distinct package identity and the original pinned dependency versions (zero external version differences).
The repaired comparison fixture is an immutable copy at 3e44caef. Their hashes are retained below.
The earlier comparison using mutable Cargo output paths was discarded; only `actual-compare-*` data is accepted.
Invalid companion setup (loopback down), compiler-cache access inside the namespace, and overlong fixture-state paths were corrected and rerun before accepting evidence.
The full gate uses `RUST_TEST_THREADS=1`, `TRACER_TEST_PORT=4291`, and the 46-byte job scratch root as `INFRATERNAL_TEST_STATE_ROOT`.

## Environment and measurements

```json
{
  "machine": "infraternal-dev",
  "kernel": "6.12.111+deb13-amd64",
  "architecture": "x86_64",
  "logical_cpus": 8,
  "cpu_model": "Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz",
  "load": "28.48 20.79 17.36 6/3054 1581916",
  "scope": "systemd-run --user --scope -p CPUWeight=10000",
  "profile": "isolated user/network namespaces on shared infraternal-dev; no induced load"
}
```

Rust toolchain: 1.99.0. Packet comparison fixtures use the debug profile with server and agent features; shipping and optimized library runs use x86_64-unknown-linux-musl release builds.

These sequential samples had no overlapping builds or tests from this job. Other jobs remained active; load averages were roughly 27–34 on 8 cores. They are diagnostic samples, not a statistically controlled regression comparison. The post-translation check is required for correctness even when it adds packet work.

| Fixture revision | Backend | IPv4 mesh RTT p50/p99 (ms), 25 packets | Mesh throughput (Mbit/s), 128 MiB | Load at sample |
| --- | --- | --- | --- | --- |
| a5f744fb | nft | 0.196 / 0.22 | 1267.16 | 23.71 25.58 21.06 |
| 3e44caef | nft | 0.21 / 0.265 | 1282.68 | 23.43 25.46 21.07 |
| a5f744fb | nf-tables | 0.193 / 0.248 | 1481.99 | 26.88 26.13 21.36 |
| 3e44caef | nf-tables | 0.195 / 0.807 | 1485.85 | 29.37 26.68 21.59 |

Immutable fixture provenance:

```json
{
  "baseline-kernel_node": "65eee7293afbcd2b1a734a394b5b62d4e8cac7112a432871e6f29a93f80cb881",
  "fixed-kernel_node": "c74be5c4b97fbe706349eba8d94f3df7312c1365cbf4e2c532666fce599133d0",
  "baseline_revision": "a5f744fbc1d5e8966de46982b995d816e91baff5",
  "fixed_revision": "3e44caef",
  "external_dependency_version_differences": 0
}
```

The production namespace proof uses two shipping daemons with **1000 peers each**, one real direct pair and 999 additional public members, compiled by the production-schema coordinator fixture. The authenticated control fixture uses an inherited socket. No relayed or WAN capacity is claimed. IPv4 and IPv6 each received 25/25 packets; deny-new ping/TCP, established-flow survival and port grant/narrowing all pass. Component off passes on both nodes.

IPv4 RTT p50/p99: 0.197 / 8.0 ms; IPv6: 0.194 / 0.235 ms. Direct throughput: 1403.97 Mbit/s. Join to first packet: 1605268 µs. Load: 31.65 28.58 22.89. The 8 ms IPv4 tail is retained rather than hidden; this 25-packet shared-load sample does not establish a tail-latency budget.

RSS at 1,000 peers: 8,388,608 and 8,519,680 bytes per daemon, mean × expected 1,000 nodes = 8,454,144,000 bytes across the fleet. Both daemons used 0 CPU ticks in 10 idle seconds. This is a fleet projection, not 1,000 daemons measured on one machine.

Shipping single-node scale (includes durable save and RPC):

| Measurement | Result |
| --- | --- |
| Peers | 1,000 |
| Chunks | 32 |
| Snapshot apply (µs) | 267,134 |
| One endpoint update (µs) | 16,192 |
| Component down (µs) | 26,208,642 |
| RSS on (bytes/node) | 8,388,608 |
| RSS off (bytes/node) | 8,040,448 |
| RSS on × expected 1,000 nodes (bytes) | 8,388,608,000 |
| Idle CPU ticks in 10 s, on | 0 |
| Idle CPU ticks in 10 s, off | 0 |

Public CLI/status/pagination/lifecycle/skill declarations pass. Load: 16.27 24.11 22.06.

Optimized library diagnostics at 1,000 peers (no durable directory, unlike the shipping scale result):

```text
METRIC nft_policy machine=infraternal-dev peers=1000 apply_us=69799 single_peer_us=101643 load=30.19 27.62 22.25 33/3197 1707802
METRIC nf_tables_policy machine=infraternal-dev peers=1000 apply_us=337092 single_peer_us=310278 load=30.19 27.62 22.25 34/3207 1708008
METRIC mesh_node machine=infraternal-dev peers=1000 chunks=33 apply_us=220588 single_endpoint_us=1070 load=31.06 27.84 22.35 44/3214 1708360
```

All eight final runs pass: optimized kernel suite, production 1,000-peer namespace, shipping single-node scale, IPv4/IPv6 underlay ingress and transit refusal for both backends, and fallback namespace connectivity/policy proof. Legacy fallback upgrade and translated IPv6 refusal are also retained in the R2 evidence.

## Gate and size

`scripts/verify fast` on production/test head `9091e49fe868dcef6735260817978fef49a8e779`:

```text
+---------------------------+--------------+
| Rust gate                 | Result       |
+---------------------------+--------------+
| fmt                       | PASS         |
| VT native fmt             | PASS         |
| clippy                    | PASS         |
| test                      | PASS         |
| cargo-deny                | PASS         |
| static builds             | FAIL (1)     |
+---------------------------+--------------+
```

The only failed row is the known x86_64 size budget (D205); no baseline or allowance changed. Static, stripped PIE has no PT_INTERP. ARM builds were not reached because the size row stops the dispatcher.

| Stage | x86_64 bytes | Delta vs recorded a5f744fb |
| --- | --- | --- |
| Recorded a5f744fb | 20,614,656 | 0 |
| R2 | 20,615,552 | +896 |
| R1 / unused route primitive | 20,616,448 | +1,792 |
| Final, including restart route reconciliation | 20,634,560 | +19,904 |

The final production increment adds route-dump validation, desired-address membership and exact deletion during adoption; dev-only clock support and test-only changes do not add runtime behavior. Existing max is 16,404,816 bytes, overrun 4,229,744 bytes. The a5f744fb shipping size is the recorded prior measurement, not a freshly rebuilt CLI baseline.

Accepted logs: `round2-red-*.log`, `r3-green-*.log`, `r3-ordinary-*.log`, `r3-integration-clippy.log`, `deadline-ordering-red.log`, `deadline-repeat.log`, `deadline-mutation-red.log`, `deadline-restored-green.log`, `deadline-clippy.log`, `actual-compare-*.log`, `release-mesh-kernel.log`, `production-1000-peer-namespace.log`, `production-agent-scale.log`, `final-mesh-*-proof-*.log`, `final-namespace-nf-tables.log`, `legacy-filter-upgrade.log`, `translated-v6-actual-*.log`, `verify-round2-final.log`, and `ts-fast-round2.log` in the job scratch directory. Temporary build targets, archived baseline sources and probe executables are removed after recording evidence.

Reproduce kernel tests by building outside the namespace, then running each saved test executable with `--ignored --test-threads=1` inside the scope and `unshare -Urn`. Reproduce scale with `scripts/mesh-agent-scale.py --binary <static-binary> --scratch <job-scratch>`, and the production pair with `scripts/mesh-namespace-proof.py --binary <static-binary> --coordinator <coordinator_fixture> --scratch <job-scratch> --extra-members 999`. The fallback pair uses `--fixture <kernel_node> --nf-tables`. Build baseline comparisons in a fresh baseline-specific target directory, or a distinct package identity with pinned versions; never trust a reused Cargo executable path as revision provenance.
