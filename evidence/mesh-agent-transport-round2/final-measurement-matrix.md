<!-- Prepares serial frozen-artifact namespace and retained-input checks for D215/#129; contains no acceptance result. -->

Run only after root freezes the shipping CLI and optimized server fixture and all owned compilation, functional tests and fuzzers stop. Use the same two immutable executables for all three rows; identify exact executable paths from Cargo JSON build artifacts, never a newest-file glob. Retain hashes, byte sizes, profile/target, Rust toolchain, Cargo.lock, branch head, source-tree hashes and uncommitted source diff at the build freeze and before each run. A matching head alone cannot identify an executable built from an uncommitted source union.

| Configured RTT | Each namespace's netem delay ± jitter | Silent cut to real terminal echo budget | Local echo p99 check |
| --- | --- | --- | --- |
| 0 ms | none | 250,000 us | mesh <= direct + 2,000 us |
| 150 ms | 75 ms ± 7 ms | 400,000 us | record direct and mesh; local-only bound does not apply |
| 300 ms | 150 ms ± 15 ms | 550,000 us | record direct and mesh; local-only bound does not apply |

The fixture serially measures 31 echoes each on direct, mesh and fallback, then silent UDP loss without a close, mesh restoration, restart while the underlay listener is blocked and explicit component down. Persist the report before lifecycle assertions and distinguish `silent_cut_to_echo_us` from `silent_cut_to_fallback_status_us`. `lifecycle_complete=false` preserves partial numbers, but does not pass the lifecycle proof. The existing report labels total configured jitter as RTT/10; at 150 ms the integer code actually applies 7 ms on each side, so record actual qdisc arguments as well.

```sh
# Supply exact frozen artifact paths, already built with mesh-transport-proof.
MAT_SERVER_FIXTURE=/absolute/path/to/optimized/infraternal_server-test-artifact
MAT_SHIPPING_CLI=/absolute/path/to/frozen/infraternal
# Repeat serially with MAT_RTT=0, 150, 300 after recording each provenance snapshot.
MAT_RTT=0
systemd-run --user --scope -p CPUWeight=10000 env \
  PATH="$PATH:/usr/sbin:/sbin" \
  INFRATERNAL_MESH_PROOF=1 INFRATERNAL_TEST_RTT="$MAT_RTT" \
  INFRATERNAL_MESH_BINARY="$MAT_SHIPPING_CLI" \
  unshare -Urnm "$MAT_SERVER_FIXTURE" \
  remote_runtime::tests::mesh_namespace::mesh_transport_real_namespaces_preserve_the_terminal \
  --exact --ignored --nocapture --test-threads=1
```

Before every row, require `/home/kayg/.cache/codex-scratch/mat-r2-ns` absent. If it exists, identify its owning fixture and stop; do not remove another live run's state. The test refuses host network/mount namespaces, owns its children and uses short Unix socket paths. Private key material crosses only an inherited pipe; do not capture stdin bundles or private state directories. After each process exits, copy only the freshly timestamped public `namespace-transport-<RTT>.json`, fixture stdout/exit and public firewall/path-timeout diagnostics to evidence. Preserve partial reports from failure; reject stale JSON from earlier runs. Confirm fixture state/children retired before the next row.

The same optimized server artifact measures 200 retained-input states, 31 writes per state (6,200 writes), with production command handlers and real Unix socket frames:

```sh
systemd-run --user --scope -p CPUWeight=10000 "$MAT_SERVER_FIXTURE" \
  input_retention_cost_at_200_terminals --ignored --nocapture --test-threads=1
```

Report write p50/p99, peak retained capacity, zero capacity after complete ACK, state bytes per terminal and maximum buffer bytes per terminal multiplied by 200. This fixture is **200 input states**, not 200 live PTYs, and its one-byte writes do not measure the full 4 MiB per-writer cap. The separate cap/backpressure regressions remain required.

Final six review tests, using exact frozen prebuilt artifacts and serial CPUWeight scopes:

| Finding | Artifact / test filter | Isolation |
| --- | --- | --- |
| MAT-R1 | mesh `review_ingress_translation`: `nft_translated_underlay_ingress_is_refused` | `unshare -Urn`, exact ignored test |
| MAT-R1 | mesh `review_ingress_translation`: `nf_tables_translated_underlay_ingress_is_refused` | `unshare -Urn`, exact ignored test |
| MAT-R2 | mesh `review_endpoint_transaction`: `refused_endpoint_persistence_preserves_kernel_endpoint` | `unshare -Urn`, exact ignored test |
| MAT-R3 | mesh `review_restart_routes`: `restart_retires_orphan_peer_host_routes` | `unshare -Urn`, exact ignored test |
| MAT-R4 | server: `review_pending_input_limit_retires_only_its_attachment` | normal library test; also require retained-input credit isolation regression |
| MAT-R5 | infraternal-agent: `review_silent_mesh_interruption_returns_to_fallback_within_local_reconnect_budget` | ignored real mTLS QUIC discard test, unique owned scratch output |

Read-only prerequisite snapshot: uid 1001/gid 1001, no effective host capabilities, NoNewPrivs=0; `kernel.unprivileged_userns_clone=1`, `user.max_user_namespaces=256636`, process AppArmor label `unconfined`. Existing WireGuard and sch_netem modules and `/dev/net/tun` are present. ip/unshare/nsenter/systemd-run are available; tc/nft/sysctl/iptables-nft are installed under `/usr/sbin`, absent from the current PATH, hence the per-process PATH extension above. No existing named network namespace was listed and short fixture state was absent. These reads do not execute a new namespace or guarantee a later unshare/qdisc operation; actual permission evidence comes from the isolated fixture. Kernel is 6.12.111+deb13-amd64. No host settings were changed.
