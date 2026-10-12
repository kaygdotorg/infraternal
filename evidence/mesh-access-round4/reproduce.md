<!-- Reproduction commands for D242 exact established-state retirement, issue #173. -->
# Reproduction

Use a disposable scratch target under `$HOME/.cache/codex-scratch/<job>/` and
build `infraternal-plugin-mesh` with feature `agent`, examples `kernel_node` and
`connection_state_fixture`. The native examples and scripts are AGPL-only
repository code; no new runtime dependency is needed.

Functional namespace proofs may run on the build host:

```sh
PATH=/usr/sbin:/usr/bin:$PATH unshare -Urn python3 scripts/mesh-access-state-proof.py --fixture "$TARGET/debug/examples/kernel_node" --evidence "$SCRATCH/state-nft"
PATH=/usr/sbin:/usr/bin:$PATH unshare -Urn python3 scripts/mesh-access-state-proof.py --fixture "$TARGET/debug/examples/kernel_node" --evidence "$SCRATCH/state-compat" --nf-tables
```

Repeat each state proof with `--outgoing`. Run
`mesh-connection-rollback-proof.py` and `mesh-connection-recovery-proof.py` with
`--fixture "$TARGET/debug/examples/connection_state_fixture"` and private
`--evidence` directories; each also accepts `--nf-tables`. State roots are
created below the evidence directory and contain only disposable public
intent. These harnesses print pass/fail counts; raw kernel state stays in files.

Performance runs belong exclusively on the authorized VM, through NetBird SSH,
under `/var/lock/perf-bench.lock`, with the requested CPU-weight scope.
`perf-campaign.sh` shows the balanced base/head/head/base sample order and all
change/peer-count/RTT cases. Its final run uses the corrected probe and the
final node artifact. Native packaging follows the existing private-loader
fixture procedure and records source/adapted/executable-segment hashes.
The VM campaign uses only its own disposable network namespaces.

The final static gate uses `scripts/verify fast`, a private scratch target,
`TRACER_TEST_PORT=4373`, and a short disposable test-state root. The complete
output is retained on #173. No gate threshold is relaxed.

The final gate places `gate-python3.sh` at `<scratch>/gate-bin/python3` on PATH.
Only the exact fast setup call (`latency_proxy.py self-test --samples 3`) is
routed to the authorized locked VM to satisfy the owner timing rule; the current
repository script is copied there first. Every other Python call uses the same
installed Python as the original gate. No argument or limit is changed. Set
`CARGO_BUILD_JOBS=4`, `RUST_TEST_THREADS=4`, `TRACER_TEST_PORT=4373`, the private
`CARGO_TARGET_DIR`, and the short disposable `INFRATERNAL_TEST_STATE_ROOT`.
The original shared-host setup failures remain retained and qualified as setup
attempts, not performance evidence.
