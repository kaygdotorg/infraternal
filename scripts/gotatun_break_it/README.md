# GotaTun break-it suite

The Linux matrix runs a real infraternal agent pair and the production-schema
mesh coordinator fixture inside a disposable user and network namespace on
compute01. Every case owns its veth pair, coordinator database, agent state and
evidence directory. It leaves the host network configuration untouched.

Build the product and coordinator fixture through the compute01 build slot,
using the job target on `/mnt/build`:

```sh
export CARGO_TARGET_DIR=/mnt/build/targets/J526
~/infraternal-ops/build-slot nice -n10 nix develop . -c cargo build --release --locked \
  -p infraternal --bin infraternal \
  -p infraternal-plugin-mesh --example coordinator_fixture \
  --features infraternal-plugin-mesh/agent
```

Run the matrix with `tc`, `nft`, `conntrack`, `unshare`, `nsenter`, and `ip`
available on `PATH`. The Nix shell below supplies those tools without
installing them on compute01. Choose a new evidence directory for every run;
the `--output` path must not already exist because the matrix creates and owns
that directory:

```sh
~/infraternal-ops/build-slot nice -n10 nix shell \
  nixpkgs#iproute2 nixpkgs#nftables nixpkgs#conntrack-tools nixpkgs#util-linux \
  --command bash -c '
    cd /home/claude/worktrees/J526
    unshare -Urn python3 scripts/gotatun_break_it/linux_matrix.py \
      --binary /mnt/build/targets/J526/release/infraternal \
      --coordinator /mnt/build/targets/J526/release/examples/coordinator_fixture \
      --output /home/claude/.cache/codex-scratch/J526/evidence/linux-YYYYMMDD-runN
  '
```

Pass `--case CASE_ID` one or more times to run a subset. The default runs the
full matrix. Each case writes `case.json`; the run writes `host.json` and
`summary.json`. Results include fault and recovery intervals, p99 probe latency,
probe loss, payload bytes sent, verified bytes, bytes stalled at fault-clear,
integrity, and manual-fix status. DNS is queried directly over the mesh route.
Peer-scale rows count the 148-byte handshake initiation evidence in peer
counters after the initial config commit; later packet capture is reported
separately because those attempts can precede its capture window.
Endpoint IP and NAT rebind recovery starts when the changed endpoint becomes
active; link recovery starts when the link is restored. Those three rows apply
D41's 300 ms reconnect budget from that reference, even when an injected NAT
mapping remains active after reconvergence. Reports include the recovery
reference and whether the budget was met.
Before injecting a fault, the runner requires at least 1 MiB to be sent and
received. A flow that cannot establish that sustained payload fails setup and
its probe and payload processes are stopped.

The `coordinator-restart` row restarts the production-schema coordinator
fixture with its SQLite database preserved, then reapplies its config. The
`server-restart` row restarts the real `infraternal server` process in the
isolated test namespace while the already-configured peer flow remains active;
its private data directory is retained and `/healthz` must return 200 after the
new process starts. The coordinator fixture still supplies the test peers in
this row, so it measures whether a server outage interrupts the established
data plane, not recovery of a server-owned mesh database. The
`rekey-timer-expiry-under-load` row marks the coordinator's persisted schedule
due before exercising the real infraternal agent's rotation actions. These
fixture boundaries are recorded in the case details so they are not mistaken
for an independently scheduled background worker.

## Continuous loaded-latency soak

Run the one-to-two-hour leak and latency soak on compute01 under one build-slot
hold. It keeps the same product pair alive and samples per-thread scheduler
wait, RSS, descriptors, threads, CPU ticks, GotaTun queue depth, and probes on
one monotonic timeline. compute01 does not grant unprivileged kernel tracepoint
access; the separate 10-minute backup01 window captures TID-filtered `perf
sched` events. The product binaries must already be built in the job target on
`/mnt/build`. Use a fresh evidence directory each time:

```sh
CARGO_TARGET_DIR=/mnt/build/targets/J526 \
~/infraternal-ops/build-slot nice -n10 nix shell \
  nixpkgs#iproute2 nixpkgs#util-linux nixpkgs#python3 \
  --command bash -c '
    cd /home/claude/worktrees/J526
    python3 scripts/gotatun_break_it/long_soak.py \
      /home/claude/.cache/codex-scratch/J526/evidence/loaded-latency-long-YYYYMMDD \
      3600 \
      /home/claude/.cache/codex-scratch/J526/j88c-kit \
      /mnt/build/targets/J526/release/examples/coordinator_fixture \
      /mnt/build/targets/J526/release/infraternal \
      --underlay-rate-mbit 800
  '
```
