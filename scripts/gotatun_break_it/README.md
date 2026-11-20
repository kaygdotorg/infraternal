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

Run the matrix with `tc`, `nft`, `conntrack`, `tcpdump`, `unshare`, `nsenter`, and `ip`
available on `PATH`. The Nix shell below supplies those tools without
installing them on compute01. The runner creates private network and mount
namespaces, with a private `/run/infraternal` directory for the server's
embedded agent. This keeps its root-owned session state inside the test mount
namespace. Choose a new evidence directory for every run; the `--output` path
must not already exist because the matrix creates and owns that directory:

```sh
~/infraternal-ops/build-slot nice -n10 nix shell \
  nixpkgs#iproute2 nixpkgs#nftables nixpkgs#conntrack-tools nixpkgs#util-linux nixpkgs#tcpdump \
  --command bash -c '
    cd /home/claude/worktrees/J526
    scripts/gotatun_break_it/run_linux_matrix.sh \
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
The NAT rebind row behaves like a router that has moved B's mapping: the
translated port and a drop for new flows to the old port stay in place until
the case's namespace is torn down, and the row fails unless A ends up
addressing B at the new port. Every run, pass or fail, keeps
`underlay-a.pcap` and `underlay-b.pcap` (UDP headers on both ends, until
teardown) and `nat-rebind-evidence.jsonl`: B's conntrack, the injected NAT's
counters and both agents' live peer rows before the rebind, right after it and
after the fault window. Never delete that nat table mid-flow: it is the
namespace's only nat chain, so removing it un-translates the live flow while a
stale reverse mapping keeps dropping A's packets for good (#517).
After recovery, a run of lost probes longer than one probe timeout (1 s) is a
relapse and fails the row; `post_recovery_*` fields report it.
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

## Three-client candidate walk and restart proof (#483)

`three_node_walk_restarts.py` uses four real mesh agents: the server's mesh
node and three clients behind one non-hairpin NAT. It requires all six
client-to-client directions and the server links to settle on direct paths,
using the shared NAT's per-host public mappings while all clients bind the
default listener port. It then checks idle handshake counters. It kills and
starts one client process and the server mesh-node process separately,
requiring all affected routes and traffic to recover within 30 seconds. It
also restarts the actual server process and checks its health endpoint, changes
one client's LAN address, and checks that the other clients learn the new
endpoint from the live-session announcement without user traffic. A changed stale candidate snapshot then
checks that a still-authenticated endpoint is retained. The runner deletes all
of its named namespaces before it exits.
Use `--restart-only` to repeat the direct-path and restart checks without the
later underlay-change phase.
Set `J967_CAPTURE_UNDERLAY=1` to save UDP captures from C, S and the shared
router around the address change; the report lists each capture and its decoded
packets. This diagnostic mode needs `tcpdump` in the root proof's `PATH`.

Run this root-only proof on compute01. Build the product and four-identity
coordinator fixture with the job target, then use a private short scratch path
for the row and its report:

```sh
mkdir -m 700 -p ~/.j967
~/infraternal-ops/build-slot nice -n10 nix develop . -c cargo build --release --locked \
  -p infraternal --bin infraternal \
  -p infraternal-plugin-mesh --example coordinator_fixture \
  --features infraternal-plugin-mesh/agent

~/infraternal-ops/build-slot nice -n10 nix shell \
  nixpkgs#iproute2 nixpkgs#nftables nixpkgs#conntrack-tools nixpkgs#util-linux \
  --command python3 scripts/gotatun_break_it/three_node_walk_restarts.py \
    --binary /mnt/build/targets/J967/release/infraternal \
    --coordinator /mnt/build/targets/J967/release/examples/coordinator_fixture \
    --scratch /root/.j967 --report /root/.j967/three-node-report.json
```

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
