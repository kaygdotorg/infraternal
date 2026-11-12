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
  -p infraternal-plugin-mesh --example coordinator_fixture
```

Run the matrix with `tc`, `nft`, `conntrack`, `unshare`, `nsenter`, and `ip`
available on `PATH`. The Nix shell below supplies those tools without
installing them on compute01. Choose a new evidence directory for every run:

```sh
~/infraternal-ops/build-slot nice -n10 nix shell \
  nixpkgs#iproute2 nixpkgs#nftables nixpkgs#conntrack-tools nixpkgs#util-linux \
  --command bash -lc '
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
integrity, and manual-fix status. DNS is queried directly over the mesh route;
the peer-scale rows also count outgoing handshake-initiation packets.

The `server-restart` row restarts the production-schema coordinator fixture
with its SQLite database preserved. The `rekey-timer-expiry-under-load` row
marks the coordinator's persisted schedule due before exercising the real
infraternal agent's rotation actions. These fixture boundaries are recorded in
the case details so they are not mistaken for an HTTP-server process restart
or an independently scheduled background worker.
