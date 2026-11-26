# Mesh idle-wakeup harness (#260, J1253)

Where an idle mesh hub's wakeups come from. It reuses J1234's hub test binary and peer simulator
(`../../many-peer-hub/harness`).

| File | What it is |
|---|---|
| `hub-bench.patch` | J1234's ignored test `node::many_peer_hub_bench::many_peer_hub`, ported to current dev, plus per-peer candidates in the peer list and a `trace` command that counts the engine's timer trace events (`HUB_TRACE=1`). No product code changes. Apply with `git apply`. |
| `idle.py` | Driver: one scenario (`offline`, `connected`, `keepalive`, `realistic`) as a timeline of windows; wakeups per second per hub thread, CPU, UDP datagrams, timer events, optional `perf record` of `sched:sched_waking`. Root, network namespaces only. |

Build (release, with symbols and frame pointers for `perf`):

    git apply research/mesh-idle-wakeups/harness/hub-bench.patch
    CARGO_PROFILE_RELEASE_STRIP=none CARGO_PROFILE_RELEASE_DEBUG=1 RUSTFLAGS=-Cforce-frame-pointers=yes \
      cargo test --release -p infraternal-plugin-mesh --lib --features agent,test-support,cutoff-measure --no-run
    cargo build --release --manifest-path research/many-peer-hub/harness/peersim/Cargo.toml

Run:

    python3 idle.py --hub <testbin> --sim <peersim> --out out --peers 4096 --scenario offline --secs 150 --window 10 --candidates 2
