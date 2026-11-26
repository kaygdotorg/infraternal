# Many-peer hub harness (#260, J1234)

Measures one mesh node (the production `Node`, GotaTun engine) acting as a hub for N simulated peers.

| File | What it is |
|---|---|
| `hub-bench.patch` | Adds the ignored test `node::many_peer_hub_bench::many_peer_hub` to `crates/plugins/mesh` (no product code changes): the hub as the real `Node`, driven over a FIFO. Apply with `git apply`, then build with `cargo test --release -p infraternal-plugin-mesh --lib --features agent,test-support,cutoff-measure --no-run`. |
| `peersim/` | Separate cargo project. `peersim sim` runs N WireGuard peers (boringtun `Tunn`, one UDP socket each) in one process; `peersim sink` counts the inner datagrams the hub delivers. |
| `run.py` | Driver. Builds two network namespaces joined by a veth (no default route, nothing in the host namespace), starts hub, sink and simulator, walks the measurement steps for one peer count and writes `rows-<N>-<run>.csv`. Needs root; run under `perf-run --root`. |
| `summarize.py` | Pivots the per-run CSVs into one table. |

Source-address modes of the simulated peers (`run.py --mode`):

- `single`: every peer shares one source address (a whole site behind one NAT).
- `spread`: one /24 per peer; the hub does not know the peers' endpoints before they dial in.
- `known`: as `spread`, and the snapshot carries each peer's endpoint, as a coordinator's candidates would.

## Authority epoch (`--epoch-per-apply`)

By default every snapshot of a run carries the same authority epoch, so each apply after the first
is an ordinary revision, which is what a running coordinator sends. `run.py --epoch-per-apply`
(environment `HUB_EPOCH_PER_APPLY=1` in the hub) stamps each apply with a new epoch instead and
adds `-epoch` to the run tag. That is the authority-replacement path (a coordinator restart or
rollback), which is rare. `summarize.py` pools every `rows-*.csv` of a folder whatever its tag, so give the
two modes separate `--out` folders.

The `apply_*` rows published in `../2026-11-25/` (J1234) were all taken with a new epoch per apply,
so compare them only with `--epoch-per-apply` runs. J1240 measured the difference: with one peer's
policy changed at 4,096 peers (spread mode), the base of that job took 265 ms as an ordinary
revision and 398 ms as an authority replacement (receipts on #260).

The hub's handshake admission has per-source, per-network and per-node budgets
(`crates/plugins/mesh/src/handshake_admission.rs`), so the mode decides how a handshake storm behaves.
