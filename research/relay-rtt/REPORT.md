<!-- Role: J1105's measurements of RTT-ranked relay choice for mesh pairs (#201, D185, D233, D313 Q5); it changes no decision. -->
# Relay choice by measured round trip: results (J1105, #201)

Job J1105, 2026-11-21. Follows J1064's report (`research/direct-path/REPORT.md` on
`j1064-direct-mesh-latency`, #569), which found that the mesh fell back to the first relay
of a fixed list and that a badly placed relay costs hundreds of ms on every key.

## What changed

- `infraternal_mesh::path_choice`: the D313 Q5 rule as a pure module. A challenger replaces
  the current path only when both sample windows agree it is faster by max(5 ms, 15 %): every
  one of its last five samples (spanning at least 3 s, none older than 30 s) beats the current
  median, and its median beats the current best sample. At most one move per 10 s. Direct
  wins inside the band.
- `relay_path.rs`: a relayed pair keeps a link on every live relay and measures each link end
  to end with a 12-byte probe DATAGRAM answered by the peer's shim on the same link. Probe
  rounds ride on the pair's own traffic (at most one per second, only with two links or more),
  so an idle pair sends nothing. Until anything is measured the lowest index carries the pair
  (both ends agree during setup); the first complete probe round leaves that default at once
  for a link that beats it by the margin; later moves follow the sustained rule.
- Direct against relay is unchanged (failure rule only): nothing produces a direct-path RTT
  sample yet. See "Open questions".

## Method

- `crates/plugins/mesh/examples/relay_echo.rs` runs the real `RelayPaths` with a loopback UDP
  socket standing in for the engine (no root, no interface), and times one 64-byte key at a
  time through the pair. Relays are `relay_fixture relay`. Base = origin/dev `32ceb2a16` with
  the same example (head-only counters removed); head = this branch. Both static musl builds.
- `relay_rtt.py`: two nodes and two relays in four throwaway namespaces on the perf VM
  (`perf-run --root`), netem only on its own veths; each node↔relay leg has the same round trip
  per relay, so a pair's path through relay N costs 2 × RN.
- `real_mesh.py`: the same processes on the build VMs over NetBird (user processes on a high
  UDP port; nothing on the hosts changes).

## Results

### Flapping between equal relays

| where | paths | jitter | duration | switches |
|---|---|---|---|---|
| perf VM netns | 2 × 40 ms | 10 % | 5 min, 3000 keys | 0 |
| perf VM netns | 2 × 40 ms | 20 % | 5 min, 3000 keys | 0 |
| perf VM netns | 2 × 40 ms | 30 % | 5 min, 3000 keys | 0 |
| real mesh compute01 ↔ dev-02, relays on dev-02 and compute01 | ≈146–153 ms each | real | 3 × 3 min, 5400 keys | 0 |

The selector's own one-hour simulation (unit test and module doc): 0 / 2.4 / 6.8 switches
per hour at 10 / 20 / 30 % jitter, against 0.4 / 15 / 32 for the simpler
"every sample against the median" rule.

### Idle cost

60 s of silence after the keys, 3 runs each, perf VM netns:

| build | probe datagrams while idle | process context switches in 60 s |
|---|---|---|
| base (origin/dev) | n/a | 938, 908, 916 |
| head | 0, 0, 0 | 923, 916, 934 |

Both are dominated by the existing 1 s QUIC keepalive to each relay. While keys flow, head
sends one probe per link per second (≈2/s with two relays).

### A far relay first in the list (the J1064 problem)

Each end relays only after every relay is connected, as a node does after its direct-path
grace period; one key every 100 ms; 3 runs per build, interleaved. "On the best relay" is
the time from link to the pair's final move; "after" is every key from one second later.

| setup | build | p50 per key | p99 per key | on the best relay after | after: p50 / p99 |
|---|---|---|---|---|---|
| netns, relay 1 at 2 × 150 ms, relay 2 at 2 × 15 ms | base | 300.2–300.3 ms | 300.3–300.4 ms | never | 300.3 / 300.4 ms |
| | head | 30.2–30.3 ms | 300.3–300.4 ms | 1.30–1.40 s | 30.2–30.3 / 30.3–30.4 ms |
| same, 30 % jitter | base | 300.9–305.1 ms | 398–417 ms | never | 301.6–307.3 / 398–417 ms |
| | head | 30.2–30.7 ms | 290–303 ms | 1.26–1.43 s | 30.1–30.8 / 38.5–40.0 ms |
| netns, near relay first | base | 30.2–30.3 ms | 30.3–30.4 ms | at once | same |
| | head | 30.2–30.3 ms | 30.3–30.5 ms | at once, no move | same |
| real mesh: both ends on compute01 (Europe), relays [dev-02 at the home site, compute01] | base | 294.3–297.9 ms | 387–911 ms | never | 294.3–298.2 ms / 387–911 ms |
| | head | 0.68–0.72 ms | 297–301 ms | 1.30–1.32 s | 0.66–0.71 / 9.3–17.7 ms |

Head's p99 over the whole run still shows the first 12–13 keys (the first ~1.3 s), when the
setup default holds the pair on the far relay until the first probe round answers. The real
mesh "after" p99 reflects compute01's load (load average 30–200 during the runs).
Raw: `perf-before-after-2/`, `real-mesh/m1b.jsonl`, summary `before-after-summary.txt`.

### First version's setup bug (fixed)

The first build counted the setup default (lowest index) as a failover, which started the
10 s dwell: with the far relay first, keys paid 300 ms for 10.5 s (103 of 300 keys slow,
3 runs). With setup moves starting no dwell and the first probe round deciding, the pair
reaches the near relay ≈1.3 s after link (6–11 slow keys; settled p99 30.3 ms instead of
300 ms). Raw: `perf-head-v1/`, `perf-head-v2/`.

## Open questions

1. **Direct against relay on measured RTT (D233).** The rule supports it (direct wins inside
   the band), but nothing measures a direct path while a pair is relayed: kernel WireGuard
   exposes no RTT, and a relayed pair sends nothing direct. Recommendation: a follow-up slice
   with seam C probes from the WireGuard port to the peer's direct candidate, keyed per pair,
   feeding the same `path_choice` samples; keep direct → relay on failure as it is.
2. **The ~1.3 s setup detour.** Until anything is measured the lowest index carries the pair,
   so both ends agree; when that relay is the far one, the first ~12 keys pay its RTT.
   Keeping the first link that comes up instead would usually pick the nearest relay, but the
   two ends could then sit on different relays when the relays are equal (still delivering).
   Recommendation: keep the agreement for now; revisit with the namespace proof updated to
   accept either relay.
3. **Authenticated probes.** A relay sees the probe token and could answer for the peer; it
   cannot look faster than its own leg, which the node's QUIC connection measures.
   Recommendation: key probes per pair (an exporter-derived MAC) when relays outside the
   owner's control appear (D313 Q3 allows any relay in the mesh).
4. **The relay path is still off in shipping builds** (`relay` feature, contracts/mesh-relay.md).
   This changes relay choice where it runs (fixtures, proofs); production pairs keep their
   current paths until the relay feature ships.
