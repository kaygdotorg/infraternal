# Faster hashers for GotaTun's per-packet bookkeeping (#260, J1204)

Measurement and recommendation only. Nothing in the product changed; a hasher is a dependency
choice and the owner's call. Questions answered: which hash tables sit on the data path, what
does each cost per lookup with its real key shape, what would another hasher (or no hash) save
per packet and per Gbit, and what does each choice do to HashDoS exposure.

**Short answer.** Swapping std's SipHash for `foldhash::fast::RandomState` (already in the
dependency graph through hashbrown, licence Zlib, keyed per process) saves ~50-60 ns per received
packet, about 5 ms of CPU per Gbit, 0.6% of the receiver's ~0.8 s per Gbit. It does not weaken
HashDoS handling anywhere, and it *improves* it for the flow table, whose hash today has fixed
zero keys. Larger levers sit next to it and are not hashers: `FlowKey::canonical()` (13 ns) and
the allowed-IPs radix trie (68 ns per `longest_match`, once per packet on each host). See section 6.

## 1. Where the hashing is (per-packet call sites)

Sources: infraternal `be2641544` (`crates/plugins/mesh/src/packet_filter.rs`) and the GotaTun
fork at the pin `e87fef91` (`gotatun/src/device/mod.rs`, `allowed_ips.rs`, `side_port.rs`).

| # | Table (call site) | Key | Per packet | Who chooses the stored keys? | Bounded? |
|---|---|---|---|---|---|
| 1 | `flow_start` / `fragment_start` (packet filter slot function; `DefaultHasher::new()` = SipHash-1-3 with **fixed zero keys**, over `FlowKey::canonical()`, `% 512`) | inner 5-tuple (`IpAddr`×2, port×2, proto) | 1 per filtered packet (`check`) | the **peer** (an authenticated mesh member) and local processes, through the tuples they use | yes: 512 slots per peer, 256 flows per direction, open addressing |
| 2 | `CompiledPolicy::peer_addresses: HashMap<IpAddr, usize>` (std `RandomState`) | peer mesh address | 2 (`resolve` and `allows_flow`) | the coordinator (addresses are handed out in order from one `/16`); the packet only supplies a lookup key | yes: one entry per peer address, rebuilt per policy snapshot |
| 3 | `PacketLookup::peers_by_idx: HashMap<u32, _>` (`peer_by_index`) | WireGuard receiver index | 1 per received packet | the **peer** (`register_handshake_idx` inserts the `sender_idx` of its handshake) | live indices only (`retain_live_indices`) |
| 4 | `PacketLookup::peer_ids: HashSet<usize>` (`contains_peer`) | heap address of the peer cell | 2 per received packet | nobody remote (pointer values) | one per peer |
| 5 | `incoming_runs: HashMap<usize, _>` and `group_by_key` in `handle_incoming` | internal peer key | 1 `entry` per received packet | nobody remote | peers in one batch |
| 6 | `AllowedIps` (`ip_network_table`, a binary radix trie, **no hashing**) | inner address | 1 per packet each way (`peer_by_ip`) | configuration | n/a |
| 7 | `side_port::BulkRecency: HashMap<SocketAddr, Instant>` (only with the side socket on, off by default) | peer endpoint | 1 per sent datagram | the peer's roaming (authenticated) | pruned at 64 |

Not on the per-packet path (timers, handshakes, UAPI): `timer_queue::entries`, `peers_by_key`, the
`IndexTable` set, the `HashSet`s in `configure`/`builder`.

## 2. HashDoS exposure per table

A non-keyed hash is a security regression only where an attacker chooses keys that get **stored** in
a table whose cost grows with collisions, and where the table is not bounded. Today's state first,
because it changes the comparison:

- Row 1 is **already unkeyed**: `DefaultHasher::new()` is SipHash-1-3 with keys `(0, 0)`, the same on
  every process and build. A peer that knows the tuple-to-slot function (it is public source) can
  precompute tuples that share one slot and make `find()` walk up to 256 slots per packet in its own
  table (per-peer lock, 512-slot table, so the damage is bounded to that peer's traffic and one CPU
  worth of walking, not memory). `bench/src/bin/collide.rs` (output in `results/collide.txt`) does exactly that search: about 120,000 candidate tuples (milliseconds) find 256 flows that all start at slot 0 under today's function, and the same 256 tuples then probe a mean 127.5 slots (max 255) in the table, against a mean 0.35-0.59 (max 5-16) under any keyed hasher the attacker cannot see. The same attack works against Fx in the same time. A per-process **random seed** (std `RandomState`, `foldhash::fast::RandomState`,
  `ahash::RandomState`) closes the offline precomputation; an unkeyed fast hash (`FxHasher`) would make
  the collisions trivial to build without any computation.
- Row 3 takes **peer-chosen** `u32` keys on every handshake. It needs a keyed hasher; an identity or
  Fx hash on a `HashMap` that a peer can fill with colliding indices is a regression. (hashbrown's
  SwissTable degrades from O(1) to O(n) per lookup under full collisions.)
- Rows 2, 4 and 5 store keys nobody remote picks (coordinator-assigned addresses, heap pointers,
  internal ids); a lookup miss with an attacker-chosen key walks at most one probe group. Any hasher
  is safe in the HashDoS sense; keyed ones cost nothing extra, so keep them keyed for uniformity.
- Row 7 stores the peer's endpoints, which an authenticated peer can move; it is pruned at 64 entries.
  Keyed hasher.

Library stance on HashDoS (primary sources, `foldhash` 0.2.0 README, `ahash` 0.8.13 README,
`rustc-hash` 2.1.3 README): foldhash states it is "minimally DoS-resistant" (per-instance random
seed; defeats simple attacks) and **does not claim resistance against interactive attackers**, who can
recover the secret from outputs or timing. ahash documents DoS resistance (random keys per
`RandomState`) and says it is not cryptographically secure. rustc-hash (`FxHasher`) is explicitly
for settings with no hostile input and has no seed. std SipHash-1-3 with `RandomState` is the only
one of these with a cryptographic-grade (PRF) design goal.

## 3. Micro-benchmarks: ns per lookup (hold M1 + M2, x86)

Host: infraternal-perf-01-backup01 (AMD Ryzen 7 3700X, Debian 13, kernel 6.12.113), lock held,
one CPU pinned (`taskset -c 3`), static x86_64 musl, the product's release profile (opt-level 3,
fat LTO, one codegen unit). Four criterion runs (two builds of the same bench code, two runs
each); the table shows the median and the spread between runs. Each iteration walks 1,024 lookups
(64 for `incoming_runs`); ns/op = iteration time / that. Full table with every candidate and the
spread: [`results/micro-table.md`](results/micro-table.md). Key streams are shuffled, tables are
filled with realistic keys (mesh addresses `10.254.0.n` handed out in order, random `u32` receiver
indices, sequential ephemeral ports to six server ports).

| table (key) | SipHash-1-3 (today) | foldhash fast | foldhash quality | ahash | rustc-hash (unkeyed) | no hash |
|---|---:|---:|---:|---:|---:|---:|
| `flow_start` v4: canonical + hash + `% 512` | 25.9 | 18.6 | 19.4 | 21.1 | 17.8 | symmetric manual fold, no `canonical()`: 3.1 |
| `flow_start` v6 | 34.5 | 26.3 | 27.9 | 30.6 | 26.9 | manual fold 8.8 |
| `peer_addresses` get, 1 / 100 / 1,000 peers | 15.6 / 15.5 / 16.0 | 2.9 / 3.1 / 3.2 | 3.5 / 3.8 / 3.7 | 4.1 / 4.3 / 4.5 | 2.5 / 2.6 / 2.7 | direct index 1.2 |
| `peers_by_idx` get (`u32`, `Arc` clone) | 14.7 / 14.8 / 16.4 | 8.6 / 8.7 / 8.8 | 8.5 / 8.6 / 8.7 | 8.6 / 8.6 / 8.8 | 8.8 / 8.8 / 8.8 | identity 8.6 / 9.3 / 8.8 (unsafe) |
| `peer_ids.contains` (`usize`) | 7.7 | 1.9 | 2.3-2.5 | 2.4-2.6 | 1.7-2.0 | |
| `incoming_runs.entry` + push, 1 / 8 peers per batch | 23.1 / 34.7 | 13.2 / 25.2 | 13.8 / 24.1 | 15.9 / 25.6 | 10.6 / 22.0 | |
| `BulkRecency.recent` (`SocketAddr`), 1 / 64 | 18.9 / 18.8 | 3.8 / 3.8 | 4.2 / 4.7 | 5.1 / 5.1 | 3.3 / 3.3 | |
| allowed-IPs `longest_match`, 1 / 100 / 1,000 peers | trie 68.4 / 68.4 / 68.4 | host-route hash 2.9 / 2.9 / 3.2 | 3.4 / 3.8 / 3.7 | 4.1 / 4.2 / 4.5 | 2.5 / 2.6 / 2.7 | direct index 1.2 |

Noise: median run spread 0.4%; a few rows move 10-30% between runs of the same binary
(`flow_start` v4 with ahash 33%, foldhash 10%), so read those to within about ±10%. Probe-length
quality of the 512-slot flow table for 256 tuples (`results/quality-x86.txt`, aarch64 in
`results/quality-aarch64.txt`): every keyed hasher is within noise of SipHash (mean probe
0.37-0.67 against 0.42-0.47; max probe 4-13). Unkeyed Fx hashes consecutive ports to consecutive
slots (mean 0.000): perfect for honest traffic and exactly what a peer could exploit.

## 4. One packet, all the hashing

Per **received** data packet (the A receiver in the cross-VM kit): `peers_by_idx` 1, `peer_ids` 2,
`incoming_runs` 1, `peer_addresses` 2, `flow_start` 1 (+ the trie, which has no hash). Per-packet
sum of the table above (1 peer, v4), ns, and the CPU it is worth per Gbit (1 Gbit = about 90k
packets of 1,390 B, so ms per Gbit = ns x 0.09):

| hasher set | ns per packet | saving vs today | ms CPU per Gbit saved | % of the receiver's ~0.85 s/Gbit |
|---|---:|---:|---:|---:|
| SipHash-1-3 (today) | 109 | – | – | – |
| rustc-hash (unkeyed) | 46 | 63 | 5.7 | 0.7% |
| foldhash fast | 50 | 59 | 5.3 | 0.6% |
| foldhash quality | 54 | 56 | 5.0 | 0.6% |
| ahash | 59 | 51 | 4.6 | 0.5% |
| foldhash fast + symmetric flow hash (no `canonical()`) | 36 | 73 | 6.6 | 0.8% |
| the same + direct index for `peer_addresses` | 33 | 76 | 6.8 | 0.8% |
| (not a hasher) host-route hash in front of the allowed-IPs trie, 1 lookup per packet per host | – | 65 | 5.9 | 0.7% |

Whole-filter check (`PacketFilter::check_at`, established TCP flows, both directions, same test in
two static test binaries, one CPU pinned, order base h1 h1 base twice, hold H1): 172-174 ns per packet
at 1 peer, 190-192 at 100, 210-213 at 1,000 (the flow tables are 52 KiB per peer, so cache misses
add ~40 ns at 1,000 peers). With foldhash in the filter: 134-135 at 100 peers (-57 ns, -30%) and
157 at 1,000 (-53 ns, -25%), 140 at 1 peer (-33 ns; one run read 111, treated as an outlier).
Raw runs in `results/hbench/`.

## 5. Macro: the product, two builds, cross-VM (holds on calternal-perf-01 A and infraternal-perf-01 B)

Rows **I** = infraternal static x86_64 musl build of origin/dev `be2641544`; **H** = the same tree
plus `patches/infraternal-h1-foldhash.patch` and `patches/gotatun-h1-foldhash.patch` (foldhash fast
with a per-process random seed in the packet filter and in the GotaTun fork's per-packet maps).
The mesh is the product's own (two nodes plus the coordinator fixture), in a private netns
`j94` on ipvlan `10.70.3.204/.205` with no default route and an in-netns drop for everything
outside `10.70.3.0/24` (counters recorded; the hosts' egress guard stays on). Windows: 60 s full
speed (40 s steady), CUBIC, 1 and 8 flows, both directions (reverse: B sends, the 2-core A
receives). CPU s/Gbit is whole-machine busy time (steal excluded) of A and B together. Order per
hold: `I.1 H.1 H.2 I.2` (A/A pairs inside the hold). Raw: `results/macro/windows-*.csv`,
paired table `results/macro/pairs-*.md`.

Hold m1b (09:56-10:26Z), one hold:

| cell | Gbit/s I | Gbit/s H | Δ | CPU s/Gbit I | CPU s/Gbit H | Δ CPU | A/A gap Gbit/s, CPU |
|---|---:|---:|---:|---:|---:|---:|---|
| forward, 1 flow | 3.066 | 3.069 | +0.1% | 1.235 | 1.212 | -1.8% | 0.2%, 0.3% |
| forward, 8 flows | 3.133 | 3.143 | +0.3% | 1.259 | 1.236 | -1.9% | 0.4%, 0.9% |
| reverse, 1 flow | 3.251 | 3.317 | +2.0% | 1.057 | 1.049 | -0.8% | 0.5%, 2.9% |
| reverse, 8 flows | 3.226 | 3.323 | +3.0% | 1.036 | 1.023 | -1.3% | 2.8%, 7.3% |

Binary size (static musl, release): 33,792,632 B baseline, 33,806,712 B patched (+14,080 B, +0.04%).

## 6. Candidates side by side, and the recommendation

ns per received packet = section 4 sum (1 peer, v4). CPU Δ is *measured* for foldhash fast
(section 5) and *derived from the micro table* (ns x 0.09 ms per Gbit, against ~1.2 s/Gbit for A+B
together) for the others: only foldhash was built into the product and run on the perf VMs. Size
Δ is the size probe (a `HashMap<IpAddr, usize>` program, static musl, product profile), so it is
the hasher's own code against std's SipHash; the product figure for foldhash is +14,080 B for the
whole patch.

| candidate | ns/packet | CPU/Gbit Δ vs today | binary size Δ | licence | in `Cargo.lock` today | HashDoS note |
|---|---:|---|---|---|---|---|
| std SipHash-1-3 `RandomState` (today for the maps) | 109 | – | 0 | std | yes | keyed, PRF-grade. The flow-table slot function uses `DefaultHasher::new()`, i.e. **zero keys**: precomputable (`results/collide.txt`: mean probe 127.5 of 512) |
| **foldhash fast `RandomState`** | 50 | **measured -1.8 / -1.9% forward, -0.8 / -1.3% reverse (reverse inside its A/A gap)** | -2.8 KB in the probe; +14 KB for the whole patch | Zlib (in `deny.toml`) | yes, via hashbrown 0.16 / 0.17 | per-process random seed, "minimally DoS-resistant", **no claim against interactive attackers** (README). Closes the offline precomputation of the flow table |
| foldhash quality | 54 | about -1.6% (derived) | similar | Zlib | yes | same family, slightly stronger mixing; no measurable gain here |
| ahash (random state) | 59 | about -1.4% (derived) | -8.4 KB (no-rng build) | MIT OR Apache-2.0 | **no** (new crate and `zerocopy`) | documented DoS resistance with random keys; not cryptographic |
| rustc-hash (Fx) | 46 | about -1.9% (derived) | -9.6 KB | Apache-2.0 OR MIT | yes, via quinn | **unkeyed**: collisions are constructible without any search; not acceptable for the flow table or for `peers_by_idx` (peer-chosen keys); acceptable only for rows 2, 4, 5 |
| no hash: symmetric manual fold with a per-process secret (flow table only) | 36 with foldhash elsewhere | about -2.0% (derived) | none | own code | n/a | keyed by the secret; also drops `canonical()`; needs its own review |
| no hash: direct index for `peer_addresses` | 33 with the above | about -2.1% (derived) | none | own code | n/a | nothing attacker-chosen is ever stored; dense `/16` addresses; adds a structure to maintain for ~1.7 ns over foldhash |

**Recommendation (the owner decides; nothing here is switched):**

1. If a hasher swap is wanted, use **`foldhash::fast::RandomState`** for rows 2-5 and 7 and
   for the flow-table slot function, with the per-process seed. It is already linked (no new
   crate, licence already allowed), measured on the real product at -1.8% CPU per Gbit forward with
   throughput unchanged, and it strictly improves the flow table's HashDoS posture over today.
   Do **not** use unkeyed Fx for the flow table or `peers_by_idx`.
2. Be clear about the size of the prize: ~5 ms CPU per Gbit (about 0.6% of the receiver's CPU
   budget by arithmetic; 1.8% of total A+B CPU measured forward). It does not explain J1160's
   ~80 ms/Gbit of bookkeeping; the rest is parsing, the filter's locks and cache misses (the
   whole filter is 173-213 ns per packet and grows with active peers).
3. The two larger, non-dependency levers I would measure next (separate job, no dependency choice):
   (a) a symmetric flow hash that needs no `FlowKey::canonical()` (13 ns of the 26 ns per packet,
   -21 ns); (b) a host-route table in front of the allowed-IPs trie (68 ns per `longest_match`,
   once per packet on each host, 3 ns for a `/32` hit; mesh peers are `/32`s, so the trie stays
   only for subnet routes). (b) changes a GotaTun data structure, so it is a fork change to
   propose upstream rather than a hasher.
4. Mac and iOS clients use the same code on Apple Silicon; the only aarch64 data here is the
   probe-length output. The ns/op table should be rerun on `mba` (M1) before the Mac client
   relies on it; no macOS binary was built for this job (builds on the Mac are not allowed).

## 7. Reproduce

- Micro: `cd bench && cargo build --release --benches --bins` (static musl: see
  `patches/build-product.sh` for the toolchain settings), run `hot_paths --bench --warm-up-time 1
  --measurement-time 3 --sample-size 50` pinned to one CPU of a quiet host, then
  `python3 -I summarize_micro.py crit-rep*.txt`. `target/release/quality`, `collide` and the
  `size_probe` features (`fold`, `ahash-probe`, `fx`) are the other measurements.
- Whole filter: append `patches/hbench-test.rs.txt` to `crates/plugins/mesh/src/packet_filter_tests.rs`
  in both trees, build the test binary with `--features agent`, run
  `--ignored hasher_bench --nocapture --test-threads 1` (see `kit/hbench.sh`).
- Macro: `patches/*.patch` on the two trees (`build-product.sh`, `build-tests.sh`), then
  `kit-macro/macro.sh <hold> I.1 H.1 H.2 I.2` from a host with ssh to both perf VMs.

Limits: one build host class (x86, Ryzen 3700X VMs); the macro run is one or two holds, and
throughput on the 2-core receiver moves by up to 3% between rows of the same binary; the
patched row uses the same foldhash seed policy as the recommendation but the patch is
throwaway code, not a proposal for review.
