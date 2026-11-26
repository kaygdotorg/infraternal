# Two bigger per-packet levers: a symmetric flow hash and a host-route table (#260, J1227)

Measurement only. Nothing in the product changed (the prototypes are throwaway patches in
`patches/`), and each lever is a design change the owner decides. J1204 (README.md in this
directory, sections 4 and 6) found that after the hasher swap the two largest per-packet costs left
in the filter and the data path are not hashers:

1. `FlowKey::canonical()`: 13 ns of the flow slot function's 26 ns, every packet, both hosts.
2. The allowed-IPs radix trie: 68-74 ns per `longest_match`, once per packet on each host,
   against ~3 ns for a `/32` hit in a hash table. Mesh peers are `/32`s (`/128`s).

This job prototypes one change for each, proves what each must keep, and measures each alone and
together, micro (criterion, 1 / 100 / 1,000 peers) and on the product on the perf VMs.

**The base moved while this job ran.** Everything here is measured against origin/dev `373a47057`,
whose flow slot function is still SipHash with fixed zero keys. J1226 (seeded `foldhash` for the
per-packet tables, merge `698623bf3`) has since landed on dev: there the flow slot function is
`foldhash(key.canonical())`, the "foldhash + canonical" column below, and the GotaTun pin is
`a0be34f8`. So for lever 1 the gain still open on today's dev is the smaller one against that
column (14.3 ns v4, 16.7 ns v6), and lever 1's macro rows (which include the hasher change)
overstate it. Lever 2 is unaffected: J1226 did not touch the allowed-IPs table.

**Short answer.**

| | micro, ns per packet and host | macro (product, perf VMs), CPU s per Gbit, A + B | worth a product change? |
|---|---|---|---|
| (1) symmetric flow hash (S) | 23.7 -> 5.2 (v4), 35.0 -> 10.5 (v6); against dev now: 19.5 -> 5.2, 27.2 -> 10.5 | forward -1.2% / -0.8% (1 / 8 flows), as large as the A/A gap (1.1-1.2%); reverse inside noise | not on its own; a small rider |
| (2) host-route table in front of the trie (R) | 73.9 -> 6.7 (`/32` hit), +1.2 to +2.9 on a subnet-route miss | forward -0.9% / -1.0%, negative in all 6 hold cells (matches the arithmetic ~1.0%), each cell about the size of the A/A gap | **yes** |
| both (Q) | about 86 ns saved per packet and host (18.5 + 67.2) | **forward -3.0% / -2.2%**, negative in all 6 hold cells, rows do not overlap the base rows | the measured case for doing the work |

Throughput is unchanged forward (-0.1% to +0.5%); reverse medians are +0.7% to +2.4% Gbit/s. No probe lost a request in 96 windows.

## 1. Lever 1: a flow slot function with no `canonical()`

### What the measured base does

`flow_start(key)` hashes `key.canonical()` (the smaller of the tuple and its reverse, by derived
`Ord`) with `DefaultHasher::new()` (SipHash-1-3, fixed zero keys) and reduces it `% 512`, so both
packet directions of a flow land in the same slot of the same per-peer table. `canonical()` builds
the reversed tuple and compares the two tuples: 11 ns (v4) to 17 ns (v6) on its own (`canonical_only(floor)` in
the micro table).

### The prototype (`start_symmetric_mixed`, patch `infraternal-j1227-symmetric-flow.patch`)

```
a   = H((source, source_port))        H = foldhash::fast::RandomState, one per-process seed
b   = H((destination, destination_port))
sum = a + b + protocol                 (wrapping; addition commutes: a reply gives the same sum)
slot = H(sum) % 512
```

No ordering step and no reversed copy. The last hash is not decoration: without it (`start_symmetric`,
the variant J1204 timed at 4.8 ns) the slot is the sum of two independent endpoint hashes, which is
**additive in the endpoints**: for four flows `(A:p1,B:q1) (A:p2,B:q2) (A:p1,B:q2) (A:p2,B:q1)` the sums
obey `h(1)+h(2) = h(3)+h(4)` for every seed (test `pre_mix_sum_is_additive_in_the_endpoints`), and
sequential ports to one server port cluster (table below: probe mean 0.584 / p99 max 42 against 0.49 / 20).
One more seeded hash of the sum removes both, for about 0.4 ns (v4) or 1.1 ns (v6).

### What it must keep, and the evidence

Tests (`bench/tests/flow_levers.rs`, `cargo test --release`, dev-02 aarch64, all pass):
- `symmetric_hash_puts_both_directions_in_one_slot`: slot(k) == slot(reverse k) for 200,000 random
  v4 and v6 tuples x 8 seeds, including both endpoints equal, port 0, protocol 0 / 255 (also for the
  J1204 candidates, as the reference of what "one slot" means).
- `symmetric_hash_does_not_merge_unrelated_flows`: two unrelated flows share a slot at the rate 1/512
  (within 20%).
- The product's own `packet_filter` tests, built with the symmetric function (tree S+R, `cargo test
  --release -p infraternal-plugin-mesh --features agent --lib packet_filter`): **67 passed**, 0 failed
  (both directions, established TCP, fragments, ICMP errors, SSH reply rewriting).

Collision resistance (`bench/src/bin/symmetric_quality.rs`, 2,000 seeds per candidate; identical
numbers on x86 and aarch64, `results-j1227/sym-quality-*.md`). A "seed" is a process start; the
reference rows are what the table is judged against:

| candidate | probe mean / p99 of max, 256 flows in 512 slots: seq ports v4 | one server port, ports +1 | v6 | many source hosts | chi-square over 512 buckets (mean / p99; expect ~511 / ~590) | offline-crafted set (256 tuples that all start at slot 0 under one seed), under 2,000 other seeds: mean probe / p99 max |
|---|---|---|---|---|---|---|
| canonical + SipHash-1-3, random key (reference, PRF) | 0.490 / 20 | 0.492 / 20 | 0.491 / 20 | 0.494 / 20 | 509.7 / 574.0 | 0.489 / 20 |
| canonical + foldhash fast (J1204 recommendation) | 0.494 / 22 | 0.492 / 20 | 0.472 / 22 | 0.493 / 20 | 510.6 / 595.0 | 0.493 / 20 |
| symmetric sum, no final mix | 0.497 / 23 | **0.584 / 42** | 0.493 / 21 | 0.489 / 21 | 511.9 / 598.0 | 0.590 / 23 |
| **symmetric sum + final mix (the prototype)** | 0.493 / 20 | 0.496 / 22 | 0.493 / 21 | 0.494 / 20 | 512.2 / 575.1 | **0.493 / 21** |
| manual keyed fold (J1204's no-hasher ceiling, own mixing code) | 0.494 / 20 | 0.496 / 21 | 0.490 / 20 | 0.496 / 20 | 510.1 / 577.1 | 0.494 / 22 |

Read: the prototype is indistinguishable from the keyed canonical hashes on probe length, uniformity
and the HashDoS case a per-process seed has to defeat (tuples crafted offline for one seed, ~116,000
candidates tried, are spread as for random once the seed differs). It is no weaker than what J1204
already recommended, and stronger than the base's fixed-key SipHash (mean probe 127.5 of 512 under the
same crafted set, `results/collide.txt`). Like foldhash itself it makes no claim against an
interactive attacker who can observe slot positions (J1204 section 2); it needs no new crate (foldhash
is already linked).

### Micro (hold M1, criterion, infraternal-perf-01, one pinned CPU, two runs; run spread under 2%)

| ns per slot computation | measured base (SipHash fixed key + canonical) | foldhash + canonical (J1204; dev since J1226) | **symmetric + final mix** | symmetric, no final mix | manual keyed fold |
|---|---:|---:|---:|---:|---:|
| v4 | 23.66 | 19.50 | **5.16** | 4.78 | 3.07 |
| v6 | 35.02 | 27.17 | **10.51** | 9.45 | 9.07 |

So about 14 ns of the 18.5 ns saved against the measured base comes from dropping `canonical()`, only
4 ns from the faster hasher. The product reads the seeded state through a `OnceLock` (one acquire
load), which the micro bench does not include.

## 2. Lever 2: a host-route hash table in front of the allowed-IPs trie

### The prototype (GotaTun fork patch `gotatun-j1227-host-routes.patch`, against the pin `e87fef91`)

`AllowedIps` keeps `hosts: HashMap<IpAddr, D, foldhash::fast::RandomState>` for every `/32` and
`/128` route and the existing `IpNetworkTable` for every shorter prefix. `find(ip)`: one hash lookup
(skipped when no host routes exist); a hit is the answer, a miss falls through to the trie.

Why the semantics are the trie's, and why invalidation is trivial:
- A host route is the longest possible match for its own address, so whenever the hash has an entry
  for `ip` it is exactly what `longest_match` would return; a miss means "no host route", and then the
  trie holds the longest match among the shorter prefixes.
- Host routes live **only** in the hash, never duplicated in the trie. `insert` (new or replacing),
  `remove(predicate)` (`retain` on both) and `clear` each touch the one structure that holds a route,
  so there is no second copy to invalidate and the two cannot disagree. A route change takes effect at
  once (the lookup happens under the same short read/write lock as today's trie).
- IPv4 and IPv6 are separate key spaces exactly as in the trie (an IPv4-mapped IPv6 address does not
  match a v4 route in either).
- The test-only `iter()` merges both structures back into the trie's order, so the six existing
  `allowed_ips` tests pass unchanged.

Tests (dev-02, `cargo test --release -p gotatun --lib --no-default-features --features device,tun,ring`,
`device::allowed_ips`): **7 passed**: the 6 existing ones (kernel-compatibility v4 / v6, insert / find /
remove / iter) and `host_routes_agree_with_a_plain_trie` (30 seeds x 2,000 random inserts, replacements,
nested prefixes and removals, v4 and v6, 6 random lookups after every step, against a plain
`IpNetworkTable`). The same model test exists in the bench crate (`hybrid_table_matches_the_trie_under_random_operations`,
40 seeds) plus `host_route_changes_are_visible_at_once` (replace, remove, fall back to the covering `/16`).

HashDoS: the stored keys come from configuration (the coordinator's peer addresses), not from packets;
the lookup key is a packet's source or destination address, so a miss costs one probe group. The hasher
is seeded per process anyway, like every hash in J1204's recommendation.

### Micro (hold M1; `allowed_ips/<n>_peers`, ns per lookup; the table holds n host routes plus a `/24` behind every tenth peer)

| stream | peers | trie only (today) | hybrid | bare hash lookup (same run) |
|---|---:|---:|---:|---:|
| every packet to a peer's own address (`/32` hit) | 1 / 100 / 1,000 | 74.1 / 73.9 / 73.9 | **6.7 / 6.7 / 6.7** | 2.9 / 3.0 / 3.2 |
| address behind a gateway peer (hash miss, then trie) | 1 / 100 / 1,000 | 57.3 / 57.3 / 57.2 | 58.6 / 60.1 / 58.9 | |
| 9 of 10 packets to a peer, 1 of 10 behind a gateway | 1 / 100 / 1,000 | 72.9 / 72.6 / 72.6 | **11.3 / 11.4 / 11.4** | |

The hybrid's hit costs 6.7 ns, not the 2.9 ns of J1204's bare `HashMap::get`: the `find` wrapper
(empty check, the miss branch to the trie, returning `Option<&D>`) is another ~3.8 ns that I did not
chase. The cost of a subnet-route destination rises by 1.2 to 2.9 ns (one wasted hash lookup); it is
only paid by traffic to addresses behind a router peer. Memory was not measured: the hash holds one entry per host route and the trie keeps only the shorter
prefixes, so the per-peer footprint moves from trie nodes to hash entries (a few tens of bytes); the
trie's 74 ns is already flat in the number of peers, so the gain does not depend on it.

## 3. Macro: the product, base and three variants, on the perf VMs

Rows are the product's own two-node mesh (coordinator fixture, production nodes, the product's
nftables guard, private netns `j94` on ipvlan `10.70.3.204/.205` with no route out; the hosts'
egress guard stays on), static x86_64 musl builds of origin/dev `373a47057` with throwaway patches:
**B** = that dev as it is (the build tree differs from it only under `research/`); **S** = B plus the
symmetric flow hash; **R** = B plus the host-route table (GotaTun fork patched through a `[patch]`
entry; the build log shows the fork compiled from the patched path, other dependency versions
unchanged); **Q** = both. One build target per tree. Binary size: B 33,842,168 B, S +1,024, R +3,456,
Q +9,216. Builds
(sha256 prefix): B `1b1200051cc2a36a`, S `b4cac53ad8e680b1`, R `eae1c3100f4d2df1`, Q `7e9104635317ecdc`.
Windows: 60 s at full speed (40 s steady), CUBIC, 1 and 8 flows, both directions (reverse: B sends,
the 2-core A receives), plus the `rr.py` 64 B and 1,200 B request-reply probes. CPU s/Gbit is
whole-machine busy time (steal excluded) of A and B together. Each hold takes the locks of both VMs
(perf-run's, calternal's, the build slot) and records the machines before and after. Row order in a
hold is palindromic (M1 `B S R Q Q R S B`, M2 `Q S R B B R S Q`, M3 `R Q B S S B Q R`) so every engine
has its own A/A pair and a slow drift cancels. Three holds (M1 19:29-20:42, M2 21:10-22:11, M3
22:41-23:42 UTC, 2026-11-25), 96 windows, all exit 0, no probe lost a request. The micro numbers
above come from the start of hold M1.

| cell | variant | holds | Gbit/s B | Gbit/s variant | Δ Gbit/s | CPU s/Gbit B | CPU s/Gbit variant | Δ CPU/Gbit | A/A gap B (Gbit/s, CPU) | A/A gap variant (Gbit/s, CPU) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| forward cubic1 | S | 3 | 3.082 | 3.077 | -0.1% | 1.239 | 1.226 | -1.2% | 0.5%, 1.1% | 0.4%, 0.9% |
| forward cubic1 | R | 3 | 3.082 | 3.082 | -0.0% | 1.239 | 1.227 | -0.9% | 0.5%, 1.1% | 0.4%, 1.1% |
| forward cubic1 | Q | 3 | 3.082 | 3.087 | +0.1% | 1.239 | 1.203 | -3.0% | 0.5%, 1.1% | 0.8%, 1.2% |
| forward cubic8 | S | 3 | 3.137 | 3.152 | +0.4% | 1.258 | 1.248 | -0.8% | 0.6%, 1.2% | 0.4%, 1.0% |
| forward cubic8 | R | 3 | 3.137 | 3.147 | +0.2% | 1.258 | 1.246 | -1.0% | 0.6%, 1.2% | 0.4%, 0.8% |
| forward cubic8 | Q | 3 | 3.137 | 3.151 | +0.5% | 1.258 | 1.230 | -2.2% | 0.6%, 1.2% | 2.1%, 0.8% |
| reverse cubic1 | S | 3 | 3.228 | 3.258 | +1.0% | 1.074 | 1.045 | -2.8% | 1.2%, 4.2% | 1.7%, 1.1% |
| reverse cubic1 | R | 3 | 3.228 | 3.276 | +1.5% | 1.074 | 1.053 | -2.7% | 1.2%, 4.2% | 1.2%, 5.0% |
| reverse cubic1 | Q | 3 | 3.228 | 3.298 | +2.4% | 1.074 | 1.036 | -4.3% | 1.2%, 4.2% | 11.9%, 5.7% |
| reverse cubic8 | S | 3 | 3.237 | 3.255 | +0.7% | 1.056 | 1.044 | -2.2% | 0.4%, 4.5% | 0.5%, 6.0% |
| reverse cubic8 | R | 3 | 3.237 | 3.276 | +1.2% | 1.056 | 1.008 | -5.1% | 0.4%, 4.5% | 0.8%, 1.6% |
| reverse cubic8 | Q | 3 | 3.237 | 3.300 | +1.5% | 1.056 | 1.004 | -4.9% | 0.4%, 4.5% | 5.7%, 3.9% |

How to read it: Δ is the median over holds of (variant row mean - B row mean) / B row mean; the last
two columns are the largest A/A gap, the same binary's two rows in one hold, seen in that cell.
A delta no larger than that gap is not distinguishable from noise.

Per hold and cell, CPU s/Gbit against B (M1, M2, M3):

| cell | S | R | Q | B's own A/A gap |
|---|---|---|---|---|
| forward, 1 flow | -1.2, -0.5, -1.2% | -0.9, -0.5, -1.3% | -3.1, -2.3, -3.0% | 0.3, 0.7, 1.1% |
| forward, 8 flows | -0.8, -0.1, -1.1% | -1.0, -0.2, -1.0% | -2.5, -1.1, -2.2% | 0.0, 0.2, 1.2% |
| reverse, 1 flow | -3.7, +1.2, -2.8% | -2.7, -3.0, -1.5% | -4.3, -1.3, -4.5% | 4.2, 4.0, 3.3% |
| reverse, 8 flows | -3.6, +1.8, -2.2% | -5.1, -0.9, -5.5% | -4.9, +1.7, -7.9% | 4.2, 4.5, 3.4% |

- **Forward is the readable direction.** Q is lower in all six hold cells; over the six rows per cell
  Q's range does not overlap B's (1 flow: 1.194-1.209 against 1.227-1.250 s/Gbit; 8 flows: 1.222-1.238
  against 1.250-1.265). That is 28-36 ms of CPU per Gbit. S and R are each lower in all six hold cells,
  but each step is about the size of the A/A gap, so the consistent sign is the only evidence for one
  lever alone. S + R adds up to about Q (-2.1 / -1.8 against -3.0 / -2.2).
- **Reverse is noisy** (B's two rows in one hold differ by 3.3-4.5%). The medians favour the levers
  (S -2.8 / -2.2, R -2.7 / -5.1, Q -4.3 / -4.9%), R is lower in all six hold cells, S and Q flip sign in
  some. Do not quote a reverse percentage as a result. Q's 11.9% A/A gap in Gbit/s is one window
  (M2 Q.2, 2.933 Gbit/s).
- **Against the arithmetic** (each packet is looked up once on each host, 90,000 packets of 1,390 B per
  Gbit, about 1.24 s of CPU per Gbit for A + B): S 3.3 ms (0.27%), R 12 ms (1.0%), Q 15 ms (1.2%).
  R matches; Q's forward gain is 1.8-2.5 times the arithmetic (J1204 saw about 2x for its hasher patch);
  S's median is 3-4.5 times the arithmetic and inside noise, so read S as "somewhere from 0.3% to
  1.2%" on the old base, and less on today's dev (arithmetic 0.2% against J1226's function).
- **Latency under load** (64 B probe during full-speed transfers): forward 8 flows and both reverse
  cells show no difference. Forward with one flow, Q's rows sit higher: p50 4.9-7.1 ms (median 6.55)
  against B's 4.6-5.7 (median 5.05), p99 8.8-10.6 against 7.6-10.4; S alone does not (4.5-5.0), R
  alone is in between (4.7-6.6). J1204's own rows of this cell ranged 4.6-7.3 ms on builds without
  either change, so I do not call it an effect, but I have not explained it. A product change should
  rerun this cell and compare latency, not only CPU.

## 4. Is each lever worth a product change?

These are recommendations; the owner decides, nothing is switched.

- **(2) Host-route table: yes.** It removes the largest single table cost J1204 found on the packet path
  (67 ns per packet per host; the lookup is 11x faster for every mesh peer), its macro
  effect is the size the arithmetic predicts, the semantics argument is short and tested against a
  reference trie, and the code is about 30 lines plus its test. Costs: it is a change to the GotaTun
  fork's data structure (to carry, and to propose upstream, which needs a human author), 1.2-2.9 ns
  more for subnet-route destinations, and about 3.4 KB. On today's dev the fork already depends on
  `foldhash` and has a `packet_hash` module (J1226), so the product version needs no new dependency:
  use `PacketHash` for the new map. The `allowed_ips.rs` hunk of the patch applies cleanly on the
  current pin `a0be34f8` (checked with `git apply --check`; not built or tested there).
- **(1) Symmetric flow hash: not worth a change for performance alone, cheap as a rider.** On today's
  dev it saves 14.3 ns (v4) / 16.7 ns (v6) per packet per host, about 0.2% of mesh CPU by arithmetic,
  which these holds cannot resolve. It is about 10 lines in `flow_start` (`canonical()` then goes
  away), it keeps the collision resistance of the J1226 function (section 1) and needs nothing new.
  If someone is in the packet filter anyway, take it, with J1226's
  `flow_slot_collisions_stay_spread_under_a_crafted_search` and the both-directions property as its
  tests. Do not claim a measurable product gain for it.
- **Both together** on the old base: forward CPU per Gbit -2.2% to -3.0%, throughput unchanged. On
  today's dev expect less than that, because part of lever 1's share was the hasher J1226 already
  changed; that combination was not measured.

## 5. Reproduce

- Micro: `bench/` (`cargo build --release --benches --bins`, static musl through the product's
  `scripts/static-cargo`), `hot_paths --bench 'flow_start|allowed_ips' --warm-up-time 1
  --measurement-time 3 --sample-size 50` on one pinned CPU of a quiet host, `python3 -I
  summarize_micro.py crit-rep*.txt`. Tests: `cargo test --release` in `bench/`. Quality:
  `target/release/symmetric_quality`. Tables: `results-j1227/`; the raw criterion output, hold logs
  and binary hashes are in `j1227-evidence.tar.gz` on #260.
- Macro: `patches/infraternal-j1227-symmetric-flow.patch` on origin/dev (S), the fork patch
  `patches/gotatun-j1227-host-routes.patch` on the pin with `[patch."https://github.com/kaygdotorg/gotatun"]
  gotatun = { path = ... }` (R), both (Q); build each tree with its own target dir; then
  `kit-macro-j1227/macro.sh <hold> B.1 S.1 R.1 Q.1 Q.2 R.2 S.2 B.2` (`MICRO_INHOLD=1` runs the criterion
  bench first, inside the same hold; binaries are staged inside the hold from
  `~/.cache/codex-scratch/j1227/stage-macro/ab/`) and `kit-macro-j1227/table.py`, `macro_pairs_j1227.py`.
  Both patches apply to `373a47057` / pin `e87fef91`, not to today's dev. CSVs: `results-j1227/macro/`.

Limits: one build-host class for the macro (x86, Ryzen 3700X VMs); the allowed-IPs micro bench and the
macro mesh traffic are IPv4 only (the IPv6 host table is covered by tests, not timed); the micro numbers
are x86 only (the aarch64 data here is the collision statistics, not timing; rerun on the Mac before
a client relies on them); the prototypes are throwaway code, not a proposal for review; the fork patch
is not submitted anywhere (upstream CONTRIBUTING needs a human behind it, owner decision 2026-11-24).
