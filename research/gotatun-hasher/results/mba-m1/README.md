# J1228: hasher micro-bench on Apple Silicon (#260)

Reruns J1204's `hot_paths` criterion bench on the mba (MacBook Air, Apple M1, 8 GB, AC power at
100%, no thermal or performance warning, mba lock held, nothing else of ours running; the host's
background load average was 1.3-2.4). The binary is the same bench source at origin/dev
`373a47057`, built natively on std (arm64, toolchain 1.99.1, the crate's release profile: fat LTO,
1 CGU), copied over and run only for measurement. Three runs, each with
`--warm-up-time 1 --measurement-time 3` (shorter than J1204's; run spread is in `micro-table.md`).
The binary sha256 was `7f2472a6...9aef`. No CPU pinning exists on macOS, so the scheduler may
move the thread between performance and efficiency cores; spreads were still mostly under 5%,
with a few 6-10% rows at 100 peers (see `micro-table.md`).

Files: `run1-3.txt` (raw criterion output), `machine.txt` (load and thermal before each run),
`micro-table.md` (all rows, median of 3), `side-by-side.md` (perf VM vs mba).

## Result

The ranking is the same as on x86 and the recommendation does not change.
- SipHash-1-3 is 3.3-5x slower than foldhash fast on `peer_addresses` and `peer_ids`
  (M1: 10.4-11.7 vs 2.2 ns; 6.2-6.8 vs 1.4-1.8 ns).
- foldhash fast, ahash and Fx are within about 1 ns of each other on M1 (foldhash 2.2, Fx 1.9-2.2,
  ahash 3.3-3.6 ns on `peer_addresses`). Fx is no longer a meaningful speed win, and it is
  unkeyed, so the reasoning for keyed foldhash stands.
- `flow_start` v4 is 15.2 ns today and 6.9 ns with foldhash (x86: 25.9 and 18.6); v6 29.2 vs 7.7 ns
  (x86: 34.5 and 26.3). The saving is larger on M1 than on x86, because the M1 hashes the tuple
  faster than it runs the SipHash rounds, and `canonical()` is cheap there.
- `peers_by_idx` (the `Arc` clone dominated lookup) drops from 8.9-10.0 ns to 3.7 ns at 100 and
  1,000 peers. At one peer all hashers sit at 7.1 ns: the cause was not investigated
  (the x86 rows show no such step), so do not read anything into the 1-peer row.
- The allowed-IPs trie is 44.7 ns on M1 against 68 ns on x86, so it is still the largest single
  lookup per packet and still not a hasher question.

Per received packet (one `peers_by_idx`, two `peer_ids.contains`) foldhash saves about
5.5 + 2 x 4.7 = 15 ns on M1 at 100+ peers, against about 6 + 2 x 5.8 = 18 ns on x86 from the same
rows. Absolute savings are a little smaller on the M1, relative savings similar or larger.
At the mesh's line rates that is still under 1% of per-packet work.

Nothing here changes J1204's recommendation (keyed `foldhash::fast::RandomState`). Caveat: one
laptop at one thermal state; not pinned, and 3 shorter runs instead of 4 longer ones.
