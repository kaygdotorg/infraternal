# J88 perf evidence notes

Machine: infraternal-perf-01-backup01, Debian 13, kernel 6.12.113+deb13-amd64, AMD Ryzen 7 3700X (4 cores), 7880 MiB. Each case used perf.slice CPUs 1–3 with a 6 GiB cap, through `perf-run --root`; one sample per workload.

The first full paired sweep used the R4b kit at results/20261102T062117Z. Seven cases (underlay, kernel WireGuard before/after, wireguard-go before/after, GotaTun before/after) exited 0 with empty machine diffs. The mixed case completed the workloads but exited 3 because the machine snapshot caught only a changing root Nix sentry cache entry; its diff contains no other change. The initial run did not forward `H2H_REORDER_CHECK`, so it has no reordering measurements.

The temporary perf-all wrapper was fixed to explicitly pass `H2H_REORDER_CHECK` through perf-run. The follow-up at results/20261102T064841Z reran GotaTun before/after/mixed. All three cases exited 0, all machine diffs are empty, and there are no `.failed` files. This follow-up contains the final GotaTun rows and reordering profile.

Under 25% correlated reordering and 198 ms RTT, each GotaTun variant received 300/300 probes at 64/512/1400 B with no reported probe loss. TCP throughput fell to 0.003/0.016 Gbit/s for baseline and 0.003/0.015 for patched/mixed at 1/8 flows. No case crashed. This is an intentionally severe reordering profile; it demonstrates survival, not a realistic throughput expectation.

The mixed run puts the baseline GotaTun binary on one endpoint and patched GotaTun on the other, and checks both directions, loss, reordering and 1/1000 peer memory.

The perf kernel supports Linux TUN offload; unsupported `IFF_VNET_HDR` and `TUNSETOFFLOAD` paths were covered by focused fallback unit tests on compute01 (the TUN creation fallback seam and an ioctl failure on `/dev/null`). IPv6 TSO/checksum/length and max-size paths were unit-tested; the perf mesh fixture itself uses IPv4.

No product code changed. No upstream PR, issue or comment was made.
