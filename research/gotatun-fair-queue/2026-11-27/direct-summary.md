date: 2026-11-27T05:10:47Z  host: infraternal-perf-01-backup01  kernel: 6.12.113+deb13-amd64
cpu: AMD Ryzen 7 3700X 8-Core Processor  online: 6
governor: n/a
rmem_max: 212992  wmem_max: 212992  netdev_max_backlog: 1000
loadavg at start: 0.00 0.06 0.23 1/239 1221473
cpus: A=1 B=2 iperf-server=3 iperf-client=3 rr-probe=3
run: holds=1 secs=30 idle=5 flows=[1 8] cc=[cubic] delay=0ms loss=0% mtu=1420 rr=64B/20ms
tools: iperf 3.21 (cJSON 1.7.15); wireguard-tools v1.0.20260223
veth offloads: tcp-segmentation-offload: on generic-segmentation-offload: on generic-receive-offload: off rx-gro-hw: off [fixed] rx-gro-list: off
arm base: /root/j1268/bin/gotatun-base sha256=ce67a5de6a6d4fee gotatun-cli 0.10.3
arm fair: /root/j1268/bin/gotatun-fair sha256=6e6bd29c74fb8665 gotatun-cli 0.10.3

### A/A noise floor (largest gap between the two runs of one hold, %)

| cell | Gbit/s | p99 | CPU s/Gbit |
|---|---|---|---|
| cubic 1 flows | 1.0 | 0.9 | 0.8 |
| cubic 8 flows | 0.2 | 0.1 | 0.2 |

### Results (median over holds; delta = paired, against the first arm; `=` = within noise)

| cell | arm | Gbit/s (min-max) | Δ | p50 ms | p99 ms | Δ | CPU s/Gbit | Δ | RSS MiB | wakeups/s | lost % |
|---|---|---|---|---|---|---|---|---|---|---|---|
| cubic 1 fl | base | 3.45 (3.45-3.45) |  | 7.06 | 8.27 |  | 0.547 |  | 15 | 1 | 0.00 |
| cubic 1 fl | fair | 3.10 (3.10-3.10) | -10.2% | 1.15 | 1.89 | -77.1% | 0.611 | +11.6% | 14 | 1 | 0.00 |
| cubic 8 fl | base | 3.40 (3.40-3.40) |  | 54.38 | 57.78 |  | 0.556 |  | 14 | 1 | 0.00 |
| cubic 8 fl | fair | 3.24 (3.24-3.24) | -4.5% | 56.88 | 60.95 | +5.5% | 0.602 | +8.3% | 15 | 1 | 0.00 |

holds per cell: 1 paired (A B B A); A/A holds: 1. `?` = no A/A data, so no noise verdict.
