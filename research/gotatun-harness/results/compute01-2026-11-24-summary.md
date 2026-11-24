# Validation run: stock 0.10.3 (e95ba96) vs fork pin (e6efb96) vs kernel WireGuard

**compute01, indicative.** compute01 is a shared build VM: load average was 4 to 20 on 16 CPUs during the run (see `load_start` / `load_end` in the CSV) and the A/A noise floor below is large. Read the direction and the CPU per Gbit column (which is steady across holds); do not quote the absolute Gbit/s. Run time: 3 arms, 3 holds, 4 cells, 20 s runs: 2,522 s (42 min) for 96 runs. `runs.csv` here is the raw per-run data (J1144, #260).

date: 2026-11-24T06:22:20Z  host: infraternal-dev-01-compute01  kernel: 6.12.115+deb13.1-amd64  
cpu: Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz  online: 16  
governor: n/a  
rmem_max: 212992  wmem_max: 212992  netdev_max_backlog: 1000  
loadavg at start: 10.82 8.75 6.28 19/552 748115  
cpus: A=0,1 B=2,3 iperf-server=4 iperf-client=5 ping=6  
run: holds=3 secs=20 idle=5 flows=[1 8] cc=[cubic bbr] delay=0ms loss=0% mtu=1420  
tools: iperf 3.21 (cJSON 1.7.15); wireguard-tools v1.0.20260223  
veth offloads: tcp-segmentation-offload: on generic-segmentation-offload: on generic-receive-offload: off rx-gro-hw: off [fixed] rx-gro-list: off   
arm stock: /mnt/build/targets/j1144-e95ba96/release/gotatun sha256=4b59e7011aedc9c8 gotatun-cli 0.10.3  
arm fork: /mnt/build/targets/j1144-e6efb96/release/gotatun sha256=05f1780a87b09d34 gotatun-cli 0.10.3  
arm kernel: kernel wireguard

### A/A noise floor (largest gap between the two runs of one hold, %)

| cell | Gbit/s | p99 | CPU s/Gbit |
|---|---|---|---|
| bbr 1 flows | 14.2 | 65.6 | 12.4 |
| bbr 8 flows | 19.4 | 71.7 | 5.2 |
| cubic 1 flows | 66.0 | 104.7 | 16.2 |
| cubic 8 flows | 5.2 | 7.8 | 5.3 |

### Results (median over holds; delta = paired, against the first arm; `=` = within noise)

| cell | arm | Gbit/s (min-max) | Δ | p50 ms | p99 ms | Δ | CPU s/Gbit | Δ | RSS MiB | wakeups/s | lost % |
|---|---|---|---|---|---|---|---|---|---|---|---|
| bbr 1 fl | stock | 0.71 (0.59-1.85) |  | 6.62 | 87.36 |  | 2.990 |  | 62 | 16 | 4.11 |
| bbr 1 fl | fork | 2.92 (1.63-3.01) | +176.9% | 2.18 | 44.70 | -45.3% = | 0.807 | -60.9% | 26 | 5 | 0.03 |
| bbr 1 fl | kernel | 1.76 (1.25-2.12) | +112.5% | 0.99 | 12.82 | -66.2% | n/a |  | n/a | n/a | 0.00 |
| bbr 8 fl | stock | 1.75 (0.91-1.80) |  | 6.58 | 19.51 |  | 2.066 |  | 72 | 16 | 3.92 |
| bbr 8 fl | fork | 3.56 (1.06-4.41) | +103.4% | 7.86 | 24.19 | +23.9% = | 0.817 | -60.4% | 40 | 5 | 0.03 |
| bbr 8 fl | kernel | 1.58 (1.07-1.91) | +9.3% = | 4.52 | 45.81 | +13.7% = | n/a |  | n/a | n/a | 0.03 |
| cubic 1 fl | stock | 1.05 (0.96-1.99) |  | 3.21 | 18.61 |  | 3.268 |  | 61 | 16 | 0.19 |
| cubic 1 fl | fork | 3.14 (1.64-4.38) | +120.3% | 2.38 | 9.31 | -29.3% = | 0.738 | -62.4% | 26 | 5 | 0.00 |
| cubic 1 fl | kernel | 1.91 (1.25-2.04) | +19.3% = | 2.29 | 3.88 | -76.9% = | n/a |  | n/a | n/a | 0.00 |
| cubic 8 fl | stock | 1.22 (0.91-2.00) |  | 4.26 | 19.14 |  | 2.483 |  | 66 | 16 | 0.98 |
| cubic 8 fl | fork | 2.90 (2.58-4.25) | +112.0% | 4.21 | 25.29 | +15.2% | 0.844 | -65.2% | 42 | 5 | 0.03 |
| cubic 8 fl | kernel | 1.83 (1.81-2.02) | +48.9% | 4.64 | 7.36 | -61.2% | n/a |  | n/a | n/a | 0.00 |

holds per cell: 3 paired (A B B A); A/A holds: 3. `?` = no A/A data, so no noise verdict.
