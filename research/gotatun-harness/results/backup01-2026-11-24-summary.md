# Quiet-host rerun: stock 0.10.3 (e95ba96) vs fork pin (841ef3e, replies-first default)

**backup01, quiet.** infraternal-perf-01-backup01 (6 pinned vCPUs on a Ryzen 7 3700X host), held through the perf-VM lock for the whole run, so no cooperating job ran (load average at start 3.4; the load columns in the CSV peak at 4.5, which is our own processes). Each run is 20 s; 3 holds, 4 cells, 2 arms: 72 runs, 33 min (J1170, #260). Latency is the TCP round-trip probe (`rr.py`: 64-byte request every 20 ms, 64-byte reply, open loop), not ping. Engines are pinned to 2 CPUs each (A=1,2 B=3,4), iperf3 server to 5, iperf3 client and probe to 0. `runs.csv` here is the raw per-run data.

Read the Δ column against the A/A floor: `=` means the difference is no bigger than the largest gap between two identical runs of the same cell. The pin carries our whole patch series, so these rows compare two builds, not one patch.

date: 2026-11-24T21:52:32Z  host: infraternal-perf-01-backup01  kernel: 6.12.113+deb13-amd64  
cpu: AMD Ryzen 7 3700X 8-Core Processor  online: 6  
governor: n/a  
rmem_max: 212992  wmem_max: 212992  netdev_max_backlog: 1000  
loadavg at start: 3.37 2.42 1.61 1/240 388935  
cpus: A=1,2 B=3,4 iperf-server=5 iperf-client=0 rr-probe=0  
run: holds=3 secs=20 idle=5 flows=[1 8] cc=[cubic bbr] delay=0ms loss=0% mtu=1420 rr=64B/20ms  
tools: iperf 3.21 (cJSON 1.7.15); wireguard-tools v1.0.20260223  
veth offloads: tcp-segmentation-offload: on generic-segmentation-offload: on generic-receive-offload: off rx-gro-hw: off [fixed] rx-gro-list: off   
arm stock: /root/j1170/bin/gotatun-upstream sha256=18bce737a0dc364d gotatun-cli 0.10.3  
arm pin: /root/j1170/bin/gotatun-pin sha256=bcc8dab6160dd9a4 gotatun-cli 0.10.3

### A/A noise floor (largest gap between the two runs of one hold, %)

| cell | Gbit/s | p99 | CPU s/Gbit |
|---|---|---|---|
| bbr 1 flows | 5.8 | 8.1 | 6.2 |
| bbr 8 flows | 0.8 | 122.9 | 0.8 |
| cubic 1 flows | 1.5 | 27.7 | 1.7 |
| cubic 8 flows | 3.4 | 4.2 | 2.8 |

### Results (median over holds; delta = paired, against the first arm; `=` = within noise)

| cell | arm | Gbit/s (min-max) | Δ | p50 ms | p99 ms | Δ | CPU s/Gbit | Δ | RSS MiB | wakeups/s | lost % |
|---|---|---|---|---|---|---|---|---|---|---|---|
| bbr 1 fl | stock | 2.32 (2.32-2.34) |  | 1.02 | 1.62 |  | 1.649 |  | 59 | 16 | 0.00 |
| bbr 1 fl | pin | 5.30 (5.28-5.30) | +127.1% | 1.33 | 2.85 | +75.5% | 0.575 | -65.0% | 24 | 5 | 0.00 |
| bbr 8 fl | stock | 2.24 (2.23-2.25) |  | 6.85 | 51.09 |  | 1.690 |  | 73 | 16 | 0.00 |
| bbr 8 fl | pin | 5.53 (5.50-5.54) | +146.3% | 4.74 | 8.53 | -84.8% = | 0.589 | -65.0% | 36 | 6 | 0.00 |
| cubic 1 fl | stock | 2.50 (2.48-2.52) |  | 2.32 | 3.74 |  | 1.546 |  | 65 | 16 | 0.00 |
| cubic 1 fl | pin | 5.52 (5.51-5.61) | +122.9% | 1.74 | 3.25 | -13.1% = | 0.563 | -63.8% | 25 | 5 | 0.00 |
| cubic 8 fl | stock | 2.31 (2.27-2.31) |  | 3.62 | 6.58 |  | 1.654 |  | 68 | 16 | 0.00 |
| cubic 8 fl | pin | 5.60 (5.55-5.65) | +144.1% | 2.67 | 4.37 | -34.7% | 0.572 | -65.6% | 33 | 5 | 0.00 |

holds per cell: 3 paired (A B B A); A/A holds: 3. `?` = no A/A data, so no noise verdict.
