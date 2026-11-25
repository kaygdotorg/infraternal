# gotatun-netns-bench

A small benchmark harness to compare WireGuard engines (GotaTun, wireguard-go, kernel WireGuard) on **one machine**, written so
that it could live in the GotaTun repository (`bench/`). It is three files: `run.sh` drives the run, `rr.py` is the latency probe,
`summarize.py` turns the output into a table. Licence: MPL-2.0 (same as upstream).

**Read this first:** the numbers are for *relative* comparison of builds on a quiet machine, run back to back. Do not quote an
absolute figure from a shared CI runner or a busy VM. The harness prints how noisy the machine was (the A/A series) so you
can see whether a difference is real.

## What it does

```
 ns gtb-a                                    ns gtb-b
 ┌────────────────────┐  veth (underlay)   ┌────────────────────┐
 │ engine -> gtba0    │ ─────────────────── │ engine -> gtbb0    │
 │ 10.77.0.1 (tunnel) │  10.78.0.1 / .2    │ 10.77.0.2 (tunnel) │
 └────────────────────┘  optional netem    └────────────────────┘
```

Both namespaces and the veth pair are created by `run.sh` and removed in a `trap` when it exits. The ranges `10.77.0.0/24`
and `10.78.0.0/24` exist only inside them, there is no default route, and nothing touches the host network namespace (the
script refuses to run if a veth end shows up there). Nothing else on the machine is changed: no sysctl, no offload setting.
They are only recorded.

Per run it starts two fresh engine processes, configures keys with `wg set`, waits for the first ping to get through, then:

| Metric | How |
|---|---|
| Throughput | `iperf3 -P N -C cc -J`, receiver-side bits per second, 1 and 8 flows, CUBIC and BBR |
| Loaded latency | `rr.py`: a 64-byte TCP request every 20 ms with a 64-byte reply (a keystroke echo), open loop, during the iperf3 run; p50 and p99 over all probes, unanswered probes count as lost. Not ping: ping busy-waits and costs an engine 1 to 9% of throughput, and an engine may treat a small non-TCP packet differently from TCP data |
| CPU per Gbit | utime+stime of both engine processes over the iperf3 window, divided by Gbit transferred |
| Memory | `VmHWM` of both engines after load (sum) |
| Idle wakeups | voluntary context switches of all threads of both engines, per second, over `--idle` seconds after load |
| Handshake time | first ping reply after configuring the peers (in `runs.csv`) |
| WAN profile | `--delay 99` puts 99 ms netem on both veth ends (198 ms RTT); `--loss 2` adds loss |

The kernel arm has no process to read, so its CPU, memory and wakeup columns say `n/a`.

## Method

1. **A/A first.** The first arm is run twice per hold and cell. The largest gap between the two runs is the noise floor.
2. **A B B A.** Then every hold runs the arms in order and then in reverse (`A B C C B A`), so a slow drift of the machine
   averages out. Each hold is compared with itself: delta = median over holds of `(arm - A) / A`.
3. A delta no bigger than the A/A floor of the same cell and metric is marked `=` (no difference we can see).
4. Engines, iperf3 server, iperf3 client and the round-trip probe are pinned to separate CPUs with `taskset` (needs at least 4 online CPUs;
   override with `--cpus "A B SERVER CLIENT PING"`). Kernel WireGuard cannot be pinned: its work runs in softirq and workqueues
   on whatever CPUs the traffic hits.

## Usage

```
sudo ./run.sh --arm stock=/path/to/gotatun-cli-main --arm patched=/path/to/gotatun-cli-pr --arm kernel=kernel
python3 summarize.py out-YYYYMMDD-HHMMSS
```

Needs root, bash, iproute2 (`ip`, `tc`), `wg` (wireguard-tools), `iperf3`, `ping` (handshake check), `taskset`, `lscpu`, python3 (standard library
only). An arm is any program that accepts `-f INTERFACE` and serves the WireGuard userspace API on
`/var/run/wireguard/INTERFACE.sock` (`gotatun`, `wireguard-go`), or the word `kernel`. `run.sh --help` lists the options
(`--holds`, `--secs`, `--idle`, `--flows`, `--cc`, `--delay`, `--loss`, `--rr-reply`, `--rr-interval`, `--out`).

Output directory: `machine.txt` (CPU, kernel, governor, buffer sysctls, offloads, tool versions, binary hashes, CPU layout),
`runs.csv` (one row per run, with load average at start and end), `raw/` (iperf3 JSON, round-trip JSON and engine logs per run).

A full run with 3 arms, 2 flow counts, 2 congestion controls and 3 holds of 20 s takes about 42 minutes (96 runs; the A/A series is 24 of them); each run is about 30 s (20 s load, 5 s idle, a few seconds of setup). Use `--secs 10 --holds 1` for a smoke test.

## What it does not do

No multi-peer scale, no DAITA, no macOS, no cpuset audit. It does not tune the machine: set a performance governor and stop
other work yourself, and read `machine.txt` and the load columns before you trust a result. Our own tables use a larger
internal kit; this harness exists so that anyone can reproduce a claim in an afternoon.

GotaTun's CLI needs `WG_SUDO=1` when run as root without a login session (it looks up the sudo user); `run.sh` sets it.

Worked examples in `results/`: stock 0.10.3 vs a patched fork vs kernel on a busy shared VM (`compute01-*`, noisy, ping latency), and stock vs the fork pin on a quiet, exclusively held 6-vCPU VM with the TCP round-trip probe (`backup01-*`; A/A floor 0.8 to 5.8% on Gbit/s).
