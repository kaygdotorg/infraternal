# Relay manager slice 1: relayed against direct, measured (J1254, D401 Q9, D167)

Driver: `research/relay-manager/relay_perf.py`. Each profile runs in its own
rootless namespace (J536b's topology, 34 ms round trip on the public core): two
real infraternal agents and a third serving the relay role. `full-cone-both` is
the direct baseline (its nodes get no relay list); `symmetric-both` is relayed
after the 5.5 s backstop. TCP goodput is Python senders, 10 s per run; CPU is
utime + stime of each agent process from /proc; idle wakeups are context
switches per second over every agent thread for 30 s with no traffic.

## Where it ran

The perf VM run (perf-01-backup01, x86_64, through `perf-run`) did not happen in
this job: the perf lock was held by another job's root `sleep 14400` lock-hold
(started about 17:16 CET); my `perf-run` stayed queued behind it. The direct baseline did run there once (`perfvm-perf2.log`,
binary built from `878496fc8`): 0.72 Gbit/s with one flow, 2.68 Gbit/s with 8,
0.28–0.33 CPU seconds per Gbit on each node.

The numbers below are from dev-02 (aarch64, 10 vCPU, shared build VM, no other
build running during the run), binary sha256 `eb52f3caa606f2ad…` (final code),
report `perf-dev02c.json`. Treat them as indicative, not as perf-VM evidence.

## Results (dev-02)

| | Direct (full-cone-both) | Relayed (symmetric-both) |
|---|---|---|
| First packet | 77 ms | 5,678 ms (5.5 s backstop + one QUIC handshake) |
| RTT p50 / p99 at rest | 33.4 / 40.2 ms | 33.4 / 39.9 ms |
| Relay added latency (p50 / p99) | — | 0.0 / −0.3 ms (the relay sits on the same core) |
| TCP, 1 flow | 0.231–0.413 Gbit/s | 0.070 Gbit/s |
| TCP, 8 flows | 1.85–3.74 Gbit/s | 0.193 Gbit/s |
| CPU s per Gbit, 8 flows: node A / node B / relay | 0.25–0.27 / 0.28–0.29 / — | 1.32 / 1.62 / 1.01 |
| Idle wakeups per s: node A / node B / relay node | 0.4–0.6 / 0.3–0.7 / 0.03–0.07 | 12.4 / 13.0 / 15.9 |
| Relay process killed, a new one serving at the same address | — | serving again 48 ms after the kill; pair back 4,048 ms after that |

## Reading

- **Latency** through the relay is the path's own: on this topology the relay
  adds nothing measurable. A relay far from both ends adds its detour; that is
  what the home-relay choice (D401 Q5) is for.
- **Throughput** is the open problem: relayed is 3–6 times slower than direct
  with one flow and 10–19 times slower with eight, and costs about five times
  the CPU per Gbit on each node plus the relay's own. The 8 KiB receive-queue fix
  (`summary.md` §2) took it from 2 to 70 Mbit/s; the next suspects are the
  256 KiB per-pair forwarding budget, the two quinn congestion windows in series,
  and one loopback-shim hop and one QUIC DATAGRAM per packet in each direction
  (no batching). Slice 1b measures each of those separately on the perf VM.
- **Idle cost**: a node with no relayed pair holds no relay connection and adds
  nothing (D81). A node with a relayed pair wakes about 12 times a second while
  idle: the 1 s QUIC keep-alive and the relay paths' 1 s route-MTU poll per
  connection, each waking the relay runtime. D401 Q5's slow keep-alive home
  relay and an event-driven MTU watch are the slice 1b fix.
- **Failover** to a restarted relay takes about 4 s (QUIC reconnect with
  back-off, a new link, a new WireGuard session); D401 Q7's fast failover between
  two relays is slice 1b, and needs a second relay to fail over to.
- **Loopback shim against an in-process hand-off** (D401 Q10) was not measured:
  the in-process hand-off does not exist yet.
