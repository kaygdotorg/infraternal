# Relay manager slice 1: relayed against direct, measured (J1254, D401 Q9, D167)

Driver: `research/relay-manager/relay_perf.py`. Each profile runs in its own
rootless namespace (J536b's topology, about 30 ms round trip on the public core):
two real infraternal agents and a third serving the relay role.
`full-cone-both` is the direct baseline (its nodes get no relay list);
`symmetric-both` is relayed after the 5.5 s backstop. TCP goodput is Python
senders, 10 s per run; CPU is utime + stime of each agent process from /proc;
idle wakeups are context switches per second over every agent thread for 30 s
with no traffic.

## Perf VM (primary)

perf-01-backup01 (x86_64, Debian 13), through `perf-run` (perf.slice, cpus 1–3,
quiet before and after: no process above 5 % CPU). Final code, binary sha256
`b2051dcb0d4c6aec…` (built from `78733f8cd`), report `perf4.json`.

| | Direct (full-cone-both) | Relayed (symmetric-both) |
|---|---|---|
| First packet | 114 ms | 5,714 ms (5.5 s backstop + one QUIC handshake) |
| RTT p50 / p99 at rest | 30.1 / 33.8 ms | 30.6 / 33.9 ms |
| Relay added latency, p50 / p99 | — | +0.5 / +0.1 ms (the relay sits on the same core) |
| TCP, 1 flow | 0.720 Gbit/s | 0.145 Gbit/s |
| TCP, 8 flows | 2.725 Gbit/s | 0.313 Gbit/s |
| CPU s per Gbit, 1 flow: A / B / relay | 0.28 / 0.31 / — | 1.66 / 2.07 / 1.47 |
| CPU s per Gbit, 8 flows: A / B / relay | 0.33 / 0.31 / — | 2.47 / 2.33 / 1.56 |
| Idle wakeups per s: A / B / relay node | 0.43 / 0.70 / 0.07 | 10.8 / 11.2 / 14.3 |
| Relay process killed, a new one serving at the same address | — | serving again 162 ms after the kill; pair back 3,985 ms after that |

## dev-02 (indicative)

dev-02 (aarch64, shared build VM), binary sha256 `eb52f3caa606f2ad…` (same code),
report `perf-dev02c.json`: direct 0.23–0.41 Gbit/s with one flow and 1.85–3.74
with eight; relayed 0.070 and 0.193; added RTT 0.0 ms; idle wakeups 12.4 / 13.0
/ 15.9 relayed against 0.3–0.7 direct; relay restart 48 ms, pair back 4,048 ms.

## Reading

- **Latency** through the relay is the path's own: on this topology it adds
  under a millisecond. A relay far from both ends adds its detour; that is what
  the home-relay choice (D401 Q5) is for.
- **Throughput** is the open problem: relayed is 5 times slower than direct with
  one flow and 9 times with eight, and costs 5–8 times the CPU per Gbit on each
  node plus about 1.5 s per Gbit on the relay. The receive-queue fix
  (`summary.md` §2) took it from 2 to 145 Mbit/s; the next suspects are the
  256 KiB per-pair forwarding budget, the two quinn congestion windows in series,
  and one loopback-shim hop and one QUIC DATAGRAM per packet in each direction
  (no batching). Slice 1b measures each of those separately.
- **Idle cost**: a node with no relayed pair holds no relay connection and adds
  nothing (D81). A node with a relayed pair wakes about 11 times a second while
  idle: the 1 s QUIC keep-alive and the relay paths' 1 s route-MTU poll per
  connection, each waking the relay runtime. D401 Q5's slow keep-alive home
  relay and an event-driven MTU watch are the slice 1b fix.
- **Failover** to a restarted relay takes about 4 s (QUIC reconnect with
  back-off, a new link, a new WireGuard session). D401 Q7's fast failover
  between two relays is slice 1b and needs a second relay to fail over to.
- **Loopback shim against an in-process hand-off** (D401 Q10) was not measured:
  the in-process hand-off does not exist yet. The shim's share is part of the
  CPU per Gbit above.
