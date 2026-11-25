<!-- J1199 (#260, #580): results of the fair engine and product comparisons on the cross-VM perf pairing, 2026-11-25. -->
# Fair comparisons, 2026-11-25: results

Method, fixture and caveats: [README.md](README.md). Full tables (every metric, with the A/A floor and the min–max over
holds): [results/engine-tables.md](results/engine-tables.md), [results/product-tables.md](results/product-tables.md).
Raw numbers: [results/windows.csv](results/windows.csv) (144 loaded windows), [results/rows.csv](results/rows.csv).

**Holds:** engine e3 (07:50–08:58Z, `I.cap G.1 W K J G.2`) and e4 (10:26–11:31Z, `G.1 J K W G.2`); product p1
(09:00–09:55Z, `I.1 T N I.2`) and p2 (13:07–14:01Z, `I.1 N T I.2`). All 144 windows exit 0. A third engine hold (e5)
lost its lock wait to another job's hold and was not run. In every engine hold the netns guard counted 0 dropped packets.
In each product hold it dropped 6 packets (650 bytes) on each of A and B: some product tried an address outside the
LAN, and the packets were dropped inside the netns. The counters are per hold, not per row.

How to read the tables: "for" = A (4 vCPU on 2 cores) sends, "rev" = A receives. Δ is paired within a hold against the
base row, and the median of two holds is reported. `=` means the Δ is no bigger than the A/A floor (the largest gap between
the base row's two runs in one hold). With two holds the floors are small, and on the throughput and CPU rows the
two holds agreed within 0–2%.

## A. Engine row: the bare protocol, like for like

G = `gotatun-cli` at the dev pin `e87fef91`, sender off; J = the same binary with `GOTATUN_SIDE_SOCKET=1`;
W = wireguard-go; K = kernel WireGuard. Every row: `wg set`, MTU 1390, the product's guard table, the whole VM.

**Gbit/s** (Δ against G)

| cell | G | J | W | K |
|---|---|---|---|---|
| for bbr 1 | 3.06 | 3.07 = | 1.76 −43% | 3.08 +1% = |
| for bbr 8 | 3.11 | 3.11 = | 2.11 −32% | 3.06 −1% |
| for cubic 1 | 3.25 | 3.25 = | 2.10 −36% | 2.64 −19% |
| for cubic 8 | 3.15 | 3.15 = | 2.21 −30% | 3.11 −1% |
| rev bbr 1 | 3.42 | 3.43 = | 1.98 −42% | 1.18 −65% |
| rev bbr 8 | 3.50 | 3.49 = | 2.00 −43% | **4.15 +18%** |
| rev cubic 1 | 3.33 | 3.31 = | 2.11 −37% | 2.99 −10% |
| rev cubic 8 | 3.37 | 3.34 = | 2.06 −39% | **4.16 +23%** |

**Round trip under load, p99 ms** (64 B request/reply every 20 ms; p50 and p99.9 are in the full tables)

| cell | G | J | W | K |
|---|---|---|---|---|
| for bbr 1 | 4.11 | 3.85 −6% | 5.83 +42% | **3.03 −26%** |
| for bbr 8 | 10.59 | 6.22 −41% | 14.32 +35% | **8.56 −19%** |
| for cubic 1 | 8.68 | 5.23 −40% | 18.59 +114% | **1.98 −77%** |
| for cubic 8 | 12.61 | 6.37 −49% | 24.67 +96% | **9.89 −22%** |
| rev bbr 1 | 8.10 | 7.69 = | 10.98 +36% | **1.44 −82%** |
| rev bbr 8 | 26.37 | 25.28 = | 16.83 = | 29.32 = (floor 43%) |
| rev cubic 1 | 4.96 | 4.61 −7% | 18.03 +263% | **1.55 −69%** |
| rev cubic 8 | 7.17 | 7.39 = | 39.78 +456% | 6.40 = |

**CPU s/Gbit, A + B** (whole machine, steal excluded)

| cell | G | J | W | K |
|---|---|---|---|---|
| for bbr 1 | 1.19 | 1.21 +1% | 2.79 +134% | 1.30 +9% |
| for bbr 8 | 1.25 | 1.26 = | 2.50 +99% | 1.22 −2% |
| for cubic 1 | 1.18 | 1.19 = | 2.47 +109% | 1.36 +15% |
| for cubic 8 | 1.25 | 1.26 +1% | 2.48 +98% | 1.19 −5% |
| rev bbr 1 | 0.99 | 0.99 = | 1.91 +94% | 1.37 +39% |
| rev bbr 8 | 1.02 | 1.04 = | 2.12 +107% | 0.95 −7% |
| rev cubic 1 | 1.04 | 1.03 = | 1.86 +79% | 1.04 = |
| rev cubic 8 | 1.05 | 1.04 = | 2.10 +101% | 0.95 −9% |

**Idle and memory** (both nodes; kernel WireGuard has no process; machine context switches/s with no engine at all:
A 447, B 442)

| row | idle wakeups/s, before / after load | RSS MiB A+B, before / 15 s after load | setup, s |
|---|---|---|---|
| G | 0.5 / 0.7 | 34 / 73 | 0.12 |
| J | 0.3 / 0.2 | 35 / 75 | 0.12 |
| W | 8.7 / 8.6 | 147 / 598 | 0.12 |
| K | (no process) | (kernel) | 0.02 |

What this shows:

1. **GotaTun beats wireguard-go on this pairing, in every cell.** wireguard-go moves 30–43% less (GotaTun is 1.4–1.8×
   as fast) at about twice the CPU per Gbit, with higher round-trip latency in 14 of 16 p50/p99 cells. wireguard-go is
   lower in one (reverse BBR 8 p50, −12%), and the other difference is inside the floor. Idle: 0.5 against 8.7 wakeups/s, and 34 against 147 MiB before load (73 against
   598 MiB just after it).
2. **GotaTun has not beaten kernel WireGuard.** Kernel WireGuard has lower round-trip latency in every cell where the
   difference is outside the floor (p99 −19 to −82%), and it moves **18–23% more at 8 flows when the 2-core VM A
   receives** (4.15 against 3.50 Gbit/s), at 7–9% less CPU per Gbit. Forward at 8 flows the two are level (within 1%).
   GotaTun is ahead only in single-flow cells: forward CUBIC (+23%, kernel 2.64), reverse CUBIC (+11%), and reverse
   BBR, where kernel WireGuard reaches only 1.18 Gbit/s in all four runs. That single-flow kernel BBR number was not
   investigated. It is the same in both holds, but it looks like a pacing interaction on this VM, so it should not be
   read as "GotaTun beats kernel WireGuard".
3. **The side-socket sender (J) costs nothing measurable here and cuts the forward round trip by 40–74%** (p50 and
   p99 at CUBIC 1/8 and BBR 8, for example forward CUBIC 8 p99 12.6 → 6.4 ms; forward BBR 1 only −6 to −7%). Reverse is unchanged, because the sender
   that matters there is B, where `fq` does not fill. Throughput and CPU are inside the floor everywhere except +1%
   CPU in two forward cells. Forward CUBIC 1 p99 with J (5.2 ms) is still above kernel WireGuard (2.0 ms). It stays a
   bench switch until the owner decides (docs/design/gotatun-side-socket.md).
4. Every engine connects in the time it takes to poll (0.02 to 0.12 s). Idle GotaTun is quiet: 0.2 to 0.7 wakeups/s for both
   nodes together.

## B. Product row: infraternal against Tailscale and NetBird

I = infraternal mesh (dev `7c719e8a2`, production node binary + coordinator fixture, MTU 1360); T = Tailscale 1.104.4
with headscale 0.29.7 on C (MTU 1280, direct path, no reachable DERP); N = NetBird 0.82.0 in its default kernel
WireGuard mode with `netbird-server` on C (MTU 1280).

**Gbit/s** (Δ against I)

| cell | I | T | N |
|---|---|---|---|
| for bbr 1 | 2.93 | 2.54 −13% | 2.48 −15% |
| for bbr 8 | 3.08 | 2.79 −9% | 2.49 −19% |
| for cubic 1 | 3.08 | 2.81 −9% | 2.10 −32% |
| for cubic 8 | 3.14 | 2.81 −10% | 2.39 −24% |
| rev bbr 1 | 3.25 | **3.75 +15%** | 1.05 −68% |
| rev bbr 8 | 3.29 | **3.91 +19%** | 2.84 −14% |
| rev cubic 1 | 3.19 | **3.92 +23%** | 2.66 −17% |
| rev cubic 8 | 3.18 | **3.97 +25%** | 3.01 −5% |

**Round trip under load, p99 ms**

| cell | I | T | N |
|---|---|---|---|
| for bbr 1 | 4.24 | 5.10 +20% | 4.45 = |
| for bbr 8 | 11.03 | 25.52 +130% | 39.82 +258% |
| for cubic 1 | 8.25 | 12.12 +47% | **1.89 −77%** |
| for cubic 8 | 12.91 | 13.42 = | **7.58 −41%** |
| rev bbr 1 | 9.04 | **5.82 −36%** | **1.86 −79%** |
| rev bbr 8 | 27.58 | 101.21 +280% | 20.56 = |
| rev cubic 1 | 4.93 | 9.43 +92% | **2.05 −58%** |
| rev cubic 8 | 7.59 | 9.87 +30% | **5.19 −32%** |

**CPU s/Gbit, A + B**

| cell | I | T | N |
|---|---|---|---|
| for bbr 1 | 1.26 | 1.69 +35% | 1.58 +26% |
| for bbr 8 | 1.27 | 1.63 +28% | 1.54 +22% |
| for cubic 1 | 1.24 | 1.60 +29% | 1.61 +30% |
| for cubic 8 | 1.26 | 1.63 +29% | 1.63 +29% |
| rev bbr 1 | 1.05 | 1.01 = | 1.67 +59% |
| rev bbr 8 | 1.07 | 1.04 = | 1.18 +10% |
| rev cubic 1 | 1.08 | **0.96 −11%** | 1.21 +12% |
| rev cubic 8 | 1.04 | 1.00 = | 1.16 +11% |

**Idle, memory and setup** (every process the product runs, nodes and control plane; machine context switches/s
with nothing running: A 462, B 538, C 408)

| row | idle wakeups/s, before / after load | RSS MiB, before / 15 s after load | processes after load (RSS, wakeups/s) | second node start → first packet, s |
|---|---|---|---|---|
| I | 1.6 / 1.0 | 52 / 94 | node A 52 MiB 0.4/s, node B 35 MiB 0.4/s, coordinator fixture 7 MiB 0 | 4.7 (not comparable: fixture compile + apply, no sign-in) |
| T | 125 / 128 | 159 / 178 | tailscaled 59 + 58 MiB (44 + 39/s), headscale 56 MiB (48/s) | 17.5 (no reachable DERP; see README) |
| N | 63 / 68 | 206 / 210 | netbird 66 + 63 MiB (30 + 30/s), netbird-server 78 MiB (10/s) | 0.39 |

What this shows:

1. **Forward (A sends), infraternal moves the most**: 9–13% more than Tailscale and 15–32% more than NetBird, while
   Tailscale and NetBird spend 22–35% more CPU per Gbit.
2. **Reverse (the 2-core VM A receives), Tailscale moves 15–25% more than infraternal** (3.75–3.97 against 3.18–3.29
   Gbit/s) at equal or lower CPU per Gbit. This is the same receiver-bound direction where kernel WireGuard beats bare
   GotaTun (A.2). Tailscale's userspace data path receives faster here than ours does, even though bare wireguard-go
   receives 40% slower than GotaTun.
3. **NetBird (kernel WireGuard) has the lowest round trip**, outside the floor, in 5 of 8 cells (p99 −32 to −79%), as the engine row
   predicts. infraternal beats Tailscale on p99 in 6 of 8 cells. Its worst cell is reverse BBR 8 (27.6 ms against
   Tailscale's 101 and NetBird's 20.6).
4. **Idle and memory: infraternal is the lightest product.** 1–2 wakeups/s for both nodes and the coordinator, against
   ~125/s (Tailscale + headscale) and ~65/s (NetBird + server). 52 MiB before load, against 159 and 206 MiB.
5. Setup time is measured but not comparable across the three; the README says why.

## Short answers

- **Have we beaten wireguard-go?** Yes on this pairing: 1.4–1.8× the throughput at half the CPU per Gbit, with lower
  loaded latency and a fraction of the memory. One pairing, one LAN hop.
- **Have we beaten kernel WireGuard?** No. Kernel WireGuard has lower loaded latency in every resolvable cell, and it is
  18–23% faster when the small VM receives 8 flows. GotaTun leads only in single-flow cells, and in BBR where kernel
  WireGuard behaves oddly. Forward at 8 flows the two are level.
- **infraternal against Tailscale and NetBird (as products):** infraternal is ahead on forward throughput, CPU per
  Gbit, idle wakeups and memory. Tailscale is ahead on receive-bound throughput (+15–25%). NetBird, on kernel
  WireGuard, is ahead on round-trip latency.
