# Relay manager slice 1: what the relay changes (J1254, D401, #580)

Branch `j1254-relay-manager-1`. Raw receipts (JSON reports, logs) are outside the
checkout under `~/.cache/codex-scratch/j1254/evidence/` on hd01.

## 1. J536b's matrix with the relay on

`scripts/mesh_nat_censorship_proof.py --model relay` on dev-02 (aarch64, Ubuntu
24.04, kernel 6.8, rootless namespaces, 34 ms round trip on the public core). A
third real infraternal agent on the public core serves the relay role through
`mesh.relays`, exactly as the server's node does; both measured nodes get the
relay list and a host leaf. Final code, binary sha256 `eb52f3caa606f2ad…`
(report `m13.json`; one 8 s TCP flow, while a `verify fast` ran on the same VM,
so the Mbit/s are indicative only):

| Profile | Before (J536b) | With the relay | First packet | Relay connection | TCP Mbit/s |
|---|---|---|---|---|---|
| symmetric one side vs port-restricted | no path | relayed | 5,655 ms | yes | 88.8 |
| symmetric both | no path | relayed | 5,673 ms | yes | 73.6 |
| DPI dropping WireGuard handshakes | no path | relayed (QUIC carries the handshakes) | 5,674 ms | yes | 63.7 |
| UDP blocked | no path | relay chosen; no packet (the QUIC relay is UDP) | — | attempted | — |
| TCP 80/443 only | no path | relay chosen; no packet | — | attempted | — |
| the 13 other profiles | direct | direct | 52–169 ms | none | 1.4–5,863 |

Every relayed pair records "no direct handshake within 5 seconds". Three of the
five profiles that had no path now connect; none of the 13 that go direct opens a
relay connection (their nodes hold no QUIC connection and pay no keep-alive).
UDP-blocked and TCP-only networks need the TLS 443 transport (D401 Q1: next
slice). Every relayed pair waits the 5.5 s backstop plus one QUIC handshake; the
hard-NAT prediction (D401 Q6) is slice 1b.

Two bugs this matrix found on the way, both fixed on the branch: the deadline
compared the handshake with a time taken after the snapshot applied, so a direct
pair that finished its handshake during the apply was briefly relayed
(cgnat-both's relay paths carried 17,224 packets before the probes moved it
back); and the relay's receive queue (§2).

## 2. Finding: relayed TCP was capped at about 2 Mbit/s

In the first run every relayed row carried 1.5–2.4 Mbit/s, against 270–570
Mbit/s for the direct rows on the same topology (34 ms round trip). The relay
forwarded every DATAGRAM it read (dropped 0), the shim reported no oversized
packet, the relayed route MTU was 1392 as designed, and BBR→Cubic,
`GOTATUN_AQM=off` and `GOTATUN_DIAG_UDP_SINGLE_SENDS=1` changed nothing. The
cause was the relay's 8 KiB per-connection DATAGRAM receive queue: a TCP sender
inside the tunnel sends its window in bursts, and quinn drops the oldest DATAGRAM
when that queue is full, before the relay's reader or counters see it. TCP never
grew past about 8.5 KB in flight (1.7 Mbit/s × 34 ms). The existing relay proof
(`scripts/mesh-relay-proof.py`) has a 0.2 ms round trip, where 8.5 KB still makes
208 Mbit/s, so it never showed.

symmetric-both, one flow, 8 s, dev-02:

| Relay receive queue | Mbit/s |
|---|---|
| 8 KiB (before) | 1.5, 1.6, 1.7, 1.9, 2.0, 2.4 |
| 64 KiB (kept) | 67.3, 76.6 |
| 256 KiB | 46.7 |

The worst-case sum of receive queues at 4,096 hosts rises from 32 to 256 MiB,
reached only if every connection bursts at once; the forwarding budgets are
unchanged. Relayed is still far below direct at this round trip (§4).

## 3. Relayed against direct

`perf.md` beside this file: latency through the relay is the path's own (0 ms
added on this topology); relayed goodput is 70 Mbit/s with one flow and 193 with
eight, against 0.23–0.41 and 1.9–3.7 Gbit/s direct, at about five times the CPU
per Gbit; a node holding a relayed pair wakes about 12 times a second while
idle; a restarted relay has the pair back about 4 s after it serves again.
Measured on dev-02 (the perf VM's lock was held by another job all evening).

## 4. Open for slice 1b

- Relayed goodput at WAN round trips (§3, `perf.md`). Next suspects, in order:
  the 256 KiB per-pair forwarding budget, the two quinn congestion windows in
  series, the node's 256 KiB DATAGRAM send queue, and one shim hop and one QUIC
  DATAGRAM per packet (no batching).
- Idle wakeups of a node with a relayed pair (about 12 per second): the 1 s QUIC
  keep-alive and the relay paths' 1 s route-MTU poll.
- The hard-NAT prediction (Q6) and its accuracy on these 18 profiles.
- Fast failover (Q7) and the home relay with a slow keep-alive (Q5, Q9).
- `relay_path` on macOS (Q10) and the loopback-shim cost against an in-process
  hand-off.
