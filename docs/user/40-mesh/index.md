<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Role: the overview of the "Mesh" section, published at /docs/mesh/ (D317). One screen: what the section is, where its pages are, and a Planned callout for what is not built. The build adds the list of the section's pages under this text. -->
# Mesh

The mesh is a private network that joins your machines.

## What is here

Every machine joins the mesh, and the traffic between two machines is encrypted with WireGuard. The keys involved renew by themselves while a machine is online. See [Between machines](/docs/reference/keys/#between-machines) for each key and how long it lasts.

- [Mesh networking](/docs/mesh/networking/) explains the UDP port, direct connections through firewalls, and host input rules.
- [Mesh DNS](/docs/mesh/names/) explains machine names, split DNS on Linux and macOS, and how hidden names are answered.
- [Subnet routes](/docs/mesh/networks/) explains sharing private IPv4 networks behind a Linux machine, approving them in the app, and how clients route them.

> [!WARNING] Planned
> Pages for connections and the mesh's keys settings are planned. Each appears when its feature ships.

## Keeping transfers responsive

On Linux, the mesh engine bounds its receive queue. When packets keep waiting
longer than 1 ms for at least 10 ms, it marks ECN-capable packets to ask their
senders to slow down. It drops a selected packet only when it cannot mark it.
This controls the engine's local queue; it does not propagate outer tunnel ECN
bits into inner packets.

Small packets share an allowance per peer. Authenticated plaintext frames up
to 256 bytes can pass without a congestion signal, at 32 KiB per 10 ms with a
64 KiB burst. Both the size ceiling and allowance count padding, so a large
frame cannot claim exemption by declaring a small inner packet. This covers
measured interactive SSH, TCP ACKs and latency probes alongside bulk transfers.
Sending more small packets exhausts the allowance. Changing addresses or ports
does not change eligibility. Small traffic within the allowance passes even
when its flow keys change; larger frames always face the queue controller.
Credit recovers fully after 20 ms without small traffic. A drained peer queue
starts a new observation interval. If a stall leaves the engine without a fresh
queue observation for more than one interval, old signalling deadlines expire.
The engine measures receive age against the wall clock and uses elapsed time
for signal deadlines and credit refill. Packets with timestamps in the future or
more than one second old pass unchanged. The next valid sample starts a new
observation interval.

For diagnosis, set `GOTATUN_AQM=off` in the infraternal agent's environment before
starting it. This disables receive timestamp collection, packet judgement and
AQM telemetry. `GOTATUN_AQM=drop` uses drops for every selected packet; the default
is `ecn`. `GOTATUN_AQM_TARGET_US` and `GOTATUN_AQM_INTERVAL_US` change the queue
controller's timing, independently of the fixed small-packet allowance.
Invalid timing values fall back to the defaults.
`GOTATUN_AQM_STATS_PATH` optionally writes counters to the given path with the
process ID appended. macOS keeps this bound disabled because its receive path
does not provide the kernel timestamps needed to measure the queue.
