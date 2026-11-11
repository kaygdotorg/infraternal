<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Role: explain the mesh UDP listener, direct paths through stateful firewalls, and host input for traffic inside the tunnel. -->
# Mesh networking

## UDP listener

Each mesh node listens on UDP **10254** by default. The port matches the default mesh subnet, `10.254.0.0/16`, and stays the same across ordinary restarts.

If UDP 10254 is already in use, the infraternal agent chooses another free UDP port. `mesh status` shows the port that is actually bound, and the node saves that choice for its next start. If that saved port is no longer free, it selects and reports another one.

To choose a port yourself, set `INFRATERNAL_MESH_PORT` in the infraternal agent's environment before it starts. The value must be a port from 1 to 65535, except 51820, which is reserved for another WireGuard service. An explicitly configured port is used as given; if it is occupied, startup reports the bind error instead of selecting a different port. Leave the setting unset to use UDP 10254 and its automatic fallback.

TCP 10254 is separate from UDP 10254. For example, ingress-nginx can use TCP 10254 for health checks while the mesh uses UDP 10254.

## Direct connections through stateful firewalls

The coordinator distributes each node's observed UDP endpoint in its ordinary configuration snapshot; it does not send a synchronized start command. GotaTun configures active peers with a 25-second persistent keepalive, and installing an endpoint starts that peer's outgoing handshake. The snapshots may arrive at different times. If A learns B's endpoint first, A's packet can arrive at B as a new inbound flow and be dropped by B's input policy. A's own firewall has already tracked A's outgoing flow. When B learns A's endpoint and initiates, that packet matches the reverse direction of A's flow and passes A's `established,related` rule. B's outgoing flow then lets A's handshake response pass B's rule as established. The namespace test delivers the endpoints separately and verifies both handshakes without an inbound UDP allow rule.

This direct path depends on both nodes being able to send UDP and on their firewalls admitting replies to those outgoing packets. Some NATs, including symmetric NATs that choose a different public mapping for each destination, cannot use the observed peer endpoint for a direct connection. UDP-blocking networks can also prevent it. In those cases the mesh needs its existing server or relay path; if neither can carry the traffic, the peers cannot connect.

## New connections arriving through the tunnel

Hole punching only opens the encrypted UDP path between mesh nodes. After the mesh decrypts a packet, it arrives on the receiving host's `infraternal0` interface. A new SSH or TCP connection from a peer is a new inbound connection on that interface, so a host input chain with `policy drop` still drops it.

The host input chain needs this rule for new connections arriving through the mesh:

```nft
iifname "infraternal0" accept
```

The mesh's own table and its D384 userspace filter continue to enforce each peer's grants. Accepting traffic from `infraternal0` in the host input chain does not grant a peer new mesh access. Tables named `infraternal_*` belong to Infraternal and are managed by the product; do not add this rule by hand to an app-owned table.
