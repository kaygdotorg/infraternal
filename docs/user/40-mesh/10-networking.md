<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Role: explain the mesh UDP listener, direct paths through stateful firewalls, and host input for traffic inside the tunnel. -->
# Mesh networking

This page explains which UDP port the mesh uses, how peers make direct connections, and which host rule admits traffic inside the tunnel.

## UDP listener

Each mesh node listens on UDP **10254** by default. The port matches the default mesh subnet, `10.254.0.0/16`, and stays the same across ordinary restarts.

If UDP 10254 is already in use, the infraternal agent chooses another free UDP port. `mesh status` shows the port that is actually bound, and the node saves that choice for its next start. If that saved port is no longer free, it selects and reports another one.

To choose a port yourself, set `INFRATERNAL_MESH_PORT` in the infraternal agent's environment before it starts. The value must be a port from 1 to 65535, except 51820, which is reserved for another WireGuard service. An explicitly configured port is used as given; if it is occupied, startup reports the bind error instead of selecting a different port. Leave the setting unset to use UDP 10254 and its automatic fallback.

TCP 10254 is separate from UDP 10254. For example, ingress-nginx can use TCP 10254 for health checks while the mesh uses UDP 10254.

## Direct connections through stateful firewalls

The coordinator distributes each node's observed UDP endpoint in its ordinary configuration snapshot; it does not send a synchronized start command. GotaTun configures active peers with a 25-second persistent keepalive, and installing an endpoint starts that peer's outgoing handshake. The snapshots may arrive at different times. If A learns B's endpoint first, A's packet can arrive at B as a new inbound flow and be dropped by B's input policy. A's own firewall has already tracked A's outgoing flow. When B learns A's endpoint and initiates, that packet matches the reverse direction of A's flow and passes A's `established,related` rule. B's outgoing flow then lets A's handshake response pass B's rule as established. The namespace test delivers the endpoints separately and verifies both handshakes without an inbound UDP allow rule.

## Which addresses a node tries

A router often changes the UDP port on the way out, so the port a node listens on is not the port its peers must aim at. The server sees the real public address and port of each node's mesh packets, because the server is a mesh peer too, and hands that address to the node's peers. Two nodes behind the same router also get each other's address on the local network, because many routers cannot send a packet from one of their own machines back to another through the public address. A node tries these in order: the local network address (only for a peer behind the same public address), then the address the server saw, then the server's older guess of public address plus listen port. When a router hands out a new port, for example behind a carrier-grade NAT or a double NAT, peers switch to the new address within about half a minute: the node's next keepalive to the server (one every 25 seconds) shows the server the new port, the server checks for changes every 5 seconds, and it then hands the new address to the node's peers.

Private addresses (a local network, a carrier-grade NAT or VPN range such as 100.64.0.0/10, link-local, or IPv6 unique local addresses) only go to peers that Access lets reach the node or be reached by it. A peer without that access never gets a node's private address, wherever it sits. With access:

- A node's local network address goes only to peers behind the same public address.
- If a node reaches the server over a private address, for example because the server is on the same local network or across a VPN, that private address is the server's guess for it, and peers with access get it wherever they are. In a home lab where the server and every node share one network it is the address that works.

Nodes behind one carrier-grade NAT share its public address, and IPv6 nodes in one /64 (some hosting providers give several servers one /64) share a network prefix. Each group counts as one site, so its members with access to each other also get each other's local network addresses.

This direct path depends on both nodes being able to send UDP and on their firewalls admitting replies to those outgoing packets. Symmetric NATs, which choose a different public mapping for each destination, give the server a port that no peer can use, so a direct connection needs the other side to accept new senders. UDP-blocking networks can also prevent it. Production mesh nodes do not start a relay transport, so peers in those networks cannot connect through the mesh.

## New connections arriving through the tunnel

Hole punching only opens the encrypted UDP path between mesh nodes. After the mesh decrypts a packet, it arrives on the receiving host's `infraternal0` interface. A new SSH or TCP connection from a peer is a new inbound connection on that interface, so a host input chain with `policy drop` still drops it.

The host input chain needs this rule for new connections arriving through the mesh:

```nft
iifname "infraternal0" accept
```

The mesh's own nftables table and userspace filter continue to enforce each peer's grants. Accepting traffic from `infraternal0` in the host input chain does not grant a peer new mesh access. Tables named `infraternal_*` belong to Infraternal and are managed by the product; do not add this rule by hand to an app-owned table.

---

Behind this page: D386, D391, #483, #489 and #515 (mesh-owned host firewall behavior, the UDP listener and direct-path candidates).
