<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Role: user guide for subnet routes (advertised networks, approval, Mesh view, Networks window, Linux router, Mac client, safety skips). Published at /docs/mesh/networks/. -->
# Subnet routes

A Linux machine on your mesh can share private IPv4 networks it reaches, such as a home or office LAN, with other machines on the mesh.

> [!NOTE] What works today
> **Works:** advertising IPv4 networks from Linux, approving, declining and revoking them in the app or from the server command line, masquerading or keeping source addresses, and reaching them from Linux and macOS clients.
> **Planned:** IPv6 subnet routes and exit nodes (`0.0.0.0/0`).

## How subnet routes work

A machine that sits on a local network can **advertise** that network to your server. Advertising alone changes nothing: no traffic is routed until the server owner **approves** the network and grants access to it with arrows in the Mesh view.

Only Linux machines can route (advertise and forward) subnet routes. Both Linux and macOS machines can use approved subnet routes as clients.

An approved network is always the **target** of an arrow, never the source. Machines on that network are not mesh members and cannot be identified by the mesh, so they cannot initiate connections back into the mesh.

## Advertising a network from Linux

On the Linux machine that can reach the network, run as root:

```sh
sudo infraternal mesh routes advertise 192.168.10.0/24
```

You can pass more than one network, or run the command again later to add more. The advertised list is saved across restarts.

To check what this machine advertises, serves and reaches through other machines:

```sh
infraternal mesh routes
```

To stop offering one or more networks (or omit the network arguments to withdraw every advertised network):

```sh
sudo infraternal mesh routes withdraw 192.168.10.0/24
```

Withdrawing stops routing immediately while keeping the server's approval on record. If the machine advertises the network again later, routing resumes without a new approval.

### What networks are accepted

Networks must be written in canonical IPv4 CIDR form, with no host bits set (`192.168.10.0/24` is accepted; `192.168.10.5/24` is refused with a hint). One machine can advertise up to 64 non-overlapping networks.

The server refuses to approve:

- **Default routes** (`0.0.0.0/0`), which are exit nodes rather than subnet routes.
- **IPv6 networks**, which are not routed yet.
- **Special ranges:** `0.0.0.0/8`, loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), multicast (`224.0.0.0/4`) and reserved space (`240.0.0.0/4`).
- **The mesh's own range** (default `10.254.0.0/16`) or anything that overlaps it.
- **Overlapping approvals:** a network that overlaps one already approved on the mesh. Revoke the existing route first or advertise a non-overlapping range.

## Approving, declining and revoking

### In the app

Advertised networks appear in two places once a machine offers one:

- **Mesh view:** waiting and approved networks appear as cards beside your machines. Approved networks can receive arrows from machines or tags to grant access. Declined networks do not appear on the canvas.
- **Settings › Mesh › Networks:** sits between Access and Connections, and appears once the server lists at least one network. It shows waiting, approved and declined networks in that order.

For each network you can:

- **Approve:** begins routing the network through the advertising machine. Draw an arrow to the network in the Mesh view to let a machine or tag reach it.
- **Decline:** turns down a waiting advertisement. The server remembers the decline so the machine does not keep asking. The network leaves the Mesh view but stays in Settings › Mesh › Networks so you can still approve it later if you change your mind.
- **Keep Each Machine's Address:** a switch on each approved network, **off** by default.
  - **Off (masquerade, default):** the router rewrites forwarded packets to its own address on the target network. Devices on that network see the router's address and need no extra routing configuration.
  - **On (keep source):** devices on the target network see each mesh machine's real mesh address. That network's own router must have a route back to the mesh range through the advertising machine.
- **Revoke:** stops routing the network. The app asks first, naming the network and how many arrows end on it. Confirming deletes every arrow ending on that network and returns it to waiting for approval. Approving the network again later does not bring deleted arrows back.

### From the server command line

On the server machine, run as root or as the account the server runs as:

```sh
sudo infraternal server mesh routes
sudo infraternal server mesh routes approve router-01 192.168.10.0/24
sudo infraternal server mesh routes approve router-01 192.168.10.0/24 --keep-source
sudo infraternal server mesh routes revoke <route-id>
```

## What happens on the router

When a Linux machine serves an approved network:

- **IPv4 forwarding:** if `net.ipv4.ip_forward` is off, the infraternal agent turns it on and records that it did so. When the machine stops serving networks or the mesh goes down, the infraternal agent turns forwarding back off. If forwarding was already on (for example for containers or another router), the infraternal agent leaves it untouched.
- **Firewall rules:** the infraternal agent installs nftables forward and masquerade rules for the served networks. If those rules or IPv4 forwarding cannot be put in place, the packet filter refuses forwarded packets rather than half-configuring the router, and `infraternal mesh routes` reports the reason.

> [!IMPORTANT] A network grant never reaches the router itself
> A router usually has its own LAN address inside the network it serves. The router's mesh firewall drops traffic arriving from `infraternal0` addressed to any served network before local delivery. A grant to a subnet route reaches only the hosts behind the router, never services running on the router's own LAN address. To reach services on the router itself, grant access to the router node and connect to its mesh address.

## What happens on client machines

When a Linux or macOS machine has a grant to an approved network, the infraternal agent installs a route for that network through the mesh interface.

### Networks a client leaves out on purpose

A client never installs a route that would break its own connectivity. Instead it skips the network, keeps the rest of the mesh working, and explains why in `infraternal mesh routes`:

- **Already routed locally:** the network overlaps a route or interface network the machine already has, such as its own LAN or another VPN. Taking it over would cut the machine off from that network.
- **Holds a mesh peer's underlay address:** the network contains an address this machine uses to reach a mesh peer (its configured endpoint, a candidate address, or a learned live endpoint). Routing that network into the tunnel would loop the tunnel's own encrypted packets back into the tunnel.
- **Overlaps the mesh's own range:** the network overlaps the machine's mesh address or prefix.

### macOS client limits

A Mac acts only as a client of subnet routes and never advertises or forwards them.

- **User mode (default):** the on-demand mesh helper routes only private IPv4 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` and `100.64.0.0/10`), up to 64 networks. Public IPv4 ranges are skipped with a message explaining that user mode routes private networks only.
- **Root mode:** routes any IPv4 network the server approves, subject to the local-overlap and underlay-address checks above.

---

Behind this page: D162, D164, D197 M3, D295, D384, D400, #580 (J1156, J1169, J1179, J1195 and J1203).
