# Mesh names in the host resolver (#580, J1155)

Every mesh node answers DNS for the mesh suffix (default `internal`, configurable)
on its mesh address, UDP and TCP port 1053. When the mesh starts as root, the
agent also points the host's own resolver at it, so `ssh web.internal` works in
any program. Stopping the mesh (or `mesh down`) undoes every change. Only the
mesh suffix is routed; the host's default DNS, `resolv.conf` and other VPNs'
DNS are never replaced. `infraternal mesh status` shows a `Host DNS` row.

## What the agent chooses on Linux

| Order | Host has | What is installed | Status mode |
|---|---|---|---|
| 1 | systemd-resolved (`resolvectl status` works) | per-link DNS `<mesh address>:1053` and routing domain `~<suffix>` on the mesh interface; `default-route no`; undone with `resolvectl revert` | `resolved` |
| 2 | NetworkManager with `dns=dnsmasq` and `nmcli` | the marked drop-in `/etc/NetworkManager/dnsmasq.d/infraternal-mesh.conf` (`server=/<suffix>/<address>#1053`), then a DNS-only reload | `networkmanager` |
| 3 | neither (for example NetBird owns `/etc/resolv.conf`) | a marked block in `/etc/hosts` listing every mesh name under every suffix; rewritten on each snapshot and removed on stop or after a crash | `hosts` |

Option 3 answers exact names only (no wildcards, no `search` completion, no
DNS-over-mesh for other tools), but it is the one change that cannot disturb
another tool's resolver files. It refuses when `/etc/hosts` is a symlink, is
writable by others, has damaged marker lines, or is bind-mounted (containers);
the error then says to install systemd-resolved, set NetworkManager's
`dns=dnsmasq`, or make `/etc/hosts` a regular root-owned file.

Rejected: rewriting `/etc/resolv.conf` (another tool owns it and would fight
us), running a stub on `127.0.0.53` (collides with resolved), `resolvconf`
hooks (no per-domain routing).

A process that is not root serves names to peers but leaves the host alone
(`unprivileged` in the status).

## macOS

Root mode writes `/etc/resolver/<suffix>` (`nameserver <mesh address>`,
`port 1053`) and refreshes `mDNSResponder`; stop removes the marked files. In
user mode (J998) the one-shot root helper writes the same file with
`nameserver 127.0.0.1` and the agent answers on loopback `:1053`
(`render_macos_resolver` already renders both; the loopback listener arrives
with J998).

## Search domain

Off by default: a search domain changes how every bare name resolves. Set
`INFRATERNAL_MESH_DNS_SEARCH=1` for the agent to also add the suffix as a
search domain (resolved: plain `<suffix>` next to `~<suffix>`; macOS: a
`search` line).
