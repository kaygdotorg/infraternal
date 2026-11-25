<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Role: user guide for mesh DNS (machine names, suffixes, privacy/answer codes, Linux split DNS and /etc/hosts fallback, macOS /etc/resolver). Published at /docs/mesh/names/. -->
# Mesh DNS

Every machine on the mesh gets a DNS name so you can reach it by name from any program without remembering IP addresses.

> [!NOTE] What works today
> **Works:** resolving reachable machines under `<host>.<suffix>` and `<host>.internal`, split DNS on Linux (`systemd-resolved`, `NetworkManager` dnsmasq, or `/etc/hosts` fallback) and macOS (`/etc/resolver`), and privacy-preserving answers.
> **Planned:** changing the custom suffix from Settings › Mesh › Names.

## Machine names and suffixes

Every mesh node runs a local DNS resolver that answers for the machines it is allowed to reach, as well as its own name.

- **Default suffix:** `internal`, so a machine named `web` resolves as `web.internal`.
- **Custom suffix:** when your mesh uses a custom suffix, every machine resolves under `<host>.<suffix>` **and** continues to resolve under `<host>.internal`, so existing scripts and bookmarks keep working.
- **IPv4 and IPv6:** positive answers carry a 30-second cache lifetime (TTL) and negative answers carry a 5-second TTL so newly added machines become reachable quickly. A machine running IPv4-only returns an `A` record and an empty `AAAA` answer so clients do not stall waiting on an unreachable IPv6 address.

### Search domain

Mesh suffixes are installed as **routing-only domains** by default, so bare single-word names on your host are not altered.

If you want bare host names (such as `ssh web`) to complete with the mesh suffix, set `INFRATERNAL_MESH_DNS_SEARCH=1` (also accepts `true`, `yes` or `on`) in the infraternal agent's environment before starting it.

## Privacy and answer codes

Each machine's resolver holds only the names of peers that Access allows it to reach.

| Query | Answer | Why |
|---|---|---|
| A reachable machine in a mesh zone | `A` / `AAAA` record | Normal resolution for peers you may reach. |
| A missing name, or a machine this node may not reach | `NXDOMAIN` | Hidden names look identical to nonexistent names; nothing reveals that a restricted machine exists. |
| A query from another peer to this node's resolver | `NXDOMAIN` | A peer cannot learn names from another node's view. |
| Any name outside the mesh zones (or non-`IN` class) | `REFUSED` | Non-authoritative refusal tells your system resolver to move on at once instead of timing out. |
| Unsupported opcode or malformed question count | `NOTIMP` / `FORMERR` | Every well-formed query receives an immediate answer rather than silence. |

Unparseable bytes, packets larger than 4096 bytes and DNS response packets (which must never be answered to prevent reply loops) are dropped and counted in a rate-limited log line that never records the queried name.

## How mesh DNS connects to your system

Only the mesh suffixes are sent to the mesh resolver. Infraternal never replaces your host's default DNS servers, never overwrites `/etc/resolv.conf`, and never disturbs other VPNs' DNS. Stopping the mesh (`infraternal mesh down`) undoes every change.

Run `infraternal mesh status` and look at the **Host DNS** row to see which mode is active.

### Linux

Each Linux mesh node listens on its own mesh IPv4 address, UDP and TCP port **1053**. When the infraternal agent runs as root, it picks the first mechanism available:

1. **`systemd-resolved`** (status mode `resolved`): configures per-link DNS (`<mesh address>:1053`), routing-only domains (`~<suffix>`), and `default-route no` strictly on the mesh interface index that the infraternal agent created. It never writes to any other network link on the host, and reverts only that exact link index on stop. If `systemd-resolved` is running but the owned mesh link cannot be verified, the infraternal agent reports an error rather than falling back to another mechanism.
2. **`NetworkManager` with `dns=dnsmasq`** (status mode `networkmanager`): writes one marked drop-in file at `/etc/NetworkManager/dnsmasq.d/infraternal-mesh.conf` forwarding the mesh suffixes to the node's mesh address on port `1053`, and asks `NetworkManager` to reload DNS only.
3. **`/etc/hosts` fallback** (status mode `hosts`): when neither of the above is available (for example when another tool manages `/etc/resolv.conf`), the infraternal agent maintains a marked block in `/etc/hosts` listing every reachable mesh name under each suffix. It updates the block on every policy snapshot and removes it on stop or after a crash.

> [!NOTE] Limits of the `/etc/hosts` fallback
> The `/etc/hosts` block answers exact host names only (no wildcards and no search-domain completion). For safety, the infraternal agent refuses to edit `/etc/hosts` if it is a symlink, writable by non-root users, bind-mounted (as in some containers), or contains damaged marker lines.

If the infraternal agent is not running as root, it still serves mesh names on its mesh address port 1053, leaves host DNS untouched, and reports `unprivileged`.

### macOS

macOS reads per-domain resolver files from `/etc/resolver/<suffix>`. Infraternal writes one marked file per mesh suffix and removes its marked files when the mesh stops or is uninstalled. Existing files without the infraternal marker are never modified.

- **User mode (default):** the on-demand root helper writes `/etc/resolver/<suffix>` pointing at the deployment's in-mesh IPv6 resolver address (port 53), which sits inside the tunnel rather than on a local port. The infraternal agent answers those queries directly from the tunnel. For safety, the helper writes files only for reserved private-use suffixes.
- **Root mode:** the infraternal agent writes `/etc/resolver/<suffix>` pointing at `<mesh address>` port `1053` and refreshes `mDNSResponder`.

---

Behind this page: D327, #266, #578, #580 and #584 (J1142, J1155, J1183 and J1208).
