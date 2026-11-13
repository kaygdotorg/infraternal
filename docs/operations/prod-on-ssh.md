# Host input policy on ssh.kayg.org

The infraternal server owns `inet infraternal_host` on Linux system installs.
The server saves its typed listener, trusted-proxy, remote-listener and admin
settings under `/var/lib/infraternal`; the product-owned
`infraternal-firewall.service` applies them in one nft transaction before
`network-pre.target`. Mesh activation adds `infraternal0` and the UDP port the
mesh node actually bound (10254 by default) to that same table, and stopping
the mesh removes both. The mesh grant filter still decides which mesh flows pass.

## Current hand-installed policy

The hand-installed `infraternal-firewall.service` currently loads
`/etc/nftables/infraternal-host.nft`. A read-only production capture at
2026-11-11 15:48 UTC shows these rules on ssh.kayg.org:

```nft
table inet infraternal_host {
    chain input {
        type filter hook input priority filter - 10; policy drop;
        iifname "wt0" counter packets 484546 bytes 2161989060 accept
        iifname "lo" accept
        ct state invalid drop
        ct state established,related accept
        ip protocol icmp accept
        meta l4proto ipv6-icmp accept
        iifname "eth0" udp dport 51820 accept
        iifname "wt0" ip saddr 10.69.69.0/24 tcp dport 22 accept
        iifname "wt0" ip saddr 10.69.69.99 tcp dport 7011 accept
        iifname "eth0" ip saddr 10.69.0.99 tcp dport 7011 accept
        iifname "eth0" ip saddr 10.69.0.99 tcp dport 7012 accept
        iifname "wt0" ip saddr 10.69.69.0/24 tcp dport 7443 accept
        iifname "wt0" ip saddr 10.69.69.0/24 udp dport 7443 accept
    }
}
```

The `wt0` rule is broader than the file and accepts every input packet on that
interface. Keep it with `--host-firewall-accept-interface wt0` until an
operator chooses to narrow it. The packet and byte values are a point-in-time
counter from the read-only capture; nft increments them as traffic arrives and
the product does not persist counter values.

The hand-loaded file omits this broad `wt0` allowance even though it is present
in the active table. The product takes over the live table and reports the
difference between those loaded rules and its desired configuration.

## Product configuration for the next deploy

Pass the host rules to `infraternal server init --system --force`. `--force`
lets the product replace the existing server unit with the current settings.
Include the server's actual data directory, web root, public origin, remote CA
directory and any TLS settings used on the host. These host-policy arguments
reproduce the current allowances:

```sh
infraternal server init --system --force \
  --data /var/lib/infraternal \
  --listen 10.69.0.89:7011 \
  --web-root /opt/infraternal/73b1d61a6/web \
  --public-origin https://ssh.kayg.org \
  --remote-listen 10.69.69.89:7443 \
  --remote-ca-dir /var/lib/infraternal/remote-ca \
  --behind-proxy \
  --trusted-proxy 10.69.0.99 \
  --host-firewall-listen-interface eth0 \
  --host-firewall-remote-interface wt0 \
  --host-firewall-remote-source 10.69.69.0/24 \
  --host-firewall-accept-interface wt0 \
  --host-firewall-allow 'eth0,*,udp,51820' \
  --host-firewall-allow 'wt0,10.69.69.0/24,tcp,22' \
  --host-firewall-allow 'wt0,10.69.69.99,tcp,7011' \
  --host-firewall-allow 'eth0,10.69.0.99,tcp,7011' \
  --host-firewall-allow 'eth0,10.69.0.99,tcp,7012' \
  --host-firewall-allow 'wt0,10.69.69.0/24,tcp,7443' \
  --host-firewall-allow 'wt0,10.69.69.0/24,udp,7443'
```

The main listener's TCP rule comes from `--listen` and is restricted to
`--trusted-proxy` while `--behind-proxy` is enabled. The remote listener's TCP
and UDP rules come from `--remote-listen`, its interface and its allowed source
networks. The extra rules cover NetBird UDP ingress, SSH, fridge ingress and
the proxy health listener. They retain each existing source/interface/port
allowance while listener-derived rules also match the configured destination.
A system install needs an explicit TCP/22 admin rule; when installed over SSH,
the active connection is checked before the host table is replaced.

## Expected product ruleset

After the product takes over, it replaces the dynamic `wt0` counter with the
equivalent configured interface allowance, derives the listener rules from
server flags and retains the configured extra rules. Listener rules also match
the configured destination addresses. The table remains default-drop. Mesh
adds the two lines at the end when enabled:

```nft
table inet infraternal_host {
    chain input {
        type filter hook input priority filter - 10; policy drop;
        iifname "wt0" accept
        iifname "lo" accept
        ct state invalid drop
        ct state established,related accept
        ip protocol icmp accept
        meta l4proto ipv6-icmp accept
        iifname "eth0" udp dport 51820 accept
        iifname "wt0" ip saddr 10.69.69.0/24 tcp dport 22 accept
        iifname "wt0" ip saddr 10.69.69.99 tcp dport 7011 accept
        iifname "eth0" ip saddr 10.69.0.99 tcp dport 7011 accept
        iifname "eth0" ip saddr 10.69.0.99 tcp dport 7012 accept
        iifname "wt0" ip saddr 10.69.69.0/24 tcp dport 7443 accept
        iifname "wt0" ip saddr 10.69.69.0/24 udp dport 7443 accept
        iifname "eth0" ip saddr 10.69.0.99 ip daddr 10.69.0.89 tcp dport 7011 accept
        iifname "wt0" ip saddr 10.69.69.0/24 ip daddr 10.69.69.89 tcp dport 7443 accept
        iifname "wt0" ip saddr 10.69.69.0/24 ip daddr 10.69.69.89 udp dport 7443 accept
        iifname "infraternal0" accept
        udp dport 10254 accept
    }
}
```

The generated migration report lists every removed and added rule line. The
boot unit writes that report to the system journal. One nft batch deletes and
recreates only `inet infraternal_host`; tables outside the `infraternal_*`
namespace are not included in the transaction.

## Clearing the server host policy

For a system install, `infraternal server init --host-firewall-off` clears the
server role's marked host-policy file through the product. Pass the same
server listener, data, web root, origin, TLS, remote-listener and proxy flags
as the current service because `server init` also rewrites that service unit.
The dry run shows the plan before it is applied.

If an agent role still has a marked policy, infraternal applies that policy and
keeps the shared table and loader. If no role remains, it atomically deletes
`inet infraternal_host`, reports the removed rule lines, unlinks only the
product-marked network-pre loader and policy files, then reloads systemd. This
opens input instead of retaining a default-drop table. A cleared configuration
that reaches the boot apply path performs the same cleanup, so the loader does
not recreate an empty policy on the next boot. The product marker in role JSON
and its systemd unit gates file removal; unmarked files, foreign units and nft
tables outside `infraternal_*` stay untouched.

The staging restore to an absent-table baseline uses this product path with
the staging server's current service flags. It does not edit nftables,
systemd, or policy files by hand.

## Retiring the hand-installed unit

The next product system install replaces
`/etc/systemd/system/infraternal-firewall.service` with the product-owned
oneshot unit, reloads systemd, enables it for `network-pre.target`, and
restarts it to apply the saved policy immediately. The existing
`/etc/nftables/infraternal-host.nft` file is no longer loaded by that service
and can be removed later as routine cleanup. Do not edit or apply nft rules
over SSH to complete this migration; the product install performs the takeover
and reports the rule differences.

`infraternal up` installs the same early boot unit on hosts that run only an
infraternal agent. It
stores a root-owned agent policy, keeps the active SSH source (or accepts
additional `--host-firewall-allow` entries), and takes over this hand loader
with rollback support. Both server and agent installs leave unrelated nftables
tables alone. Their migration report is written to the system journal by
`infraternal-firewall.service`.
