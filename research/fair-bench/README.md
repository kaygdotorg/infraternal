<!-- J1199 (#260, #580): how the fair engine and product comparisons were run, and how to rerun them. -->
# Fair comparisons: GotaTun against wireguard-go and kernel WireGuard, infraternal against Tailscale and NetBird

**Jobs:** J1199; setup times re-measured by J1237 · **Issues:** #260, #580 · **Results:** [`summary.md`](summary.md),
`results/windows.csv` (one line per loaded window), `results/rows.csv` (one line per row and hold),
`results/setup.csv` (J1237 setup-time runs).

The owner's correction on 2026-11-25: we had not shown that GotaTun beats wireguard-go or kernel WireGuard, and a fair
comparison with Tailscale or NetBird is between **products**: infraternal (its mesh, with our GotaTun inside) against
theirs, not a bare protocol against a product. So there are two tables, measured on the same VMs with the same windows:

- **A. Engine row (bare protocol).** Four tunnels configured the same way (`wg set`, one peer, MTU 1390):
  `gotatun-cli` from the dev pin, the same binary with the side-socket sender on, wireguard-go, kernel WireGuard.
- **B. Product row.** Three products, each with its own defaults: the infraternal mesh, Tailscale with a self-hosted
  headscale, NetBird with its self-hosted combined server.

## Fixture

J1137/J1160's cross-VM pairing on `backup01` (Proxmox, Ryzen 7 3700X):

| VM | Role | vCPUs | Fixture address |
|---|---|---|---|
| `calternal-perf-01-backup01` (A) | node A; iperf3 client and round-trip probe | 4 (on 2 cores) | 10.70.3.196 |
| `infraternal-perf-01-backup01` (B) | node B; iperf3 and round-trip servers | 6 | 10.70.3.197 |
| `calternal-perf-02-backup01` (C) | control planes only (headscale, NetBird server) | 4 | 10.70.3.198 |

- Everything runs in one network namespace per VM (`j99`), whose only link is an ipvlan child of `eth0`. It has no default
  route, and an nft table inside it drops and counts anything leaving for an address outside 10.70.3.0/24, plus all IPv6.
  The counters are kept per hold (`guard-counters.txt`); the host's `egress-guard.service` stays on.
- `kit/lock.sh` takes every perf and build flock on each VM and marks the hold with `/run/j1199.lock`. It waits while
  another job's `/run/j1*.lock` exists, so no other measurement overlaps a hold.
- **CPU budget:** no pinning for any row. Kernel WireGuard runs in softirq and kworkers on whatever CPU the packet lands on,
  so it cannot be pinned. Giving userspace engines fewer CPUs than the kernel would not be fair, so every row gets the
  whole VM. CPU is reported as whole-machine busy time (user, nice, system, irq, softirq; steal excluded) on A plus B,
  per Gbit moved through the tunnel.
- **Guard table:** every engine row runs behind the same `inet infraternal_mesh` nft table the product installs. It is
  captured from a product node (`I.cap`; in e3 from the dev+J1159 build `5ffb8edd…`, whose guard is the same as
  `7c719e8a2`'s for a node that serves no subnet, J1179 only adds subnet-router rules) and only the interface name is
  changed. J1160 measured that table alone costing
  kernel WireGuard ~20% and GotaTun ~11% of reverse throughput on this pairing, so leaving it off any row biases the
  comparison. Product rows keep exactly what each product installs (Tailscale and NetBird add their own iptables-nft
  rules).
- **MTU:** engine rows use 1390 (the VMs' eth0 MTU is 1450). Product rows use each product's own value, as recorded on the
  tunnel device: infraternal 1360, Tailscale 1280, NetBird 1280. Smaller packets cost more per byte, which is part of
  each product's result, not something this fixture corrects.

## Windows and metrics

Per row: up, a 3 s warm-up, 15 s settle, a 20 s idle sample, 8 loaded windows, 15 s settle, a 20 s idle sample, down.

| Metric | How |
|---|---|
| Throughput | `iperf3 -P 1\|8 -C cubic\|bbr -t 60 -O 2`, receiver side, full speed. "forward" = A sends, "reverse" = A receives (`-R`). |
| Latency under load | `rr.py`: one 64-byte TCP request every 20 ms with a 64-byte reply (a keystroke echo), open loop, 50 s inside the load; p50, p99 and p99.9, loss-aware. A second stream asks for 1,200-byte replies (a screen update). **No ping**: iputils busy-waits for its send tick and burns up to 0.7 of a core on A when the round trip is short (J1159), which charges low-latency rows a cost the probe creates. |
| CPU per Gbit | Whole-machine busy seconds (steal excluded) on A and B over the 40 s steady part of each window, divided by the Gbit moved through the tunnel device in that time. |
| Idle wakeups/s | Voluntary plus involuntary context switches, summed over the threads of every non-kit process in the netns on A, B and C, over 20 s with no traffic, before and after the load. Kernel WireGuard has no process; its only idle signal is machine context switches against row X (no engine at all). |
| Memory | RSS of every process the row runs (nodes and control plane), at the start of each idle sample. |
| Setup time | From the start of the second node's process (`up`, `tailscaled`, `netbird`, `wg set`) to the first ping reply through the tunnel, both stamped on the VMs' own clocks (a background poller on the second node's VM, started before the node). Kernel WireGuard's 0.02 s is the method's floor. J1237 re-measured it in dedicated setup-only holds (5 runs per row, no load windows): see "Setup-time rows (J1237)" below. |

**A/A floor.** Every hold runs its base row first and last (G.1 … G.2, or I.1 … I.2). The largest gap between those two
runs over all holds is the floor of that cell and metric, and a difference no bigger than the floor is printed as `=`.
Deltas are paired within a hold, and the reported delta is the median over holds.

## What it does not cover

- One VM pairing, one LAN hop, no WAN delay, no loss. A is the smaller VM (4 vCPU on 2 physical cores), so "reverse" is
  the receiver-bound direction.
- In J1199's holds Tailscale's relay (DERP) was not reachable: headscale refuses to start without a DERP map, so its
  embedded DERP and STUN server ran on C, but Tailscale only talks to a DERP server over TLS and headscale served plain
  HTTP. Every Tailscale window used the direct path (`tailscale status`: `direct 10.70.3.197:41641`), so the throughput and
  latency rows are unaffected. The J1199 **setup time** (17.5 s) was affected and is superseded by the J1237 rows below.
- J1199's infraternal row ran the production node binary and the production coordinator compiler through the mesh test
  fixture (`xix.py`, `coordinator_fixture`), not through `infraternal up` against a server. The data path and the guard
  are the product's; sign-in, the server and its relay were not part of the row, so its 4.7 s setup time was not
  comparable with the others'. Superseded by the J1237 rows below.
- macOS, iOS and many peers are not covered.

## Setup-time rows (J1237)

Same fixture, same floor (kernel WireGuard), same stamps; only the setup row is re-run, in holds with no load windows
(`SETUP_ONLY=1`, five runs of each row per hold, rows interleaved `K T N R K T N R ...`).

- **Tailscale (T), with a reachable relay.** headscale now serves HTTPS with a throwaway self-signed certificate
  (ECDSA P-256, one day, CN and SAN only the LAN address 10.70.3.198, generated on C at the start of each row; `HS_TLS=0`
  restores plain HTTP). The certificate is the only trust anchor of `tailscaled` and `tailscale up` (`SSL_CERT_FILE`),
  so its embedded DERP and STUN server (also on C) are reachable over TLS: `tailscale netcheck` reports it as the nearest
  DERP at about 0.2 ms. No public name, no ACME, nothing leaves 10.70.3.0/24 (the netns guard counters are kept per hold).
- **infraternal (R), through the production join path.** A real `infraternal server` on C (web app from a production
  build of this checkout, `--behind-proxy` behind a `socat` TLS front with its own throwaway certificate, the remote
  listener and its CA directory on). The owner is created and the host-connection authority unlocked once per row by a
  scripted owner (`kit/rp-approver.ts`: headless Chromium with a virtual passkey, driving the production pages with the
  same clicks as `apps/tracer/real/up-approval.spec.ts`). Node B then runs `infraternal up https://<server>`; the printed
  approval code goes to the scripted owner, which opens the printed link, ticks the confirmation and taps the passkey;
  `up` enrols, installs and starts the agent. Node A does the same while a poller on A waits for the first ping reply from
  B's mesh address, so A is the second node, like the others. The setup time is A's `up` start to that reply; the stamps
  inside it (code printed, approval done, `up` returned) are recorded per run in `rp-stamps`.
  What stands in for the host: `up` and the agent run in a private sandbox (new mount, pid and uts namespaces inside the
  fixture's network namespace, a chroot with tmpfs `/run`, `/var/lib`, `/tmp` and a private `/etc` on the VM's disk) where
  `/usr/bin/sudo` and `/usr/bin/systemctl` are stand-ins: sudo runs the helper as the root we already are, and systemctl
  runs the unit's `ExecStart` (the firewall unit's oneshot in the foreground, the agent in the background) instead of
  asking systemd. Nothing in the VM's own files changes (`up` writes `/.infraternal-up.journal` at the root of its
  filesystem; in the sandbox that is the run folder). The shipped binary trusts only `/etc/ssl/certs/ca-certificates.crt`,
  so the sandbox's copy of that file holds the host's roots plus the server's certificate. The binary is the unmodified
  release build (`scripts/static-cargo`, dev `4b95d8362`).
  Not covered: the systemd start-up of the unit (a stand-in starts the same command), the kernel's nft rules being
  loaded by the firewall unit at boot (the oneshot is run, in the netns), a real public name and certificate chain, and
  the owner's human time to find and tap the approval (the scripted owner's span from printed code to answer is about
  0.45 s, reported separately).
  TLS on the server uses a front because `infraternal server --tls-cert` together with `--remote-listen` refused to start on
  compute01 ("TLS configuration failed") while the same command started on hd01; the cause was not investigated.
- **NetBird (N)** as in J1199 (combined server on C, kernel WireGuard mode, relay inside the combined server).
- **Floor (K).** Kernel WireGuard through the same stamps.

## Rerun

```
# on compute01 (or dev-02), inside the repo's nix devshell: infraternal + coordinator_fixture + gotatun-cli
kit/build2.sh        # edit WT / the fork revision first
# on hd01: stage binaries (refuses while any hold is active), then holds
kit/stage.sh
kit/series.sh e3 I.cap G.1 W K J G.2      # engine hold (I.cap captures the guard table)
kit/series.sh p1 I.1 T N I.2              # product hold
# J1237 setup-time holds (own staging under /root/j1237; binaries and the browser app: kit/stage.sh with FB_JOB=j1237):
FB_JOB=j1237 SETUP_ONLY=1 kit/series.sh s1 K.1 T.1 N.1 R.1 K.2 T.2 N.2 R.2 K.3 T.3 N.3 R.3 K.4 T.4 N.4 R.4 K.5 T.5 N.5 R.5
python3 -I kit/setup_table.py <raw-dir> s1 --csv results/setup.csv
# R also needs, in <job's stage dir>: ab/infraternal and c/{infraternal,tracer-dist.tgz} (the release build and the
# tarred `apps/tracer/dist`), ab/app-node_modules.tgz (`playwright` and `playwright-core` from apps/tracer/node_modules);
# on B bun (/nix/store, BUN=), a headless shell (PW_BROWSERS=) and its libraries (stage.sh copies J1197's private set).
python3 -I kit/table.py <raw-dir> e3 e4 e5 p1 p2 --windows windows.csv --rows rows.csv
python3 -I kit/summarize.py windows.csv rows.csv --base G --holds e3,e4,e5
python3 -I kit/summarize.py windows.csv rows.csv --base I --holds p1,p2
```

Third-party binaries: Tailscale 1.104.4 and NetBird 0.82.0 (client and `netbird-server`) as pinned in
`research/head-to-head/pins.txt`; wireguard-go, wg and iperf3 from the head-to-head kit (J1137 staging); headscale
0.29.7 (`headscale_0.29.7_linux_amd64`, sha256 `e827fc9b12d958bc95b081c4401dd63f8e0471d025b45b508535a920532150a8`,
the release's `checksums.txt`). Our builds: `gotatun-cli` at fork `e87fef91` (`--no-default-features --features
ring,mimalloc`, static x86_64 musl, the product's crypto backend and allocator; sha256 `94e7b745…`), infraternal at dev
`7c719e8a2` (`scripts/static-cargo`, sha256 `df78b9eb…`), `coordinator_fixture` from the same tree (`2ca20014…`).
