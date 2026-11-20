# J519: mesh DNS route-loss review (#483)

Verdict: **REQUEST CHANGES** on `j485-mesh-dns-route-loss` at
`103178e65ce1dc148967afa623def3ac904e9f3f`.

## Findings

1. **P2: unavailable and Nix-only resolver tools are silently missed.**
   `dns_integration.rs` only searches distro paths for resolvectl, nmcli and
   NetworkManager. No installation-selected root-owned Nix path is supported.
   Missing tools, failed resolver commands and failed owned-file installation
   end in `Ok(())` with a cached `mode: None`; identical records never retry.
   The caller cannot report the missing tool or attempted paths. Preserve
   fixed trusted lookup, cover Nix installation, and expose actionable failure.
   `review_j519_missing_tools_are_reported` fails on the unexpected success.
   Neither-mode hosts safely avoid device reapply, but still lack host mesh
   name resolution. Fedora's resolved configuration does not establish
   RHEL/Alma default-plugin support. See issue comment 91257.

2. **P2: cleanup after process loss strands the marked dnsmasq file.**
   `DnsIntegration::remove` requires its memory-only install record. A fresh
   process cannot clean the previous process's durable marked forwarding file
   when no accepted snapshot recreates the record, or the resolver mode has
   changed. It can continue forwarding old suffixes to an absent listener.
   Reconcile only the safely owned marked file; do not restore device reapply.
   `review_j519_restart_cleanup_removes_owned_file` calls cleanup twice and
   fails because the marked file remains. See issue comment 91265.

3. **P2: networkd reconfiguration deletes protocol-250 peer routes.**
   In a private namespace with systemd 257.13, the matching network file is
   confirmed configured. An unchanged `networkctl reload` preserves both
   routes. Adding `[Link] MTUBytes=1400` to that file and reloading causes
   networkd to reconfigure the link and remove both routes. The final presence
   assertion fails in `scripts/review-j519-networkd-route-survival`.
   This requires a networkd-managed mesh interface and changed configuration;
   it does not describe production's NetworkManager or an unchanged reload.
   Protocol 250 alone is not a universal route ownership boundary. See issue
   comment 91266.

## Independent verification

All runs used compute01, build-slot and nice -n10. Network and filesystem
mutations were in disposable user/network/mount namespaces, with private
D-Bus and PID namespaces for the daemon fixtures. Production and mesh-staging
were untouched.

- J485's real-kernel route assertion against the old wireguard implementation:
  expected failure, `protocol=static`, exit 101 (`red-route.log`).
- Exact reviewed wireguard implementation, original ownership regression in
  its own namespace: 1 passed (`green-orphan_route_retirement_preserves_foreign_routes.log`).
- New restart/upgrade regression in its own namespace: 1 passed. Both missing
  peer routes are recreated with protocol 250; a second restart preserves peer
  and foreign routes (`green-review_j519_restart_repairs_missing_routes.log`).
- Existing DNS unit selection: 12 passed, 0 failed; 2 new regressions ignored
  until run separately (`dns-unit.log`). Resolved argument generation is
  checked; live resolved queries were not exercised.
- New DNS regressions: 0 passed, 2 failed on the intended assertions
  (`dns-regressions.log`).
- Nix NetworkManager 1.58.1: the old DNS cleanup reapply deletes both static
  routes, while protocol 250 survives that reapply and DNS-only reload
  (`nm-route-survival-r2.log`). The fixture used NM's default DNS plugin;
  live dnsmasq forwarding was not exercised.
- networkd harness: exit 1 on missing peer routes after configuration reload
  (`networkd-committed-harness.log`). Earlier pending-link fixture results
  were invalidated and do not establish survival.

Receipts are under `/home/claude/.cache/codex-scratch/j519/evidence/` on
compute01 and `/home/kayg/.cache/codex-scratch/j519/evidence/` on control,
with selected raw logs attached to #483. No end-to-end traffic acceptance is
claimed. These functional checks make no latency claim.

The author's exact-head full gate is recorded in #483 comment 90958:
`VERIFY_EXIT=0`. The review brief explicitly forbids reviewer quick/fast
reruns; only the focused checks above were run. Review regressions are
intentionally failing and are not a green gate.
