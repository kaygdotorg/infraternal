# Product-owned host firewall policy

## Intent

The server and infraternal agent must own their host input policy so mesh traffic and application listeners survive restarts and boot. The owner-approved contract is D386: resources named `infraternal_*` belong to the product, fixes ship as product behavior, and unrelated nftables tables remain untouched.

## Goals and limits

- Render the host input rules from server listener flags, trusted proxy settings, and typed extra admin rules.
- Add `infraternal0` and UDP 10254 input when mesh is enabled.
- Keep the host input chain default-drop and enforce mesh grants in the existing mesh filter.
- Apply a candidate ruleset in one nft transaction, reject incomplete admin access before invoking nft, report migration differences, and restore policy before `network-pre`.
- Mark role policy files and the loader unit as product-owned so clearing the last role atomically removes `inet infraternal_host`, its enablement and its marked config; repeated removal is a no-op.
- Removing the default-drop host table opens input. Unmarked files and units remain untouched, and removal errors name the failed item.
- Resolve nft from fixed root-owned system or Nix paths, never by searching `PATH`.
- Never inspect or alter tables outside the `infraternal_*` namespace.
- Replace the hand-installed loader at its known service name on the next product install; this job does not change production.

## Approaches

1. Keep a static nft file and a separately managed loader. This preserves today's ownership split and caused mesh traffic to be dropped when the file was not updated, so it does not meet D386.
2. Let each daemon rewrite host rules when it starts. This can derive listeners from runtime flags, but applies too late for `Before=network-pre` and gives server and agent separate writers.
3. Use one product-owned oneshot service with a persisted, structured policy. Server and agent configuration feed the same manager; it validates SSH access, reports takeover differences, and applies a single atomic transaction. This is selected because one serialized policy has one boot path and one writer.

## Design

The shared host-firewall library lives beside the existing mesh firewall in the mesh plugin, which is available to both server and mesh-agent roles. It accepts typed listener, proxy, mesh, and admin rules and produces deterministic nft text. It rejects a policy without at least one explicit TCP/22 admin rule before tool discovery or mutation. The system service invokes the product binary with a root-owned, marked policy file and a resolved absolute nft path. Server install writes its listener/proxy inputs and extra rules into that file. Mesh activation updates the same policy's mesh bit before applying it. Takeover reads the current named table, prints a difference report, then replaces the table in one nft batch. An empty configuration deletes only the product table in one nft transaction and removes only marked policy and loader files. `server init --host-firewall-off` clears the server role while retaining any agent role. The product unit has `DefaultDependencies=no` and `Before=network-pre.target`.

The product writes `infraternal-firewall.service` at system installation, intentionally replacing the hand-made unit of that name. Existing firewall sources needed for SSH, WireGuard, proxies, and remote listeners are represented as typed policy entries. Table names outside the prefix are never listed for mutation.

## Review focus

- Missing or malformed SSH admin rule: reject before any nft command.
- Existing hand-made table: report the concrete current and desired rule lines before atomic takeover.
- Missing nft in distro paths but present in Nix store: find a root-owned fixed-path executable or report every searched location.
- nft transaction error: prior rules remain installed and the command fails loudly.
- Unrelated nft tables: inventory may read them, but generated transactions name only `infraternal_host`.

## Implementation calls

The job may choose the exact Rust crate boundaries and config encoding while preserving this contract. No production host changes are in scope.
