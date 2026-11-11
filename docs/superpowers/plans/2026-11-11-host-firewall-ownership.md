# Host Firewall Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the server and infraternal agent own a boot-persistent, default-drop host input policy and prove it with takeover and mesh traffic tests.

**Architecture:** A shared module in the existing mesh plugin renders and applies `inet infraternal_host`, so both server and mesh-agent roles use one implementation without adding a workspace crate. It validates typed admin and listener config, discovers nft only from fixed root-owned distro/Nix locations, compares current and desired rules, and replaces the table atomically. Product installation owns one `infraternal-firewall.service` ordered before `network-pre.target`; server and mesh startup update its persisted policy.

**Tech Stack:** Rust 2024, nftables transactions, systemd oneshot units, Linux network namespaces, existing `scripts/verify-privileged` gate.

**Spec:** `docs/superpowers/specs/2026-11-11-host-firewall-ownership-design.md` and D386 in `DECISIONS.md`.

## Global Constraints

- Only nftables tables and chains named `infraternal_*` are owned; unrelated tables are untouched.
- Keep `inet infraternal_host` input default-drop and preserve explicit admin access.
- Mesh rules include `infraternal0` and UDP 10254; mesh grants remain enforced in the mesh filter.
- nft changes use one atomic transaction and a fixed root-owned executable path, including Nix paths; never search `PATH`.
- Every new or changed Rust item has a friendly documentation comment (D345).
- Do not change production. Do not merge. Push only this branch.

## Review Focus

- SSH path missing or malformed: Task 1 validation test must reject before nft execution.
- Failed nft batch: Task 2 namespace test must show the old ruleset remains installed.
- Nix-only nft executable: Task 1 resolver test must accept a fixed Nix path and reject PATH-only candidates.
- Non-owned nft table: Task 2 namespace test must show it is byte-for-byte unchanged.
- Mesh disabled/enabled: Task 3 namespace test must prove UDP 10254 and `infraternal0` admission only when enabled, with default-drop for other traffic.

---

### Task 1: Typed host policy and nft manager

**Files:**
- Create: `crates/plugins/mesh/src/host_firewall.rs`
- Create: `crates/plugins/mesh/tests/host_firewall_policy.rs`
- Modify: `crates/plugins/mesh/src/lib.rs`, `crates/infraternal/Cargo.toml`
- Modify: `scripts/verify-privileged`, `scripts/test-verify-privileged.py`

**Interfaces:**
- Produces: `Policy`, `AllowRule`, `Listener`, `render(&Policy)`, `validate(&Policy)`, and `apply(&Policy, Option<&Path>)` in `infraternal_plugin_mesh::host_firewall`.
- `Policy` carries listener and trusted-proxy rules, typed extra admin rules, and a mesh-enabled flag.

- [ ] Write failing tests for exact prod-shaped rendering, mesh additions, invalid admin config, and rule-diff output.
- [ ] Run the focused crate test on dev-02 and confirm expected missing-interface failures.
- [ ] Implement rendering, validation, fixed-path nft discovery, current-table comparison, and one `nft -f -` atomic batch.
- [ ] Run focused unit and ignored namespace tests on dev-02.

### Task 2: Server/agent startup and product-owned systemd unit

**Files:**
- Modify: `crates/infraternal/Cargo.toml`, `crates/infraternal/src/main.rs`, `crates/infraternal/src/install.rs`, CLI action definitions.
- Modify: `crates/infraternal/src/up.rs`, `crates/infraternal/src/up_install.rs`, and the mesh activation path.
- Modify: `scripts/verify-privileged` to include the new package's namespace tests.

**Interfaces:**
- Consumes: Task 1 `Policy` and `apply` API.
- Produces: server `--host-firewall-allow` config, internal `firewall apply` execution, generated `infraternal-firewall.service`, and mesh-enabled policy updates through the shared mesh-plugin module.

- [ ] Add failing tests for server flags becoming typed firewall rules, unit ordering before `network-pre`, Nix path pinning, and migration replacement of the named hand unit.
- [ ] Run the focused server install/config tests on dev-02 and confirm failure.
- [ ] Implement system policy persistence and install integration; user units do not manage system firewall state.
- [ ] Run the focused unit tests and the privileged gate selection on dev-02.

### Task 3: Takeover documentation and prod-shaped namespace proof

**Files:**
- Create: `docs/operations/prod-on-ssh.md`
- Modify: product help/install documentation and `crates/infraternal-host-firewall/tests/`.
- Modify: `crates/plugins/mesh/src/firewall.rs` if needed to adopt named `infraternal_*` tables without marker dependence and to reuse Nix-aware discovery.

**Interfaces:**
- Consumes: Tasks 1–2 policy and boot integration.
- Produces: exact before/after prod ruleset and a gate test for SSH survival, bidirectional mesh, and default-drop behavior.

- [ ] Write a failing real-nft namespace takeover test using the prod-shaped input table and an unrelated control table.
- [ ] Run it in an isolated network namespace and confirm it fails before the fix.
- [ ] Implement only the required adoption/path behavior, then prove admin access, both mesh directions, and default-drop.
- [ ] Document how product installation replaces the hand unit; do not change prod.
- [ ] Run `scripts/verify fast` on compute01, record measured outputs, and post finish receipts on #483 and #489 after any staging window is granted.
