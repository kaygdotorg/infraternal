# Traefik Proxy Slice 1 Implementation Plan

> **For agentic workers:** execution is authorized by the J62 implementation request. Follow the test-first steps and commit each independently verified change.

**Goal:** Add a downloaded-on-demand Traefik component that publishes explicitly authorized node services through mesh-bound listeners and renews DNS-01 certificates on the issuing node.

**Architecture:** Keep component trust and installation in the proxy plugin, with a separate bounded component policy. Render a complete static configuration and atomic dynamic snapshots from a typed exposure model; supervise one process per node and retain its ACME state when idle. Keep DNS token storage behind `DnsTokenCustody` and use the owner's interim owner-only file implementation.

**Tech Stack:** Existing Rust workspace, existing OpenSSH release signature trust, serde JSON, Traefik 3.7.17, the existing plugin action registry, and VM-only Cargo verification.

**Spec:** Forgejo issue #281 and `DECISIONS.md` D316, D314, D303; owner answers recorded on #281.

## Global Constraints

- Keep the application release payload cap at 128 MiB; component limits remain separate at 256 MiB archive and 512 MiB executable.
- Install only the signed target executable, under its digest, with owner-only directories and mode 0500 executable.
- Default publication is mesh-only and binds only the node mesh address; public publication requires first-use confirmation.
- Per-machine wildcard certificates are the default and their keys remain on that node; flat names use exact per-service certificates and are logged in CT.
- Provider credentials remain in interim owner-only files behind `DnsTokenCustody`; pass only `*_FILE` paths to Traefik.
- Use the existing grant revision and exact host matching; disable API/dashboard, insecure mode, remote plugins, and telemetry.
- Run builds, tests, and gates only on assigned VMs through `build-slot`; keep one target directory and remove it at completion.

## Review Focus

- Wrong OS/architecture, invalid signed metadata, archive tampering, links, traversal, or oversized input never reaches the component store.
- A request with an unknown Host, denied mesh source, or forged forwarding header never reaches a backend.
- Zero exposures drains for 10 seconds, retains certificates, and a new exposure cancels drain; crashes back off without repeated downloads.
- Provider token bytes never enter rendered files, argv, environment values, or the log pipeline.
- Rootless listeners use 10080/10443; root uses 80/443 only when available and otherwise reports 10080/10443 without firewall changes.

## File Responsibilities

- `crates/plugins/proxy/src/manifest.rs` and `installer.rs`: signed metadata verification, bounded extraction, offline bundle import.
- `crates/plugins/proxy/src/download.rs`: configured mirror acquisition and verified upstream archive fallback.
- `crates/plugins/proxy/src/names.rs`: one function for per-machine wildcard and flat exact-service names.
- `crates/plugins/proxy/src/config.rs`: static and dynamic Traefik renderers, exact routing, grant filters, atomic writes.
- `crates/plugins/proxy/src/supervisor.rs`: process lifetime, private ping, log forwarding, drain and restart backoff.
- `crates/plugins/proxy/src/cli.rs` plus the existing CLI registry: the `publish` command schema and `--json` output contract.
- Proxy unit/integration tests: acquisition tampering, naming, redaction, lifecycle, and namespace/ACME staging coverage.

## Tasks

1. Add failing tests for both name shapes, default wildcard selection, CT-log disclosure in module docs, and the `publish` command table. Run them on compute01 and confirm the expected failures.
2. Implement the single naming function and command metadata, then run proxy and CLI tests on compute01.
3. Finish verifier/installer clippy and tests; implement mirror metadata acquisition and bounded archive download with signed-manifest-gated upstream fallback. Exercise mirror and fallback behavior with local fixtures.
4. Add failing config and exposure-policy tests, then implement mesh-only exact-host routes, provider `*_FILE` wiring, private health ping, disabled admin surfaces, secure atomic config writes, and root/rootless port selection.
5. Add failing lifecycle/log-redaction tests, then implement one-process supervision, the 10-second drain, certificate retention, backoff, and log pipeline redaction.
6. Add a namespace integration test using a local backend and Pebble staging ACME; verify no real certificate endpoint is contacted.
7. Run crate tests, clippy, `scripts/verify fast`, and report-only x86 static-size delta on compute01. Commit and push, post evidence to #281, and remove the sole target directory.
