# Decisions

Settled in the design grill of 2026-10-05. Each decision has a number. To change
a decision, the owner (kayg) must approve it. Record the change here with a date.

## Product

1. **What it is.** infraternal is an all-in-one, self-hosted infrastructure
   manager. It does SSH, host metrics, Docker and Podman, VNC and RDP, Proxmox
   LXC, VMs and, later, Kubernetes.
2. **Self-hosted only.** There is no hosted cloud. The server runs on-prem. One
   exception: a content-free push relay for the paid Apple apps (decision 38).
3. **Everything is a plugin.** SSH, metrics, Docker, Kubernetes and the other
   features are all plugins. infraternal integrates with respected products
   (Prometheus, Grafana, NetBird, Tailscale, Authentik). It does not replace
   them.
4. **First focus: a very good SSH client.** Save and manage hosts and open
   terminals from one web UI and PWA. The PWA must feel local on high-latency
   links and be very fluid on mobile.
5. **Performance and latency are the highest priorities.** When options are
   otherwise equal, the faster one wins. Measure; do not guess.
6. **Clients.** Web and PWA (TypeScript) first. CLI and MCP come from the same
   actions (decision 16). Native iOS and macOS apps come later on the same API.

## Architecture

7. **One static binary, two modes:** `infraternal server` and
   `infraternal agent`. Rust, static musl builds, distribution independent.
8. **The server is trusted.** It holds identity, roles, audit, state and the
   API. There is no end-to-end encryption between the browser and the agent.
9. **The server never touches a host directly.** All host work happens in an
   agent. The server has an embedded agent: a subprocess of the same binary
   (`infraternal agent --fd 3`) that speaks the same protocol as a remote agent.
10. **Always relay.** Traffic goes browser → server → agent. The browser is only
    a viewer.
11. **Transport legs.**
    - Browser ↔ server: WebTransport (QUIC) first, WebSocket as the fallback.
      One multiplexed binary protocol with sequence numbers, so streams resume
      after a drop without lost or duplicated bytes.
    - Server ↔ agent: QUIC (quinn, BBR) first, TCP/TLS as the fallback. KCP is
      only added if benchmarks on a lossy link show that it beats tuned QUIC.
12. **Wire format.** A custom binary protocol. Keep it only while it fits the
    product and benchmarks faster than protobuf, flatbuffers and Cap'n Proto.
    The parser is fuzzed.
13. **Terminal sessions.**
    - On a host with an agent, the agent spawns the PTY locally (no SSH). A
      real SSH path stays available for each host.
    - A small session shim that rarely changes owns each PTY (conmon-style).
      Sessions survive browser drops, server restarts and agent upgrades.
    - Steady state streams raw PTY bytes. On resume, the agent sends a snapshot
      of the screen state (tmux-attach style). A benchmark gate compares this
      with a mosh-style diff before we lock it.
    - Predictive local echo comes later, in the SSH plugin.
14. **Terminal renderer.** ghostty-web (Ghostty VT in WASM, xterm.js-compatible
    API) behind our own small interface. xterm.js is the drop-in fallback. Test
    on a real iPhone before we commit.
15. **Plugins.** First-party plugins are compiled in: a Rust crate plus a
    TypeScript UI package behind a stable, versioned interface. A runtime WASM
    host can wrap that interface later. Each plugin has three parts: agent
    (does the work), server (permissions, persistence, routing) and UI.
16. **One action definition, many adapters.** Each plugin action is defined
    once: schema, permission and handler. The API, CLI, MCP, UI and Apple apps
    are generated from that definition.
17. **Lockstep versions.** The server serves its own binary. When the server
    next connects to a host, it swaps the agent binary.
    - A/B slots. The new binary must check in within about 30 s. If it does
      not, the agent rolls back to the previous slot.
    - Write to a temporary file, fsync, then rename atomically. Never write to
      `/usr`: use `/var/lib/infraternal/bin`, or
      `~/.local/share/infraternal` for rootless agents.
    - The upgrade handshake is frozen forever.
    - A downgrade needs a signature and an explicit request from the server.
18. **Rootful and rootless agents.** The SSH bootstrap auto-detects sudo, the
    engine sockets, `systemd --user` and linger, and then proposes a mode. A
    host has one agent. When root becomes available, the agent upgrades to a
    root agent, moves the contexts (root docker, kayg podman, …) to it and
    removes the user agent. The agent supports systemd, openrc, runit, s6 and a
    fallback.
19. **Deployment.** One node, SQLite, and first-class backups (scheduled
    snapshot plus a restore command). No HA: HA comes from Kubernetes or
    Proxmox. The server ships as a static binary with a systemd unit, and also
    as a container image.
20. **Platforms.** Agents first for linux x86_64 and aarch64. armv7 comes when
    CI is cheap, then macOS (host stats for Macs). FreeBSD only on demand. The
    server runs on linux x86_64 and aarch64.

## SSH and hosts

21. **Host inventory.** Manual entries, import from `~/.ssh/config`, and the
    NetBird management API in slice 1. Tailscale comes next. Live sync: a new
    peer appears as "available, no agent yet".
22. **SSH authentication.** Keys, certificates and passwords. Network identity
    (NetBird or Tailscale, with no secret stored). Relayed mesh login URLs
    (NetBird JWT, Tailscale check mode).
23. **Secrets at rest.** Stored SSH keys are encrypted with keys derived from
    the user's passkeys (WebAuthn PRF). Each key is wrapped once for each
    passkey and once for the recovery key. Unattended work never uses stored
    keys. It uses the identity of the agent.

## Identity and access

24. **Passkeys only.** Each user has one passkey and a recovery key
    (mandatory) and can add one more passkey (optional). No passwords.
25. **Recovery key.** 24 words. Recovery waits 24 h. Signed-in devices can
    cancel it.
26. **First run.** The server prints a one-time setup token to its logs. You
    use it to create the owner.
27. **CLI and MCP.** API keys for each device. A signed-in browser approves the
    device with a QR code or a device code.
28. **Sessions.** 30 days, sliding, on trusted devices. A destructive UI action
    needs a fresh passkey tap. A destructive MCP action needs a dry run first.
29. **Permissions.** Plugins declare their actions. Roles are scoped to host
    tags, and you configure them in the UI. The data model supports multiple
    users from day one.
30. **OIDC.** Login through your own IdP is free. Group-to-role mapping and SCIM
    are paid. OIDC lands after slice 1.

## Licensing and pricing

31. **License.** The core is AGPL-3.0-only. The code that enforces and manages
    multiple users (invites, roles UI, group mapping, SCIM) is in `ee/` under a
    commercial license with an offline license key. The data model stays in
    the core. Contributors sign a short CLA.
32. **Tiers.** Community: free, one user, all features, unlimited hosts.
    Homelab: one-time payment, about 10 users. Team: per user per month.
    Enterprise: contact sales. Apps: a subscription for iOS and macOS, with
    push and sync. No prices go in the repo before launch.
33. **No paid feature work before there are users.** Build only the seams: the
    `ee/` directory, the license check and the role model.

## Plugins and order

34. **Slices.**
    - S0: website, repo skeleton, gates.
    - S1: core (server, agent, shim, protocol, auth, plugin and action
      framework, inventory), the SSH plugin and the mobile terminal.
    - S2: metrics plugin and the macOS agent.
    - S3: Docker and Podman.
    - S4: VNC and RDP (noVNC-style client, IronRDP).
    - S5: Proxmox LXC.
    - S6: VMs.
    - S7: Kubernetes.
35. **Metrics plugin.** Live data plus a short history: 24 h at 10 s
    resolution, then 30 days downsampled. The server has a Prometheus
    `/metrics` export. Alerting stays in Grafana.

## UI

36. **Layout.** A floating sidebar with a branched tree (hosts → plugins, live
    counts, status dots). One search capsule navigates to anything and runs
    actions. The terminal area has tabs and splits. The style is dense,
    neutral and enterprise-like. It uses calternal's tokens, but not its
    consumer feel.
37. **Mobile terminal input.** An accessory key bar (esc, tab, ctrl, alt,
    arrows, symbols, customizable), sticky modifiers, swipe for arrows,
    two-finger swipe for scrollback, pinch for font size, and snippets for each
    host. Test on a real iPhone in every slice.
38. **Notifications.** Free: ntfy and gotify. Paid apps: a content-free APNs
    relay that only sends "wake up".

## Engineering

39. **Process.** Lean, fast and iterative. Test each change hands-on, then find
    and fix performance leaks, UI leaks and breakage quickly. Grill before
    each slice. Write the contracts first. One Forgejo issue for each piece of
    work. Codex lanes work in parallel worktrees, and an independent reviewer
    checks each lane. The owner merges to `dev`. `main` only gets tagged
    releases.
40. **Strictness.**
    - Rust: `#![forbid(unsafe_code)]` except in the audited shim and PTY crate.
      Clippy pedantic as errors. `cargo-deny`. No `unwrap` outside tests.
    - TypeScript: strict mode with `noUncheckedIndexedAccess`. svelte-check
      with zero warnings. No `any`.
    - Tests run against real engines and a real sshd. Playwright uses virtual
      passkeys. The protocol parser is fuzzed.
    - Everything is benchmarked and tested.
41. **Performance budgets (hard CI gates on the perf VM).**
    - Keystroke-to-echo overhead below 5 ms p99.
    - Reconnect after a network switch below 300 ms, with no lost bytes.
    - PWA first paint below 1 s on a mid-range phone.
    - Terminal renders at 60 fps with 10 MB/s of output.
    - Idle agent below 15 MB RSS.

    Only the owner can loosen a budget.
42. **CI.** A Forgejo runner on infraternal-dev runs builds and tests. A
    separate, pinned perf VM runs the benchmarks.
43. **Repo.** Forgejo `kayg/infraternal` is the source of truth, with a mirror
    on GitHub `kaygdotorg/infraternal`. The old history is archived as
    `kayg/infraternal-v0`.

## Website

44. **infraternal.com, built first.** A static SvelteKit site in
    `apps/website`. Docs use Astro Starlight in `apps/docs`, served at `/docs`.
    Deploy to Cloudflare Pages through Forgejo Actions and
    `wrangler pages deploy` (direct upload).
45. **Positioning.** The hook is SSH: "a self-hosted terminal that feels local,
    on every device". The all-in-one control plane is the vision and the
    roadmap. Claim only what works.
46. **Pages.** Landing, docs, changelog, roadmap and a waitlist. Pricing shows
    the tiers as "free during beta", with no numbers. No third-party trackers.
    The waitlist uses a Pages Function and D1.
47. **Shared UI with calternal.** The goal is an `@kayg/ui` package on the
    Forgejo npm registry. Until it exists, the calternal `packages/ui` tokens
    and components are vendored, with a sync script.

## Open

- Prices for each tier (kept out of the repo).
- Whether KCP is worth adding for server ↔ agent (decided by benchmark).
- Pure state-diff resume against snapshot resume (decided by benchmark).
- Details of S1, which needs another grill before it starts.
