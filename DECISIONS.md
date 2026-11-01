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
    - Browser ↔ server: WebSocket only (changed on 2026-10-06, decision 63).
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

## S1 (grill of 2026-10-05, issue #5)

48. **Dogfood instance.** The owner's own server runs at
    `infraternal.kayg.org` on monitor01, as the user `kayg`. Only the owner
    uses it. It is redeployed from `dev`.
49. **Self-installing binary.** `infraternal server install` and
    `infraternal agent install` write and enable their own service (systemd
    system or user unit, other init systems per contracts/bootstrap.md). No
    install scripts.
50. **Sessions belong to the user,** not to the device. Each of a user's
    devices can see and attach to their live sessions.
51. **Agent install asks once per host.** The probe proposes a mode, and the
    user confirms with one tap. Auto-install for managed peers comes later.
52. **S1 terminal scope.** Tabs, splits, scrollback search, copy and paste,
    clickable links, the mobile key bar and resume. File transfer and
    broadcast input come in S1.5.
53. **No insecure dev mode.** The first deploy already has real auth: the
    setup token, the owner's passkey and the recovery key.
54. **Friendly first.** The product must be very user friendly: setup
    wizards, friendly nudges and a pretty UI. The first run is a wizard:
    network → hosts → agents → done.
55. **Shell exit.** A clean exit (0) closes the tab. A non-zero exit or a
    signal keeps the tab, with its scrollback and a restart prompt.
56. **Session reaping.** A session that no one has viewed for 7 days (you
    can change this for each user) gets a warning and is then reaped.
    Attached sessions are never reaped.
57. **Notify when done.** With shell integration (OSC 133), you get a
    notification (web push for the installed PWA, or ntfy) when a long command
    ends in a tab that you are not looking at. This is in S1.
58. **Keys.** All keys go to the focused terminal. App shortcuts use cmd (mac)
    or ctrl+shift. A tmux-style prefix key is an option.
59. **History and snippets.** Command history for each user comes from shell
    integration. Search over it must be very fast. You switch it on for each
    host, and it is encrypted at rest. Saved snippets for each host or tag.
60. **No danger levels per host.** The owner did not find them useful. Tags
    stay for permissions and grouping.
61. **Mesh APIs in the wizard.** Import hosts from NetBird (the official cloud
    and self-hosted management) and from Tailscale (the official API and
    Headscale's own API). The wizard probes the chosen hosts in parallel and
    shows the results in a live grid.
62. **Own visual identity.** infraternal is not a consumer product. It must
    look different from calternal. A visual grill with mockups that Claude
    builds comes before the first UI lane.
63. **WebSocket only on leg A in S1** (changes decision 11). WebTransport
    only helps on lossy links (#12: p99 216 ms against 489 ms at 1% loss; no
    difference on clean links). It costs a public certificate inside the
    app, a UDP port for browsers, a second transport, and Safari risk.
    Predictive local echo is the bigger gain for "feels local" on any slow
    link. The wire format stays independent of the transport. WebTransport
    comes back only if real-phone numbers show the stutter matters.
64. **Ports.** Managed hosts open no inbound ports: agents dial out. The
    server has one port of its own for agents (default 7443, QUIC on UDP with
    a TCP/TLS fallback, mTLS with the internal CA). The UI, API and WebSocket
    are served either on that port with the server's own certificate
    (standalone) or as plain HTTP on a local address behind a reverse proxy.
    Dogfood instance: Traefik 443 → `172.18.0.1:7011`, and agents connect to
    `10.69.69.50:7443`.

## Visual direction (grill of 2026-10-06, issue #14 to come)

65. **No reference products.** The owner dislikes existing infra and
    enterprise UIs: they feel static and old. infraternal is its own
    reference and is designed piece by piece.
66. **Calm and relaxed.** Strong highlights for what matters, little
    overload. Hierarchy instead of density.
67. **Light and dark are equal.** Both follow the system and get the same
    care.
68. **The terminal is the app** (for now). Everything else (sidebar, search
    capsule, wizards) floats over it as overlays.
69. **Three words:** calm, alive, precise. Every screen is judged against
    them.
70. **Alive** means two things: physical motion (springs, momentum, gestures
    you can interrupt) and live data that changes softly in place. All UI
    motion stays under about 250 ms. Motion is used only when it explains
    something.
71. **Color and guidance.** A near-neutral base with one vivid accent, used
    only for focus and "look here". State colors only on small marks. Less
    information, more guidance: friendly components that lead the user.
72. **Materials.** Solid, calm surfaces. A light blur only on the overlays
    that float over the terminal (sidebar, search capsule), so that the
    terminal stays visible.
73. **Type.** Geist Mono for the terminal and for code. One sans for the UI,
    chosen by eye from mockups (licensed under OFL or similar, so it is
    compatible with AGPL).
74. **Shared sessions size like tmux.** When several devices attach to one
    session, the size of the device that typed last wins (tmux's default
    `window-size latest`). The other devices show the same screen, scaled to
    fit.
75. **Nothing depends on the browser.** Each session, each SSH connection
    and each job starts and runs on the server side: in an agent, which can
    be the server's embedded agent. Hosts without an agent (routers,
    appliances) get their SSH session in a shim in the embedded agent, with
    the same persistence and resume. Browsers, CLIs and apps only subscribe
    and send input. When you close every client, nothing changes:
    notifications still come from the server.
76. **Restore after a reboot.** When a host reboots, its sessions are gone.
    infraternal offers to reopen the same tabs in the same directories, and
    the old scrollback stays visible above them, read-only.
77. **Merging** (changes decision 39). Claude merges lanes into `dev` after
    an independent review, green gates and its own check. Each merge has a
    summary on its issue and a new preview. `main` only gets stable builds,
    and the owner has the final say there.
78. **The palette searches everything:** hosts, sessions, actions and
    commands, and also the text of the UI itself (settings, labels, help).
    One index, results grouped by kind.
79. **Mobile keys float.** No bottom band. Icon pills that scroll sideways
    over a progressive blur.
80. **Themes are curated and gated.** Each theme passes the contrast audit
    (fg ≥ 7, fg2 ≥ 4.5, fg3 ≥ 3, accent and status ≥ 3, terminal colors
    ≥ 4.5 against the background). Failing colors are fixed by changing only
    their OKLab lightness, and each change is logged. Touch targets are at
    least 44 × 44 pt (Apple HIG). Both are CI gates when the UI lands.
81. **Polish only after grilling; performance first.** Each feature is
    designed and built only after a design grill, and that grill includes
    performance. Before any code, the feature gets a budget: idle CPU (zero
    by default), memory, and what runs on the server and what runs in the
    client. Features ship at the highest polish or not at all.
82. **The key toolbar auto-hides** while you scroll back, so you can read on
    the full screen. It returns when you type or when the keyboard opens. The
    prompt is never hidden under it.
83. **Backgrounds come from our own shader:** a mesh gradient with fine
    grain, painted from the active theme's colors. Very curated and very
    performant: rendered once to a still image (zero idle CPU), and rendered
    again only when the theme or the window size changes. Slow drift is
    opt-in. Your own photo stays on your device. Unsplash is an optional
    integration only when the server admin adds a key. Paper Shaders cannot
    be used (PolyForm Shield is not compatible with AGPL).
84. **Zoom changes the text, not the UI.** On touch devices, page zoom is
    off. A pinch changes the terminal font size. Inputs are 16 px, so iOS
    never zooms when one takes focus. The safe areas follow the theme.
85. **Mobile key bar: variant a.** One compact glass capsule. Keys that do
    not fit fade at the edges. The owner chose it after comparing it with a
    native keyboard row and a d-pad layout.
86. **Passkey crypto: webauthn-rs with OpenSSL** (for now). It is proven code
    for the front door. It costs about 2.5 MB of binary size and a pinned C
    toolchain. Idle RAM stays near 5 MB. A pure-Rust verifier (webauthn-rp)
    is reviewed again when it passes the advisory gate and has its own
    security review.
87. **Curated terminal fonts.** Nine OFL-1.1 monospace fonts, chosen in the
    palette with a live preview: Geist Mono (default), JetBrains Mono, Commit
    Mono, Maple Mono, Monaspace Neon, IBM Plex Mono, Cascadia Code, Fira Code
    and Source Code Pro. They are self-hosted and loaded on first use.
88. **Codec on both sides, one byte format.** The browser (TypeScript) and
    the server and agent (Rust) each have a native codec for the wire format.
    Shared golden vectors and differential tests keep them identical. No
    WASM bridge: copying through the JS↔WASM boundary would cost more than
    the about 230 ns that the JS decode itself takes. Performance is
    measured from the UI, end to end (keystroke → paint), as the main S1
    gate.
89. **Search across sessions** (S1–S4 of #18). Scrollback search fans out to
    the agents: each shim scans its own in-memory scrollback, results stream
    back, and there is no central copy of the output. Command history (from
    shell integration) has a small central index that also works when hosts
    are offline. Budget: results from 50 sessions in < 100 ms, bounded by
    the slowest host's round trip. The fastest default is always chosen, and
    the engine stays fast with very large scrollback.
90. **Binary output** is detected in the shim (thresholds calibrated by the
    #18 stress test, so that emoji, CJK and combining text never count as
    binary). It is shown live, kept out of search, and collapsed to a marker
    in scrollback that can be expanded on request.
91. **How far back search reaches:** live scrollback always. Closed sessions
    are kept read-only for 7 days. Command history is kept for 90 days,
    opt-in for each host. Hits open the session at the line, with the match
    highlighted.
92. **Order after S1: VNC next.** When SSH is complete, the next slice is
    VNC and RDP, ahead of metrics and Docker (this changes the order in
    decision 34).
93. **Terminal images: kitty graphics in S1.5.** We implement them
    ourselves: the kitty graphics protocol is intercepted before ghostty-web,
    images are drawn on a layer locked to the character cells, and the shim
    stores them per session so that they survive resume. Sixel and iTerm
    come only on request. ghostty-web 0.4 and alacritty_terminal have no
    image support.
94. **The shim's terminal-state engine is libghostty-vt** (owner decision,
    2026-10-06). It replaces alacritty_terminal, which a job chose without a
    grill. It is the same engine as the browser's ghostty-web (14), so the
    screen the shim saves and the screen the browser draws come from the
    same code. It measured 2.4× the parse speed (138 MB/s) and 60% less
    memory (about 20 MB per 10,000 lines). We write our own screen
    serializer for snapshots (its built-in formatter failed our repaint
    fixtures). Zig is pinned for the build.
95. **Onboarding is a guided wizard.** The app detects whether a server
    owner exists. If none exists, it goes straight into a stepped setup
    wizard (setup token → name → passkey → recovery key), with numbered steps
    that turn into ticks. After the passkey is registered, the owner is
    signed in automatically. Sign-in is one "Continue with passkey" button
    with no username.
96. **The sign-in and onboarding backdrop is our own "faulty terminal"
    shader,** in black and white, written from scratch after the
    sveltebits.xyz effect. Its code cannot be copied (MIT + Commons Clause).
    Budget: half resolution, at most 30 fps, paused when hidden or after
    sign-in, one still frame with reduced motion.
97. **Account identity.** Each account has an internal random user ID (the
    primary key and the WebAuthn user handle), a **username** (unique,
    lowercase, `[a-z0-9._-]`, 1–32 characters, can be changed later because
    everything refers to the ID), a free-text **display name**, and an
    **optional email** (notifications only; no email server is required).
    The passkey is created with name = username and displayName = display
    name. The wizard step "name" becomes username + display name (the
    display name is pre-filled from the username).
98. **Sign-in (updated by owner 2026-10-07, #32):** one usernameless
    "Continue with passkey" button. Discoverable sign-in opens the platform
    chooser, which lists every passkey for this site. A secondary alternate
    passkey link is unnecessary; typing a username is never required.
99. **One tick, everywhere.** Each checkmark (checkboxes, stepper steps,
    completed bootstrap steps, "copied") uses one shared spring-tick
    primitive, reimplemented from the sveltebits spring-check behaviour: one
    spring (0.2 s, bounce 0.2) drives the fill, the overshoot swell and the
    draw-on. Pointer toggles animate. Keyboard toggles are instant. The same
    rule applies to every repeated interaction: one primitive, reused.
100. **No font swap, ever.** Each page preloads the fonts that its first
     view uses. Font faces use `font-display: block`, and a view renders once
     its font is ready (with a short cap). The first frame is the final frame.
     This applies to the app, the website and the docs.
101. **Everything has motion; first sign-in has a moment.** After the
     onboarding wizard, "Welcome to infraternal" appears as glitch text
     (reimplemented, monochrome, settles after 1.6 s), then the app opens.
     The rest of onboarding is designed as we go.
102. **Waits use the count-up.** Nothing appears for waits under 400 ms. Above
     that, a count-up shows real progress when known, otherwise elapsed
     seconds. Never fake progress, and no spinners. One shared loading()
     primitive.
103. **Copy feedback:** minimal. The copy button's own icon turns into a
     tick (the D99 path, drawn on) and back: 200 ms in, a 0.9 s hold, 150 ms
     out, with strong ease-out CSS transitions, so a re-tap retargets. Nothing
     else on the page moves. A region blur and a pixel mosaic were tried and
     rejected as maximal. Reduced motion is opacity only. One shared
     copyFeedback() primitive for every copy action.

104. **Remote desktop sessions are held by the server side, like SSH:** the
     server or its infraternal agent opens and keeps the VNC (later RDP)
     connection to the target. Browsers and later Apple clients only
     subscribe to it. Closing a tab or losing a phone connection never
     ends the session. The holder keeps the current framebuffer, so a
     client that joins or rejoins gets a full image at once (the
     equivalent of the terminal Snapshot). A browser-held RFB connection
     (noVNC talking to the target) is rejected for that reason. Decoding
     in the browser is fine (owner, #23).
105. **First remote desktop targets:** macOS Screen Sharing first, then
     Proxmox/QEMU (#23).
106. **Minimum client:** iOS/Safari 17, so WebCodecs video decode is always
     available (#23).
107. **Remote desktop quality and input follow measurement:** the encoding
     from holder to subscriber (dirty rectangles, lossless or JPEG,
     H.264/HEVC low-delay video, or a mix) is chosen by benchmark for the
     lowest input-to-photon latency and the best performance on phones.
     Text sharpness, trackpad mode and clipboard follow from that
     benchmark. They are not fixed promises. Benchmark and optimise
     aggressively (#23).
108. **One passkey prompt at sign-in (A3):** discoverable sign-in and the
     PRF key unwrap use a single ceremony, with a server-wide constant PRF
     input, provided the independent auth review confirms that this loses
     no protection compared with the per-user input. Existing envelopes
     keep their stored input (#19).
109. **Browser terminal pinned to a source build (T1):** ghostty-web is built
     from source at an upstream commit that contains the crash fix
     (bec9e162, #180, or later on the 0.5.0-rc line), pinned by SHA with a
     checksum, until an official release contains it. We then switch to the
     release. No upstream release request is sent: we build it ourselves
     and move to the official release when it ships (owner) (#31).
110. **Lossless terminal state (T2):** ship with the bounded painter
     (approximate restores are flagged and counted, and a reconnect never
     closes a session). In parallel, build an engine-level state
     export/import for libghostty-vt in our own fork and test it with our
     differential suite. Propose it upstream as a PR only after it is
     proven here (#26).
111. **Auth backdrop keeps animating until sign-in completes:** the
     faulty-terminal field (D96) runs continuously on the setup and sign-in
     screens (at most 30 fps, half resolution, paused when hidden or
     off-screen, one still frame under reduced motion) and stops for good
     once sign-in completes. It is not frozen after its intro (#40).
112. **Steady cursor when idle:** the terminal stops rendering, cursor blink
     included, after 700 ms of inactivity and wakes on input, output,
     resize, scroll or pointer, so idle CPU stays at zero (D81). A steady
     cursor at idle is accepted (#40).
113. **Recovery delay:** recovery with the 24 recovery words completes
     immediately when started from a device that already holds a live
     session for the account. Started from a device without a session, it
     waits 24 hours (the existing contract delay), so a stranger with stolen
     words cannot take over before the owner notices. The sign-in card
     offers "use recovery key" instead of "use a different passkey" (#45).
114. **S1 order: remote infraternal agents first** (transport, enrollment and
     reconnect), then the SSH bootstrap, then mesh import and the add-host
     flow (P1, #9).
115. **First hosts and the add-host flow:** o1, o2 and minipc01 first, added
     and tested by the owner. The add-host flow is designed with the owner
     through an extensive grill and mockups before any screen is built
     ("no slop", "mockup the hell out of it") (P2, P4).
116. **SSH authentication in the first cut:** NetBird SSH, Tailscale SSH,
     passwords and keys (keys and passwords encrypted with the user's
     passkey, D23). Certificates follow (P3).
117. **Scale target is enterprise, not the owner's own use:** the owner
     expects 1–2 remote desktop sessions, but budgets and architecture are
     sized for an enterprise deployment. Phones get a scaled picture and
     desktops native resolution; H.264 with a persistent encoder shared by
     subscribers at the same size (P5).
118. **Scroll routing in split views (S1 = c):** nested by default, as in iOS
     scroll views: a scroll moves the content under the finger or pointer;
     only when a card is at its edge does a *new* gesture move the canvas.
     There are also explicit canvas gestures: two-finger drag on touch,
     Space+drag or middle-drag on desktop. Shift+wheel scrolls
     horizontally. A keyboard shortcut cycles the active card; arrow keys
     pan the canvas when no card has focus. **The active card shows an
     accent-colour border highlight** (#46).
119. **Windows on a tiling canvas (W1–W2):** a terminal (later VNC) view is
     called a **window** ("card" stays the styling term). Windows tile in
     rows and columns inside groups that live on an infinite canvas you can
     pan and zoom, with niri-style scrollable tiling as the reference feel.
     Scrolling follows D118.
120. **Window pill and info popover (W3–W7):** each window has a small pill
     (OS logo, user@host, session name, status dot) that opens an info
     popover with tabs: **Machine** (a GUI fastfetch: OS, kernel,
     architecture, model, cores, memory, disk, uptime, init,
     virtualization, agent mode, engines), **Connection** (route and legs,
     transport, RTT per leg, mesh, certificate expiry, bytes, reconnects)
     and **Session**. The tabs are centred, correctly padded and icon-only
     with warm tooltips, and use the MetalForge-style segmented selection
     logic (behavioural decode only, no copied code). Sharing gives an image
     or text, with IPs hidden by default. Static facts are read at install
     and on reconnect; live numbers refresh only while the popover is open.
     Root-agent promotion shows a very subtle spinner on the pill and the
     tree, with a warm tooltip carrying the status, a tick on completion and
     an activity-log line; no undo.
121. **Attach by default, with multiplexer controls (W8):** opening a host
     attaches to its last session automatically, and all sessions are one
     tap away in a session manager. Each window has a header area (no band:
     floating icons over a progressive blur) with the multiplexer actions:
     split vertically or horizontally, and the session manager. Local
     attach from the host itself (`infraternal attach`) comes later.
122. **High latency is the design case:** the owner keeps the server on
     monitor01 (Germany) on purpose, while the owner and targets are in
     India. The India → Germany → India round trip is measurable and felt,
     and high latency is more often the truth than not. Optimise for it;
     do not "fix" it by moving the server (N4, #47).
123. **Any browser works:** a normal browser outside NetBird or Tailscale
     must work fully; mesh membership is never required (N2).
124. **Enterprise scale test target:** 500 concurrent terminal sessions and
     50 remote desktop sessions per server, up to 5 viewers per session
     (N5, D117).
125. **Window header, popover and mobile canvas (M2–M8):**
     - The info popover opens from the pill on every device: on desktop and
       phone alike it sits right at the pill, with a bubble tail pointing to
       it (not a bottom sheet).
     - The header is one floating row with no band: pill on the left,
       multiplexer icons on the right, over a progressive blur. It is always
       visible, dimmed until hovered.
     - On phones, scrolling inside a window scrolls the window; canvas
       navigation gets explicit controls in the bottom toolbar if
       differentiating inside versus outside scrolling proves too complex.
     - Tooltips on touch appear on long-press, as everywhere.
     - The Machine tab (M3) and the session manager (M7) each get their own
       interactive design and mockup round.
126. **Machine tab and share card (MT1–MT6):**
     - fastfetch style, with the logo on the left when the popover is wide
       and on top when it is narrow;
     - default fields: OS and version, kernel, architecture, model, CPU and
       cores, memory, disk, uptime, load, agent mode, engines; the rest
       (init, virtualization, IPs hidden by default, shell, locale) behind
       "more";
     - thin bars for memory and disk, updated only while the popover is
       open;
     - a dedicated share card (square, theme colours and gradients, a small
       infraternal mark), shared as an image or text with IPs hidden by
       default;
     - OS logos from Simple Icons (CC0), single colour and tinted. They also
       appear in the sidebar once detected, with a generic penguin or
       machine glyph otherwise;
     - tapping a value copies it (D103).
127. **Session manager (SM1–SM6):**
     - a popover from the header icon, with a tail, scrollable;
     - rows show name, last output line, age, viewers, size and a new-output
       dot;
     - attach by tap, rename inline, open beside as a split, end with
       confirmation. All of these are GUI actions, with trackpad, Magic
       Mouse and touch swipe gestures where appropriate;
     - new sessions are auto-named and open at once ("stay out of the way");
     - the manager shows only its host's sessions. Everything, everywhere, is
       reachable through the fast search and command palette;
     - ending a busy session names what is running.
128. **Latency and session data path (N1, N3, N6–N9):**
     - sessions live in the host shim; browsers resume by byte offset over
       any route, direct or relayed, and fall back mid-session;
     - D64 stays strict (agents never listen). The direct path is WebRTC
       with TURN; the TURN relay ships in the same binary (relay mode), the
       server is a relay by default, and extra relays (e.g. o1 in India) are
       optional;
     - if the agent loses the server, direct sessions **fail closed** after
       a short lease (about 60 s); the shim keeps running;
     - **audit mode** (per deployment, host group or role) relays all bytes
       through the server. Session recording is done by the **agent**
       (signed, uploaded to the server), which works on every path; the
       server-relay recording remains available where an independent copy is
       required;
     - order: predictive local echo first (client-only), then the WebRTC
       direct path, then a KCP vs QUIC benchmark on India↔Germany, after the
       remote-agent transport (D114).
129. **Key tray modifiers on touch:**
     - Tapping any key-tray key (ctrl, option/alt, esc, tab, arrows) never
       dismisses the iOS keyboard; focus stays in the terminal.
     - A single tap of a modifier arms it for the next key only (one-shot).
     - A **double tap locks it (sticky)**: every following key gets the
       modifier (double-tap ctrl, then tap c c c → ctrl-c, ctrl-c, ctrl-c)
       until the modifier is tapped again to release it.
     - The armed and locked states are visually distinct and subtle, with an
       accessible state and a warm tooltip ("Control, locked").
130. **Make typing and output feel instant on any link (L1–L3):**
     - Predictive local echo switches on automatically when the measured
       round trip is above about 60 ms, with safety rules: off in
       full-screen apps and when echo is off, and backing off after a
       misprediction.
     - An optional **compose mode** (edit locally, send on Enter) is a
       per-window toggle, also in ⌘K. On high-latency links the app
       measures, offers to switch it on, and may switch it on automatically
       where it clearly helps.
     - Everything the client already holds (scrollback, search, selection,
       copy, window switching, resize) never waits on the network.
     - Interactive bytes get priority over bulk output; no Nagle-style
       batching; paint on the next frame.
     - **Tests run with high latency by default** (e.g. a 300 ms round trip
       or more), so protocol and app slowness shows up in every run, and
       input-to-photon regressions block merges.
131. **Relays are one command:** the single infraternal binary is agent,
     server and relay. `infraternal relay --udp-port <n>` (TCP/TLS fallback
     port optional) runs a relay with no container image and no config
     file, in the Tailscale spirit and unlike NetBird's container setups.
     Trust with the server is established with a one-line join shown in the
     UI (a one-time token); nothing else to configure. The CLI is designed
     to be human-friendly throughout.
132. **The user never runs commands (T1):** commands exist and stay
     trivially simple, but the product never makes the user run one. Adding
     a host installs and enrolls its infraternal agent automatically. A
     relay is a subtle checkbox in the host's UI ("Run a relay here"):
     tick, spinner, then "Relay running on port N". Smooth, fast and out of
     the way. Manual `agent join` / `relay` commands are for operators,
     tests and automation only.
133. **Agent certificates (T2):** 7-day agent certificates, renewed
     automatically over the existing connection well before expiry. Renewal
     is measured to be invisible: no session interruption, negligible
     CPU/RSS/bytes, no wakeups beyond the renewal itself. The server CA
     stays on the server, with overlap-based rotation.
134. **Removal (T3):** removing a host revokes its certificate at once; the
     agent removes itself, its services and its state on next contact
     (minimal footprint). An uninstall action exists for hosts that can no
     longer reach the server.
135. **Lockstep agent updates, proven resilient (T4):** the server ships the
     agent binary matching its own version, with an A/B slot swap and an
     automatic rollback when the canary fails. Every update and swap
     scenario is tested, and the tests actively try to break it: power or
     network loss mid-swap, a corrupt or partial download, a disk-full or
     read-only slot, an agent crash during the canary, a concurrent root
     promotion, a server version jump, a downgrade.
136. **One server per agent; the server is the trust anchor (T5–T6):** an
     agent enrolls with exactly one server. The server is trusted and must
     be running: it is a single point of failure by design; agents keep
     sessions alive and fail closed when it is gone (D128). High
     availability is planned later as a commercial (`ee/`) feature, not in
     the open product.
137. **Transport proof before UI (T7):** the orchestrator enrolls o1, o2 and
     minipc01 with the operator join command and runs chaos tests
     (NetBird/Tailscale restarts, agent restarts, network loss, a 300 ms+
     RTT, renewal under load, update and swap failures) and reports before
     the owner tests the add-host flow.
138. **Add-host flow, round H:**
     - **Entry points (H1):** the sidebar's "Add hosts", ⌘K and a calm
       empty state all open the same flow.
     - **Discovery (H2):** one smart field (`user@host`, an IP or a name)
       plus live lists. The server auto-detects what it can already
       reach: the mesh it is a peer of (from the local NetBird or
       Tailscale daemon), `~/.ssh/known_hosts`, `~/.ssh/config` and the
       like. Smart, simple, stupid.
     - **Mesh API tokens (H3):** optional, encrypted with the passkey and
       read-only. Never required to add hosts when the server host is
       already a mesh peer.
     - **Installs (H4):** parallel and async; one failure never blocks
       another.
     - **Credentials (H5):** asked only when needed, inline per host,
       with "use for all selected".
139. **Root needs explicit consent (H6), which supersedes the automatic
     parts of D18 and D120-W7:** passwordless sudo is never taken as
     permission. Installing a root infraternal agent, and promoting an
     existing user agent to root later, always asks first ("trust is one
     thing we can't get back once lost"). After consent, the W7 spinner
     and warm tooltip show progress.
140. **The add-host flow is a window (H7–H9):**
     - It lives on the canvas, with springy, bouncy, responsive motion in
       the spirit of the sign-in wizard (a rare action, so delight is
       allowed).
     - Finished hosts open their terminal windows automatically.
     - Failures are plain, human, simplified technical English, with a
       caret that expands to browse the logs.
141. **Add-host flow, round H2:**
     - **One list (H10):** discovered hosts are a single deduplicated list
       with source icons (NetBird, Tailscale, known hosts or SSH config,
       already added), not grouped lists. Everything is mocked up in the
       product before any piece is built.
     - **Sources (H11):** read-only, on by default, with a switch per
       source.
     - **SSH identity (H12):** the server's own keys, used in place and
       never copied, for the owner by default; pasted keys are encrypted
       with the passkey (D23); mesh SSH needs no secret. When SSH fails
       because of what looks like a mesh access policy (e.g. NetBird ACL),
       the UI says so accurately.
     - **Root consent (H13):** the root consent wording is as proposed, with
       "apply to all N hosts that allow sudo" for bulk adds.
     - **Root available later (H14):** the pill shows "Root available";
       tapping it shows a small tooltip-style confirm with yes and no.
       Never a popup, never automatic.
     - **Motion (H15):** per-host steps tick like onboarding, under Emil
       Kowalski's standards.
     - **When hosts finish (H16):** the canvas does not move; a toast says
       the host is ready, with an action to go to its window.
142. **The web UI moves to Svelte 5 now (F1), and looks identical:** the tracer
     and `packages/ui` are migrated from hand-managed DOM to Svelte 5
     components before the windows, session-manager and add-host UI is
     built. **Before and after must look the same:** a pixel-diff
     screenshot gate covers every existing screen and state (onboarding,
     sign-in, the core screen, palette, sidebar, key tray, popovers,
     themes, mono and sans, phone and desktop), and the motion audit,
     latency probe, bundle size, first paint and idle-work checks must
     match or improve. Toasts use Svelte Sonner as the queue and lifecycle
     owner, with our inner renderer per `docs/design/toast.md`. The build
     tooling (Vite or Bun plugin, and SvelteKit or plain Svelte) is settled
     before the migration starts.
143. **Svelte tooling is chosen by measurement (F2):** plain Svelte 5 as a
     static single-page app served by the Rust server; no SvelteKit, since
     its server rendering is unused. The bundler (Vite with
     `@sveltejs/vite-plugin-svelte`, or Bun with a Svelte plugin) is the
     one that measures best on the owner's criterion, **best performance
     and lowest latency**: first paint and FCP on a throttled phone at
     high RTT, bundle bytes (raw and gzip), lazy-chunk splitting for the
     terminal, the latency probe and idle work. Both are prototyped on the
     same screens and the numbers decide; no default favourite.
144. **Quiet automatic discovery, including SSH reachability:** the server
     (through its embedded infraternal agent) quietly and automatically runs
     read-only commands such as `netbird status --detail` (JSON where
     available) and `tailscale status --json` to infer every host on the
     meshes, **and especially which hosts accept SSH**. Use mesh metadata
     where it exists (for example Tailscale SSH host keys or the NetBird
     peer SSH state); otherwise a single, rate-limited, unauthenticated
     reachability check (a TCP connect or SSH banner read on 22 and the
     NetBird SSH port), never a login attempt. Results feed the one-list
     add-host view (D141): SSH-ready hosts are marked, and SSH-blocked ones
     are explained (#58). It runs in the background with no prompts,
     refreshes on mesh changes, and stays cheap and idle-free otherwise.
145. **Fact collection is an infraternal agent feature, not a shell script:**
     the agent binary gathers host facts natively. It reads `/proc`, `/sys`
     and the OS APIs directly where possible, and runs external commands as
     parallel tasks, each with its own timeout. It **detects hangs** (for
     example a stuck `df` on a dead NFS mount), abandons them without
     blocking anything else, records which source hung, and draws
     conclusions from it ("NFS mount /mnt/x is unresponsive"). Everything is
     read-only and breaks nothing. Before install, SSH runs only a tiny
     OS/arch sniff (POSIX sh or PowerShell) to pick the right binary; the
     same binary then runs once in a one-shot probe mode over that session,
     returns the structured report and exits, without being installed.
     After install, the agent refreshes facts itself per D126.
146. **Everything is configurable in the UI (B1):** no setting or operation
     is CLI-only. Every action is defined once and exposed through the UI,
     the API and MCP, with the CLI as one more adapter (round 6). Backups,
     restore, migrate, relays, discovery sources, retention: all have UI.
147. **Backups (B1–B4):**
     - A backup is a consistent snapshot (SQLite backup API) of the
       database, the CA key and the configuration, encrypted with a key
       derived from the recovery words.
     - App data is kept intentionally small, so backups can be pushed to
       any host. Any host can be an infraternal agent, a relay and/or a
       **backup host** once chosen in the UI.
     - Defaults: local, daily, 7 kept, plus one before every upgrade or
       migration.
     - `infraternal restore` shares its code with migrate (#59).
     - The audit log is kept 90 days, configurable; longer retention and
       export are enterprise.
148. **Stored SSH secrets (K1–K5):**
     - Used only for installing agents, and only while the owner is
       present; never by unattended tasks.
     - A rebuilt host waits ("needs you").
     - Decrypted only in the browser with the passkey; sent to the
       infraternal agent doing the SSH; held in memory for that session
       only, then wiped. Never stored decrypted.
     - Keys can be pasted, uploaded or generated (Ed25519, public key
       shown) with a very simple flow; keys are stored encrypted by
       default.
     - Passwords are asked each time unless "remember (encrypted)" is
       chosen.
149. **The sidebar is rearrangeable by direct drag and drop:** long-press on
     touch, or press and hold with a mouse, then drag. No drag handles.
150. **Shared credentials (K6–K7):**
     - End-to-end group keys by default: a host group's shared secrets are
       encrypted with a group key, wrapped for each member's passkey; adding
       a member needs an existing member's browser to rewrap.
     - Server-held escrow is an opt-in enterprise policy.
     - A quiet "Only me" vs host-group switch when adding a key.
     - How groups work, including OIDC, is defined in round G.
     - OIDC means standard providers (Authentik, Keycloak and similar);
       there is no direct Google or Apple login, and infraternal is never an
       OIDC provider itself.
151. **Automatic E2EE for everyone via device keys (G1):** every account has
     one account key (DEK) that the server only ever stores wrapped. Every
     browser or device creates a non-exportable key pair (WebCrypto) and
     receives a wrap of the account key, so known devices unlock silently at
     sign-in, whether the user signed in with a passkey or OIDC. Passkeys
     (PRF) and the recovery key are further unlockers in the same wrap list.
     All stored secrets (SSH keys today, anything later) are end-to-end
     encrypted automatically for local and OIDC users; there is no setting.
     Group keys are wrapped per member's account key, and pending grants are
     re-wrapped in the background by any member's device when it comes
     online; escrow remains an opt-in enterprise policy. This supersedes the
     passkey-only E2E model of D23, D148 and D150.
152. **Getting a new device in is simple (G1c):** there are no matching codes.
     A new device is brought in by:
     - **scanning a QR code**: the new device shows a QR code; scanning it
       with an already signed-in phone (camera or in-app) **signs the new
       device in and unlocks it** in one step;
     - **the recovery key**;
     - a synced passkey, for passkey users, which works automatically.
     The QR binds the request physically, so scanning it is the consent.
153. **QR sign-in confirmation (G1d):** after scanning, the phone shows one
     confirmation naming the new device and its approximate location ("Sign
     in Firefox on Linux, near Essen, Germany?"). One tap, nothing to
     compare. QR codes expire after 60 seconds. This is the minimum that
     stops QR-login phishing.
154. **Users, groups and permissions (round G, kept simple):**
     - **Groups (G2):** groups created in infraternal are free; groups
       synced from an identity provider (groups claim or SCIM) are paid,
       read-only and mapped to roles in the UI; both mix.
     - **Grants (G3):** **who × role × hosts**, where hosts are host tags or
       all hosts. Access is the union of grants; there are no deny rules.
       Actions are declared by plugins.
     - **Roles (G4):** Owner, Admin, Operator, Viewer plus custom roles. The
       session owner can always see and end their own session.
       **Simplicity of the permission system is a requirement.**
     - **Identity-provider mapping (G5):** `infraternal-admins` → Admin and
       `infraternal-users` → Operator on all hosts, editable. The first
       OIDC sign-in never becomes owner.
     - **Group keys (G6):** follow D151; losing access rotates the group key
       and re-encrypts shared secrets automatically; rotating the real SSH
       keys on hosts is offered, not forced.
     - **Removal (G7):** access is rechecked at least every 5 minutes plus
       back-channel logout; removal cuts all sessions and live terminal
       connections at once and discards that user's device keys; SCIM
       removal is immediate (paid).
     - **Local users (G8):** local accounts by invite link (24 h expiry,
       passkey registration). **Local users can be turned off entirely**
       (OIDC-only deployments).
     - **Audit (G9):** grant changes, sign-ins, device approvals, host
       changes, session open and end, and shared-credential use are logged
       and visible in the UI (90 days default, D147).
155. **Releases and upgrades (round U):**
     - **Versioning (U1):** one version for the single binary, starting at
       **0.0.1 = the first stable release**. Only stable builds ship
       publicly; there is no public edge channel. Pre-release builds go
       only to the owner's own deploys (monitor01).
     - **Auto-update on by default (U2):** the server checks, verifies the
       signature, takes the pre-upgrade backup (D147), swaps A/B slots,
       restarts with sessions kept alive (shims survive), and the infraternal
       agents follow in lockstep (D135).
     - **Auto-rollback gets a ridiculous amount of effort:** health checks
       (HTTP, WebSocket attach, agent reconnect, DB migration success,
       session resume) gate every update, and any failure rolls back the
       binary and restores the pre-upgrade backup automatically. Every
       failure mode is tested deliberately, as in D135.
     - **Distribution (U3):** signed release files on Forgejo, mirrored to
       GitHub, verified against a key built into the binary. No central
       update server.
     - **Migrations (U4):** forward-only; a downgrade restores the
       pre-upgrade backup; tested against real old databases.
     - **Browsers (U5):** a toast says infraternal updated, and the page
       reloads when idle with no unsent input; sessions resume.
156. **Discovery and facts (round D):**
     - **Extended information (D1, D3):** cheap facts are on by default
       (opt-out); expensive or sensitive facts and the noisier discovery
       sources (IPs, listeners, workloads, mesh topology, SSH and firewall
       posture, updates, disk health; LAN neighbours, mDNS, Proxmox,
       Docker/Kubernetes contexts, libvirt) sit behind one **"Gather
       extended information"** switch. Whether it is global, per host or
       both is still to be grilled and designed.
     - **Add-host list (D2):** shows names; an IP is revealed on tap with a
       text-morph animation in the spirit of SwiftUI's numericText (the
       torph library is the reference), decided against the mockup.
     - **Platform order (D4–D7):** Windows comes after the first Linux
       release (an issue carries everything a job needs to start). BSD and
       appliance priority follows enterprise relevance, to be researched
       first. Talos and Bottlerocket are unsupported for now; guests (WSL,
       Termux, Crostini) are labelled as guests. macOS 13 or later, Intel
       and Apple silicon.
     - **No one-shot probe (D8), which supersedes the probe mode in D145:**
       before install, SSH runs only a tiny read-only sniff (OS, CPU
       architecture, init, passwordless sudo) to pick the binary and ask for
       root consent. Then the infraternal agent is **installed first**, and
       it gathers every fact itself, as parallel and async as possible.
     - **Observe first, manage later (D9):** infraternal is a
       management/control plane, but management actions (updates, package
       operations, config changes) come much later, once the base is stable.
       Until then, collection is strictly read-only: no cloud metadata or
       credentials, no package refresh or updates, no root without consent,
       no host-key bypass, no login attempts, no workload dumps, no SMART
       self-tests, no SSH to shell-less appliances. We iterate slowly and
       stay stable.
157. **Extended information and compose mode (rounds E and C):**
     - **"Gather extended information" (E1–E4):** a global default, off,
       overridable per host group and per host; the most specific setting
       wins, and each place shows where a value is inherited from. It is
       switched from the Machine tab's "more", the host-group settings, the
       global settings and the add-host window. Switching it on shows one
       plain line saying what it adds and that it is read-only, with no
       dialog. Switching it off deletes the collected extended facts at
       once, and the audit log records it. **Expensive commands are
       identified and measured, and collection is conservative with them**
       (sampled rarely, cancelled on hang, never on a timer while the host
       is busy).
     - **Compose mode (C1–C4):**
       - an inline local line editor in the terminal's own font and theme
         colours, with a subtle header marker; Enter sends; local history
         is merged with the shell's history where readable;
       - it turns off automatically for full-screen apps, password prompts,
         when no prompt is detected (OSC 133 first, a heuristic otherwise)
         and on Ctrl-C;
       - completion: instant local suggestions, and Tab asks the shell;
       - it is offered once by toast when the RTT stays above 150 ms on a
         phone or 250 ms on desktop, and remembered once accepted.
158. **Machine tab adjustments (owner review of the in-product prototype):**
     - The OS logo sits **at the top**, always (it looks better). This
       replaces D126's left/top split.
     - **No copy icons on rows.** On touch, **double-tap** a value to copy
       it; on desktop, a **single click**. Feedback is the D103 tick swap
       inline, plus a warm tooltip "Copied".
     - The pills (window pill, tab tray) are vertically shorter.
     - Mobile typography is tightened: one type scale, aligned key and
       value columns, values that fit without awkward wrapping.
     - The bottom toolbar (key tray) never touches a window card: a
       consistent gap separates them, and the toolbar pill is vertically
       shorter (touch targets kept by padding).
159. **Touch and pointer model for windows on the canvas (refines D118/D125):**
     - **Activation:** one tap or click on an inactive window activates it
       (accent border) without opening the iOS keyboard; a tap on the
       already-active window focuses the terminal and opens the keyboard.
       The sidebar is never required to switch windows.
     - **One finger inside a window** scrolls that terminal: scrollback
       vertically, and horizontally when its content is wider. At the end it
       stops and never drags the canvas by accident.
     - **Two fingers anywhere pan the canvas** in both axes, with momentum.
       This is how a horizontal split (stacked windows) is reached on a
       phone. iOS Safari delivers multi-touch to web apps, so this works
       there.
     - **Pinch** changes the terminal font size (as the owner asked
       earlier); it is distinguished from a two-finger pan by finger spread
       vs common translation. The canvas overview is the toolbar's grid
       button, with toolbar ← → stepping between windows.
     - **Desktop:** the trackpad or wheel scrolls the terminal under the
       pointer; Shift is horizontal; Space+drag or middle-drag pans the
       canvas; a click activates a window.
160. **One reusable, per-instance-extensible component per UI concept:**
     every UI concept (overlay/popover/sheet material, pill, capsule tabs,
     rows, tooltip, tick and copy swap, toast, buttons, spring) exists
     **once** in `packages/ui`, is extensible per instance (props, CSS
     custom properties, slots), and is used everywhere. One-off copies are
     not allowed: the orchestrator rejects job diffs that hand-roll
     duplicates. An optimisation to a component therefore lands everywhere.
     Performance is the highest concern in every shared component. The
     **overlay material** (D72: translucent glass with a light blur,
     hairline and soft shadow) is one token set used by every popover, the
     info popover and session manager included. It is never opaque and
     never so blurred that it reads as opaque, and it is checked in every
     theme.
161. **Enterprise OS priority; BSD deferred:** platform work prioritises
     enterprise operating systems:
     - **enterprise Linux** (RHEL and its rebuilds Alma and Rocky, SUSE/SLES,
       Debian, Ubuntu, **Proxmox VE**);
     - **macOS** (13+, Intel and Apple silicon, D156);
     - **Windows** (Windows Server and 10/11, #70).
     BSD and BSD-based appliances (FreeBSD, OpenBSD, NetBSD, TrueNAS,
     pfSense, OPNsense) are **deferred**; the ranking in #71 is kept for
     later. The first release covers the enterprise Linux set; macOS and
     Windows follow as the next platforms.
162. **No new UI reaches the product without mockup rounds:** every new
     screen, flow or component goes through an in-product prototype (behind
     a flag, on the preview, never deployed to production) and several
     refinement rounds with the owner before it is integrated. Fixes to
     already-approved UI may ship directly. The recovery sign-in flow (#45),
     built without a mockup, is held back from production until it has had
     its mockup rounds.
163. **Our own WireGuard mesh, a role of the one binary (grill #79):** the
     mesh is ours and open source (AGPL). Any server or infraternal agent
     node can be a mesh peer, a relay (D131) and/or a backup host (D147).
     - **Stages:** stage 1 joins nodes (the server and infraternal agents);
       stage 2 adds user devices as native clients, **macOS first, then
       iOS**. A browser cannot be a mesh peer: it reaches mesh hosts
       through infraternal (terminals, VNC). Mesh stays optional (N2).
     - **Stage 1 platforms:** Linux only (D161 set), using **kernel
       WireGuard**. macOS and Windows nodes follow with a **userspace
       engine** chosen by the owner from measured candidates
       (AGPL-compatible).
     - **Privileges:** the mesh runs with root privileges. Kept simple: no
       split helper and no unprivileged fallback mode.
     - **Coordination:** the infraternal server coordinates: it hands out
       addresses, distributes public keys and the rules. Each node creates
       its own private key, which never leaves it.
     - **Paths:** nodes try a direct path first and fall back through the
       server, which always runs a relay, or through any other relay; they
       move back to direct when it opens. One relay role serves terminals
       and the mesh.
     - **infraternal's own traffic** (terminal, VNC, backups) moves to a
       mesh path automatically when it measures faster, falls back without
       breaking the session, and needs no arrow (session permissions
       already cover it).
     - **Interfaces:** CLI (`infraternal mesh status` and friends), API and
       MCP expose everything; the UI is the primary way to use it.
164. **Mesh membership and access:**
     - **Automatic join:** every infraternal agent joins the mesh.
     - **Deny by default:** a joined node reaches only the server until
       access is granted.
     - **Arrows grant access (stage 1: nodes and tags):** on the canvas, an
       arrow A → B lets A open connections to B (replies flow back); a
       double-headed arrow allows both ways. All ports by default,
       narrowable to ports or discovered services. Endpoints switch easily
       between node and tag; "user" is shown greyed out ("Arrives with
       devices") until stage 2, when a user arrow means "this person's
       devices can reach this". Each arrow is a D154 grant.
     - **Arrow display:** solid = direct, dashed = via relay (named), RTT
       on hover or tap only, and a quiet marker when a rule has not reached
       a peer yet.
     - Subnet routes and exit nodes come later; stage 1 stays simple.
165. **Mesh addressing and names:**
     - **IPv4:** a fixed range per deployment, **10.254.0.0/16** by default.
       Setup checks it against routes in use and offers another range on
       overlap; it never changes silently.
     - **IPv6:** each node also gets a fixed private (ULA) address, used
       for routing; the UI shows IPv4.
     - **DNS:** every node gets a name, `<host>.internal` by default. The
       suffix is changeable to any domain (e.g. `vpn.kayg.org`). The
       infraternal agent's resolver answers only that suffix and never
       takes over the host's DNS.
166. **Mesh keys and failure behaviour:**
     - **Rotation:** each node replaces its own key silently every **7
       days** by default (configurable), with no dropped connections.
     - **No expiry:** node membership never expires; nodes stay until
       removed. Removal makes the server tell every peer to drop the key at
       once, so the removed node is cut off even if it is offline. User
       devices (stage 2) are decided separately.
     - **Server unreachable:** the mesh keeps working on the last known
       rules with no time limit. A removal reaches each peer when it
       reconnects; the UI shows peers that are behind on rules.
167. **Mesh build order and performance gates:** the mesh core (join, keys
     and rotation, direct and relayed paths, DNS, deny by default, CLI,
     API, MCP) is built first, with **no UI**; in parallel a job measures
     the userspace engines. The arrows and every other mesh UI go through
     mockup rounds (D162) after the canvas is approved, even if that means
     the UI comes much later. **Performance is measured in every round** of
     backend work, not only at the end: throughput and added latency per
     path (direct, relayed, India ↔ Germany), CPU and memory per peer ×
     the expected peer count, idle cost, join time, rule-propagation time
     and rotation impact. A round that regresses a number needs a
     benchmark that justifies it (priority 1).
168. **Internal CA: Ed25519, locked until an administrator unlocks it**
     (#78):
     - The CA signing key is **Ed25519** (measured equal to P-256 in speed
       and memory; it matches the existing host keys and gives smaller
       certificates).
     - The CA private key is stored encrypted. After a cold start it stays
       **locked** until **any user with the administrator role** unlocks it
       with their passkey. The CA key is wrapped once per administrator
       (as with device keys, D151), and granting or revoking the role
       rewraps it.
     - **While locked**, existing connections and infraternal agent
       reconnects keep working (verifying needs only the public CA
       certificate). Only enrolling new hosts and renewing certificates
       wait.
     - The server **locks only on a cold start**: a crash, a host reboot or
       power loss, a manual stop/start, or a restore or migration to another
       host. It never locks on a timer. An **auto-update or rollback hands
       the unlocked key to the new process in memory**, so updates do not
       lock it (unless the handoff itself fails, which then counts as a
       cold start).
     - Infraternal agents renew at half of the 7-day lifetime, so any
       restart leaves every certificate at least 3.5 days. While locked,
       administrators are notified, and again before any certificate gets
       close to expiry.
169. **WireGuard engines (#81, research/mesh-engines):**
     - Linux kernel WireGuard is driven by **our own small typed netlink
       client** (on MIT/Apache crates, chunked peer updates; measured 66 ms
       for 1,000 peers and 10 µs for a one-peer change).
     - The userspace engine for macOS nodes is **GotaTun** (Rust, MPL-2.0,
       independently audited), with our own macOS tunnel adapter in place
       of its bundled one (whose licence we cannot use). wireguard-go was
       rejected: it adds a second language runtime (+3.5 MB) and
       cross-language integration risk.
     - The Windows tunnel driver is **deferred** until Windows nodes, with a
       licence review then.
170. **Scale, order, test hosts, self-measurement, deploys (round B):**
     - **Design point per server:** 1,000 nodes, 200 concurrent terminal
       sessions and 50 users; tests run at 10,000 nodes for headroom. Every
       "per unit × expected count" budget uses these numbers.
     - **Backend order after remote infraternal agents phase 1:** relay mode
       (D131), then auto-update with rollback, then wiring the mesh to the
       server and infraternal agents, then backups (D147).
     - **Test hosts:** monitor01 runs the server **as root** (fresh deploy
       2026-10-07, system unit, data in `/var/lib/infraternal`), so the
       owner can test the user → root infraternal agent upgrade. o1 and o2
       take rootless test agents that are removed after each test.
     - **Self-measurement:** the deployed server records its own latency
       (RTT, echo p99, reconnect, sign-in) on the real path, stored locally
       and visible to administrators, never sent anywhere.
     - **Deploys:** lean and fast: every change that passes its gate and a
       hands-on check is deployed to monitor01 with a short note, for many
       quick test rounds. Mockups never deploy before owner approval.
171. **The orchestrator builds the UI (owner, 2026-10-07):** after GPT-built
     mockups were repeatedly rejected as heavy and unsubtle, every UI mockup
     and UI change is written by the orchestrator (Claude) itself, in the
     product code, and checked by clicking through it before the owner sees
     it. Codex jobs keep backend, tests, measurement and mechanical work. The
     taste rules apply to all UI: subtle; focus rings only for keyboard focus;
     no glossy bevels on in-page controls (glass only for floating overlays,
     D160); desktop-sized controls on desktop; every state change animated;
     one input rather than mode tabs; no settings sections inside flows.
172. **Discovery sources live only in Settings (owner, 2026-10-08; supersedes the
     in-flow switches of D141-H11):** add host never shows source toggles or
     an "extended information" switch. Discovery uses every source
     automatically; per-source switches exist only in Settings.
173. **QUIC's binary cost is accepted (owner, 2026-10-08, #78):** the quinn QUIC
     transport (D41) needs rustls with the ring provider next to OpenSSL; it
     adds about 2.8 MB (x86) and 2.4 MB (ARM) to the static binary. Pointing
     rustls at OpenSSL saved only 0.4 MB and nearly doubled per-connection CPU,
     so it was rejected. The size baseline is raised for this growth only,
     with the per-crate breakdown recorded; the allowance for future growth
     stays 256 KiB.
174. **Type scale: one text size, bigger touch targets (owner, 2026-10-08):**
     text sizes follow the sign-in card on every platform (no larger phone
     text scale); touch devices get 44 px targets through padding and row
     height only. Supersedes the separate touch text scale in TASTE.md.
175. **Maple Mono NF is the default font (owner, 2026-10-08):** the UI and the
     terminal use Maple Mono NF (SIL OFL 1.1, AGPL-compatible) instead of
     Geist Mono, for its cursive italics, ligatures and Nerd Font glyphs
     (which fix powerline symbols in prompts). Fonts are subsetted and
     self-hosted as woff2 to keep load time low; ligatures are on in the UI,
     and in the terminal only where they keep every glyph on its cell
     (measured, with cursor-alignment tests).
176. **QUIC stays on quinn + rustls + ring (owner, 2026-10-08, #88):** measured
     against OpenSSL's native QUIC on the same harness. rustls + ring
     handshakes in 0.96 ms vs 4.9 ms, holds 44 KB per idle connection vs
     70 KB (about 44 MB vs 70 MB at 1,000 hosts), matches throughput on a fast
     link, integrates directly with the async runtime and supports 0-RTT.
     OpenSSL's only advantage is about 1.8 MB of binary size, already
     accepted in D173. The delayed-path row needs a rerun with matched packet
     loss before its exact gap is quoted; it does not affect this choice.
     Next: measure BBR congestion control at the India–Germany latency.
177. **Canvas vocabulary, toolbar and locks (owner, 2026-10-08, #89, #91):**
     - **Names:** the *toolbar* is the bottom bar on touch devices, with
       two rows: the *key row* (terminal keys the on-screen keyboard
       lacks) and the *canvas row* (canvas controls). The *canvas lock*
       (snap) keeps the canvas snapped to windows; the *input lock* (the
       padlock) keeps all input inside one window. A *view* is a named
       area of the canvas (Console, Containers, Topology); the *top pill*
       is the centred pill at the top.
     - **Rows:** switch automatically by focus; swipe up for the canvas
       row, down for the key row; horizontal swipe scrolls a row. The
       toolbar never hides (slim strip while reading scrollback).
     - **Canvas row:** ⌘K · views · ← → window · canvas lock · overview ·
       input lock · split · add host · sidebar, customisable in
       Settings → Toolbar (reorder, show/hide, reset).
     - **Key row:** current keys, sticky Ctrl/Alt, Paste; custom keys later.
     - **Canvas lock:** on by default and re-enabled on every view switch
       or fly-to; one window per swipe (a flick may move two); phones show
       neighbours peeking; one finger scrolls the terminal, two fingers or
       ← → move windows; when turned off it stays off until the next view
       switch. Desktop: icon buttons right of the top pill; ⌘1–9 views;
       the canvas lock is ⌘⇧G (Ctrl+Shift+G elsewhere).
     - **Top pill:** the view's icon and name, a quiet session count, the
       connection status icon and the ⌘K hint; tap for the view switcher;
       it is the morph source for `?` and the floating terminal; it does
       not name the active window.
     - **Input lock on touch:** in the canvas row; input stays in the
       window, swipes don't move windows, the key row stays; locking with
       the canvas lock off snaps to the window first and unlocking
       restores the previous state.
     - **Follow-ups (same day):** every shortcut is configurable in
       Settings → Shortcuts (one registry feeds `?`, ⌘K, tooltips and the
       toolbar; conflicts warn with swap or cancel). The toolbar layout is
       per account with a per-device override. Long-pressing the toolbar
       opens the same editor in place (wiggle, drag, hide, add). A
       horizontal swipe on the top pill steps between views with motion,
       and the canvas lock re-engages on landing.
178. **Sessions, the per-account canvas and the sidebar (owner, 2026-10-08, #89):**
     - **The canvas belongs to the account:** open windows and their
       arrangement are the same on every device; each device keeps only
       its own camera (current view and position). A ⌘K "Jump to where you
       were on <device>" action hands off between devices.
     - **Session states:** open (has a window on the account's canvas),
       detached (running, no window), exited (final screen and exit code
       kept with "Run again" until dismissed or 7 days). Viewing by other
       accounts ("shared") is designed with multi-user (enterprise).
     - **Splits and windows:** a split always opens a new shell, no prompt;
       splits are windows in the one structure, no nesting, with the
       droplet animation. Closing a window never ends its session.
       Detached sessions are never ended automatically by default; an
       optional per-host idle limit exists.
     - **Terminal size:** when a session is visible on several devices,
       the device last typed on decides the size, automatically; others
       show it scaled to fit.
     - **Names:** automatic from the running command or folder (later
       inferred from what the user is doing), renameable; the session
       name is the window's name.
     - **Activity:** detached sessions show a quiet dot for new output and
       ✓/✗ when a command finishes; push notifications later.
     - **Session manager:** an icon at the top right of each window
       (desktop), an action in the mobile canvas row, and every session
       on every host in ⌘K.
     - **Sidebar = inventory, canvas = workspace:** the sidebar has one
       section per view the account's grants allow (Console, then
       Containers, VMs and so on as they arrive), each listing hosts and
       their items with open/detached/exited markers, ordered by frecency;
       tapping a view flies the canvas there, tapping an item opens or
       flies to it. Section expansion belongs to the account.
     - **Settings → Devices:** lists every device signed in to the account,
       with where each is looking, for handoff.
       Each device has an editable name, type, last seen, current view and
       online state, with "Jump to its view" and "Sign out this device"
       (compact confirm). Opening the app on a different device shows a
       one-time "Continue from <device>?" chip that fades on its own.
179. **Settings is a view on the canvas, not an overlay (owner, 2026-10-08, #89):**
     Settings is a view like Console or Topology, listed last in the sidebar
     and the view switcher. Each section (Appearance, Toolbar, Shortcuts,
     Devices, Account, About; admin sections by grant) is a window in that
     view, using the same window frame, tiling and canvas lock. ⌘K jumps to
     any section. Leaving Settings is switching views. Changes apply live.
     Supersedes the Settings overlay mentioned in D177 and D178.
180. **The canvas document (owner, 2026-10-08, #93):** our own small,
     versioned JSON format (`infraternal.canvas`), per account (D178).
     - It holds layout and references only, never content (no scrollback,
       secrets or configuration).
     - Views have a kind and a layout (tiled: columns of windows with
       relative weights; graph: nodes and edges). Views sit on a coarse cell
       grid.
     - Windows reference their target by a stable ID plus a readable name;
       the same IDs back deep links (#86).
     - Edges reference grants by name only, never the rules themselves.
     - Sync works by small server-applied operations with a revision
       number, so concurrent edits from several devices all survive.
     - Graph nodes are laid out automatically; nodes the user drags are
       pinned and saved.
     - Exports: our JSON (with import), Markdown, image (share studio, #94)
       and Excalidraw; JSON Canvas only if cheap. IPs are redacted by default
       in exports, hostnames and usernames on request.
     - The Topology view is renamed **Mesh**.
     - Live sharing of content (a link for instance users or anonymous
       viewers, with view or edit permission) is a separate feature from
       the share studio, still to be designed.
181. **Adding hosts uses the system OpenSSH (owner, 2026-10-08, #78):** the
     add-host flow runs the system `ssh`, so the user's `~/.ssh/config`,
     `known_hosts`, keys and agent work unchanged. A built-in client (russh)
     comes later for interactive browser sessions, with its own security
     review, and falls back to the system OpenSSH wherever it lacks support.
182. **Sharing layouts with teammates (owner, 2026-10-08, #93):** a layout (one
     or more views, picked in the share dialog; "everything" is selecting
     all) can be sent directly to users or groups on the instance. The
     recipient gets a **copy** that is theirs to change, arriving as a new
     view on their canvas (named after the sender, e.g. "Incident (from
     kayg)"), never replacing or merging into an existing view, with a quiet
     notification. Windows connect as the recipient through their own grants
     ("no access" where they lack one). Admins and owners can also publish
     **team layouts** that stay linked and update for everyone who follows
     them (enterprise). Export and import use the same mechanism across
     instances.
183. **Backend for the real canvas and add-host (owner, 2026-10-08, backend
     grill round 1, #98, #99, #100, #87):**
     - **One connection:** a device's windows share its one WebSocket as
       streams of the multiplexed protocol (D11).
     - **Hidden windows:** windows off-screen, in other views or zoomed
       out get no live bytes, only a "changed" marker. They get a snapshot
       when shown; thumbnails refresh at about 2 Hz.
     - **The canvas document** (D180 JSON) lives in the server's SQLite per
       account as an operation log plus periodic snapshots, over the same
       WebSocket. Each operation carries its base revision; the later edit
       of a window wins, and a close beats a move or resize.
     - **Add-host** runs from the infraternal server with the system
       OpenSSH (D181). It detects automatically whether **network auth**
       (NetBird, Tailscale, Twingate and similar) or **local auth** applies.
       Local auth tries the server's own dedicated Ed25519 key first (never
       the system's keys; locked with the CA after a cold start, D168),
       then the user's passkey-encrypted key, then a password used once.
       It asks the user to choose only as a last resort; a pasteable
       one-line install command remains for unreachable hosts.
       The server's key is created automatically on first start and its
       public half is shown in Settings, ready to copy into hosts.
     - **Exited sessions** keep the final screen and the last 256 KB of
       output on the server for 7 days or until dismissed. A fast command
       history and log search (history-style and log-indexing features)
       comes later.
     - **Names:** the infraternal agent derives session names from the
       foreground command and working folder, only while active.
     - **Command finished:** comes from shell integration markers, else
       "output stopped and the prompt returned". Shell integration is
       injected automatically and additively without editing the user's
       shell files.
     - **Terminal size** follows the device that last sent keys or a paste,
       with about 500 ms of hysteresis; focus, scroll and viewing don't
       count.
184. **Update source and signing (owner, 2026-10-08, backend grill round 3):**
     server and agent releases come from **builds.infraternal.com** (the
     URL stays configurable). Every release is signed, and the server refuses
     unsigned or wrongly signed artifacts. The release signing key's public
     half is built into the binary and the private half never lives on a
     server.
185. **Updates, channels and relays (owner, 2026-10-08, backend grill round 3):**
     - **Updates:** the server updates itself automatically as soon as a
       verified release appears, keeping the previous binary for automatic
       rollback when the new one fails its health check (mirroring the agent
       A/B swap, D135). A quiet window or manual updates are optional
       settings.
     - **Channels:** "stable" by default; anyone can opt in to "edge" (the
       owner runs edge).
     - **Signatures:** minisign-style Ed25519 (D184), verifiable offline.
     - **Relay and direct path, side by side:** relay mode (the TURN relay in
       the same binary, the server relaying by default, and the "Run a relay
       here" checkbox) and the WebRTC direct path are built side by side, so
       they can be benchmarked against each other.
     - **Relay choice:** the client automatically uses the relay with the
       lowest measured round trip, re-checks on network changes and switches
       mid-session without losing bytes; the user can override the choice
       at any time.
186. **Channels, backups and recording (owner, 2026-10-08, backend grill round 4):**
     - **Both channels are public** on builds.infraternal.com: stable by
       default, edge opt-in for anyone (labelled "may break"); Forgejo and
       GitHub are mirrors. Supersedes D155's "no public edge channel" and
       "no central update server" (the builds host is the project's own).
     - **Backup destinations** (extends D147): local, any infraternal host,
       S3-compatible and SFTP, plus **Proxmox Backup Server**. Every
       destination receives only already-encrypted backups. PBS gets
       **native** support only (no CLI wrapper), built later; its library
       choice is measured and brought to the owner when that work starts.
     - **Backup proof:** the latest backup is test-restored automatically
       every week into a scratch area and verified; failures alert the
       admins.
     - **Backup key:** a dedicated key wrapped for every admin (as D168 does
       for the CA), not one person's recovery words.
     - **Recording and audit mode** (D128): off by default, enabled per host
       group or role; recorded by the infraternal agent, signed and uploaded;
       a compact binary format with timing, replayed with the same terminal
       renderer; kept 90 days; an enterprise feature.
187. **Several people on one instance (owner, 2026-10-08, backend grill round 5; refines D154):**
     - **Visibility:** owners and admins see every session; everyone else sees
       only their own. Joining a colleague's session goes through explicit
       sharing (#96).
     - **Joining:** shared sessions use the share's permission (view or
       edit). An admin looking in uninvited is view-only, and typing needs the
       session owner's approval. Every join is shown to the session owner and
       audited (D154 G9).
     - **Views follow grants:** a view appears when the person holds any grant
       whose role includes that view's actions on at least one host. Settings
       is always present; admin windows appear only for admins. There is no
       separate view permission.
     - **Granular roles:** permissions such as "publish team layouts" (D182)
       are actions inside roles. Roles are granular, and custom roles are
       easy to make (start from a built-in role, tick actions), keeping the
       system simple (D154 G4).
     - **Presence:** avatars on a window's pill when others have the same
       session or view open, and an "is typing" marker; no extra cursors (a
       terminal has one).
188. **Transfer budgets: a strict critical path, a separate deferred budget (owner, 2026-10-08):**
     the JavaScript transfer gate measures the **critical path** (everything
     needed before the first paint of sign-in and the first screen) against
     the existing strict budget, which serves the under-1-second first paint
     on a mid-range phone. Code loaded after the first paint (the canvas
     views, Mesh, toolbar editing, the droplet, settings windows) has its own
     separate budget, so neither can grow unnoticed. Budgets change only with
     measurements in the commit.
     **A third class, on demand (owner, 2026-10-08):** code loaded only when
     the person takes an action (the add-host wizard, the share studio,
     Settings windows) has its own budget instead of counting as
     after-first-paint code.
     **Critical budget raised to 320 KiB gzip / 267 KiB brotli (owner,
     2026-11-01):** dev measured gzip 306,074 B (300 KiB cap) and the approved
     #259 rename work alone reached 307,714 B; the owner chose a moderate
     raise that keeps the gate (growth stays visible) over removing it or
     loading rename on demand. Big features still load on demand.
189. **Card and window transparency (owner, 2026-10-08):** four levels for each,
     "Glass" renamed **Frosted**. Dark/light tint and blur:
     - **Solid:** cards 1.00/1.00, 0 px; windows 1.00/1.00, 0 px.
     - **Tinted:** cards 0.70/0.78, 8 px; windows 0.85/0.90, 0 px.
     - **Clear:** cards 0.40/0.50, 24 px; windows 0.65/0.75, 0 px.
     - **Frosted:** cards 0.20/0.30, 32 px; windows 0.45/0.55, 24 px.
     Defaults are **Tinted cards and Solid windows**. Every level must keep
     text legible (ghost-text and contrast checks). Per-level performance
     benchmarking is deferred; the code paths stay cheap (Solid windows paint
     no transparency or blur).
190. **The droplet split (owner, 2026-10-08):**
     - **Budding:** a small droplet swells out of the window's edge on the
       split side, pinches off through a liquid neck, snaps free with a
       wobble, then grows into the new window while the original springs to
       its new size.
     - **Content:** stays crisp. The liquid is the frame and outline only;
       the new shell fades in once grown, and text is never warped.
     - **Timing:** about 500 ms (bulge ~120, stretch and pinch ~150, snap,
       wobble and growth ~230), interruptible; reduced motion crossfades.
     - **Closing a split window** plays the reverse: it shrinks into a
       droplet that flows back and is absorbed with a small ripple.
     - **Rendering:** a per-pixel signed-distance smooth-min silhouette in a
       single short-lived GPU surface (iOS memory rule), anti-aliased at the
       device's real density, held to 60 fps or more.
191. **Phone window width, the keyboard and the plain background (owner, 2026-10-09):**
     - **Background:** the default background is **Plain** (it was Soft).
     - **Window width:** on phones a terminal window takes 99% of the screen
       width by default; desktop keeps today's width. The width is a setting
       under **Settings → Window Sizes**, with plain option names (technical
       detail, such as the percentage, only in an option's subtitle).
     - **Keyboard:** the on-screen keyboard never changes a window's width or
       its terminal's columns; only the height adapts.
     - **Focus on open:** a terminal never looks ready for typing (a blinking
       cursor) unless the keyboard can actually appear; on iOS the keyboard
       needs a tap, so the first tap on the terminal opens it.
192. **The direct path uses str0m (owner, 2026-10-09):** the browser-to-host
     WebRTC direct path (D185, #103) is built on str0m 0.24.x (sans-IO, driven
     by our own transport event loop; OpenSSL, already in the binary). Chosen
     over webrtc-rs 0.21 on the quiet perf-VM comparison: keystroke echo p99
     0.90 vs 2.90 ms, connection set-up 8.5 vs 209 ms, throughput equal within
     noise (11.3 vs 12.8 MiB/s median, overlapping ranges). The webrtc-rs
     candidate is removed; the trait boundary stays so the engine remains
     replaceable.
193. **Full screen a terminal (owner, 2026-10-09):** any terminal window can
     go full screen: it fills the viewport and shows nothing else except one
     small exit (un-full-screen) control in the top-right corner, which is
     always visible, on desktop and phone. On phones the key row is the only
     other thing shown (while typing). Keep it simple: no extra gestures or
     hidden chrome. It returns exactly where it was; the window grows to the
     viewport and the terminal refits once at the end. Mockup first (D162).
194. **Mesh arrows live only in the Mesh view (owner, 2026-10-09):** access
     arrows and the drag-to-allow connector are drawn only inside the Mesh
     view. Terminal windows on other views never show arrows on hover, split
     or move.
195. **Resizing windows (owner, 2026-10-09):** every window has four edges and
     four corners of its own, and a resize always moves the edge or corner
     being dragged; the opposite edge stays put. There is no shared divider
     between neighbouring windows: other windows make room by moving, never
     by changing their own size. Any window can be resized, including one
     alone in its strip, between the minimum size and the widest option of
     Settings → Window Sizes (D191), with the matching resize cursor on every
     edge and corner.
196. **Getting through NATs (owner, 2026-10-09, mesh grill N1–N6):**
     - **Direct paths, our own:** each node learns its public address from
       the server and relays (address discovery), the server swaps the
       candidate addresses between the two peers, and both send at the same
       moment to open their NATs. Built on our QUIC transport and relays
       (D176, D131). A job measures success rates per NAT type.
     - **Hard NATs** (both sides port-changing) are relayed in stage 1; port
       prediction is added only if measurements show many relayed pairs that
       could have been direct.
     - **Router port mapping:** nodes ask the home router to open a port with
       PCP and NAT-PMP first and UPnP as a fallback; on by default, with a
       per-node switch.
     - **Networks that block UDP:** relays also accept the mesh over TCP/TLS
       on port 443, so the mesh works wherever a website does.
     - **Any node can be a relay** (D131); peers pick the lowest-latency
       relay, as for terminals (#103).
     - **Priority features:** SSH over the mesh with our identities, exit
       nodes and subnet routes are very important and move ahead of the
       other extras (D164 had exit nodes and subnet routes "later"); a
       public exposure of services, file drop, device posture checks and
       connection logs come later.
197. **Mesh round 2: SSH, roles, DNS, exit nodes, routes (owner, 2026-10-09):**
     - **SSH over the mesh (M1):** works exactly like NetBird SSH and Tailscale
       SSH: the infraternal agent serves SSH on the mesh address only,
       authenticates the connecting mesh identity against the arrows, and
       needs no change to the host's sshd; plain `ssh host.internal` works.
       A lone SSH server is one easy command (`infraternal mesh up --ssh`).
     - **Every role runs on its own:** server, agent, relay, SSH, backup (and
       mesh) are each usable independently with sensible defaults. Roles turn
       each other on where it is obviously right: a host provisioned through
       add-host gets the agent, which enables SSH and relay; backup checks the
       free space and enables itself when there is enough.
     - **CLI:** human-readable, intuitive commands for everything, each with
       `--json` for scripts and AI agents.
     - **Exit nodes (M2):** an administrator marks any node as an exit node;
       arrows decide who may use it; clients pick one, with a "keep access to
       my local network" switch.
     - **Subnet routes (M3):** a node advertises networks; an administrator
       approves each; traffic is masqueraded by default (keeping the real
       address is an option); an approved network is a target for arrows in
       the Mesh view; overlaps are refused with a plain explanation. The
       Mesh view must make all of this pretty, simple to change and easy to
       read.
     - **Coexistence (M4):** our mesh runs side by side with NetBird and
       Tailscale; opt-in migration paths come later.
     - **Paths (M5):** whatever gives the least interruption and latency:
       probe at start and on network changes, switch only on a clear,
       sustained win, never lose bytes (D128), prefer direct when equal.
     - **Mesh settings in the UI:** change the address range and the domain
       suffix, add custom DNS records (name = value) for the whole mesh, and
       forward every other query to an upstream resolver of the owner's
       choice (a public resolver or their own, e.g. AdGuard).
     - **Build order (M6):** WireGuard data plane with coordinator wiring and
       deny-by-default first, then NAT traversal and port mapping (D196),
       then TCP/443, then SSH, subnet routes and exit nodes. The UI is
       mocked up as the pieces land.
198. **Every role and feature is a plugin you can switch and remove (owner,
     2026-10-09; restates D3, D15, D16):** server, agent, relay, SSH, mesh,
     backup and every later feature are plugins behind
     `infraternal-plugin-api`:
     - **Removable at build time:** each plugin is its own crate behind a
       cargo feature; a build without it compiles and runs, and its UI
       package drops out of the bundle.
     - **Switchable at run time:** each can be turned on or off per node
       (Settings, `infraternal <role> up|down|status`, API, MCP) without a
       restart of the others; turning one off leaves no listener, timer or
       background work behind.
     - **Declared, not wired by hand:** a plugin declares its actions,
       permissions, settings, defaults and which other roles it can turn on
       (D197), and the core discovers them; no feature is special-cased in
       the core.
     - New work (mesh data plane, relay, backup, metrics) is built this way
       from the start; existing code moves behind the interface as it is
       touched.
199. **Mesh settings and the CLI shape (owner, 2026-10-09, grill G1–G6):**
     - **No change ever drops a connection (G1):** changing the address
       range, suffix, rules or keys is seamless: names update first, nodes
       carry old and new addresses until every peer has moved, and only then
       is the old state removed.
     - **Old domain suffix (G2)** keeps resolving as an alias for 7 days, with
       a notice in the Mesh view saying when it stops.
     - **Upstream DNS (G3):** plain DNS, DNS over HTTPS and DNS over TLS, one
       global upstream plus selective routing (send chosen domains to chosen
       resolvers, e.g. a home AdGuard for one zone).
     - **Backup turning itself on (G4)** waits for a measurement of how large
       backups grow, and a separate backup grill (including high
       availability, automatic rollback of failed updates, and the
       architecture they need).
     - **CLI (G5):** one pattern for every role, `infraternal <role> up |
       down | status` (e.g. `infraternal mesh up --ssh`), each with `--json`;
       bare `infraternal status` summarises everything running on the
       machine. Very intuitive, very easy.
     - **Mesh view extras (G6):** "why can't A reach B", preview and undo of
       changes, temporary access, service discovery, live paths, `infraternal
       mesh doctor` and per-arrow traffic are each filed as an issue, to be
       grilled and refined for the easiest UX before they are built. Per-arrow
       traffic and service discovery grow with a later metrics, graphs and
       logs component. The basics come first.
200. **Remote desktops: native capture first (owner, 2026-10-09, VNC grill
     V1–V8; extends D104–D107):**
     - **Capture (V1):** where the infraternal agent runs on the machine, it
       captures the screen natively (ScreenCaptureKit on macOS, PipeWire or
       X11 on Linux) and encodes with the machine's hardware encoder; VNC
       stays for machines without an agent (Proxmox/QEMU consoles,
       appliances, third-party VNC servers). Both feed the same server-held
       session (D104). Feasibility is researched first (#139).
     - **Quality (V2):** latency first, adaptively: responsive on poor
       connections matters more than fidelity; at LAN speeds both. Video
       while things move, a sharp refresh once the screen settles. Encoder
       libraries come to the owner as measured candidates.
     - **Resolution (V3):** stream at the size the window needs (its
       on-screen size × the device's density), adapting on resize and zoom;
       full resolution in full screen.
     - **Phone input (V4):** trackpad mode by default (drag moves a cursor,
       tap clicks, two-finger scroll), direct touch one switch away; the key
       row gains Esc, Ctrl, ⌘, arrows and more; clipboard sync both ways when
       allowed.
     - **Several viewers (V5):** one person controls input at a time; others
       watch; taking control is one tap with a visible handover.
     - **Apple Screen Sharing logins (V6):** Macs with our agent first
       (native capture, no password); Apple's VNC login types later.
     - **In the canvas (V7):** a desktop is a window type like a terminal
       (frame, header pill, splits, full screen, lock, frame meter); off
       screen it stops streaming and keeps only its last frame.
     - **Order (V8):** native macOS capture, then Proxmox/QEMU over VNC, then
       native Linux capture, then RDP (IronRDP). Browser windows reuse this
       pipeline (#140).
201. **One control plane, many node components (owner, 2026-10-09, N7):**
     - **The server is the control plane** (sign-in, database, rules, web
       UI), one per deployment. It is created only by an explicit, confirmed
       `infraternal server init` ("This machine will become an infraternal
       server"; `--yes` for scripts), which prints the setup token; afterwards
       `infraternal server` runs it as a service. No other command ever
       creates a server.
     - **Server features, not modes:** what the server offers (terminals,
       mesh coordination, backups, add-host, …) is a set of features
       switchable at any time in Settings → Server and with `infraternal
       server features`; setup asks "What should this server do?" with all
       ticked. A mesh-only server is the same server with only Mesh ticked.
     - **Node components:** `infraternal up` joins this machine to a server
       with sensible defaults (agent, SSH, relay, mesh node, backup where
       there is room); it finds or asks for a server and can never create
       one. Each component also runs alone: `infraternal <component> up |
       down | status` (mesh, relay, ssh, backup, agent). The server machine
       also joins as a node.
     - `infraternal status` shows the machine's role ("server" and/or "node
       of <server>") and every component running; every command has `--json`
       (D199).
202. **The CLI is pretty by default and teaches AI agents (owner, 2026-10-09):**
     - **Output:** every command prints clean, organised, human-readable
       output by default: short sections, aligned columns, plain-language
       states and next steps, colour and symbols used sparingly and turned
       off when output is not a terminal or `NO_COLOR` is set. `--json` gives
       the full machine form for every command (D199).
     - **`infraternal skill`:** prints agent skills for AI agents: for each
       command and subcommand, a concise description and step-by-step
       instructions (what it does, when to use it, inputs, outputs, `--json`
       shape, safety notes such as dry-run first for destructive actions).
       `infraternal skill` lists them, `infraternal skill <command>` prints
       one, and an option writes them as skill files for agent tools.
     - **One source:** help text, skills, the API, MCP and UI labels come
       from the same action definitions (D16), so they never drift; wording
       follows the plain-language rules (#112). Concise, cleanly organised,
       methodical.
203. **Terminal images and native capture, round 2 (owner, 2026-10-09):**
     - **Images (I1):** the shim keeps the original compressed PNG and sends
       it; browsers decode it in a Worker, cached by digest.
     - **Formats (I2):** the terminal renders only kitty formats (PNG, raw
       RGB/RGBA). Any other image format is converted to PNG and shown inline,
       with the original stored in shell history. Conversion of formats
       without a trusted decoder is decided in I2a.
     - **Decoder (I4):** the most performant and reliable PNG decoder by
       measurement (speed plus fuzzing), reported to the owner.
     - **Capture (C2):** on macOS the infraternal agent stays a daemon; a
       small per-user helper in the logged-in session does capture and input,
       as part of the desktop plugin (D198).
     - **Engines (C4):** capture bindings and encoders are measured
       (latency, CPU and memory per session at ×10 and ×50); nothing chosen
       without numbers. The owner has an Apple Developer account for signing
       (C3, set up later).
     - **Test Mac permissions (C1):** jobs may grant Screen Recording and
       event-posting permission to our own spike binary on the shared macOS
       VM, through VNC over an SSH tunnel, and remove them afterwards.
204. **macOS capture bindings and encoder (owner, 2026-10-09, #139):**
     - **Bindings (C5):** the maintained `screencapturekit` Rust crate,
       pinned to an exact version after an AGPL compatibility check, behind
       our capture trait so it can be replaced. Measured on the macOS VM at a
       960×600 window: 0.8 / 3.6 ms delivery p50/p95 against 29.6 / 158.6 ms
       for generated `objc2` bindings, which also reported spurious idle
       frames.
     - **Encoder (C6):** VideoToolbox. H.264 first for the widest browser
       support; HEVC where the browser supports it. Encode latency is
       re-measured on physical Apple hardware when the owner's Mac is
       available (the VM measured 25–30 / 40–44 ms at 1080p60).
205. **Binary size, image limits and unsafe formats (owner, 2026-10-09):**
     - **Binary size (B1):** the binary may grow as features land; growth
       is not a reason to block a feature. Every change still optimises and
       strips aggressively (features off by default where D198 allows,
       no duplicated dependencies, size-focused build settings), and each
       job reports its size change with what it comes from.
     - **Image limits (I3):** up to 4096 px on a side and 4 megapixels per
       image, about 32 MB of images kept per terminal with the oldest
       dropped first; a larger image shows a "too large, open original"
       card.
     - **Formats without a trusted decoder (I2a):** conversion runs in a
       sandboxed helper with memory-safe decoders; HEIC and AVIF show a
       placeholder card with the original kept in history until a trusted
       decoder exists.
206. **Shortcuts and the iteration loop (owner, 2026-10-09):**
     - **Rebindable shortcuts:** every shortcut can be rebound and is
       remembered per account; per-device overrides come later with their
       own UX round (the model leaves room for them). Defaults never use
       Option/Alt alone (it is Meta inside terminals and types characters
       on macOS) nor Ctrl+Alt on Windows/Linux (it is AltGr on many
       layouts). On macOS, split right and split down default to
       ⌃⌥R / ⌃⌥D, with ⌘D / ⌘⇧D kept as alternates; elsewhere Ctrl+Shift+D
       and Ctrl+Alt+Shift+D stay. Browser reload (⌘R/Ctrl+R) is never
       taken. Keyboard actions never animate.
     - **Merging (P1):** a branch merges and deploys when its review has no
       P0/P1 findings; P2/P3 failing tests are fixed forward in the next run.
     - **Reviews (P2):** one full review per branch, then delta reviews of
       each repair's diff plus the earlier findings.
     - **Testing (P3, P5):** production is the owner's test target; the
       mockup is only for unbuilt UI and is rebased onto dev before every
       publish.
     - **UI authority (P4):** the orchestrator decides reversible UI details
       on its recommendation and the owner vetoes afterwards; foundational
       and security choices still wait for an explicit answer.
207. **Stream what people already use first (owner, 2026-10-09):** streaming
     apps that are already open and signed in on the owner's machines comes
     before the server-held browser window, because it needs no onboarding.
     An app window on a machine running the infraternal agent becomes a
     canvas window through the D200 pipeline (macOS first, using D204). The
     server-held browser window (#140, W1–W3) is parked for later
     exploration.
208. **App windows from a machine (owner, 2026-10-09, A1–A6; extends D200, D207):**
     - **What can be added (A1):** single app windows and the whole screen.
       A machine's "add window" list shows its open app windows with icon,
       app name and title; what infraternal shows about an app is inferred
       automatically from what macOS already records (researched first).
     - **Input (A3):** remote input brings the app forward; the Mac shows a
       small "Controlled from infraternal" indicator, and local mouse or
       keyboard input pauses remote input for 2 seconds so the person at
       the machine always wins.
     - **Menus and dialogs (A4):** the app's own windows that overlap its
       main window (menus, sheets, dialogs) are part of the stream; other
       apps' windows never are.
     - **Which apps (A5):** any app, no default exclusions.
     - **Order (A6):** macOS first.
     - **Permissions:** using Accessibility and Screen Recording is
       expected and fine; the code is open source so users can see exactly
       what is done with them.
     - **Resizing (A2):** the real window follows the canvas window (size ×
       the machine's pixel density) so the stream is 1:1 sharp with no bands,
       and returns to its original size and position when the stream closes.
       Letterboxing in the window's background colour is used only where
       following is wrong: an app that refuses the size (sized as close as it
       allows), or local input on the machine in the last minute (it snaps to
       size once the machine is idle).
209. **Mesh pages and Access (owner, 2026-10-09, grill round 1):**
     - **Pages:** Machines (landing list), Map (the canvas view), Names &
       routes; Mesh settings live in the global Settings (round 2).
     - **Names:** "Map" for the canvas view; user-friendly names everywhere.
     - **Access:** one table of rules, each row a sentence with chips
       ("[tag:ci] can reach [nix-cache]", "[group:ops] can operate
       [tag:prod]"); people and machine rules together, filtered by chips;
       it lives in the global Settings (placement in round 2).
     - **Editing:** the table and the Map edit the same rules and update
       each other instantly; rules are added with a sentence builder whose
       blanks are chip pickers; saving needs a fresh passkey.
     - **Chips are live:** hovering a chip shows useful facts; clicking it
       opens that item where it lives, without losing the dialog the user
       was in (UX in round 2).
     - **"Why can/can't X reach Y":** wanted, made simpler (round 2).
210. **Settings, Access placement and live chips (owner, 2026-10-09, grill round 2):**
     - **One Settings (S1):** a single "Settings"; each switched-on
       component adds its own section and it disappears when the component
       is off; component pages carry a small gear that opens their section.
     - **Access (S2):** Settings → Access, first in the list; each machine's
       popover has an Access row that opens it filtered to that machine.
     - **Chips in dialogs (C1):** hover shows a small fact card; click goes to
       the item, selected, instantly (no camera flight); the dialog parks in
       the top pill as a chip and one click restores it exactly; at most one
       parked dialog.
     - **K1–K3 ("can X reach Y", people, live state):** decided against a
       mockup.
     All of the above is mocked up while the backend is built.
211. **Scoped rule managers cover every tag (owner, 2026-10-09, F1):** to
     create, move, delete or rename an access rule that touches a machine, a
     tag-scoped manager must cover every tag that machine has, the same rule
     as editing the machine itself. Someone scoped to `prod` cannot change
     access into a machine that `dev` also owns.
212. **Four window actions: split divides, new window opens beside (owner,
     2026-10-10):** split right and split down divide the window's own space
     into two windows; new window right and new window below add a full-size
     window next to it.
     - **No nesting:** windows stay in one flat layout. Splitting a window
       that shares its column with others divides only that window's space:
       the layout is a flat grid in which a window may span columns, so the
       windows above and below keep their width. No window contains another.
     - **New window below** adds a full-size window under the current one;
       the column grows and the camera moves to it, as new window right does
       sideways.
     - **Keys use the usual terminal bindings:** ⌘D splits right and ⌘⇧D
       splits down (Ctrl+Shift+D and Ctrl+Shift+Alt+D off a Mac). New window
       right and new window below take ⌃⌥R and ⌃⌥D. All four stay
       rebindable and appear in ⌘K and the window's header pill.
     - **Words:** "Split right", "Split down", "New window right", "New
       window below". There are no tabs.
213. **Zig is the C toolchain for static builds (owner, 2026-10-10):** the
     C dependencies of the static musl binaries (OpenSSL, SQLite, and
     libghostty-vt, which is written in Zig per D94) are compiled with `zig
     cc` for x86_64 and aarch64, from one build host. The version is pinned
     (0.15.2) and the download is checked by SHA-256 in
     `scripts/auth-toolchain`. It lives in the build's target directory and is
     never installed system-wide. This confirms the choice a job made in
     469d0e87 (#17) without a grill. Rejected: a musl cross-gcc per
     architecture, and clang with a separate musl sysroot; both mean more
     toolchains to keep in step. There is exactly one Zig in the build: no
     second copy from the system or nixpkgs.
214. **Terminal connections: lowest latency, no arbitrary caps (owner,
     2026-10-10, replaces D183's "one connection"):** "do whatever is most
     performant/least latency because arbitrary caps make no sense."
     - The number of WebSockets per page is a measured choice, not a rule.
       The interim is a pool of 28 terminals per socket. The candidates are
       one socket with server-side priority for the active terminal, a pool,
       and the active terminal on its own interactive lane. They are measured
       on the India↔Germany link: typing echo p99 in the active terminal while
       other terminals flood, plus memory and handshakes. The lowest typing
       latency wins.
     - The server's fixed limit of 32 attachments per socket goes. Resource
       bounds replace it: bytes buffered per connection and streams per
       person, sized from measured memory. A limit must protect a resource
       and say which one; a round count protects nothing.
215. **Infraternal agents talk to the server over the mesh (owner,
     2026-10-10):** once a machine is in the mesh, its connection to the
     server automatically takes the best mesh path (direct, then relay, then
     TCP/TLS 443), using the same path selection as every other mesh link
     (D196, D197). The agent's 7-day certificate (D168) is its mesh identity.
     The server's agent port (D64, 7443) stays for the first join and as a
     last fallback. Owner: "that's good ux - it also removes the need to have
     ports open." It is built as part of the mesh data plane (#129), not as
     a separate feature.
216. **Mesh default policy depends on the edition (owner, 2026-10-10;
     amends D164):** the open-source edition is **allow by default**: a new
     mesh lets its members reach each other until rules narrow it. The
     enterprise edition ships **deny by default**. Either way, the default is
     one switch in **Settings → Access** (D210: Access lives in Settings and
     comes first), with a plain explanation. Rules in the Access table work
     the same under both defaults. Turning deny-by-default on shows, in one
     sentence, which machines lose reach before it applies.
217. **Updates never lock the CA; deploys use the in-memory handoff (owner,
     2026-10-10; implements D168):** D168 stays as written: the CA locks only
     on a real cold start (crash, reboot, power loss, manual stop/start,
     restore). Every update, including the orchestrator's deploys, replaces
     the server process through an in-memory handoff: the running server
     passes the unlocked CA key to its successor over a private,
     authenticated, local channel, without ever writing it to disk. If the
     handoff fails, the server simply stays locked, and that counts as a cold
     start. Deploying by plain stop/start, which locked the CA on every
     deploy on 2026-10-10, is retired.
218. **Closing a window ends its session only when nothing is happening
     (owner, 2026-10-10; amends D178):** closing a window ends the session
     only when the shell is the only process in its terminal session: no
     foreground program, no background or stopped job, nothing `nohup`ed or
     `disown`ed. This is checked across every process of the shell's
     session, not just its children.
     - **Kept:** a session running `tmux`, `screen`, `ssh`, `sudo`, an
       editor or any program is never ended. It stays in the background and
       is counted.
     - **Undo:** the shell is ended 30 s after the close. Meanwhile a toast
       "Closed · Undo" (or reopening the session) restores it exactly as it
       was.
     - Detection is conservative: when in doubt, the session is kept. The
       owner: "we should be really conservative here".
219. **UX audit decisions, round 1 (owner, 2026-10-10, #152):**
     - **Reattach on load:** when the Console has no windows on load, the app
       reattaches the person's most recent background session instead of
       starting a new shell. A new shell starts only when none exists. The
       audit measured 8 → 9 → 10 background sessions over three reloads.
     - **Recovery ships:** the recovery screen is included in production
       builds now. Setup no longer asks for 24 words that production can't
       use.
     - **Host keys over trusted paths:** a host's key is trusted on first
       contact when the host is reached over the mesh or a private network,
       and the person is asked only when a known key *changes*. Public
       networks keep the fingerprint confirmation (amends D181).
     - **`root@host` is consent:** typing `root@` counts as the root consent
       of D139, shown as one line explaining the effect, with no tick box and
       button.
     - **A typed password may install the server's key:** when the person
       signs in with a password or a key, the same connection installs this
       server's key on the host, so later reinstalls need nothing. Said in one
       line under the field. Not when the sign-in came from network identity
       (mesh or Tailscale/NetBird SSH identity), because no secret was given.
     - **Remove host uninstalls by default:** "Remove host" revokes the host's
       certificate first, then uninstalls the infraternal agent over its own
       connection (SSH as the fallback), then says "X was removed" (D134).
     - **Pending:** device keys (D151) wait for the PRF research (#153);
       shortcuts are re-grilled after their research (see #155); the agent
       binaries proposal, the built-in web app, TLS, `server init` and the
       single name field are still open.
220. **Agent payloads come from signed releases; the website is three pages
     (owner, 2026-10-10; implements D184, amends D44/D46):**
     - **Payloads:** to install a host, the server uses its own executable
       for its own architecture. Other architectures are downloaded from the
       signed release on **builds.infraternal.com** the first time they are
       needed, verified against the release key built into the binary (D184),
       and cached. The server checks this before the add-host flow asks
       anything, so nobody answers questions and then hits "binary
       unavailable". No files are placed next to the server by hand. This is
       the permanent fix; shipping both architectures by hand was a stopgap.
     - **Website:** infraternal.com ships exactly **/releases, /docs and
       /changelog**. /releases lists versions and links each artifact on
       builds.infraternal.com. The landing page, roadmap and waitlist of D46
       are dropped.
     - **Web app inside the binary (#152 Q10):** the web app is built into
       the server binary; `--web-root` stays as a development override.
       Automatic TLS belongs to a separate **reverse-proxy component**, a
       plugin per D198, not to the core server.
221. **Remote desktop: our own capture first, VNC as the universal fallback
     (owner, 2026-10-10; amends D105):** on a Mac running the infraternal
     agent, app windows and the whole screen come from our own capture
     (D207, D208). VNC is no longer the first Mac target. VNC is the lowest
     common denominator and fallback: it covers any machine our agent can't
     capture or isn't installed on (Linux desktops, Proxmox/QEMU consoles,
     appliances, and Windows until RDP or our own capture exists). It keeps
     D104's model: the server or infraternal agent holds the session. Order:
     app windows from a Mac (#146) first, then the VNC fallback, then RDP.
222. **Shortcuts follow each platform's terminals (owner, 2026-10-10;
     replaces D212's key table, amends D206; research #155):**
     - **Terminal conventions win** wherever the browser lets a page claim the
       key. Only keys the browser truly reserves (close tab, new tab/window,
       tab switching, quit) get the nearest free key. No function-key chords
       as defaults.
     - **Mac** follows iTerm2/Ghostty: ⌘D split right, ⌘⇧D split down,
       ⌘⇧P and ⌘K palette, ⌘] / ⌘[ next/previous window, ⌥⌘+arrows move
       between windows, ⌘+/⌘−/⌘0 font size, ⌘/ shortcuts panel.
     - **Windows and Linux** use the same actions on **Ctrl+Shift** (where Mac
       terminals use ⌘), following Windows Terminal, Konsole, Kitty and
       Ghostty: Ctrl+Shift+D split right, Ctrl+Shift+E split down,
       Ctrl+Shift+P/K palette, Ctrl+Shift+] / [, Ctrl+Shift+arrows,
       Ctrl+Shift+/ panel; font size on plain Ctrl+/−/0. Plain Ctrl+K and other
       shell keys always reach the terminal. No default uses Ctrl+Alt (AltGr).
       The Windows/Super key is never a default: the OS and desktops own it.
       It stays available through rebinding.
     - **Reserved keys:** close window (⌥⌘W on Mac) and new window
       right/below take free keys. The final choice comes from a real-browser
       test (Chrome, Edge, Safari, Firefox; tab and installed app). The owner
       sees the final table before it ships.
     - **Matching by character,** not key position, with labels from the
       person's keyboard layout.
     - **Fullscreen bonus:** where the browser supports Keyboard Lock in
       fullscreen (Chrome, Edge, Safari 26.4; not Firefox), the reserved keys
       work too: ⌘W closes the window, and any key that isn't ours (for
       example Ctrl+W, Ctrl+T on PC) goes straight into the terminal, as in a
       native terminal. Automatic, with no setting.
223. **Website and builds on Cloudflare (owner, 2026-10-10; implements
     D184, D220):** infraternal.com (/releases, /docs, /changelog) is served
     by Cloudflare Pages. builds.infraternal.com is a Cloudflare R2 bucket on
     a custom domain, holding the signed release artifacts, checksums and
     signatures. Binaries go to R2, not Pages, because of the size limit per
     Pages file. The owner owns infraternal.com, and its DNS is on Cloudflare.
     Downloads never depend on the owner's homelab. Signing (D184) keeps the
     artifacts trustworthy wherever they are hosted. Deploying either site
     needs a Cloudflare token scoped to that job (Pages; R2 for one bucket).
     The owner provides it, and it never enters the repo, logs or argv.
224. **Release signing: a Cloudflare Worker secret, keys mastered in 1Password
     (owner, 2026-10-10; amends D184):** two Ed25519 keys are created in the
     owner's **personal** 1Password: the signing key and a spare. Every
     binary trusts both public keys.
     - **Signing:** the signing key's private half (exported as PKCS#8) is a
       write-only Cloudflare Worker secret. The Worker
       (`apps/release-signer`) hashes a release's files in R2 itself, signs
       SHA256SUMS as an OpenSSH signature (namespace "infraternal-release",
       verifiable with `ssh-keygen -Y verify`), appends to the public
       releases/index.json and notifies the owner.
     - **Nobody but the Worker can use the key.** Agents and the pipeline
       can ask for a signature, but cannot read the key. Their Cloudflare
       token never gets Workers edit rights, and only the owner deploys the
       Worker, because whoever can change its code could read the secret.
     - **The spare** never leaves the owner's personal vault. It signs only a
       rotation that retires the signing key; servers follow on their next
       update check.
     - **Rejected:**
       - a key in a 1Password service account, which is readable in full;
       - a root-only signer on the build host, which passwordless sudo
         defeats;
       - the Mac Secure Enclave and the 1Password SSH agent, which need the
         owner for every release.
225. **Add-host gets its binary by architecture (owner, 2026-10-10; amends D220):**
     - **Same architecture as the server:** the server copies its own
       running binary to the new host.
     - **Another architecture:** the server downloads the binary for that
       architecture, at the server's exact version, from
       `builds.infraternal.com`, and verifies its signature (D224, both
       built-in keys) before sending it. The host never trusts the network:
       the server verifies, then sends it over the existing SSH or mesh link.
     - **Already downloaded:** a verified download is cached under the
       state directory (#34), so a second add-host of that architecture is a
       local copy.
     - **Failure:** if the download or verification fails, add-host stops at
       a named step ("Get the arm64 binary") and says why; nothing unverified
       is ever installed.
     - **Development builds** that are not on `builds.infraternal.com` fall
       back to a locally built payload next to the server, as before.
226. **Two release channels, stable by default; edge is an explicit opt-in (owner, 2026-10-11; amends D224):**
     - **Channels:** `stable` (versions `x.y.z`) and `edge` (versions
       `edge-<UTC timestamp>`, written `edge-YYYYMMDDTHHMMSSZ`, for example
       `edge-20261011T071500Z`; it sorts by time as text).
     - **Default:** every install and update follows `stable`. Switching to
       `edge` is a deliberate, explicit action that names what it means
       (unreviewed builds, published as they are made); nothing switches to
       it silently, and no prompt nudges toward it.
     - **For now only edge is published.** Until a stable release exists, a
       stable install reports that no stable release is available yet and
       how to opt in to edge, instead of falling back to edge.
     - **The channel comes from the version string,** which the signed
       `VERSION` file carries, so it is covered by the release signature;
       there is no separate unsigned channel field to trust. The signing
       Worker also writes `releases/channels/<channel>.json` pointing at the
       newest release of each channel.
     - **Add-host** keeps D225: a new host gets the server's exact version,
       whatever its channel.
227. **Mesh build order after slice 1 (owner, 2026-10-11; amends D197 M6):**
     1. **D215:** infraternal agents reach the server over the mesh, so
        the product's own traffic travels through it.
     2. **TCP/TLS on 443 (D196):** the fallback for networks that block UDP.
     3. **SSH over the mesh (D197 M1):** hosts are reached over our own
        mesh instead of NetBird SSH.
     4. **Then the rest, by priority:** NAT traversal and router port
        mapping (D196), subnet routes and exit nodes (D197 M2, M3), and Mac
        nodes (D169).
228. **Mesh rollout and fallbacks (owner, 2026-10-11, mesh grill M2–M5):**
     - **Direction:** the mesh becomes stable by replacing the NetBird
       dependency step by step (NetBird stays until our own iOS and macOS
       clients are stable), and is improved after that.
     - **On by default, allow by default (M2):** the mesh is on for every
       infraternal agent, and the open-source default lets members reach
       each other (D216). The default is the access policy in Settings →
       Access.
     - **First real test (M3):** monitor01 and o1, two public VPSes on
       different networks.
     - **No port to open (M4):** nobody opens a firewall port for the mesh.
       Each node picks a free UDP port itself (never NetBird's 51820), the
       server learns it through address discovery, and both sides send at
       once so stateful firewalls let the traffic in.
     - **No root, no question (M5):** where the infraternal agent cannot
       create a kernel WireGuard interface, it switches to a userspace
       tunnel on its own, without asking. In that mode infraternal's own
       traffic (agent to server, terminals, SSH) uses the mesh; other
       programs on that host reach mesh addresses only through the
       agent's local proxy. The canvas says which mode a node runs in.
229. **`server init` and the user sessions run as (owner, 2026-10-11, Q11):**
     - `server init` installs a system service that runs as root, with its
       data in `/var/lib/infraternal` (#34). It is documented on the
       website under `infraternal.com/docs/edge/…` later.
     - **Preferred user:** a global setting and a per-host override choose
       which user terminals open as, because most people don't want root
       by default.
     - **A real login:** sessions start as a full login of that user
       (PAM session, environment, limits, home directory), not a bare
       process switch.
     - **The server's own host** is reached through the embedded
       infraternal agent, the same way as every other host, with no SSH to
       itself.
230. **Account names (owner, 2026-10-11, Q12):** setup asks for a username
     (required; no spaces; it names the passkey and the account) and a
     display name (optional, a real name). Sign-in asks only for the
     username, then the passkey. Display name and other details are edited
     later in Settings → Account.
231. **Preferred user default and the server's own host (owner, 2026-10-11, Q11b–c; extends D229):**
     - **Default user:** the global preferred user defaults to the owner's
       own infraternal username. On a host without that user, a terminal
       opens as root and says so in the window ("No user kayg here, opened
       as root"); the per-host override changes it from the window menu.
     - **The server's own host** opens terminals through the embedded
       infraternal agent like every other host, never by SSH to itself.
       Opening must feel instant: a real login that stays lean (measured,
       with a budget), because this is infrastructure.
     - **SSH to the server's own host stays possible** as an option; its
       design is grilled separately.
232. **App-window stream transport (owner, 2026-10-11, T1–T2; extends D104, D107, D185, D214):**
     - **Path (T1):** desktop and app-window streams use the same path
       selection as terminals: direct when measurably faster, the server
       relay otherwise, switching up or down automatically as conditions
       change, with no setting. The server still holds the session (D104),
       so reconnecting and extra viewers keep working.
     - **Lost frames (T2):** both a reliable stream and unreliable
       datagrams (skip a lost frame, repair with the next keyframe) are
       built behind one interface on our QUIC transport and measured on a
       lossy India↔Germany link; the owner picks from the numbers.
233. **"Automatically upgrade connections" (owner, 2026-10-11; amends D232 T1 and D214):**
     one switch, **on by default**: terminals, desktops and app windows
     pick the fastest path themselves (direct when measurably faster, the
     server relay otherwise) and switch both ways as conditions change.
     Turning it off reveals a path choice per window type (terminals,
     desktops and app windows), so people who want control get it. Good,
     easy defaults; room to geek out. It lives with the other host settings
     (Settings → Hosts, "Connections").
234. **An inbox for pending actions (owner, 2026-10-11):**
     - **Where:** a persistent floating card at the bottom left of the
       sidebar, inside the sidebar's bounds with minimal padding,
       responsive. It disappears entirely when it has no items.
     - **What goes in:** things that wait on the person, never things
       hidden in Settings. First item: the host-connection unlock (D168,
       D217) for administrators.
     - **Toasts first:** while an item waits, every sign-in by someone who
       can act on it shows a persistent toast with the action. When the
       toast is dismissed or expires, the item lives in the inbox. Once the
       action is done (the CA is unlocked), the toast stops appearing for
       every administrator and the item leaves the inbox on its own.
     - Settings keeps the state and the action too, as a second place,
       never the only one.
235. **SSH over the mesh: identity, access and linking (owner grill, 2026-10-11; extends D197 M1, D215, D227, D228, D229–D231; research #162):**
     - **Two checks, always (Q1).** A login needs the machine allowed by the
       network policy and the person allowed by login access. Machine trust
       alone never lets one local account act as another.
     - **Two policies (Q1b).** *Network policy* (TCP, UDP, ICMP) is
       allow-all by default (D228 M2). *Login access* (who may be which
       account on which host) covers every way to a shell: plain SSH,
       infraternal terminals, app windows and files.
     - **Plain `ssh` upgrades itself (Q2).** The local infraternal agent
       holds each linked person's SSH certificate and serves it through an
       SSH key socket, checking the asking process every time. One file in
       `ssh_config.d`, scoped to mesh names and addresses, points `ssh` at
       that socket and trusts our host certificates (no host-key prompt).
       On the target, port 22 of the mesh address reaches the embedded SSH
       server (D197); host `sshd` is never touched (Q3). The target checks
       the certificate, the network policy and login access. The target
       account's `authorized_keys` keeps working, without a person identity.
     - **Certificates (Q2b, Q2d, Q2e, Q12).** Valid only from the node they
       were issued to (source address), with the key in the Secure Enclave
       or TPM when present, otherwise memory only. Lifetime **24 h by
       default**, an admin setting from 1 to 24 h; renewed quietly while the
       CA is unlocked. After a restart that locks the CA, a countdown toast,
       push and inbox item ask an administrator to unlock. Revocation (node
       removed, link removed, person disabled) is pushed to every node at
       once.
     - **Forwarded agents refuse.** The local infraternal agent never signs a
       request that arrives through SSH agent forwarding.
     - **Who a process is (Q2f, "session-carried").** In order: a process
       started inside an infraternal session acts as the person who opened
       that session; otherwise the original login user (Linux login uid,
       macOS audit user, kept through `sudo`/`su`) if that account is
       linked; otherwise machine identity (only what an admin granted to
       that node and account), or nothing. Root is never linked.
     - **Linking a local account to a person (Q2a).** Automatic when a node
       joins (the account used to add it). Otherwise, on the first
       interactive `ssh` over the mesh from an unlinked account, the
       pre-connection check prints a plain-language description with the
       chips UI, a link, a QR code and a short code; the browser page shows
       the same description ("Let `agents` on `mbp` act as you (kayg)"),
       asks the person to pick the code shown in the terminal, and confirms
       with their passkey. Links expire in 5 minutes, work once and are
       rate-limited. Without a terminal it prints one line and continues
       with ordinary keys; it never hangs. Root, system accounts and shared
       accounts (`deploy`, `ci`) are never person-linked; they use machine
       identity. The person and any administrator can remove a link
       (Settings → Account, Settings → Access), effective immediately (Q2g).
     - **Which accounts (Q4, Q10).** Setup creates two ordinary, visible,
       editable policies: "everyone → all hosts → their own username"
       (matches only ordinary user accounts: UID ≥ 1000 on Linux, ≥ 501 on
       macOS; sign-up refuses reserved and system names) and a starter grant
       "first administrator → all hosts → any account". Being an
       administrator manages policy; it grants no hidden login rights.
       Every grant change is logged.
     - **Reattach (Q2c).** A later `ssh` to the same host can reattach a
       session that is still running; dropped links never end sessions
       unintentionally.
     - **Audit (Q6, Q6b).** Free and on by default: the connection log (who,
       from where, as whom, when, how long), link approvals, grant changes,
       issued certificates. Enterprise (`ee/`): session recording, long
       retention, export, refusing sessions when recording is unavailable,
       time-limited grants and second-person approval (Q11), identity-
       provider group sync and deprovisioning, shorter certificate lifetimes
       and hardware-held CA keys.
     - **Packets (Q7).** IPv4 and IPv6 behave the same. Packets the kernel
       rewrites onto a mesh address (port publishing) are refused; node-local
       traffic is allowed. The future reverse proxy must run in userspace in
       the infraternal agent, never as kernel port-forwarding rules, so this
       rule holds.
     - **Rollout and retention (Q14–Q16).** Login access applies to the web
       terminal in the same release as SSH: never a period where one path
       ignores the policy. The community connection log keeps 30 days.
       A link always needs the person's own passkey; an administrator cannot
       approve one on their behalf (a visible machine grant is the stopgap).
236. **Session rows say what is in them (owner, 2026-10-11):** a session's
     label is, in order, the name a person gave it, the foreground program
     (`htop`, `cargo test`), or the current folder's last component (`~` for
     home). The infraternal agent reads the foreground process and working
     directory from the operating system and reports changes (at most about
     once a second); it needs no shell configuration.
237. **People add their own machines (owner grill, 2026-10-11; extends D235, D228, D215, D234):**
     - **One flow (Q17a).** `infraternal join <server>` on any machine shows
       the same screen as linking (D235): a plain-language description, a
       link, a QR code and a short code; the person picks the code and
       confirms with their passkey. The machine joins and the account that
       ran the command is linked to that person. The app's add-host flow
       offers a "copy command" with the server filled in; add-host over SSH
       (D229) remains for machines you cannot sit at. No join tokens to copy.
       Without root the machine joins in userspace mode automatically (D228
       M5), with nothing asked (Q17g).
     - **Ownership is a label, never access (Q17b).** A machine someone adds
       is *personal* (they may remove it, and its accounts can be linked to
       them); an administrator can make it *shared* by tagging it, which
       removes person links. What any machine or person can reach always
       comes from policies and grants, never from owning a machine.
     - **Reach (Q17c).** Community default: the allow-all network policy
       (D228). Enterprise can restrict personal machines to their owner's
       machines plus grants.
     - **Removal (Q17d).** People remove their own machines; administrators
       remove any. Disabling a person removes their personal machines at
       once; shared machines stay.
     - **No routine key expiry (Q17e).** Seven-day node certificates renew
       silently while online (D215); a machine offline for more than 90
       days needs a passkey re-approval when it returns.
     - **Approval (Q17f).** Enterprise policy: each new machine waits in the
       administrators' inbox (D234) until approved.
238. **Native apps (owner grill, 2026-10-11):**
     - **All native on Apple, iOS first** (Q27): SwiftUI for the chrome
       (sidebar, pills, palette, settings, inbox, sheets, approvals) and
       Metal for the canvas, terminals and app-window frames. iPadOS and
       macOS reuse it; tvOS is out. Linux and Windows keep the installable
       web app; a native desktop UI is revisited only on demand.
     - **A full Rust client core** (Q29 (a)): the mesh node (inside the iOS
       network extension's memory limit), sign-in sessions, certificates and
       links (D235), the codec and protocol, the layout tree and its sync
       (Q20/Q21), actions (D16) and terminal state (D14, native Ghostty).
       Swift calls it through generated bindings; hot paths cross as byte
       buffers once per frame, never per byte or as strings. Android and
       Windows can reuse it later.
     - **The web stays TypeScript** (D88 unchanged): no WebAssembly bridge
       for the client logic. The TypeScript and Rust cores stay identical
       through shared golden vectors and differential tests.
     - **Measured before building** (Q26): a spike draws 10/25/50 live
       terminals with pan, zoom, snap and typing, twice (SwiftUI + Metal,
       and the web canvas in a WebKit view), on the owner's iPhone 16 Pro
       Max at 120 Hz: frame times, keystroke-to-paint, memory per session ×
       50, and the Rust↔Swift boundary cost. If the boundary is too costly
       on hot paths, layout state moves to Swift (scope (b)); the mesh and
       security code stay in Rust regardless.
     - **When:** after the mesh is stable and the control/data-plane split
       (canvas nodes) is settled. Until then no iOS work starts; new
       protocol and sync work keeps native clients in mind (intent-based
       layout edits, byte-buffer frames).
239. **`infraternal up`: the CLI is a client through the canvas (owner grill, 2026-10-11; extends D235, D237):**
     - **Commands (Q31):** `infraternal up`, `down` and `status`; the
       installer also provides `infra` as a short alias.
     - **The local UI is the canvas (Q32):** the infraternal agent on the
       machine serves the canvas on loopback; connection state (peers, direct
       or relayed, latency, connect/disconnect) is one more canvas view, the
       *Connection* view, that pops up when needed. The same view on the
       server's embedded infraternal agent manages the server node's own mesh
       connection.
     - **Sign-in (Q33):** with a desktop session and a browser, `up` opens the
       loopback canvas, asks which server, and sends the browser to the
       server's own page for username and passkey (auth always happens on the
       server origin); the server redirects back to loopback with a one-time
       code bound to that attempt (RFC 8252 loopback redirect with PKCE and
       state), and the CLI exchanges it for the node certificate and the link
       (D235, D237). Without a desktop, or with `--no-browser`, the terminal
       link + QR + code flow of D237 runs instead.
     - **Always running (Q34):** the loopback canvas stays up with the
       infraternal agent; onboarding starts there. Only the local OS user who
       ran `up` can use it. `up` (and `infra status --open`) asks the local
       infraternal agent over its Unix socket, which checks the caller's UID,
       for a single-use token valid about 60 s, and opens the loopback URL
       with it. The first load swaps it for an HttpOnly, SameSite=Strict
       cookie and strips it from the address bar; the token cannot be used
       again. After sign-in the same cookie becomes the signed-in person's
       session and renews while a tab is open; it expires when idle. The
       loopback server refuses any Host other than its own loopback address
       and port (DNS rebinding) and checks Origin on every state-changing
       request.
     - **What the loopback canvas serves (Q35, owner 2026-10-11):** the
       binary embeds only the critical canvas (shell, Connection view and
       sign-in). After sign-in, the rest comes from the signed-in server as
       its signed web bundle, cached, always matching that server's version
       (signing in needs the server anyway).
     - **Address (Q36):** a fixed default loopback port, configurable; if it
       is taken, the next free one, printed by `infra status`.
240. **Real logins, one per person per account per host (L1, owner 2026-10-11; settles D229/D231 login mechanics; measured on #159):**
     - Terminals run inside a real PAM login (limits, environment, login
       records, the user's systemd session). The first terminal of a person
       using an account on a host opens that login; later terminals start
       inside it. Each terminal stays its own process. The login ends a short
       grace period after its last terminal closes, and ends at once when the
       person's access is revoked.
     - Logins are never shared between people: Alice and kayg both using
       `deploy` on o1 get two logins, so `who`/`last` and the connection log
       (D235) show the person.
     - The preferred user's login (D229) is opened in advance.
     - The per-terminal `systemd-run` scope is replaced by the login's own
       session.
     - Measured on the perf VM (median, real rc files): today 49 ms per
       terminal; full PAM login per terminal 63–65 ms (rejected); reused login
       6–8 ms per later terminal, 19–24 ms for the first; opened in advance
       about 6 ms.
241. **Auto-started multiplexers give way to infraternal sessions (owner, 2026-10-11; #170):**
     infraternal sessions already keep shells alive, reattachable and shared,
     so when a host's startup files would auto-start tmux or zellij inside a
     session, infraternal skips that start automatically without editing
     dotfiles (satisfying the multiplexer's own "already inside" check during
     startup only; running it by hand later still works). Every session
     exports `INFRATERNAL_SESSION`. The first time on each host one quiet line
     says so: "zellij start skipped: infraternal keeps this session for you ·
     [Use zellij here]"; the button turns the skip off for that host. After
     that, nothing. A global switch exists as well.
242. **Removing access cuts open connections at once (owner, 2026-10-12, #173;
     amends D164 and D216):** when a grant is removed, a peer is revoked, or
     the default policy tightens, connections that the new policy no longer
     allows are cut immediately on every node, not only new ones. Allowed
     connections are untouched. The time from the change to the last node
     refusing traffic is measured and reported with each mesh change.
243. **Binary size goes down, not up (owner, 2026-10-12):** the static binary
     must not keep growing towards the size of a typical Go static binary.
     The size gate is not raised to match today's build. A size-reduction
     push starts now: measure where the bytes come from, cut, and ratchet the
     gate down to each new measured size so growth needs a justified,
     measured exception.
     **Amended by the owner, 2026-11-01 (#284):** when told “every feature
     slice comes in at 85–167 KB; the 16 KiB budget makes every feature a
     size negotiation”, kayg replied: “let's remove that cap please”. Binary
     size caps and the 16/64 KiB approval bands are removed. Measure and
     report stripped static size and its signed delta against the recorded
     baseline for each shipping target on every slice; avoid gratuitous
     bloat. Size growth or shrinkage does not fail the gate or require a
     size exception. Artifact correctness and static-linkage checks remain
     gates. The orchestrator records the merged measurements as the next
     baselines, as documented in `docs/PROCESS.md` §7.
244. **CA key memory on static builds (owner, 2026-10-12, #154):** the static
     musl release builds get OpenSSL's locked, dump-excluded key heap by
     removing the `OPENSSL_NO_SECURE_MEMORY` define that the OpenSSL build
     crate adds for musl targets, in our pinned compiler wrapper (D213). The
     OpenSSL version and sources stay unchanged. The gate starts the real
     static release binary under an 8 MiB memlock limit and fails unless the
     key heap is locked and excluded from dumps. Root servers keep failing
     closed. Rejected: a maintained patch of the build crate, protecting only
     our own key copies, and warning instead of refusing.
245. **Sign-out removes everything on the device (owner, 2026-10-12, #171):**
     signing out deletes all of the account's data stored in that browser,
     including canvas layout. The canvas layout lives on the server (the
     control plane holds layout) and the browser keeps only what is needed
     to draw quickly, so signing back in restores it from the server. Device
     storage stays lean.
246. **Browser sessions stay server-trusted for now (owner, 2026-10-12; keeps
     D8):** end-to-end encryption between browser and host is not added now.
     Native apps are mesh nodes and get it over WireGuard. A per-session
     private mode in the browser is measured before it is offered.
247. **Real logins go through the host's own login path (owner, 2026-10-12,
     #172; amends D240, keeps D7):** the static binary does not load PAM
     itself. On systemd hosts, the per-person login (D240) is a long-lived
     systemd unit with `PAMName=`, and the infraternal agent starts that
     person's shells inside it. Hosts without systemd fall back to the host's
     own `su`/`login`. Condition: this is chosen because it is the standard
     path and expected to be the fastest; it must be measured against the
     glibc helper option on the perf VM (first terminal, later terminals,
     opened in advance). If it is clearly slower, the owner decides again.
     Measured 2026-10-12 (N=200 p50, perf VM): first terminal 44.6 ms vs
     production 33.8 ms (once per person per host, usually hidden by opening
     in advance); later terminals 3.3 ms and opened-in-advance 3.3 ms vs the
     helper's 6.5/6.2 ms. The owner confirmed the systemd path (2026-10-12).
     Rejected for now: a glibc helper binary next to the static one, and a
     dynamic glibc build of the whole binary.
248. **Canvas nodes (owner, 2026-10-12, Q20–Q25, #167; builds on D239):**
     - **Layout:** the server (control plane) holds every canvas layout and
       is its source of truth. Layout changes travel as intents ("move
       window", "open session"), never as whole-layout overwrites.
     - **Content and credentials:** content lives on the hosts. Credentials
       are sealed to the infraternal agent that uses them; a canvas only
       asks for them and never holds them.
     - **Speed:** both the server canvas and a node's canvas must be very
       fast ("keep both reaaaaly performant").
     - **Who:** each person can open only their own canvas. In the community
       edition the server's own canvas is always on.
     - **Addresses:** a node serves its canvas at two addresses, shown
       together: `http://localhost` on the machine itself, which always
       works (including behind routers with DNS-rebind protection), and a
       name the person configures for remote use. That name gets HTTPS via
       HTTP-01 by default; DNS-01 is optional.
     - **Sign-in:** always on the server's own page, with passkeys or OIDC
       as today. The server hands the node's canvas a single-use token that
       becomes an HttpOnly, SameSite=Strict cookie, without `Secure` on
       loopback only (WebKit drops `Secure` cookies on http://127.0.0.1). A
       node name under the server's domain may use the passkeys directly;
       other domains use the handoff, or related origins where supported.
     - **Browsers:** Chrome asks once for local network access; the handoff
       works in Chrome, Firefox and WebKit (measured, #167). A node-served
       canvas answered in 1.2 ms against 151.6 ms across a long link.
249. **The cursor blinks while you can type (owner, 2026-10-12; amends D112):**
     when typing will reach the terminal (focused, and on phones the keyboard
     is up), the cursor blinks. It is drawn as its own small layer above the
     terminal and blinked by a compositor-only CSS animation, so the terminal
     renderer stays asleep (D81, D112). The blink stops, leaving a steady
     cursor, when the tab is hidden, the keyboard goes away, focus leaves, or
     after about 30 seconds without input; any input restarts it. Its CPU and
     battery cost is measured on an iPhone and on the idle canary before it
     ships. When typing cannot reach the terminal, the cursor stays a steady
     underline (TASTE "A blinking cursor means you can type").
250. **How changes reach production (owner, 2026-10-12):**
     - **One line:** `dev` is the only development line. A production
       deploy is a tag on a `dev` commit that passed its review and gates;
       `main` is fast-forwarded to whatever production runs, so `main` stays
       the stable line. The `release-prod-*` branches end once batch 4 and
       its merge back into `dev` are done. No more ports.
     - **Deploy each change on its own** as soon as its review passes, not
       in batches. The owner's own testing in production is the main test;
       small deploys make each problem easy to find and roll back.
     - **No CA lock on binary deploys:** deploys use the in-process binary
       handoff (#154) instead of stop and start, once release pipeline
       round 4 (signature check, sealed image, recovery) has passed review.
       This was already decided as D217 (2026-10-10); the orchestrator's
       deploy script never implemented it, which is why deploys locked the CA.
     - **Builds within the host's capacity:** only as many build-heavy jobs
       run as the build host can take; release builds get a reserved CPU
       share and are built for each `dev` head that passes, so a deploy only
       copies a binary.
     - **Timing on the perf VM:** every timing, CPU, memory and frame
       number, native or browser, is measured on the perf VM; build-host
       timings are not evidence.
251. **Production follows edge and updates itself (owner, 2026-10-12;
     extends D186, D250):**
     - **Edge is "reasonably stable":** a `dev` commit is published to the
       edge channel only after its gates pass AND its break-it review has no
       P0/P1. Gates alone do not publish.
     - **infraternal.kayg.org follows edge.** Every published edge build
       reaches it without an orchestrator deploy.
     - **When it applies:** automatically in a quiet window (the server is
       idle for a few minutes: no typing, no attach in progress), through
       the in-process handoff, so the CA stays unlocked (D250). An update
       never interrupts typing.
     - **Manual control:** a ready update first appears as a toast, then
       stays as an Inbox item ("Update ready · <version>") with **Update
       now**. The same controls live in **Settings → Server → Updates**:
       current version and channel, the quiet-window setting, Update now,
       Roll back to the previous version, and the update history. Hosts'
       infraternal agents follow their server's version.
252. **Names for access (owner, 2026-10-12; renames terms in D154, D164,
     D216, D228, D235):** three kinds of access, each a list of **rules**,
     all in Settings → Access under these headings. The words "grant" and
     "policy" are no longer used for them in the product, docs or code.
     - **Roles** (app level; was D154 "grants"): what a person can do in
       infraternal — Owner, Admin, Operator, Viewer and custom roles, over
       all hosts or host tags.
     - **Network access** (mesh level; was "network policy" and the D164
       arrow "grant"): which machine may reach which machine, on which
       ports and protocols. The Mesh view's arrows are network access
       rules; the edition default (D216) is "Machines can reach each other
       until you add rules".
     - **Login access** (host and account level; D235): which person may
       become which account on which host. It covers every way to a shell —
       `ssh` over the mesh, infraternal terminals through the server, app
       windows and files — whether or not the mesh is involved.
     A mesh `ssh` login passes network access and login access; a terminal
     opened in the app passes roles and login access.
253. **Boot Machines (network boot, PXE) (owner, 2026-10-12, #156):** a
     section called **Boot Machines**, off by default.
     - **What boots:** a versioned list of curated profiles (Debian, Ubuntu,
       Fedora, Proxmox, SystemRescue, memtest, …), each tested to finish
       installing. Any other image can be offered with "Try anyway (may
       stop after the boot menu)". infraternal never hosts Windows; people
       download it from Microsoft and drop it in.
     - **Where:** each LAN needs one infraternal node with Boot Machines on.
       It answers boot requests next to the existing DHCP server (no router
       change); one node answers per LAN. Images may live anywhere in the
       mesh; the LAN's boot node caches each after verifying it, with
       "Prepare for <LAN>" to fetch ahead.
     - **Reliable:** detects other boot servers, switches that block boot
       traffic, port clashes and missing DHCP, and says so plainly; **Test
       this LAN** boots a small VM end to end; a live boot log in plain
       words; a fallback (router DHCP settings or a USB boot stick) when a
       network card ignores the answer; a tested firmware list.
     - **Who may boot:** access rules with **boot**: "the next machine that
       asks" or a MAC address, one time, for 1 hour by default; "any machine
       on <LAN>" only as an explicit, time-limited rule.
     - **Joins by itself:** curated installs add the infraternal agent and a
       one-time join token; the machine installs, joins the mesh, waits in
       the Inbox until approved (with a preview of its access), then is a
       normal machine. Live images join as temporary machines that leave
       when switched off. Talos and Windows come later.
     - **Watch it install:** once Linux runs on the installing machine, its
       screen streams live to an app window on the canvas (framebuffer
       capture by the in-memory infraternal agent over the D232 transport),
       with optional control if an install stops to ask something; a
       terminal is available too. Firmware screens before Linux need a
       management controller (IPMI/Redfish) or the hypervisor, later.
     - **Firmware:** UEFI and legacy BIOS first; Secure Boot and Windows
       later, each measured first. Failures are explained in plain language.
     - **Integrity:** originals must match the distribution's signed
       checksums; our changes are built locally from the verified original
       and every built file's hash is recorded, serving only those exact
       bytes; dropped-in images are approved by hash once; nothing is served
       before the whole image is verified.
     - **Storage (#34):** dropped-in images are data in
       `/var/lib/infraternal/boot-images` (rootless
       `~/.local/share/infraternal/boot-images`), kept; downloads and caches
       in `/var/cache/infraternal/boot` (rootless `~/.cache/infraternal/boot`),
       evicted oldest first under a configurable limit.
     - **Built by us:** boot-request answering, TFTP and HTTP serving in Rust
       inside the plugin; iPXE shipped as separate boot files (licence
       checked per build); measured against dnsmasq before shipping.
254. **App windows run at the display's refresh rate (owner, 2026-10-12;
     amends D232):** an app window updates at 60 fps, and at 120 fps on a
     120 Hz screen, whenever the source changes that fast, and does no work
     when nothing changes. The target is "super responsive": damage-only
     updates, zero-copy capture, one encode per source shared by every
     viewer, frame pacing to the viewer's display, and drop-to-newest for
     slow viewers; input-to-photon latency is measured end to end at 60 and
     120 fps. Codec, encoder and capture-engine choices are measured and
     brought to the owner.
255. **Adding a host gives you a shell almost at once (owner, 2026-10-12,
     #189, #169):** the shell lives in an infraternal session from the first
     keystroke, and only the connection to it changes.
     - **Order:** sign in over SSH; upload the compressed binary (reused when
       the host already has it); over that same SSH connection start the
       session process and the shell inside it; the canvas window attaches
       through SSH and the person can type. The infraternal agent then
       installs and joins in the background, finds the same session, and
       the window reattaches through it (the normal reattach and replay);
       the SSH connection closes. Same shell, scrollback and running
       program. A shell started by SSH outside the session process is never
       adopted afterwards (no process stealing).
     - **Targets:** time to a working prompt ≈ 0.3 s on a LAN and ≈ 1.5 s at
       150 ms; fully joined well inside the D189 targets.
     - **Progress in the pill:** when the prompt appears, the setup status
       moves (animated) into the window's machine pill as a small circle
       split into the remaining setup stages; each segment fills as its stage
       completes; when all finish the circle turns into a tick, then into the
       machine's OS icon. A failed stage turns its segment into the failure
       state and the pill explains it on tap, in plain words.
256. **The perf VM's small size is the target, on purpose (owner,
     2026-10-12):** every performance target is met on the perf VM as it is
     (4 vCPU, 7 GB). It is deliberately modest so that the code is optimised
     to fit modest machines, not tuned for people with lots of resources. A
     result that misses a target is fixed in the code, never by asking for a
     bigger machine. The owner's own Mac and iPhone are available for
     real-device checks on request.
257. **Two crypto size options are decided by measurement (owner,
     2026-10-12, #175, D243):** S1 — the static build drops OpenSSL's
     AVX-512 AES-GCM code (about 659 KB) only if measurement shows no change
     in keystroke latency and less than 5% bulk-throughput loss on an
     AVX-512 machine; otherwise it stays. S2 — one crypto library: QUIC and
     passkey verification move from ring onto the OpenSSL already in the
     binary only if QUIC handshakes and passkey checks are no slower, the
     replacement crates are maintained and AGPL-compatible, and the auth code
     passes the strictest review; if the replacements look poorly
     maintained, ring stays. Measure first; the orchestrator applies these
     rules to the numbers and reports the outcome before anything ships.
258. **`/install` and `/download` on the person's own server (owner,
     2026-10-12, Q28):** `/install` is the one-line host install that
     add-host offers when the server cannot reach a host over SSH:
     `curl -fsSL https://<server>/install | sh` returns the script; a browser
     gets a short page showing the command and what it does. `/download` is
     the page for people with the apps (macOS, iOS, later Windows) and the
     CLI, added when apps ship. Both are served by the infraternal server
     itself, never by a third party.
259. **Reconnect has two budgets (owner, 2026-10-12, #192):** (1) the
     session's last screen is back within one frame (16 ms; 8 ms at 120 Hz),
     drawn from the copy the client already holds, with a subtle sign that it
     is catching up; (2) the terminal is up to date and typable within one
     round trip + 50 ms after the network path recovers (about 200 ms
     India–Germany). Keystrokes typed meanwhile get normal prediction (D130).
     The goal is that reconnecting feels instant, while the second number keeps
     the claim honest. Full-screen prediction, a latest-screen view lane and a
     UDP transport for mesh SSH are decided only after measurement.
260. **Logs, metrics and alerting are our own, built lean (owner,
     2026-10-12, #193):** the guiding line: "we keep it lean, we keep it
     small. we are non-intrusive, extremely reliable and ridiculously fast."
     - **Placement: hybrid.** The server keeps a small recent summary per
       machine (about 15 minutes of errors and warnings, grouped repeats,
       vitals; about 64 KB per machine) that answers ⌘K at once; full history
       stays on the machine and is fetched on demand. Results state their
       coverage ("searched 12 of 14 machines"). A machine can be pinned to
       send everything when outage-time completeness matters.
     - **Engine:** SQLite FTS5 (SQLite already ships) goes to a production
       spike first; our own small index stays a challenger for hot recent
       data. Tantivy is not used (+3.6 MB, new lines searchable too slowly).
     - **Vitals (an explicit D81 exception):** one reading every 10 s for
       history (24 h, then thinned to 30 days), once a second only while a
       graph is open; nothing when the feature is off. History is never
       invented: finer detail exists only from when it was recorded.
     - **Alerting is ours (amends D35):** built-in plain warnings in the
       Inbox first (disk filling, restart loops, sustained pressure), no
       formula language, no required exporter; an optional export stays off
       by default. A full alerting design is a later grill.
     - **Secrets are redacted on the machine** before anything is indexed or
       sent; the server summary keeps safe fields and redacted examples.
     - **Retention defaults wait for research** on real log volumes per kind
       of machine.
     - Who can read logs is an ordinary access rule; no port scans or
       endpoint guessing; AI agents get the same evidence through MCP with
       no automatic remediation. Nothing is built until measured end to end
       on the perf VM at 1,000 machines.
261. **Observability, round 2 (owner, 2026-10-12, #193; extends D260).**
     Decided now, built later: logs, metrics and alerting come before
     container and Kubernetes support, which then plug into them.
     - **Retention rule:** each machine keeps N days of logs, never more than
       5% of its free disk, whichever limit is reached first; N per kind of
       machine comes from the log-volume research. History the OS already
       keeps stays searchable on demand. The UI states the real span covered.
     - **Where alerts reach people:** the Inbox is always the record; push
       notifications to phone and desktop for what needs someone now;
       optional email; outgoing webhooks for chat tools.
     - **Who gets alerts is an access rule:** a new verb, "get alerts", in the
       sentence model ("Ops get alerts for tag:prod", "Kayg gets alerts for
       db-01 until Friday"). On-call is a rule with an ending; view rights
       bound what anyone can be alerted about.
     - **No noise:** one alert per problem, updated in place, never repeated
       on a timer; related alerts grouped; snooze is an ending; an alert
       clears itself with a quiet "resolved" note.
     - **Search without choosing:** people type natural language or plain
       keywords; recognised parts (level, machine, service, time) show as
       chips the person may remove, but nobody ever has to pick a filter.
       Parsing is local and instant; no AI model is needed to search.
     - **Watched by default, zero setup:** CPU and pressure, memory and
       memory pressure, disk space and time-to-full, disk I/O, network,
       services (unit restarts and failures), reboots, clock drift.
       Per-process detail is live while viewed, never stored by default.
     - **Containers and Kubernetes,** when they arrive, are more sources in
       the same search, vitals and alerts.
     - **Process monitoring** is its own feature, to be grilled later.
262. **Evidence lives on the issue, not in the repo (owner, 2026-10-13,
     #200; changes how CLAUDE.md "Codex jobs attach the screenshots" is
     carried out):** screenshots, captures, raw logs, traces, gate
     transcripts and measurement receipts are attached to the Forgejo issue
     of the work, next to the numbers in the comment. The repo holds code,
     tests, fixtures that tests read, docs and decisions only. A gate refuses
     new large or evidence-type files. The existing `evidence/` and
     `apps/tracer/captures/` trees leave the repo, and history is rewritten
     once to remove them (about 600 MB of `.git`, two thirds of it
     screenshots and evidence). Rejected: a short per-job evidence README in
     the repo (owner: evidence belongs to the issue), and Git LFS (another
     server-side store for what the issue already holds).
263. **Dogfooding cut-over, logs and alerts (owner, 2026-10-13, grill
     round 1; extends D243, D164, D260, D261):**
     - **Cut-over waits for #199:** production moves to the dev build (the
       last classic restart, then handoff deploys) only after the fix for
       windows that stop taking input across a server restart is merged.
       The owner then starts the new calternal-dev VM on it to dogfood
       instead of tmux or zellij.
     - **One-time size exception (D243):** the cut-over may ship the larger
       dev binary once. Owner: "this is really a one-time exception"; the
       size work (#198) must cut it down and ratchet the gate right after.
     - **New machines start on SSH, then move to the mesh by themselves:**
       add-host connects over the network sign-in (NetBird) or SSH, the
       machine joins our mesh (D164), and its traffic switches to the mesh
       path automatically and fast as part of add-host; NetBird stays as a
       fallback until the mesh has run a week without problems.
     - **Log retention per kind of machine (D261):** quiet 30 d, laptop
       14 d, CI 14 d, web 7 d, database 7 d, proxy 3 d, Kubernetes 3 d,
       edge 30 d, each also capped at 5% of free disk, whichever ends first.
     - **Quota counts compressed bytes on disk.**
     - **Alerts go to everyone with the "get alerts" verb** on the machine;
       whoever adds a machine gets that verb automatically.
     - **Compose mode (D130) comes after dogfooding;** the Boot Machines
       questions (#156) wait until mesh and dogfooding are stable.
     - **Logs nodes are planned next (no build yet):** a machine can be
       marked a "logs" node that stores all logs synced from other
       machines. To be grilled before anything is built.
264. **S1 decided without an AVX-512 measurement; revisit later (owner,
     2026-10-13, #175; amends D257 S1):** the static build drops OpenSSL's
     AVX-512 AES-GCM code (about 659 KB) now. None of our machines can run
     it (i9-9900K, Ryzen 5 3600, Apple M2 Max, the production VPS's generic
     CPU), so D257's condition cannot be measured here. OpenSSL keeps its
     AES-NI and AVX2 assembly, which encrypts several GB/s per core,
     far above anything infraternal carries over OpenSSL today (the host
     daemon's TLS link: terminal output, at most tens of Mbit/s for app
     windows). Browser and QUIC traffic use ring and are unaffected.
     **Revisit** when infraternal carries bulk data near gigabit rates over
     OpenSSL (backups, file transfer) or when an AVX-512 machine is at
     hand: measure, and restore the code if bulk throughput drops more than
     5% or keystroke latency changes.
265. **Resume token and realistic reconnect budgets (owner, 2026-10-13,
     #176; amends D259):**
     - **The resume token travels in the first message after the
       WebSocket opens,** never in a header or URL, so proxy logs and
       browser tools do not show it. It costs no extra round trip.
       Rejected: a header (the branch did this without a decision) and
       keeping the old mechanism.
     - **D259's "typable within one round trip + 50 ms" applies when the
       connection can be reused or resumed.** The server pings, so a dead
       or half-open link is detected within about one round trip; input
       typed meanwhile is kept, never lost. After a real network change a
       fresh TCP + TLS + upgrade needs about three round trips, so that
       case's budget is **three round trips + 50 ms**, measured on the
       perf VM through real TLS. The last screen still returns within one
       frame from the client's copy (D259, unchanged).
     - **QUIC/WebTransport resumption is researched next** (0–1 round trip
       after a network change, browser support including Safari, size and
       code cost) and decided after measurement. Rejected for now: a
       second warm connection per open tab (an idle socket per tab works
       against D260's lean principle).
266. **App windows are captured at the source's full rate (owner,
     2026-10-13, #146; extends D232, D254):** "the window that is being
     captured must be captured at the max frame rate." Capture never caps
     a window below what it draws (120 Hz on a ProMotion Mac); the viewer
     shows it at its own display's rate. Safari pages run near 60 Hz, but
     many people view infraternal in Chromium or Firefox, which can present
     120 Hz, so measurements and budgets cover Chromium, Firefox and Safari,
     not Safari alone. Lowering the rate of windows nobody is watching, and
     combining windows into one stream, are measured before any decision;
     neither may lower the rate of a window being captured for a viewer.
267. **Device rules later; no WebTransport for resume; honest reconnect
     budget (owner, 2026-10-13, Q16–Q18; amends D265):**
     - **Access stays per person.** A person may use their sessions from
       any of their signed-in devices; mesh arrows only limit network
       traffic between machines. Rules that limit by device or device tag
       ("only from company laptops") are recorded for later, as a "from …"
       word in the existing rule sentence.
     - **No WebTransport for browser resume now:** browsers cannot migrate
       WebTransport sessions in 2026 and the gain is one round trip, against
       a second transport, its own UDP port and certificate, and binary
       growth (D243). Native apps resume in one round trip over plain QUIC
       migration (mesh). Revisit when a browser migrates WebTransport or
       the proxy can carry it. Lossy-link typing over WebTransport
       datagrams is measured separately (#208).
     - **Browser reconnect after a network change costs four round trips
       + 50 ms** (TCP, TLS, upgrade, then the first-message resume token
       of D265), replacing D265's three. Reusable links keep one round trip
       + 50 ms; the last screen still returns within one frame.
268. **Flood, memory and OpenSSL size decisions (owner, 2026-10-14,
     Q19–Q21):**
     - **Q19 (#197):** ship the reviewed server-side flow control now
       (keystrokes ahead of bulk output; native echo p99 4.5/156/328 ms at
       LAN/150/300 ms against ~600 ms before) and start the browser fix as
       its own lane: background windows' terminal output is decoded off the
       main thread (a worker), so it never delays the window being typed
       in. The owner also asks the orchestrator to look actively for user
       experience gaps of this kind.
     - **Q20 (#205):** reduce relocation-dirtied memory now by shrinking
       pointer tables (no security trade; ASLR stays), and start work on one
       process per user hosting that user's sessions, measured against
       isolation, D240 per-person logins, restart survival (D128) and
       upgrades. Goal from the owner: "really crush idle, average and worst
       case usage."
     - **Q21 (D264):** measure the assembler-capability override in the
       pinned compiler wrapper (OpenSSL then emits its own stubs instead of
       the AVX-512 AES-GCM code) — bytes saved, OpenSSL known-answer tests,
       and a gate check that fails if a future OpenSSL brings the code back —
       before adopting it.
269. **Mac mesh node now, for our own traffic (owner, 2026-10-14; amends
     D227's order):** "i would loooove if we were able to do it via our mesh
     data plane so it would be a double bonus: measure our own data plane
     throughput, measure our app windows feature." The macOS userspace node
     (GotaTun with our own adapter, D169) moves ahead of NAT traversal and
     SSH over the mesh, in the no-root mode of D228 M5: infraternal's own
     traffic (agent ↔ server, terminals, app-window streams) rides the
     mesh; no system tunnel, no root, no setting changed on the Mac. The
     first underlay may be the existing NetBird addresses. App-window
     end-to-end measurements and mesh throughput measurements run over it.
270. **One process per user becomes the target design (owner, 2026-10-14;
     extends D268 Q20):** "would love if we could make the one process per
     user design reaaaaly optimised and stable." Work on it is no longer only
     a prototype to measure: it is the design we harden, with optimisation
     and stability as the goals (idle, average and worst-case memory and
     CPU; crash containment; restart and upgrade survival per D128;
     per-person logins per D240). Switching the default still waits for
     measured gates — soak, fault injection and the head-to-head numbers on
     #205 — and the owner's go.
271. **Program status and connection state in the window pill (owner,
     2026-10-14; Q22, #209, #212 gap 3):**
     - **Q22a:** a program's own message (OSC 7501) is never written in the
       pill. The pill shows only the status mark; the words appear on
       hover, in the toast and in the Inbox.
     - **Q22b:** no toast when the window that changed state is the
       focused one; the person is already looking at it.
     - **Connection state per window (mostly approved):** the pill's dot
       becomes the shared connection indicator (connected, slow,
       reconnecting, offline). Keys typed while the link is down are shown
       by a small amber **key** on the glyph — the owner asked for the
       thing itself instead of an amber dot — and are sent when the link
       is back. One status dot per pill, never two.
272. **Adopt the assembler-capability override (owner, 2026-10-14; settles
     D264 and D268 Q21, #175):** "approved!" The pinned compiler wrapper
     makes OpenSSL's assembler probe report no AVX-512/VAES support, so
     OpenSSL emits its own fallback stubs for the AVX-512 AES-GCM path.
     Measured: x86_64 −784,736 B (−3.5%); AES-GCM known-answer tests and
     the D244 key-memory gate pass; AES-GCM, TLS and QUIC speed unchanged
     within noise on hardware without AVX-512. A gate check fails the build
     if a future OpenSSL brings the AVX-512 AES-GCM code back. It merges
     after the switch-over, once its review's P2 fixes pass.
273. **Host removal, list stability, session manager and the + picker
     (owner, 2026-10-15; #215, #212):**
     - **Removing a host uninstalls the infraternal agent.** We clean up
       after ourselves: the infraternal agent is small and the server holds
       all configuration, so there is no "keep it installed" option.
     - **Lists stay put while open.** Rows may be added or removed in the
       sidebar, but the list never moves under the person's focus.
     - **The session manager gets a Delete button** beside Rename; F2
       renames in place.
     - **The shortcuts panel lists F2, Delete and ⌘I.**
     - **The + picker lists every host that has been added,** reachable or
       not, each with its online/offline state.
     - **`/docs/privileges` is written** (Astro Starlight per item 44). It
       explains what the privileged infraternal agent can do and how to take
       the privilege back. Before any of it is built, the privileged-password
       handling goes through a design round with the owner.
274. **Privileged access: how the password is handled (owner, 2026-10-15;
     round 1 of the design pass from D273, #215):**
     - **The privilege model stays D18 and D163:** consent upgrades the
       host's rootless infraternal agent to the root infraternal agent.
       There is no separate root helper. Each person's sessions already run
       in that person's own process (D229, D270), so the code that faces
       terminals does not run as root.
     - **The password never reaches the server in readable form.** The
       browser seals it to that host's infraternal agent key. The server
       forwards bytes it cannot read.
     - **The way in is detected and has no menu,** in this order: sudo
       without a password (consent only, no field), then sudo or doas (the
       person's own password), then the root password (su).
     - **Every privileged action is recorded** in the host's activity log
       and the Inbox: what ran, who asked and when, never secrets. A failed
       attempt shows in the Inbox at once.
     - **Hold as few secrets as possible:** the password is used once to
       install the root infraternal agent's system service, then wiped from
       memory. It is never written to disk, a log or the server.
     - **Going back to the rootless agent is possible but deliberately hard
       to reach,** so that nobody downgrades by accident:
       - Only admins of that host ever see the action, anywhere.
       - It is not in the host's details: the "Full access" line there shows
         the state only. The action is found by search and in the host's ⋯
         menu.
       - **Two prompts.** The first explains why and what, as a short
         point-by-point list of what stops on this host right now (for
         example "build-01 leaves the mesh: 3 machines lose their direct
         link", "4 containers run by root disappear from Containers"),
         concise and hand-held. The second asks "are you sure", asks which
         user the rootless infraternal agent should run as, and has the
         person type the host's name.
       - Every admin of the host gets an Inbox item (who and when) with
         "Allow full access again", which asks for the password again
         because none was kept.
       - **Passkey at the last step, always:** the person confirms with
         their passkey (Touch ID or Face ID), so neither a stray click nor
         someone at an unlocked laptop can downgrade.
       - **Organisation lock:** admins can mark hosts "Full access
         required"; nobody can downgrade those, and the action says why
         instead.
       - **Second-admin approval** is an `ee/` feature (items 31 and 33):
         when an organisation turns it on, the downgrade waits in the other
         admins' Inbox until one approves. Only its seam is built before
         there are users.
       - Not adopted: a delayed downgrade with undo (it makes the real state
         unclear), and refusing while root-only things are in use (prompt
         1 already lists them).
       Removing the host removes everything (D273).
275. **The wheel scrolls what is under it (owner, 2026-10-15; refines D177,
     #215):** today a snapped canvas sends every wheel to window navigation,
     so a window's own list (Access) cannot scroll without the input lock.
     - **Split by direction.** Vertical wheel scrolls what is under the
       pointer: a list, a log, or the focused terminal's scrollback (or its
       running program, as terminals do). Horizontal (sideways trackpad
       swipe, Shift+wheel) moves between windows. ⌘/Ctrl+wheel zooms.
     - **An unfocused terminal** behaves like any other window that does
       not scroll: the wheel over it belongs to the canvas.
     - **The input lock keeps its other job:** all input, keys included,
       stays in one window and the canvas never moves.
     - **Touch:** one finger up/down scrolls the content and a sideways
       swipe moves between windows. Two fingers pan and pinch the canvas as
       before.
     - **Moving along a column of stacked windows:** a vertical wheel
       moves the column whenever the thing under the pointer cannot scroll
       that way (the window's pill, the gap between windows, a window with
       nothing to scroll, an unfocused terminal). At a list's top or bottom,
       a fresh gesture (about 150 ms of wheel quiet) moves to the
       neighbouring window. A fling's momentum stops at the end and never
       carries over. The input lock is how a person prevents the handoff.
     - **Neighbours peek in at the top and bottom** by a few pixels, the
       way they do at the sides. There is no new indicator, and no
       appearance setting turns peeking off: a window's full-screen view
       is the way to see one window alone. The phone window size "Full
       width (no neighbours showing)" is removed; phones keep "Edge to edge"
       and "Comfortable". The owner: "simplify and make UI/UX extremely
       easy".
276. **Inbox items can be dismissed (owner, 2026-10-15, #215):** every Inbox
     item can be dismissed, except the few that block something from
     working until they are acted on (for example "Allow host connections").
     Those stay until resolved, and say what they block.
277. **Commercial code lives in its own repository (owner, 2026-10-15;
     changes where item 31 puts it):** the commercial code, previously
     planned as the `ee/` directory, lives in `kayg/infraternal-enterprise`
     on Forgejo. Its licence and scope are unchanged (items 31–33): the
     commercial licence with an offline key, and only seams until there are
     users. The first planned item is second-admin approval for downgrading
     privileged access (D274). The AGPL core never depends on it and
     builds and runs alone. How the two are built together is still open.
278. **Where the mesh path change shows (owner, 2026-10-15, #201):** there is
     no separate indicator for automatic mesh switching. The path a host
     settles on (relayed, then direct) appears as a step in the add-host
     steps, and as one of the loading steps in the top pill's progress
     circle while the host connects. After that, the Mesh view's
     direct/relayed label is the only place it shows.
279. **Selecting several machines (owner, 2026-10-15, #215):** in the
     sidebar and on the Map, ⌘-click (Ctrl-click on Linux and Windows) adds
     or removes a machine, and Shift-click selects a range in the sidebar.
     The action pill then reads "3 machines" and its actions apply to all of
     them. On phones a long-press starts selecting and taps add more.
     Search does the same in words ("allow full access on all offline
     hosts"). There is no select mode and there are no checkboxes.
280. **The public GitHub mirror (owner, 2026-10-15; extends item 43):**
     `kaygdotorg/infraternal` on GitHub is public and receives `dev` and
     `main` only, never work branches. Issues stay on Forgejo. Nothing is
     pushed until the full history has been checked for secrets. The
     history is then rewritten only to (a) erase any secret found and (b)
     shrink it by removing committed artifacts that belong on Forgejo issues
     (D262). The plan and the cut-over are shown to the owner before the
     rewrite.
281. **In-app feedback (owner, 2026-10-15; design round in progress):**
     - **Fully automated:** the person never leaves the app and needs no
       GitHub account. The owner rejected opening a ready-filled GitHub page.
     - **Where:** "Send feedback" is found in search ("feedback", "bug",
       "idea") and in the version pill's popover. There is no permanent
       button. One short form follows, and whether it is a bug or an idea is
       read from the wording, not picked from a menu.
     - **Attached:** version, edition (CE/EE), browser, OS and screen size,
       shown before sending. Never host names, addresses, user names or
       terminal content in the text. **A screenshot is included by default
       (opt-out).**
     - **Everything lands in GitHub Discussions** on the public mirror. A
       Claude Code triage bot reads the list and promotes what is
       actionable to issues.
     - Still open: the transport and who holds which credential, how
       screenshots are kept from showing private things publicly, abuse
       limits, replies, authorship, and where promoted work is tracked.
282. **VNC is a window kind of its own (owner, 2026-10-15, #223; extends
     D200 V7 and D221):** besides being the fallback when our own capture
     isn't available, VNC is offered generally as a window type for any
     machine that speaks it: Proxmox/QEMU VM consoles, macOS Screen Sharing
     and Linux desktops. It keeps D104's model (the server side holds the
     session). Whether we use an existing Rust RFB library or build our own,
     and whether RFB is re-encoded to video or decoded in the browser, comes
     to the owner as measured candidates (#223). Either is acceptable to the
     owner if it is the fastest.
     - **Proxmox is zero-configuration through the infraternal agent on
       the node:** the agent on a Proxmox node detects Proxmox, lists its
       VMs and containers (and the cluster's other nodes) on its own, and
       opens a VM's console as a VNC window locally, with no API token and
       no setup by the person. Containers open as terminal windows. The
       Proxmox API path is only for nodes without our agent.
     - **Our own VNC client, written from scratch (owner, 2026-10-15, #223):**
       no third-party RFB library. Writing it ourselves takes longer, but
       lets us measure and tune it for the product, choose where to cut
       corners, and keep it small, lean and very fast, without the
       compromises a library brings. The experience to match is Screens 5
       on macOS: that seamlessness, brought to everything that speaks VNC.
       The owner's annoyances with noVNC (the Proxmox console client) are
       to be designed out.
283. **The person's card (owner, 2026-10-15; Q1 to be refined after the
     mockup):**
     - **Fields (Q1, mockup first):** name; username; email; picture
       (initials by default); organisation and role; "logs in as" (a summary
       of login access, e.g. "kayg on 12 hosts, root on 2"); sign-in health
       (passkeys, recovery key, devices); sign out of this device. Nothing
       we would have no use for (phone, address, title, timezone).
     - **One home per thing (Q2):** the card edits name, picture and email
       in place. Username, passkeys, recovery key and devices show their
       state only, and each row jumps to its home in Settings → Account.
     - **Username changes (Q3):** allowed for an admin (or yourself in
       Community) behind one confirm. New SSH certificates are issued, old
       ones are revoked at once, and access rules follow the person, not the
       name. Needs careful design before it is built.
     - **Email (Q4):** optional, never part of sign-in. It is required only
       to invite people, which is an EE feature, or it comes from the
       identity provider with OIDC.
     - **Organisation and role (Q5):** shown only with more than one person
       (EE). Community shows neither.
     - **The pill (Q6):** unchanged (picture, name, username), plus one amber
       mark when something needs attention, such as an unchecked recovery
       key or a passkey on only one device.
285. **NAT traversal details (owner, 2026-10-15, #220; extends D196,
     D131, D166):**
     - **Server down:** machines already in the mesh, with valid
       certificates, keep opening direct paths to each other using their
       last-known addresses and relays. New machines cannot join until the
       server is back.
     - **Automatic relays only on datacenter machines:** a node becomes a
       relay automatically only when it is detected as being in a
       datacenter (datacenter or cloud IP), proven reachable from outside,
       and has spare capacity. Machines on home or possibly metered
       connections are never picked automatically. The detection signals,
       the outside check and the capacity rule come to the owner with
       measurements. Relays carry only their own mesh's encrypted traffic.
     - **Relay first, measure every trick (owner):** pairs where both
       sides are behind hard NAT are relayed from day one. Every NAT
       traversal trick we come across (port prediction, the many-ports
       "birthday" technique, router port mapping and others) is measured on
       real NAT types, and each relayed pair records why it was relayed. A
       trick is built when its measured success and its cost (packets,
       time, side effects such as intrusion alarms) justify it.
286. **Privileged access upgrade flow approved (owner, 2026-10-15, #215):**
     the privileged-access consent mockup (D274) is approved as designed:
     scenarios for sudo, doas, root password, denied, wrong password,
     offline, timeout and several machines; the inline password sealed to
     the host; the tooltip kept clear of the field. The downgrade flow
     (D274) is still to be mocked up.
287. **When a paid licence ends, only the first person keeps working
     (owner, 2026-10-15, #216):** after a paid licence (Homelab, Team,
     Enterprise) ends without a new key, the first person (the account
     that set up the server) keeps everything Community gives. Everyone
     else cannot sign in until a valid key is entered, and their data,
     sessions and settings are kept, not deleted. The warning starts
     before the end date and names how many people will lose access.
288. **`infraternal mux`: sessions are automatable from inside a session
     (owner, 2026-10-15; extends D241):**
     - **A deliberate command, never an escape sequence (Q1):** `infraternal
       mux …` talks to the local infraternal agent over a socket that only
       the calling session can reach. Printed output can never open or
       control windows.
     - **Fully automatable like tmux and zellij (Q2):** list, open, type
       into, read output, monitor, rename and close sessions, and open
       windows on the person's canvas (the agent relays to the server, which
       pushes to their open devices).
     - **Hard gate across hosts and accounts:** within the person's own
       sessions on the same host and account, there is full control with no
       prompt. Anything that crosses a host or account boundary (a session
       on build-01 opening a shell on nas, typing into a root session) is
       impossible unless an access rule allows it AND it is approved. The
       approval can be set globally. The rule syntax and the approval UX are
       being designed with the owner.
     - **Unattended (Q2c):** with no approval available, cross-boundary
       requests are denied with a clear message.
     - **AI tools learn it (Q3):** a tmux-compatible subset for zero setup;
       a skill offered once per detected AI tool and installed only on the
       person's click; a built-in MCP server (`infraternal mux mcp`).
     - **Every command and subcommand of ours ships a well-written, concise
       skill** describing what it does, its commands and its safety rules.
289. **The SSH engine is russh with ring, built into the binary (owner,
     2026-10-16, #221; extends D235):**
     - **Engine:** russh with the ring crypto backend (ring is already in the
       binary). Measured at 500 sessions: 189 KiB per session (92 MiB in all)
       against 2,240 KiB for a separate OpenSSH sshd (1.07 GiB); TCP to
       prompt 100/104 ms p50/p99 against 132/197 ms on a 1 ms link.
       Rejected: a separately managed OpenSSH (about 12× the memory per
       session); libssh and Dropbear (their certificate login does not meet
       the contract); russh with AWS-LC (+2.68 MB, adds a second crypto
       library).
     - **In the binary, not a downloaded add-on:** adding a host from the
       canvas switches it to our SSH automatically, so every node needs it
       and a separate download would only add a step and a delay to adding
       a host. Rejected: an on-demand SSH add-on file.
     - **Size exception to D243:** measured +1,872,736 B x86_64 /
       +1,589,336 B aarch64 without SFTP, plus +157,088 / +133,216 B for
       SFTP. The caps rise once by the measured delta when the SSH slice
       lands, and only by that; jobs offset it with cuts elsewhere where
       they can, and the ratchet continues downward from there.
290. **App windows never fight a window manager (owner, 2026-10-16, #146;
     extends D208):** on a desktop where a window manager places and sizes
     windows (tiling managers on macOS such as OmniWM, yabai and AeroSpace,
     and their Linux and Windows counterparts), infraternal does not resize
     the real window to match its canvas window. It detects this on its own,
     with no setting: a known manager is running, or a size it set is undone
     by someone else. From then on the canvas window follows the real
     window's size and scales the picture to fit; it never retries the
     resize. Without a manager, resizing from the canvas still resizes the
     real window. Trigger: the owner saw TextEdit flicker on the MacBook as
     infraternal shrank it and OmniWM tiled it back, over and over.
291. **A new host joins through the add-host SSH connection; no agent port
     is required (owner, 2026-10-16; amends D64 and D215):** the server is
     already signed in to the host over SSH during add-host. It opens a
     reverse tunnel inside that connection, and the freshly installed
     infraternal agent makes its first connection to the server through it.
     If infraternal could sign in, the host can join; nobody opens a
     firewall port for it. After the join, the agent's link to the server
     takes the mesh path (D215): direct UDP on a port each node picks itself
     (D228 M4), then a relay, then TCP/TLS on 443 (D196). The server's agent
     port (7443) is no longer required for anything. Owner: "this is very
     non-intrusive and I love it." Trigger: adding calternal-dev failed
     because its network did not allow TCP 7443 to the server (#230).
292. **VNC build choices (owner, 2026-10-16, #223; extends D282):**
     - **Pipeline B, mirrored decode (Q1):** the Rust session owner decodes
       every update into its retained framebuffer, and the browser decodes
       the same compact updates in an on-demand worker. A late or returning
       viewer gets the server's snapshot first.
     - **The person in control sets the remote resolution (Q2);** watchers
       scale to fit.
     - **macOS Screen Sharing first, macOS 26 onwards only (Q3).** Older
       macOS versions come later.
     - **First compatibility gate (Q4):** QEMU/Proxmox and macOS Screen
       Sharing; a Linux VNC server later. The test Mac is the Mac VM, whose
       Screen Sharing listens only on its private address and localhost, so
       tests reach it through a tunnel. Its credentials are supplied by the
       orchestrator at run time, never stored in the repo, logs or argv.
     - **Clipboard (Q5):** text first, with explicit Send and Get. Two more
       features the owner wants, which other VNC clients lack: **automatic
       text recognition** of the remote screen (owner: "a big one that I
       would love"), and **a text field whose contents are typed into the
       remote window** at the cursor. Their design is grilled next.
     - **Hard gates (Q6):** extremely lean and fast. The VNC code is
       loaded only when a VNC window opens and is at most 128 KiB gzip;
       input to pixel p95 ≤50 ms; join ≤300 ms.
     - **Synthetic protocol coverage (Q7)** until a cleaned-up recording from
       the real Mac exists.
293. **VNC round 2 (owner, 2026-10-16, #223; extends D292):**
     - **Automatic text recognition (Q8):** text on a remote screen becomes
       selectable, copyable and findable in search on its own. It runs only
       after the screen settles and only on the regions that changed. It is
       lazy and must never stall search or the window.
     - **Where it runs (Q9):** on the server, which holds the screen copy,
       and through the system's own recognition on Macs with our infraternal
       agent. The engine is chosen by the owner from measured candidates.
     - **Type a text field into the remote (Q10):** one toolbar input types
       its text at the remote cursor on Enter, with progress and cancel,
       adapting its speed to the remote; works on login and boot screens;
       ⌘⇧V pastes by typing.
     - **Quality is automatic by default, and the person can choose (Q11):**
       resolution, frame rate and quality can be set, because automatic
       detection can be wrong (e.g. a LAN machine left lossy). App windows,
       VNC and later RDP are presented to people as one thing, **Remote
       Desktop**, with global settings in Settings → Remote Desktop and a
       section per kind.
     - **Fit by default, zoom toward 1:1 and pan (Q12).**
     - **Keyboard (Q13):** keys behave as they do in terminal windows.
     - **VNC password (Q14):** none where our infraternal agent can sign in
       locally; elsewhere remembered only after it is typed, sealed with the
       person's passkey.
     - **Mac whole desktop (Q15):** our own capture when the helper has its
       permissions, otherwise Screen Sharing, chosen automatically; the
       window says which.
     - **Curtain (Q16):** later, shown only where the machine proves it
       works.
294. **VNC round 3 (owner, 2026-10-16, #223; extends D293):**
     - **Settings → Remote Desktop (Q11):** General (Quality Auto / Sharp /
       Smooth, Resolution Match window / 1080p / 1440p / 4K / Custom, Frame
       rate Auto / 30 / 60 / 120), then a section per kind (App windows,
       VNC, RDP later). Each window has a per-machine override in its menu,
       remembered for that machine, and shows a small label when it is not
       on Auto.
     - **Aspect ratio (Q12):** never stretched. When the remote can resize,
       it follows the window's shape; when it cannot, the leftover space
       shows the canvas background, and double-clicking the window edge
       snaps the window to the screen's shape.
     - **Multiple displays (Q17):** one window with a Display 1 / 2 / All
       switch, plus "open this display as its own window"; all on one
       connection.
     - **Phone and tablet input (Q18):** trackpad mode by default, a
       one-tap switch to touch mode remembered per machine; a pencil always
       points directly.
     - **Files (Q19):** dropping a file on a Remote Desktop window sends it
       with **infraternal Drop**, our file-sending feature between machines
       (the "file drop" of D196), through the infraternal agent. Plain VNC
       without an agent says it cannot receive files. Drop gets its own
       design round.
     - **Several viewers (Q20):** one person in control; others watch and
       can ask for control; the controller sees Give / Keep; an idle
       controller loses control after 5 minutes when someone asks.
295. **Undoing a failed server update stays simple (owner, 2026-10-16,
     #211; narrows D251's recovery):** "let's keep it lean and simple".
     Right before switching to a new version, the server makes one safe copy
     of its database (SQLite's online backup) next to the previous binary.
     The previous version stays the one that starts on any restart until the
     new one passes its health check, within about 2 minutes. If the new
     version crashes or fails the check, the previous binary and that
     database copy come back and the server restarts; the Inbox says the
     update was undone. Data written in that short window is lost. After a
     successful check the copy is kept until the next update. Rejected:
     encrypted recovery checkpoints with a separate recovery supervisor and
     certificate restoration (estimated 4-7 days of work for the same
     outcome). Broader backup and disaster recovery remain separate work.
296. **Per-person login typing target is measured, not 5 ms (owner,
     2026-10-17, #205; amends the 5 ms echo target used for D270):** echo
     p99 of 5 ms is not reachable on our hosts; the shipping terminal
     measured 24.53 ms pooled p99 and the per-person login prototype
     31.13 ms on the perf VM. The bar is now: the per-person login path is
     no slower than the shipping terminal on the same venue and workload
     (pooled echo p99 ≤ the shipping baseline, about 25 ms today), measured
     side by side in each round. 5 ms stays the long-term aim, not a merge
     gate. India to Germany adds about 150 ms per key, so the gap is small
     to the person typing. Rejected: keeping 5 ms as a hard gate, which
     blocks SSH over the mesh (#221) for days with no known fix.
297. **Controlling machines from other machines is one switch per machine
     (owner, 2026-10-16/17; completes D288's open rule syntax and approval
     UX):** "this is the simpler version for sure".
     - **One switch (Q1):** each machine has "Can be controlled from other
       machines", off by default. On: `infraternal mux` and AI tools on the
       person's other machines may open, type into and read that machine's
       sessions, subject to the approval setting. Off: nothing from another
       machine can control it; the person still uses it normally in the
       browser. Turning it off ends any control in progress at once. No
       separate rule syntax for this; access rules (D154, D164) still decide who
       may reach the machine at all.
     - **Approval setting (D288 Q3):** global, with "Ask each time"
       (default), "Allow when a rule permits", or "Off"; a mark in the
       pill, an Inbox entry and Revoke for every grant (D288 Q4).
     - **Who approves (Q2):** anyone may start a request; only admins can
       answer the prompt. Rejected: only admins may automate at all.
     - **Other accounts on the same machine (Q5):** a request from another
       account on the same machine (`deploy` wanting to type into `kayg`'s
       terminal) asks first, exactly like one from another machine.
       Rejected: same machine means allowed.
     - Unattended requests with nobody to approve are denied with a clear
       message (D288 Q2c).
298. **Real logins ship before their size trim (owner, 2026-10-17, #172;
     a one-off D243 exception):** "you can ship it now and trim later".
     Real logins (#172) grow the shipping binary by 311,040 B on x86_64 and
     274,712 B on aarch64, against D243's 16 KiB allowance. The caps are
     raised to the measured sizes so SSH over the mesh (#221) is not held
     up. The trim is still owed: a follow-up measures where the bytes go
     and removes what is free to cut, and the caps ratchet down with it.
     This is not a new allowance for other changes.
299. **CLI overhaul, first answers (owner, 2026-10-17, #239; extends D202
     and D239):**
     - **One word: "machines" (C1):** the CLI says machine everywhere,
       like the app: `infraternal machines`, `machines add root@10.0.0.5`.
       "Node" stays only for the mesh role inside `status`. No hidden
       aliases for other words.
     - **The CLI recognises you, and asks only when it must (C2):** on a
       joined machine the CLI acts as the person linked to the local
       account it runs under; that link is set up by add-host (the local
       login account used when adding, tied to the person who added it).
       Other local accounts, and machines that aren't joined, use
       `infraternal sign-in`. Destructive actions still ask for a fresh
       passkey.
     - **Bare `infraternal` is `status` (C4):** until the machine is joined
       it says how to join (`infraternal up`); after that it shows the same
       overview as `infraternal status`.
     - **Every command has `--json` (C4):** one stable versioned envelope for
       AI tools and scripts; fields are only ever added, a removal bumps the
       schema version.
     - **Unbuilt commands are hidden (C5)** from help and from generated
       skills until they work.
     - **Access rules in the app's words (C6):** for example
       `infraternal access allow kayg deploy@build-01`, added to the CLI as
       each piece ships in the app.
     - Still open: which commands live at the root versus under
       `infraternal canvas` (C3), and the exit-code table (C7).
300. **When the server gives up on a quiet host (owner, 2026-10-17, #234;
     amends D265):** a missed liveness reply no longer cuts a healthy link.
     (A) The reply deadline follows the measured path: about twice the
     smoothed round trip plus four times its variation plus a small margin,
     so one lost packet's recovery fits (measured at 150 ms with 1% loss:
     12 cut links in 10 minutes down to 1). (B) One miss only marks the
     route doubtful and the window shows reconnecting; the link is retired
     after a second consecutive miss. A dead host is noticed after about
     0.4 s at 150 ms instead of 0.25 s; LAN is unchanged. (C) sending probes
     outside the ordered stream is a later, separate design question.
301. **Size exceptions accepted, trim later (owner, 2026-10-17; one-off
     D243 exceptions like D298):** replacing a stuck agent (#231/#235,
     about +53 KB), the honest Mesh view (#236, about +37 KB),
     connection-close logging (#227, about +37 KB) and edge auto-update
     (#211, about +636 KB x86_64 / ~800 KB aarch64) ship at their measured
     sizes; each keeps a trim follow-up and the caps ratchet down with it.
302. **Remote control rules, completing D297 (owner, 2026-10-17, #170):**
     1. Plain SSH is not covered by the per-machine switch; the switch says
        "SSH is separate" (SSH keeps D235/D289 login rules).
     2. Typing into another person's session needs both an admin's
        approval for the automation and the session owner's consent (D187).
     3. Another account on the same machine always asks an admin, whatever
        the global setting.
     4. An approval covers what that shell can do, said plainly; opening a
        new root session or falling back to root needs a fresh approval; AI
        tools never supply the D274 password.
     5. "Allow when a rule permits" counts as standing approval for
        unattended jobs; "Off" means automation is off.
     6. "A rule permits" means a named "Automate" action in Roles plus Login
        access and the session's sharing rights; the prompt shows which rule
        allowed it.
     7. The per-machine switch needs an admin covering all of the machine's
        tags (D211); widening the global setting needs an instance-wide admin
        and a fresh passkey.
     8. People handing Remote Desktop control follow D294; the switch covers
        AI tools and `infraternal sessions` only; idle handover never gives
        control to an AI tool.
     9. One approval is one described action on one session; a watch lasts
        until stopped; broader standing permission comes from Roles.
     10. Automation runs only while the target is connected to the server;
        losing the link stops it; a cold server restart ends approvals (shells
        stay); the UI shows "stop requested" apart from "stopped on the
        machine".
     The mesh default stays as D216 decided: the community edition allows
     members to reach each other by default, the enterprise edition starts
     with no rules (deny).
303. **CLI layout and exit codes (owner, 2026-10-17, #239; completes D299):**
     - **Where things happen (C3):** root commands act here, in this
       terminal: `status`, `machines`, `open <machine>` (a shell right here),
       `sessions` (list, attach, send, read, close: the D288 automation lives
       here), `logs`, `mesh`, `access`, `update`, `sign-in`, `up`, `skill`.
       `infraternal canvas …` acts on the person's screens in the app:
       `canvas open`, `canvas windows`, `canvas focus`, `canvas close`, and
       it is how AI tools put something in front of the person.
     - **Exit codes (C7, POSIX-safe):** 0 ok, 1 failed, 2 usage, 3 not
       allowed, 4 not found, 5 off or unreachable, 6 partly done, 130
       interrupted; `status` exits 5 when something that should run is down.
       The JSON envelope only ever gains fields; a removal bumps its version.
304. **Session automation and canvas commands, as shown to the owner
     (owner, 2026-10-17, #239; extends D303):** "i love it". `infraternal
     sessions [machine]`, `sessions read <machine>:<session> --last N`,
     `sessions send <machine>:<session> '<text>'`, `sessions watch`,
     `sessions open <machine> --name …`, `sessions close`; `infraternal
     canvas open|windows|focus|close`, with `--note` so an AI tool can say why
     it put something in front of the person. A refused request says why and
     what to do, and exits 3; a request waiting for approval says who must
     approve. Every command, including these, has `--json` (D299).
305. **Ctrl-C stops the calling script too (owner, 2026-10-18, #239; refines
     D303):** "this!" When the person presses Ctrl-C, `infraternal` finishes
     its `--json` envelope (`interrupted`), restores the default SIGINT action
     and re-raises the signal, the way most command-line tools end. A shell
     loop or script that runs `infraternal` then stops as well, and `$?`
     still reads 130. Programs that call `infraternal` directly see "killed
     by signal 2" instead of a plain exit code 130; that is accepted.
     Rejected: exiting with plain code 130, which let a shell loop carry on
     after Ctrl-C.
306. **Mesh view ships at its measured size, trim later (owner, 2026-10-18,
     #236; amends D301):** "sure yes". Merged onto production the honest Mesh
     view measures +74,368 B x86_64, double the ~37 KB D301 accepted,
     because its earlier figure was taken against an older, larger base. It
     ships now at the measured size, like real logins (D298); the trim job
     (#236) continues and the caps ratchet down with it.
307. **One answer per terminal query, marked on the wire (owner, 2026-10-19,
     #160, #206):** "a is fine". Every attached browser answers terminal
     queries (cursor position, device attributes, colours), so with three
     viewers three answers reached the shell and a late answer still
     arrived. The browser marks a renderer's reply as a reply, not typing,
     with an additive field on Input; the server forwards exactly one reply
     per query to the PTY and drops later or expired ones. Rejected: a
     browser-only rule (only the focused viewer answers, late replies
     dropped), which still lets two focused devices both answer.
308. **Shared layout ships at its measured size, trim later (owner,
     2026-10-19, #243; like D306):** "yes that is fine". The server-held
     canvas layout (store, op log, snapshots, browser sync) measures about
     +117 KB x86_64 over the current caps after a first trim (−13.9 KB),
     above the 64 KB band of D243. It ships at the measured size once its
     reviews and the phone pass are clean; trimming continues and the caps
     ratchet down with it. Rejected: holding the feature for a deeper trim.
309. **Owner answers 2026-10-19 (#242, #146, #94, D300, #205, #243):**
     - **Row menu and swipes (#242):** "1a agreed", "1b agreed", "1c yes,
       one shared component!". Right-click on a row opens our own menu:
       Open, Open beside, Rename, Copy name, then "End session…" last, which
       asks before ending. Swipe left reveals End, swipe right reveals Open
       beside (trackpad, Magic Mouse, touch); a short swipe reveals, a long
       swipe acts. One shared component for every row list (sessions, hosts,
       Mesh nodes, windows). Right-click never selects the row's text.
       Mockup round, then owner approval, then the build.
     - **Machine view ("infrafetch", #94):** "oh glassy carrds would be sick
       yes, needs to be mocked up though". Direction C (cards), glassy, with
       B's dot meters and A's dotted mark; mockup round next.
     - **App windows order (#146):** "agreed". First cut our own added
       latency (about 40 ms over the network round trip, target 16 ms),
       then build the direct browser-to-host path (D185, D192).
     - **Proxmox lab:** minipc01 may be used: create test guests and delete
       only those we created; never touch guests with "croit" in the name.
     - **D300 timings stand:** "sure!". Doubt after 251/376 ms, retire after
       501/751 ms.
     - **Revocation while the database is frozen:** "that's fine". The
       socket closes within about 1 s.
     - **Shells that cannot redraw:** "agreed". After reattach their screen
       carries a small "screen may be out of date" note until new output.
     - **Phone minimum column width (#243):** "agreed". On touch screens a
       column is drawn at least at a readable minimum width and the canvas
       scrolls sideways; the saved weights stay exactly what was set, so a
       phone never rewrites the desktop's layout.
310. **Machine pill uses the machine cards; per-user memory pool agreed
     (owner, 2026-10-19; completes D309):**
     - **#94:** "it should indeed replace it". The machine pill's machine
       section becomes a compact version of the glassy machine cards (name,
       OS mark, three dot meters, uptime) and opens the full Machine view.
       One look for machine facts everywhere.
     - **#205 / D270:** "agreed then". Each person's process keeps its
       terminal screens and scrollback in one pool of 1/32 of the machine's
       usable memory, clamped to 80–512 MiB, with a per-session floor of
       256 KiB–2 MiB. The pool covers only infraternal's own screen memory;
       programs run in a shell (builds, AI agents) are separate processes
       and are not limited by it. When the pool is full, a new session is
       refused with a clear message instead of pushing the machine into
       swap.
311. **Client-side mux and mesh: the app is the mux, the CLI automates
     (owner, 2026-10-29, #251; extends D288, D241, D201, D169, D27):**
     - **The app is the mux:** sessions are used interactively only in the
       web client and the native apps. The `infraternal` CLI is for
       automation only: no terminal attach, no prefix keys, no in-terminal
       tabs or status rows ("a prefix again puts us in the keyboard warrior
       category"). Rejected: a `Ctrl-B d` attach, a status row, a terminal
       tab bar.
     - **Human-friendly CLI:** plain output, and errors that name the fix
       and the next step (for example `No session called "biuld". Did you
       mean "build"?`). `--json` on every command (D299 envelope). Every
       command ships a short skill, plus `infraternal mux mcp` (D288).
     - **Mux verbs:** sessions `ls`, `new`, `send`, `capture`, `wait`
       (`--until-idle`, `--match`), `watch` (read-only), `rename`, `close`.
       Canvas: `split --beside|--below`, `open`, `focus`, `close-window`,
       pushed through the server to the person's open devices. There are no
       pixel positions or free layouts; the canvas places windows. D288's
       host and account boundaries and approvals apply unchanged.
     - **tmux-compatible subset for AI tools (D288 Q3):** `new-session`,
       `send-keys`, `capture-pane`, `list-sessions`, `kill-session`,
       `split-window`, mapped onto the verbs above. Anything else fails with
       a clear "not supported"; attach is never part of it.
     - **Laptop sign-in:** `infraternal sign-in <server>` shows a link, a
       code and a terminal QR code. The QR pre-fills the code; approval
       always needs the passkey. The code is single use and expires in 10
       minutes. The laptop gets its own revocable credential, scoped to
       automation. The native apps sign in with the passkey directly.
     - **One-command join:** `curl -fsSL https://<server>/install | sh`,
       served by the person's own server. It installs, verifies the binary
       against the signed release manifest with a release key built into the
       script (not only a checksum from the same server), reads a join code
       from the terminal (never argv or history; single use, one machine,
       10 minutes), joins and starts. Afterwards, `infraternal up <server>`
       joins. SSH add-host stays as the fallback (D291).
     - **Mesh on laptops, CLI first:** Linux already works. On macOS,
       `infraternal up` asks for sudo once and installs a launchd system
       service that runs the userspace peer (D169 GotaTun on utun); the
       native app later reuses that service. Windows follows later the same
       way, with a Windows service. The CLI works on its own on every
       platform.
     - **App windows (#146) and macOS builds** run in the lume VM
       `macos-02-std` (paravirtualized Metal). Perf numbers from it are
       labelled "VM"; release-gate perf numbers come from real Mac hardware,
       only with the owner's OK.
     - **Order:** D241 shell marker → `mux` sessions with `--json`, skill and
       MCP → canvas verbs and the tmux subset → laptop sign-in → one-command
       join → macOS mesh service → native apps and app windows.
312. **Layout edits live per tab; the server is the only saved copy
     (owner, 2026-10-30, #250; replaces the multi-tab layout journal):**
     - Each tab keeps its unconfirmed canvas layout edits in memory and
       sends them to the server; only server receipts confirm them. There
       is no shared multi-tab journal in browser storage, so nothing can be
       written or resurrected after sign-out.
     - While edits wait for confirmation, the tab says so plainly ("Not
       saved, keep this tab open"). If that tab closes, crashes or is
       discarded before confirmation, those unconfirmed edits are lost
       (owner: "this is 100% on the user"); confirmed edits and terminal
       sessions are unaffected.
     - Opening the app offline shows "Connect to load your layout"; a tab
       that is already open keeps its drawing when the connection drops.
       Owner: this matters for the planned canvas decoupling.
     - Plan: `docs/plans/250-layout-journal.md` (branch plan-250-journal).
       Rejected after three review rounds: a cross-tab Web Lock journal
       (sign-out privacy and lost-entry interleavings kept recurring).
313. **Mesh direct paths and relays: grill round 1 (owner, 2026-10-30, #220;
     extends D163, D176, D185, D196, D197, D201):** answers to the #220 design
     questions Q1–Q7; Q8 (port mapping and connection checklist code) waits
     for the size/RSS/idle comparison job.
     - **Q1 socket seam C:** direct paths stay entirely in the kernel
       WireGuard socket (raw send plus packet receive on its port for
       discovery); only relayed or hard-NAT pairs go through the userspace
       shim, where the relay hop costs more than the copy. A perf-VM job
       measures seam A (all userspace) against seam B (kernel only) in µs
       per packet and CPU per Gbit/s first; the numbers go on #220.
       Rejected: A (about a core per Gbit/s on direct paths), B alone (rules
       out hard-NAT techniques later).
     - **Q2 rendezvous signalling:** through the pair's home relay, with
       tickets the coordinator signed in advance, after the coordinator-only
       path works; it keeps working while the coordinator restarts (D166).
       Rejected: both at once (a duplicate exchange on every setup).
     - **Q3 relays:** a pair may use any relay in the same mesh; relays
       forward ciphertext only. An admin allow-list exists only as an
       override. Rejected: owner-controlled relays only (India↔India pairs
       fall back to Germany, about 396 ms).
     - **Q4 hard-NAT prediction:** built only when two weeks of production
       counters show at least 10% of relayed pair-hours with one
       endpoint-independent side and a relay cost of at least 30 ms over the
       estimated direct RTT; then sequential port prediction (one socket)
       first, the many-socket technique only after it.
     - **Q5 switch rule:** switch when the saving is at least max(5 ms, 15%)
       over 5 samples spanning at least 3 s, with a 10 s dwell between
       switches; direct wins inside that band. The same numbers as the #201
       selector.
     - **Q6 port-443 fallback, first release:** TLS on 443 with ALPN next to
       HTTPS, plus a WebSocket upgrade for networks that only pass
       web-looking traffic. Rejected for now: HTTP CONNECT proxies (they
       need proxy credentials, against the fewest-secrets rule).
     - **Q7 relay framing:** QUIC DATAGRAM frames (no head-of-line
       blocking, matches WireGuard). Rejected: one reliable stream per pair
       (one loss stalls all of a pair's flows for about one RTT).
     - **Order:** seam measurement → real-socket observation (seam C) →
       relay with QUIC DATAGRAM and TLS/WebSocket 443 → rendezvous and
       simultaneous open → upgrade and flip-back on the #201 selector →
       PCP/NAT-PMP/UPnP (after Q8) → node-relay qualification → hard-NAT
       experiments only if Q4 triggers.
314. **One CLI command set for sessions and canvas (owner, 2026-10-30,
     #251; amends D311's names, keeps D303/D304):** "agreed, love it".
     D311's `mux` verbs fold into D303/D304's nouns, one name per idea and
     `--json` on every command:
     - **Here, in this terminal:** `status`, `machines`, `logs`, `mesh`,
       `access`, `update`, `skill`, `sign-in <server>` (link, code and QR),
       `up <server>`, and `open <machine>`: a plain one-off shell here, not
       a saved session and without prefix keys.
     - **Sessions (automation only, never interactive):** `sessions
       [<machine>]` lists; `sessions new <machine> --name <n> [-- cmd]`;
       `sessions send <machine>:<session> '<text>'`; `sessions read …
       --last N`; `sessions wait … --until-idle <d> | --match <re>
       [--timeout <d>]`; `sessions watch …` (read-only); `sessions rename
       … <new>`; `sessions close …`; `sessions mcp` for AI tools.
     - **Canvas (the person's screens in the app):** `canvas windows`,
       `canvas open <machine>:<session> [--beside|--below <window>]
       [--note '…']`, `canvas focus …`, `canvas close …`.
     - **Renames from D311:** `ls` → bare `sessions`, `capture` → `read`,
       `split` → `canvas open --beside/--below`, `close-window` → `canvas
       close`, `mux mcp` → `sessions mcp`; D304's `sessions open --name`
       → `sessions new`, since "open" means "show on screen".
     - **AI tools** get MCP, `sessions`, and D311's tmux-compatible subset
       (`new-session`, `send-keys`, `capture-pane`, `list-sessions`,
       `kill-session`, `split-window`), mapped onto the verbs above. Owner:
       "support tmux style commands yes because lots of training data on it
       for LLMs". Anything outside the subset fails with a clear "not
       supported"; attach is never part of it. The tmux name appears in code
       only where it names that compatible command set.
     - Errors name the fix and the next step, for example
       `No session called "biuld" on web01. Did you mean "build"?`, exit 4
       (D303 codes).
315. **Auto-started multiplexers: never interfere, offer the guard line
     (owner, 2026-10-30, #251; replaces D241's transparent skip):**
     "agreed" (option B). Infraternal never changes a shell's startup to
     skip a multiplexer: three review rounds showed a transparent skip
     cannot be made safe (stock snippets read the multiplexer's own
     variables, a startup `exec` keeps the PID, and a skipped test under
     `set -e` can end the login). Instead, the first time a session on a
     host starts tmux or zellij from its startup files, one quiet line says
     so and offers the guard `[ -n "$INFRATERNAL_SESSION" ] || <command>`
     to copy, plus a button that adds that line to the startup file after
     the person confirms, with undo. Every session still exports
     `INFRATERNAL_SESSION`. The per-host and global switches from D241 stay.
     **Wording and flow amended (owner, 2026-11-01, #251, after the 18
     review screenshots):** "don't say 'add guard'. just ask '<Existing
     multiplexer> started automatically. Would you like to switch to the
     Infraternal Multiplexer instead?' tick cross and ? — where ? points to
     the docs about our multiplexer." The notice is that one question with
     three icon buttons, each with a tooltip and accessible name: ✓ switches
     (the same confirmed edit with the exact line shown, then a "Restore
     <file>" undo; where no startup line can be edited, ✓ copies the line),
     ✗ keeps the other multiplexer and does not ask again on this host, ?
     opens the docs page about the Infraternal Multiplexer
     (`docs/multiplexer.md`, published at infraternal.com/docs/multiplexer).
     The word "guard" no longer appears in user-facing text. The safety
     rules above are unchanged.
316. **Mesh path finding, names and the reverse proxy (owner, 2026-10-30,
     #220; answers D313's Q8, confirms D165, refines D219):**
     - **Path finding uses str0m's ICE core** for host-to-host mesh paths,
       the same engine D192 chose for the browser-to-host direct path, so
       the binary carries one implementation. Measured on #220: +207,840 B
       x86_64 / +184,240 B aarch64, accepted by the owner; it drives a
       caller-owned raw socket next to the kernel WireGuard port (seam C,
       proven on the perf VM). Port mapping (PCP, NAT-PMP, minimal UPnP-IGD)
       is our own (~9 KB estimated), with a fuzzed parser for router replies.
       Rejected: our own checker (two implementations once #103 lands),
       rtc-ice, portmapper and igd-next (0.4–2.1 MB).
     - **Mesh names:** `<host>.internal` by default (D165). A person can add
       their own subdomain (for example `mesh.kayg.org`) as an extra suffix.
     - **Reverse proxy: every client runs it, and we never write our own
       proxy engine.** Exposing a service on a name with HTTPS is built now.
       Every infraternal node can serve it, without root when it listens
       above port 1024. TLS certificates use the **DNS-01** challenge as the
       built-in default, so names behind NAT or on the mesh-only network
       still get valid certificates. Traefik itself can't be embedded in the
       single static Rust binary (it is a Go program, not a library), so the
       engine is chosen by the owner after measurement: embeddable Rust
       engines (Pingora, Sozu, rpxy) against Traefik as a managed sidecar,
       on size, memory, speed, TLS stack and licence. Rejected: our own
       proxy engine and an HTTP-01-only default.
