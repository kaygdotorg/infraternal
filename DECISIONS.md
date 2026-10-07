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
98. **Sign-in:** one usernameless "Continue with passkey" button, plus a quiet
    secondary "use a different passkey…" that opens the browser's QR or
    security-key flow. Typing a username is never required.
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
