# Reverse proxy and hosted cloud grill

## Already decided

Decision numbers point to [DECISIONS.md](../../DECISIONS.md). The inventory reflects the J1370 base and the recorded owner answers on #281.

| Decision | What it settles |
| --- | --- |
| D1 | infraternal is an all-in-one self-hosted infrastructure manager for SSH, machines, metrics, containers and other infrastructure workloads. |
| D2 | “Self-hosted only. There is no hosted cloud.” The operator runs the server. D38 is the explicit exception. |
| D3/D198 | Features ship as plugins and can integrate with existing systems. Roles and features are independently switchable. |
| D38 | Paid Apple apps may use a content-free APNs wake-up relay. Free push integrations are ntfy and gotify. |
| D45 | The original SSH-led pitch limited claims to working features. D388 replaces the pitch and retains that rule. |
| D46 | The original public pages included landing, docs, changelog, roadmap and waitlist, with no third-party trackers. D220 and D388 revise the page list. |
| D64 | Managed hosts dial out. The web app, API and WebSocket can use standalone TLS or HTTP behind a reverse proxy. |
| D291 | Add-host bootstraps through the existing SSH connection, then switches to the mesh. Public 7443 is unnecessary. |
| D196 | Direct mesh paths use exchanged candidates and NAT traversal. Hard NAT uses a relay, with TCP/TLS 443 for networks blocking UDP. |
| D391 | Fixes the relay's public port at 443 for this phase and records the original TLS/WebSocket-first order. |
| D392 | Only the server gets the app's default-drop input policy. Managed hosts do not require manual router forwards for normal mesh access. |
| D402 | Reverses the order in D391. The server node gets the independent QUIC DATAGRAM relay role first, TLS/WebSocket 443 next. The deployment CA issues dedicated relay leaves, and relay observability is counters only. |
| D220 | Supersedes D46's original page list and puts automatic TLS in a separate reverse-proxy component. D388 restores the landing page. |
| D223 | Cloudflare Pages serves the public site and R2 stores signed releases independently of the homelab. D401 changes the public release origin. |
| D325 | One Pages site with docs under /docs, built by us. App docs bundle text and fetch media when needed. D388 refines media and versioning. |
| D388/D389 | Current pitch is “Infrastructure you fully own”. The site has landing, /docs, /changelog, /releases and /install. |
| D401 | Serve signed release files through the site's /releases path with a Pages Function and R2 binding. Retire the old builds domain. |
| D253 | Boot Machines is off by default. One node per LAN handles PXE, caches verified images and enforces time-bound boot access. |
| D260 | Observability is first-party. Full logs live on machines, recent summaries live on the server, redaction happens at source, and basic alerts go to the Inbox. |
| D265 | Terminal resume tokens travel in the first WebSocket message, outside proxy-visible URLs and headers. |
| D261/D263 | Alert access is scoped, history is bounded by machine kind and disk, and the proxy log profile is three days or 5% of free disk, whichever limit arrives first. Further Boot Machines design waits for stable mesh and dogfooding. |
| D277 | AGPL-3.0-only Community builds and runs independently. Commercial code lives in the separate Enterprise repository under its offline licence model. |
| D334/D374 A14 | Community is one person with a passkey or their own IdP. Invites, additional users and local groups belong in Enterprise. |
| D310 | The Machine pill uses compact machine-card facts and opens the full Machine view. |
| D324 | The full Machine view should use a carefully composed grid. Card work waits until at least containers. |
| D385 | The machine pill has two tabs, Machine and Connection. Mesh and link details stay in Connection. |
| D164/D216/D384 | Mesh grants are directional and can narrow to ports or services. Community and Enterprise have different defaults. Userspace enforces peer grants, with a kernel guard where applicable. |
| D316 | Every client can run the proxy. Use an existing engine and default to DNS-01. The original decision called for an owner choice after measuring embeddable engines against a managed sidecar. |
| D320/#289 | The owner chose on-demand OpenBao for secrets, including future custody of DNS tokens. |
| D330 | Rootless public exposure is opt-in on unprivileged ports, normally 10080/10443, with a firewall/router reachability warning. |
| D336/D374 A15 | The owner chose Traefik as a managed sidecar with a cgroup per child. It is pinned, fetched on demand and supervised on publishing nodes. |
| #281 owner answers | `publish <port>` defaults to mesh-only, bare `publish` lists, and `--public` requires first-use confirmation. Default certificates are node-local per-machine wildcards. Flat names use exact certificates and appear in public Certificate Transparency logs. |

Public docs, release artifacts and wake-up notifications are distinct from hosting a customer's infraternal server. A hosted product would require an explicit amendment to D2. The AGPL core and Enterprise split still apply under D277.

### The engine comparison happened

J20 measured Pingora, Sōzu and rpxy against Traefik on the x86 perf VM. The Rust demos used **6.14–8.19 MiB idle RSS** versus **93.30 MiB** for Traefik and reached **34,965–38,928 req/s** versus **25,711 req/s** at HTTP/1.1 concurrency 512. Embedding added **4.73–6.38 MB** to the x86 binary. Pingora needed our own route and certificate reload logic, Sōzu's supported model was supervisor plus workers, and rpxy lost requests during reload. The load runs used one sample per workload and shared a generator/backend CPU. [J20 measurement and integration findings](https://git.kayg.org/kayg/infraternal/issues/261#issuecomment-71101)

R3 paired Caddy and Traefik. Idle RSS was **47.54–47.93 MiB** for Caddy and **93.41–93.97 MiB** for Traefik. At concurrency 512, Caddy reached **12.6–13.2k req/s** at **69.6–73.9 ms p99** and Traefik reached **20.6–23.2k req/s** at **42.2–53.0 ms p99**. Traefik preserved all checked connection types through **6/6 reloads**. Caddy closed existing HTTP/1.1 and HTTP/2 connections in each trial. WebSockets survived with an explicit delay and closed in the separate default-setting trials. Cloudflare DNS-01 also required a custom Caddy build. The owner confirmed on #281 that connection-preserving reloads and on-demand distribution justified selecting Traefik, as D374 A15 records. [R3 measurements](https://git.kayg.org/kayg/infraternal/issues/261#issuecomment-72700) · [Owner answers](https://git.kayg.org/kayg/infraternal/issues/281)

## A. Reverse proxy

### A1. Who owns public TCP and UDP 443?

The owner describes OpenWrt forwarding web traffic to the separate Traefik host at `10.69.0.99`, which serves `ssh.kayg.org` via `10.69.0.89:7011`. The intended QUIC relay target is `10.69.0.89:443/udp`. The existing UDP forward and HTTP/3 advertisement are unverified. The goal is one WAN address with only TCP and UDP 443 required. HTTPS uses host routing at the TCP edge. The web app's WebSocket and the existing `/remote/agent` HTTPS carrier must work through that edge. D402's later relay WebSocket is a separate function. Traefik's ordinary UDP router forwards to a UDP service without hostname matching. Its HTTP/3 listener claims UDP on the HTTPS port. HTTP/3's `h3` and the relay's `infraternal-relay/2` ALPN distinguish handshakes only where a QUIC-aware listener handles them. [OpenWrt DNAT](https://openwrt.org/docs/guide-user/firewall/firewall_configuration#port_forwards) · [Traefik entrypoints](https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/#http3) · [UDP routing](https://doc.traefik.io/traefik/reference/routing-configuration/udp/routing/rules-priority/) · [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1) · [Relay TLS](../../crates/plugins/relay/src/tls.rs) · [Architecture](../ARCHITECTURE.md)

1. **Recommended — split forwarding by transport.** Keep TCP 443 on the existing edge and forward UDP 443 directly to the relay. A fresh managed install can put the HTTPS edge and relay on the server node with the same split. Hold HTTP/3 on that address and use DNS-01 so TCP 80 is optional for redirects. Verify current dependants before any port 80 change.
2. Let the existing edge own both forwards and use a dedicated UDP entrypoint that sends all UDP 443 to the relay. This adds edge state and a hop. Prove NAT rebinding and relay throughput if direct forwarding is unavailable.
3. If HTTP/3 is required now, give it a second public address, with the relay on its own address. A single-socket QUIC dispatcher would need an independent design and measurements for CPU, reconnects and failure isolation.

### A2. How does the existing edge receive new routes and certificates?

D64 allows external HTTPS termination, and D220/D374 provide a managed option. A single TCP edge can select HTTP hosts after TLS termination or route selected TLS connections by SNI before termination. A browser still needs to trust the issuer. DNS-01 works for a controlled public DNS name whose service is reachable only over the mesh, with no public HTTP listener. A deployment CA leaf for a private-only name would need purpose-scoped issuance and browser trust on every client, including the iPhone. The deployment CA already authenticates roles such as the QUIC relay, with separate leaves. [TCP routing](https://doc.traefik.io/traefik/reference/routing-configuration/tcp/routing/rules-and-priority/) · [ACME challenges](https://letsencrypt.org/docs/challenge-types/) · [File provider](https://doc.traefik.io/traefik/reference/routing-configuration/other-providers/file/)

1. **Recommended — one certificate owner per hostname.** The managed edge terminates HTTPS and uses DNS-01. Existing edge operators retain TLS for their public names and add explicit routes for approved services. Keep the web origin and its WebSocket together. Authenticate the upstream link when plain HTTP would leave loopback or the mesh. Use controlled DNS names for initial private HTTPS and defer deployment-CA browser trust. Scope DNS credentials to issuance or delegate `_acme-challenge`.
2. Add an operator-enabled file-provider integration for a dedicated set of generated routes with acknowledgement and removal. External TLS and DNS custody remain with that edge. This adds a second config lifecycle to support.
3. First-class SNI passthrough for selected published names, with the publishing node terminating TLS. It keeps those keys on the node but moves browser access policy and certificate errors there too. If internal-only names are essential, add deployment-CA issuance only after agreeing on the client trust and locked-CA renewal flow.

### A3. How may a gateway reach a service on another machine?

Today's renderer uses HTTP to loopback on the publishing node. Sending all external traffic through an enrolled gateway makes the gateway the mesh peer seen by the service. A grant to that peer provides reach, while visitor access must be checked separately. Publication requires its own authorization for the exact service and hostname. [Route renderer](../../crates/plugins/proxy/src/config.rs) · [Mesh ingress](../../crates/plugins/proxy/src/ingress.rs)

1. **Recommended — an approved service and a narrow gateway grant.** Select an enrolled host and a specific port. Require the host-side publication and a revocable gateway-to-service grant. Resolve by stable host identity and current mesh address, then use an authenticated mesh path to the node's publication. Verify the upstream and end access if the host, grant or publication is removed. Unreachable hosts show a service-unavailable page. Measure the extra hop over direct and relayed paths.
2. Ship host-local publishing only, with operator-configured forwarding for selected public services. This keeps the first UI small and leaves a manual step for the single public IP setup.
3. Add outbound per-service tunnels to the gateway. This could handle sites the mesh gateway cannot reach, but adds a data path with its own identity, capacity and recovery model.

### A4. Who can publish, and who can open a private web app?

The existing node-local CLI uses `proxy.publish`. Its current registry entry has no hosted API-key scope. D164 governs network reach, and #281 already defines explicit public opt-in. An HTTP sign-in adds person-level policy. Passkeys are scoped to a relying party and validated against an origin. Copying the infraternal session cookie to arbitrary published domains would widen that boundary. A gateway sign-in also needs to cover upgrades such as WebSockets. [CLI action](../../crates/plugins/proxy/src/cli.rs) · [WebAuthn RP ID and origin](https://www.w3.org/TR/webauthn/) · [ForwardAuth](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/forwardauth/)

1. **Recommended — scoped publishing and three explicit audiences where supported.** Default to **Mesh only** with the service's mesh access. Add **Sign-in required** for private web apps that must work off mesh, using the existing trusted passkey origin and a short, revocable, host-scoped app session. Reserve **Public** for an explicit first-time confirmation and an operator who may publish the target and hostname. Gate the backend against bypass and strip client-supplied identity headers before adding trusted ones. Keep Community single-user and apply Enterprise roles where available.
2. Start with mesh-only and public access as already defined. Let applications handle their own user sign-in until gateway authorization, recovery and revocation are proven.
3. Offer operator-managed external authentication per route. This reuses an existing identity deployment, but makes audience, session expiry and denial behaviour depend on operator policy.

### A5. What does Add service own, and how does the CLI match it?

The local CLI already lists, publishes and unpublishes. The new choice is where people start the browser flow and how a remote operation uses the same authorization. The Machine pill already has a Machine and a Connection tab. D324 defers the full machine-card grid. The wireframe below uses the existing palette and an anchored confirmation, with setup and credentials in Settings. [Design taste](TASTE.md) · [CLI reference](../CLI.md)

1. **Recommended — Add service from a machine context and the palette.** Pick a discovered service or type a port in one field. Show the audience and actual URL before publishing. Keep the CLI verbs, add an explicit remote target only if A3 is approved, and give CLI and UI the same results for pending, ready and blocked. Return existing D303 exit codes and support `--json`.
2. Start with a single Sharing view and an Add service action there, with the machine selected in the form. It offers a deployment-wide list first and adds a step when the person is already on a machine.
3. Keep creation in the local CLI for the first slice and show status and removal in the browser. This trims remote mutation work and leaves new users switching surfaces.

Text wireframe for the recommended flow, using an example machine already selected from the palette.

```text
Add service
Machine     buildbox
Service     [ 3000                    ]
Access      [ Mesh only              ▾ ]
URL         https://port-3000.buildbox.example.net

                     [ Cancel ] [ Publish ]
```

The Access selector shows only supported audiences. A public confirmation names the URL and says “Anyone on the internet can reach this service.” Once saved, the service row shows its URL with the current state and can open it or unpublish. **Issuing certificate** stays pending. “That name is already in use” keeps the form intact. “DNS verification failed” offers retry after the operator fixes DNS. Cancel leaves the earlier route state intact. On a phone, the same field order fits one column with actions above the keyboard. This text wireframe fixes the decisions and copy for owner review. A product mockup would be the next approval artifact.

### A6. What is the operational contract for updates and failures?

The managed component release has signed platform manifests and a **Traefik component manifest** verification row. Dynamic routes have an applied-generation check. A legacy unit without `Delegate=yes` reports degraded containment, since a forked child may outlive the infraternal agent. Rootless cgroup containment also has limits. J164 measured **+37 µs median start**, **+36 µs median stop**, and **5–10 KiB kernel memory per leaf**. [Release check](../../scripts/verify.d/rust.sh) · [Route renderer](../../crates/plugins/proxy/src/config.rs) · [Containment measurement](proxy-containment.md)

1. **Recommended — confirm effective state and fail closed on revocation.** Stage and verify component updates, preserve the last acknowledged safe snapshot on ordinary apply failures, and remove access immediately on a grant revocation or unpublish. Report bind, DNS, expired certificate, unreachable backend and degraded containment separately. For managed public ingress, require proof that stop and rollback can close the listener before expanding rollout. Measure live WebSocket continuity, proxy reload and independent relay availability.
2. Require operator-managed upgrades for the public edge initially and have the product monitor effective route health. This is simpler for externally managed installs and leaves maintenance to their operators.
3. Require redundant ingress before any public availability promise. It reduces single-host maintenance interruptions and adds shared certificate-state, health-check and failover work.

### A7. Which diagnostics are kept for published apps?

D260/D261/D263 already establish local-first observability, and D402 specifies aggregate mesh relay counters. The open piece is the proxy's customer traffic record, such as what the operator can see when a route starts failing. [Proxy access-log controls](https://doc.traefik.io/traefik/observe/logs-and-access-logs/)

1. **Recommended — aggregate service status plus an admin audit trail.** Keep bounded per-service counts, status classes, latency and certificate expiry. Audit publication, scope changes and removal through the existing first-party model. Add an explicit, redacted and time-bounded local diagnostic mode. Keep query strings, auth headers, cookies, payloads and client addresses out of routine logs. No third-party analytics.
2. Leave request metrics off initially and report only route, backend and certificate health plus administrative changes. This limits continuous work and makes intermittent failures harder to diagnose.
3. Offer persistent local access logs by opt-in with the D263 proxy retention cap. Define which fields can be kept and who may read them before offering this option.

## B. Hosted cloud

### B1. Should D2 change, and what would customers buy?

The public download site and APNs wake-up relay have narrow existing mandates. Today the deployment operator owns the server, identities and mesh control plane. Hosting would transfer responsibility for uptime, patching, recovery, abuse response and some custody to the hosting operator.

1. **Recommended — keep D2 for now.** Keep investing in the self-hosted server. If demand is for fewer upgrades and less maintenance, first validate an opt-in install on customer-owned infrastructure where the customer controls the host, domain, keys and backups. Record who operates it before offering managed support.
2. Amend D2 to permit an invitation-only hosted server per customer, with explicit consent for operator custody. Keep a supported self-hosted path and an export plan. This addresses customers who want someone else to operate the service.
3. Amend D2 narrowly for a shared connectivity service, such as a hosted relay using customer deployment credentials, while customers run their server. This addresses NAT or reachability problems, and still commits the operator to availability, bandwidth cost, abuse handling and metadata policy.

### B2. If D2 changes, what stays with the customer?

The current browser topology sends interactive traffic through the infraternal server. A hosted server may therefore process terminal or app data in flight and hold deployment identity, host inventory, routing policy and audit state. A relay-only design has a smaller trust surface but can still observe traffic metadata. PXE answers on the local LAN, and D260 keeps full log history on the machine by default. Coordination and payload paths can be separated, but that architectural change would need proof here. [Current architecture](../ARCHITECTURE.md) · [Control and data plane example](https://tailscale.com/docs/concepts/control-data-planes)

1. **Recommended if hosting is approved — one isolated deployment per customer, with explicit custody and an exit path.** Keep workloads, PXE, local service backends and full logs on customer machines. Disclose hosting access to identity, backups, recent summaries and live traffic before enrollment. Require audited operator access, encrypted backups, documented deletion, and a tested export/recovery to self-hosting. Prove hostname and passkey behaviour during export and plan re-enrollment if identity or CA trust changes.
2. Host coordination only and keep browser/terminal payload and deployment keys in a customer-operated data plane. Measure what has to move out of the current server and how it runs during a control-plane outage.
3. Host the full server as a shared multi-tenant service. This improves resource pooling and adds cross-tenant isolation, restore and incident requirements across identities, routes, audit data and backups.

### B3. What makes hosting supportable, and where does the edition boundary sit?

A dedicated instance costs compute, storage, backups and monitoring even when idle. Shared and relay models shift costs toward data transfer, noisy-neighbour controls and abuse handling. The operating burden includes patches, incident response, restore drills, support time and upgrade/rollback testing. AGPL §13 requires an offer of corresponding source to remote users of a modified covered program. D277 keeps commercial features in their own repository and leaves composition open. Paying for operation and unlocking Enterprise features are distinct product choices. [GNU AGPL §13](https://www.gnu.org/licenses/agpl-3.0.html#section13) · [Deployment isolation patterns](https://docs.cloud.google.com/app-lifecycle-manager/overview)

1. **Recommended if hosting is approved — a capped single-region pilot using Community first.** Sell operation of the same AGPL Community build, keep the source offer for any hosted modifications, and leave Enterprise features under D277 pending a composition and licensing decision. Before accepting customers, name an operator, agree restore-time and data-loss targets, and demonstrate an upgrade, rollback, backup restore and departure from hosting. Model cost per deployment and per relayed GiB, including support hours and high-traffic cases.
2. Limit operation to customer-owned installations with support and documented upgrade responsibility. Keep the operator's fixed infrastructure cost low and make the service level conditional on the customer's environment.
3. Target hosted teams from the start. Make the Enterprise composition and source obligations explicit before committing, and budget for tenant isolation, on-call coverage, access review and incident support before promising service.

If D2 stays in force, the hosting portion ends at B1. A later amendment should name the allowed hosted component, the data it receives, who operates it and the self-hosting path before any product or site copy changes.
