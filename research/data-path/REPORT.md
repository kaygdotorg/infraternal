<!-- Role: Record measured path evidence and sourced transport trade-offs for issue #47 without choosing a transport or changing an owner decision. -->
# Fastest data path between clients and targets

Research for kayg/infraternal#47. Measurements were taken 2026-10-07 UTC. This report compares options for the owner; it makes no transport or architecture decision.

## 1. Five-minute path measurements

### Method and limits

The available build box is infraternal-dev in Falkenstein, NetBird 10.69.69.125. The server is monitor01 in Essen, NetBird 10.69.69.50. The test Mac VM is in India, NetBird 10.69.69.21. Each timed run sent 300 samples at one-second intervals. The build box and monitor01 were sampled with ICMP. The Mac VM drops ICMP sent to it, so the build-box-to-Mac measurement used TCP connection establishment to port 22; the Mac-to-monitor01 measurement used ICMP sent from the Mac. These are network-path samples, not measurements from a live infraternal browser session.

The build box load averages were 5.24/6.63/7.51 at the end of capture. monitor01 was 0.20/0.20/0.18, and the Mac VM was 0.72/0.69/0.81. No product process or NetBird configuration was changed.

### Results

| Path and probe | Samples | Loss | RTT / connect time |
| --- | ---: | ---: | --- |
| Build box 10.69.69.125 ↔ monitor01 10.69.69.50, ICMP | 300 / 299.5 s | 0/300 | min/mean/max 9.453/9.912/14.963 ms; mdev 0.698 ms |
| Build box 10.69.69.125 → Mac VM 10.69.69.21, TCP connect to port 22 | 300 / 299.2 s | 0/300 connects failed | min/p50/p95/p99/mean/max 151.790/152.665/155.840/160.425/153.220/175.116 ms; standard deviation 1.863 ms |
| Mac VM 10.69.69.21 ↔ monitor01 10.69.69.50, ICMP initiated at Mac | 300 / 299.5 s | 1/300 (0.33%) | min/mean/max 196.555/198.118/205.675 ms; standard deviation 1.432 ms |

The five-minute build-box-to-Mac TCP run had no multi-hundred-millisecond spikes: p99 was 160.425 ms and max 175.116 ms. The earlier five-ping sample in issue #47 (152 ms minimum, 436 ms mean, 1.4 s max) is a separate short capture; the results are not comparable in sample count or probe.

At the end of capture, NetBird status showed P2P on all three peer pairs. Build box ↔ monitor01 was host/host at 11.66 ms status latency. Build box ↔ Mac was srflx/srflx at 156.39 ms. monitor01 ↔ Mac was P2P (host/prflx on monitor01, host/host on the Mac) at about 202 ms status latency. The lower-level status snapshot and the timed ping/TCP results agree on the broad RTTs.

ICMP and TCP service probes from monitor01 to the Mac did not get replies, while the Mac could ping monitor01 and the build box could open TCP/22 on the Mac. This points to source-specific filtering or policy; it prevents claiming that a monitor-originated application connection to those Mac ports was tested. The Mac-to-monitor ping still measures round-trip delay on the same NetBird peer path used by the agent connection.

### Relay status and relay location

The active paths were P2P, not relayed. NetBird also printed a relay server address for these connections, but its status documentation says that field is present for P2P peers too and carries traffic only when the connection type is Relayed. [NetBird connection-status documentation](https://docs.netbird.io/help/troubleshooting-client) explains the distinction; the product can use NetBird's encrypted P2P path without putting application data through its relay.

For the Mac ↔ monitor01 peer, the available fallback was o1.kayg.org:443. DNS resolved it to 144.24.150.105. An IP geolocation lookup estimates Hyderabad, India; this is a region estimate, not a verified facility location. Five pings from the Mac to o1 averaged 23.394 ms with no loss; five from monitor01 averaged 171.139 ms with no loss. Under symmetric paths, those two legs imply about 194.5 ms RTT through o1, versus the directly measured 198.1 ms Mac ↔ monitor01 mean. This is only a triangle estimate; no relayed session was forced or measured. [IPinfo's lookup for the relay address](https://ipinfo.io/144.24.150.105) is the source for the approximate city.

### Implication for the present topology

One synchronous request-and-echo through the application server costs approximately RTT(client, server) + RTT(server, agent), plus processing and queueing. The measured server ↔ Mac leg is about 198 ms. The India client ↔ monitor01 leg was not available from this build box; if it is also near 198 ms, the current two-leg interaction would be about 396 ms before processing. This is a conditional estimate, not a measured product result. A direct client ↔ Mac session would pay one client-to-Mac RTT, which must be measured from the owner's India device before assigning a number.

## 2. Lower-latency data path options

For all options, the RTT of a completed input-and-response matters more than a single one-way packet. A direct session pays about one client-to-agent RTT. A relay located between client and agent pays roughly RTT(client, relay) + RTT(relay, agent). Keeping the application server in line pays roughly RTT(client, server) + RTT(server, agent). These are network estimates before host work, browser scheduling, and rendering.

### (a) Keep the application server in the data path

The browser keeps its current WebSocket to the server; the server forwards session records over its agent connection. The measured server ↔ Mac leg is about 198 ms RTT. If the owner's browser in India has a similar RTT to monitor01, an interactive echo through both legs is roughly 396 ms plus processing. This scenario preserves the current model and the browser path stays compatible with the iOS 17 minimum.

Moving the single server toward the owner and the first target could reduce both legs for this particular India-to-India use. A server moved toward one group makes the other group's leg longer. Enterprise users and targets spread across regions therefore need either more than one server or regional data relays; choosing a region from the server's location alone cannot make every pair local.

This is the lowest change to D8–D11 and D63–D64: the server remains trusted, authorizes and routes traffic, can inspect the session records, and has the opportunity to apply policy and audit them. The agent still dials out, so managed hosts need no new inbound service. The failure mode is geographic detour and the server's bandwidth/availability becoming part of every live session. Adding regional servers also changes the current single-node deployment in D19.

### (b1) Direct WebRTC DataChannel, server for signaling and capabilities

When ICE finds a direct peer candidate, browser ↔ agent latency is one direct RTT. If ICE has to use TURN, the data path becomes client ↔ TURN ↔ agent; the regional relay formula above applies. The current India-client-to-Mac direct RTT was not measured. The build-box-to-Mac TCP result of 152.7 ms p50 is a different geography and probe, so it is not a substitute.

Safari and iOS have supported RTCDataChannel since the early WebRTC releases, well before the repository's iOS 17 floor; WebKit also documents RTCDataChannel in WKWebView. A DataChannel carries SCTP over DTLS over ICE/UDP. ICE gathers and checks host, server-reflexive, and relayed candidates using STUN and TURN, so it can cross many NATs without asking users to configure a port forward. TURN remains necessary for symmetric NAT, CGNAT, and firewalls that block usable UDP. [WebKit's WebRTC overview](https://webkit.org/blog/7763/a-closer-look-into-webrtc/), [RFC 8831](https://www.rfc-editor.org/rfc/rfc8831.html), [RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html), and [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html) describe those browser, transport, and traversal properties.

The server can authenticate the user, issue a capability bound to the user/device, target, session, allowed operation, expiry, and nonce, and carry the agent's DTLS fingerprint through the authenticated signaling channel. The agent must validate the capability before attaching the stream. DTLS protects the direct path, but the server no longer sees each byte after handoff. It can centrally audit capability issuance and session metadata; the agent must record the events or bytes that the audit contract requires. Revocation needs a short expiry plus renewal or an explicit close signal.

This would change the no-end-to-end-encryption and always-relay model in D8 and D10, and the WebSocket-only browser leg in D11/D63. D9 keeps host work in the agent; a direct browser path would still need to preserve that boundary while adding an inbound client path that D64's current managed-host networking does not provide. It requires ICE in the agent, signaling state, candidate changes across network switches, TURN capacity, and a reconnect/resume design outside the server's current byte sequence path. If the session has multiple subscribers, the agent or a media relay must fan out data; remote desktop fan-out needs to be budgeted per session × subscribers under D104/D117. Failures include ICE checks that never find a usable pair, an unavailable TURN region, capability expiry during a long session, and Safari/PWA suspension while backgrounded.

### (b2) Direct WebTransport to the agent with server certificate hashes

If the agent is directly reachable, a browser-to-agent WebTransport session also pays one direct RTT. The API can use reliable streams and datagrams over HTTP/3, and can use HTTP/2 as a reliable-only connection where supported. Unlike WebRTC, the WebTransport API does not define ICE/STUN/TURN candidate gathering. It therefore does not solve an agent behind NAT: the agent needs a public route/port, a managed mapping, or an outbound connection to a relay.

As of this report, Safari added WebTransport in 26.4, including iOS 26.4; Safari 26.6 is the latest stable release listed by Apple. WebKit has a test result for implementing serverCertificateHashes. This is support, but it would raise the effective iOS floor from D106's 17 to 26.4 unless another transport remains available. A 2026 WebKit report describes bidirectional-stream creation hanging against non-Apple servers in Safari 26.4; it is a reason to verify the current iOS build and server implementation on a real phone, not evidence that every 26.6 build fails. [Apple's Safari 26.4 notes](https://developer.apple.com/documentation/safari-release-notes/safari-26_4-release-notes), [Safari 26.6 notes](https://developer.apple.com/documentation/safari-release-notes/safari-26_6-release-notes), [WebKit's certificate-hash implementation test](https://results.webkit.org/commit?uuid=175946337900), and the [WebKit interoperability report](https://bugs.webkit.org/show_bug.cgi?id=312697) support these points.

WebTransport certificate hashes let the page authenticate an ephemeral agent certificate instead of relying on Web PKI. The current W3C spec limits pinned certificates to a validity period of two weeks and allows overlapping hashes for rotation. This authenticates the agent to the browser, not the browser to the agent; browser credentials are omitted, so an explicit capability must be sent in a header or in-band and validated by the agent. Hash provisioning and invalidation after key compromise become part of the trusted control plane. [The WebTransport specification](https://www.w3.org/TR/webtransport/) defines the hash and client-authentication limits.

The direct path removes the geographic detour, but using WebTransport instead of WebSocket does not itself remove a network leg. [D63](../../DECISIONS.md) records the existing internal result: no clean-link difference and p99 216 ms versus 489 ms at 1% loss for WebTransport versus WebSocket. That experiment measured the browser-to-server leg; it does not establish the gain of a direct browser-to-agent path. The main failure modes here are blocked UDP/QUIC, a private or CGNAT agent with no inbound path, hash rotation mistakes, and Safari interoperability.

### (b3) Direct WebSocket to the agent

If the agent has a reachable TCP address, a direct WebSocket would pay approximately one client-agent RTT. WebSocket/WSS works in Safari and iOS 17. It has no standard browser ICE traversal, so the managed-host rule that agents open no inbound ports remains a barrier unless there is a public listener or relay.

The browser cannot tell the WebSocket API to trust an arbitrary agent certificate hash. For WSS, the browser performs the normal TLS handshake and fails it when the certificate cannot be verified. A direct endpoint needs a publicly trusted certificate matching its hostname or an already-installed enterprise trust anchor. This is the certificate-trust problem for self-signed or internal-CA agent certificates. The [WebSocket protocol specification](https://www.rfc-editor.org/rfc/rfc6455.html) requires TLS for secure WebSockets and failure on certificate verification errors; [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html) describes service-name identity verification.

WSS would encrypt the direct connection but would not make the server see the stream or authorize each byte. The agent still needs a capability or an application authentication handshake. DNS, certificate issuance/renewal, inbound reachability, and network changes add operational work. TCP's reliable in-order byte stream can delay later bytes behind a lost segment while retransmission repairs the loss ([RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html)).

### (c) Regional application relays selected by measured RTT

The browser and agent can each make outbound connections to a relay in a region, while the central server authenticates and issues a short-lived capability. If both endpoints are in India, an India relay removes the detour through Essen. The Mac-to-o1 fallback ping was 23.4 ms. If an India client has a similar 23 ms path to o1, the client ↔ relay ↔ Mac path would be about 46 ms RTT by the relay formula; the client leg is an assumption, not measured. In contrast, routing the existing monitor01 ↔ Mac leg through o1 estimates about 194.5 ms, only 3.6 ms below the measured direct 198.1 ms. A relay near only one endpoint is not automatically faster than P2P.

Selection should minimize measured client-relay plus relay-agent RTT (and consider loss, jitter, capacity, and relay availability), rather than choose the nearest relay to the browser alone. Outbound-only agent connections work through most NATs and firewalls, with a TCP/TLS fallback where UDP is blocked. Every byte is visible to an application relay if it terminates the session; a blind encrypted relay can forward bytes without content access, but then byte-level authorization and auditing must happen in the agent. The owner must define which component is trusted and what audit record is required.

Regional relays add fleet deployment, region selection, session affinity, capacity monitoring, failover, and data-residency questions. A failed or overloaded region can add delay or disconnect sessions; reconnect must resume the existing held session rather than start a new one. They can keep a trusted relay in the data path while avoiding one far-away central server, but they do not provide client-to-agent directness.

### (d) Use the existing NetBird or Tailscale mesh

The existing mesh already gives direct P2P reachability when it can establish a path, with an encrypted relay fallback. This measurement saw NetBird P2P from build box to Mac at 152.7 ms TCP-connect p50 and from monitor01 to Mac at about 198 ms ICMP mean. NetBird's [NAT and connectivity guide](https://docs.netbird.io/about-netbird/understanding-nat-and-connectivity) describes how it attempts direct connectivity and falls back to relaying. Tailscale likewise uses direct UDP when possible and falls back to DERP or a configured peer relay; DERP relays WireGuard-encrypted packets and does not decrypt them. [Tailscale's connection-type guide](https://tailscale.com/docs/reference/connection-types) and [DERP documentation](https://tailscale.com/kb/1232/derp-servers) describe that behavior.

A browser on a device that has joined the mesh can use the device's network route to reach an agent's mesh address; Safari itself does not need a special WebRTC or WebTransport feature for that IP reachability. On iOS the device must have the mesh VPN active. A browser on a device outside the mesh has no route to the private agent address, so mesh connectivity alone does not solve external browser access.

The mesh's device identity and WireGuard encryption do not replace infraternal's user, host, and session authorization. A direct browser-to-agent stream still means the server cannot inspect every byte. Direct P2P is fast and requires little new networking if all clients are already members; enrollment, mobile VPN availability, customer network policy, overlapping address spaces, and non-mesh users limit it.

### Constraints shared by direct options

D8 says the server is trusted and there is no browser-agent end-to-end encryption; D9 keeps host work in the agent; D10 says always relay; D11/D63 fix the browser leg at WebSocket; D64 says managed agents open no inbound ports. A direct browser path would add a client-to-agent route beyond today's contract even if the server remains responsible for login and capabilities. D104 can still hold the remote desktop session at the server-side holder while direct clients subscribe, but resume sequencing and audit have to work without the server carrying each byte. D117 also means direct fan-out must be measured at enterprise session counts; no throughput, CPU, or per-subscriber memory benchmark was run for this research.

## 3. Comparable products

| Product | Data path pattern | What it demonstrates |
| --- | --- | --- |
| Tailscale | Mesh clients try direct UDP P2P; peer relay or DERP is the fallback. | Direct paths are the preferred fast path, while DERP preserves reachability. DERP forwards WireGuard-encrypted packets and cannot inspect their payload. Clients and hosts must be on the tailnet. [DERP documentation](https://tailscale.com/kb/1232/derp-servers), [connection types](https://tailscale.com/docs/reference/connection-types). |
| Teleport | A browser or CLI connects through a Teleport Proxy. Agents create reverse tunnels; proxy peering routes between proxy instances. | Proxy peering reduces the requirement for every agent to connect to every proxy, but it remains proxy-mediated. The Web UI proxy terminates and re-encodes traffic and provides audit logging. [Proxy Peering guide](https://goteleport.com/docs/zero-trust-access/deploy-a-cluster/reliability/proxy-peering/), [Proxy Service architecture](https://goteleport.com/docs/reference/architecture/proxy/). |
| Cloudflare Access / WARP | Browser-rendered SSH/VNC/RDP goes through Cloudflare Access and a Cloudflare Tunnel connector with outbound connections. WARP-enrolled clients can reach private routes through Cloudflare One; Cloudflare also documents a separate Mesh mode for bidirectional device networking. | Browser access works without client VPN software, but the browser session is proxied. WARP changes the device's network path; it is not a browser-to-agent capability protocol. [Browser-rendered terminal](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/non-http/browser-rendering/), [private networks and connectors](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/private-net/), [connectivity options](https://developers.cloudflare.com/cloudflare-one/networks/connectivity-options/). |
| Parsec | Game-streaming clients normally attempt UDP P2P using NAT traversal; an on-premises High Performance Relay can carry sessions when direct setup is blocked or policy requires it. | A latency-sensitive product uses direct P2P and keeps a relay fallback for corporate networks. Parsec's own guide calls out outbound UDP plus UPnP or hole punching for a successful direct link; the HPR removes dependence on host port forwarding. This is a native client product, not a browser transport. [Parsec connectivity guide](https://support.parsec.app/hc/en-us/articles/32381482907156-Deployment-Considerations-and-Options), [HPR overview](https://support.parsec.app/hc/en-us/articles/32381058430740-High-Performance-Relay-HPR-Server-Overview-and-Prerequisites). |
| Moonlight / Sunshine | Client connects to the Sunshine host using forwarded ports, UPnP/PCP, IPv6, or an overlay VPN such as Tailscale. | This is direct host streaming when the network is made reachable; CGNAT, blocked inbound ports, or missing VPN membership stop it. The official setup documentation lists port forwarding and VPN alternatives. Clients include iOS, Android, and desktop applications; the standard path is not a browser relay. [Moonlight setup guide](https://github.com/moonlight-stream/moonlight-docs/wiki/Setup-Guide), [Sunshine troubleshooting](https://docs.lizardbyte.dev/projects/sunshine/latest/md_docs_2troubleshooting.html). |
| Apache Guacamole | Browser connects to the Guacamole web application; its guacd proxy connects to SSH, VNC, or RDP targets. The browser tunnel uses the Guacamole protocol over WebSocket or HTTP. | This keeps access and the target connection at the server and avoids installing a browser plugin, at the cost of keeping the server on every byte path. [Guacamole architecture](https://guacamole.apache.org/doc/gug/guacamole-native.html), [client API and tunnels](https://guacamole.apache.org/doc/gug/writing-you-own-guacamole-app.html). |

The examples divide into three patterns: a full mesh with direct plus encrypted fallback (Tailscale, Parsec), a centrally authorized proxy path (Teleport, Cloudflare browser rendering, Guacamole), and a device VPN/overlay that makes a direct host address routable (WARP/Mesh, Moonlight with a VPN). None makes an unauthenticated client connection to a managed host the only path.

## 4. Browser echo prototype

I ran a temporary Chromium 153.0.8010.12 headless page on infraternal-dev against two echo endpoints on monitor01: an aiohttp WebSocket echo and an aiortc DataChannel echo. Both used the same NetBird peer path and returned 300 sequential 4-byte messages. This is a transport-per-hop comparison, not a comparison against a deployed infraternal server/agent session.

| Echo path | p50 | p95 | p99 | mean | max |
| --- | ---: | ---: | ---: | ---: | ---: |
| Browser ↔ monitor01 WebSocket echo | 10.4 ms | 10.9 ms | 12.2 ms | 10.539 ms | 23.1 ms |
| Browser ↔ monitor01 WebRTC DataChannel echo | 11.0 ms | 11.5 ms | 12.9 ms | 11.013 ms | 14.2 ms |

The DataChannel was 0.6 ms slower at p50 and 0.7 ms slower at p99; its mean was 0.474 ms slower. ICE selected UDP between local 10.69.69.125 (peer-reflexive candidate) and 10.69.69.50 (host candidate), with an 11 ms ICE RTT. The WebRTC setup from creating the offer through DataChannel open took 5.389 s in this single run.

Both echo endpoints were on monitor01, so this did not include the monitor01-to-Mac agent leg that the current architecture adds. The browser-to-monitor path was NetBird P2P in Germany, not an India user's public WSS path. The local prototype also used a plaintext WebSocket over the private mesh and had no session authentication. The result says that, on a clean 10 ms path to the same host, the WebRTC transport itself did not beat WebSocket; most of the geographic opportunity comes from removing a far-away hop. Setup time needs its own repeated test before judging the WebRTC session-start experience.

## 5. Review checks and scope

- Each five-minute path names its direction, probe, sample count, duration, loss, and RTT summary. The Mac ICMP filtering and source-specific probe limitation are stated.
- NetBird's active P2P status is separated from the configured relay address. The o1 location and relay-triangle latency are labeled as estimates, not as a forced relay measurement.
- Product behavior claims link to vendor or standards documentation. Vendor latency figures are not treated as comparable measurements.
- The only unmeasured client leg is called out; the India-to-India direct RTT and the actual browser-to-public-server RTT remain open.
- D8–D11, D63–D64, D104–D107, and D117 remain unchanged. See [DECISIONS.md](../../DECISIONS.md) and [the architecture overview](../../docs/ARCHITECTURE.md).
- No product code or network configuration changed. The WebSocket and WebRTC echo listeners are temporary measurement tools, not product code.
- This report does not include a concurrency, throughput, per-session memory, mobile Safari, or real input-to-photon benchmark. Those measurements are required before a transport choice.

## 6. Ranked shortlist for the owner grill

This is an investigation order based on current evidence, not a transport choice. Direct P2P and a relay in the same region can have similar short paths; their authorization, reachability, and audit properties differ.

1. **Measure the existing mesh from the owner's actual India device to the Mac.** The build box and monitor01 already reach the Mac P2P, but the India client path is the missing measurement. If the user's iPhone or laptop is already on NetBird/Tailscale, this is the least new networking to validate.
2. **Prototype WebRTC DataChannel with a short-lived capability and TURN fallback.** It has the strongest general browser reachability while preserving the iOS 17 floor, and ICE can try direct connectivity before relaying. Measure the full India client ↔ Mac RTT, ICE setup time, and audit/resume behavior.
3. **Measure a regional application relay in India.** o1.kayg.org currently geolocates to Hyderabad and is about 23 ms from the Mac; the owner's device-to-o1 RTT is unknown. Choose only after measuring both endpoint-to-relay legs and the relay's capacity.
4. **Compare a server deployment near the user/target region.** This keeps the current authorization and audit path and may be effective when a deployment's users and targets cluster together. It does not solve globally distributed pairs without more regions, and changes the D19 single-node assumption.
5. **Keep direct WSS as a conditional candidate for publicly reachable agents.** It can pay one direct RTT and works on the existing browser floor, but needs inbound reachability and a browser-trusted hostname certificate.
6. **Keep direct WebTransport as a conditional candidate for modern, publicly reachable endpoints.** Hash-pinned certificates address ephemeral agent identity, but it has no ICE traversal and needs iOS 26.4 or newer for Safari.
7. **Retain the current central relay as the compatibility and audit baseline.** It is the current contract and handles clients outside the mesh; its geographic cost is the measured server detour.

### Questions for the owner

1. Must the trusted server see and authorize every session byte, or can it issue a short-lived grant while the infraternal agent enforces permissions and records the required audit events?
2. Are direct browser-to-agent sessions allowed to change D8/D10/D63, provided the held session still survives client disconnects and the server controls the capability?
3. Is iOS 17 a fixed minimum? If it is, WebTransport can only be an optional path for newer devices.
4. Must an ordinary browser outside NetBird/Tailscale work, or can mesh membership be required for some deployments?
5. Must D64's no-inbound-port rule remain strict? If so, should direct WebRTC with TURN or an outbound regional relay be measured as the NAT-safe path?
6. Is o1 in Hyderabad the intended India fallback region, and should an application relay choose a region from both endpoint RTTs rather than browser RTT alone?
7. What enterprise concurrency and subscriber count should the next scale run use for CPU, memory, bandwidth, fan-out, relay failover, and session resume?
