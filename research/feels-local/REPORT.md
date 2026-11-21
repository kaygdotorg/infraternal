# Remote typing should feel local: key-to-photon breakdown and ranked levers (#569)

J1059, 2026-11-21. Decisions: D130 (typing and output feel instant), D375 (120 Hz
targets, reworded today: "our own work at most 4 ms p99, and the letter appears in
the first frame after the key"), D10/D11 (always relay; QUIC to the infraternal
agent), D128/D192 (direct path). This report puts together J1059's measurements with
those of the sibling lanes posted on #569: J1063 (prediction), J1064 (direct path),
J1079 (audit), J1065 (priority), J1066 (frames) and J1067 (lossy links). When this
was written, the last three had not posted results.

## 1. Where the time goes today

Measured on the real server: the production binary, the embedded infraternal agent,
the shim, a real PTY with bash, and the production tracer in headless Chromium. Each
key is joined with its own frames by input sequence. The spec is
`apps/tracer/real/key-to-photon.spec.ts`. It ran on the perf VM under `perf-run`,
200 keys per case. The network is a per-message delay in the bridge.

| Hop | p50 | p99 | Source |
|---|---|---|---|
| keydown → `ws.send` (browser) | 0.10 ms | 0.2–0.5 ms | J1059 spec |
| `ws.send` → fixture bridge (loopback TLS) | 0.26 ms | 3.0 ms | J1059 spec |
| server → infraternal agent → shim → PTY → shell echo → server | 0.56–0.65 ms | 0.9–1.1 ms (5.3 ms on the cold first case) | J1059 spec |
| of which infraternal agent + PTY | 0.21 ms | 0.28 ms | nightly native probe, 2026-11-20 |
| browser receive work: decode + terminal write + paint callback | 1.0 ms | 1.5 ms | nightly, unthrottled |
| wait for the next display frame | half a frame on average (8.3 ms at 60 Hz, 4.2 ms at 120 Hz); up to a full frame | 16.7 / 8.3 ms | J1059 spec: every total is (RTT + 0.7 ms) rounded up to the next frame |
| network round trip | the path | the path | see below |

Measured totals, no prediction: RTT 0 → 14.2 ms, 30 → 47.5, 80 → 97.7, 150 → 164.4
(p99 within 1.2 ms of p50). The probe sends each key 2.5 ms after a frame, so these
frame waits are a worst case.

With prediction (`?predict=1`), the predicted glyph appears in 14.3 / 14.6 ms at both
80 and 150 ms RTT, the same as a zero-RTT echo. At 30 ms it stays off.

**Our own work is about 2 ms of every key: 0.7 ms on the server and host, about 1 ms
in the browser.** That is under the reworded D375 row's 4 ms. The rest is the
network round trip and the frame boundary.

The owner's real paths, measured by ping (J1059 and J1064), from mba on Wi-Fi with a
60 Hz panel:

| Host | Network RTT p50 / p99 | Felt today, p50 / p99 | Felt with prediction |
|---|---|---|---|
| LAN host (dev-02; server at the same site) | 5.8 / ~87 ms (the Wi-Fi tail) | ~16 / ~106 ms | ~9 / ~17 ms (60 Hz) |
| Mesh host (compute01; remote site) | ~150 / ~250 ms | ~160 / ~270 ms | ~9 / ~17 ms (60 Hz) |

mba's Wi-Fi delays 17–21 % of packets by 20–110 ms, in spikes every 200–300 ms
(awdl0 is active). It is the largest tail on a "local" host. The product cannot
remove it; only prediction hides it.

## 2. Ranked levers

The "gain" columns are for the owner's paths above. "Est." marks an estimate from
measured components.

| # | Lever | Gain p50 | Gain p99 | Cost | Risk | Decision |
|---|---|---|---|---|---|---|
| 1 | **Turn predictive echo on in the product.** Today it only runs behind `?predict=1` (`main.ts:488`), although D130 says it switches on automatically. Merge J1063's four fixes (bash erase, miss cascade, secret prompts, wider list) first. | mesh host ~160 → ~9 ms (est., for the ~97 % of plain-shell keys J1063 shows) | mesh ~270 → ~17 ms; LAN ~106 → ~17 ms | flip the default once rows 2 and 3 land; J1063's fixes are done | wrong letters 4.2 per 1000 drawn (J1063); secrets 0/189 with the fixes; nested ssh relies on the prompt list | D130 (the code is out of step with the decision) |
| 2 | **Prediction uses the round trip to the host, not to the server**: the key → Ack time per terminal (J1079 #1, J1088 in progress). | needed for row 1 on mesh hosts: without it, a host 150 ms behind a 5 ms server is never predicted | same | 0.5–1 day | low | D130 |
| 3 | **Switch on from the tail, not the mean.** Use the p90 of the per-terminal key → Ack time, or J1063's "on whenever safe" (0 ms). | LAN host: ~0 | LAN host ~106 → ~17 ms (the Wi-Fi tail) | small, with row 2 | J1063: the wrong-letter rate does not depend on RTT | D130 (the "about 60 ms" threshold) |
| 4 | **Echo-off signal from the shim** (J1094): prediction never draws while the host's terminal has echo off. | 0 | 0 (safety) | about 4 h | protocol addition, strict review | D130 ("off when echo is off") |
| 5 | **Screen-state matcher for zsh** (J1063 follow-up, J1079 #6). zsh redraws and today's byte matcher reads that as a miss. | zsh users: shown 41 → 85 % at 300 ms, 88 → 99 % at 10–80 ms (J1063 harness) | zsh felt p99 drops from the RTT to one frame | 1–2 days; measure the per-key cost first | medium | D130 |
| 6 | **RTT-ranked relay choice for the agent ↔ server leg** (#201, J1064): today the first relay in a static list is used. | 0 on good links; hundreds of ms where NetBird relays (J1064 saw pairs at 287–1116 ms) | same | days | medium | D215, D233, #201 |
| 7 | **Lossy and bloated links: `TCP_NOTSENT_LOWAT` on the WebSocket leg** (J1067, smoke only so far): echo under a same-connection flood at 50 ms RTT went from 1216 ms (cubic) to 107 ms (BBR + 16 KiB lowat); QUIC 137 ms. | on clean links ~0 | large under bulk output on a slow link (perf-VM matrix pending) | one socket option, and a measured cc choice | low | D11, D63 |
| 8 | **Frame alignment** (J1066 pending). Our pipeline already paints in the first frame after the data arrives; the wait is the display's. Gains: avoid missed frames under load, and use 120 Hz where the display has it (8.3 → 4.2 ms on average). | 0 on 60 Hz panels | ≤8.3 ms on 120 Hz panels | J1066 | low | D375 row 1 |
| 9 | **Keystroke priority over bulk** (J1065 pending). The flood effect is +1.46 ms (another session) on the nightly; each terminal is one QUIC stream with no input-versus-output priority. | ≤1 ms quiet | unknown under same-session floods on real links (J1067's numbers point at send buffers, not stream order) | J1065 | low | D130 |
| 10 | **Direct device → host path** (WebRTC, D128/D192; J1064). | owner's topology: 0.4 ms, or −8 to −20 ms (slower) | same | days (str0m in the infraternal agent, signalling, capability) | medium | D128, D192, D233 |
| 11 | **No SQLite read per frame**: cache the session expiry; revocations are already pushed (`websocket.rs:1284`, `auth/sessions.rs:456`). | < 0.3 ms (it fits inside the server's 0.35 ms share) | unmeasured under database write contention | 0.5 day | auth path: strict review | session expiry rules (D370) |
| 12 | Wi-Fi on the owner's laptop (AWDL). Not product code. | 0 | ~85 ms on a LAN host | an OS setting, the owner's choice | none for us | none |

How to read it:
- Rows 1–3 are one change: prediction on, from the right round trip, triggered by the
  tail. Together they turn every RTT into about one frame for predictable keys. Each
  of the other rows is worth at most a few milliseconds on the owner's own paths.
  Rows 6, 7 and 10 matter when the topology changes (a travelling owner, a remote
  server, bad relays, lossy mobile links).
- D375's reworded row 1 ("our own work at most 4 ms p99, letter in the first frame
  after the key") holds today for the server and host share (≤1.1 ms p99). Whether it
  holds end to end needs J1090's realistic-typing rows (overlapping keys, real zsh).

## 3. Measurement caveats

- The browser probe sends a key only after the previous one painted, and 2.5 ms
  after a frame boundary. It can't show type-ahead effects (J1079 #2), and its frame
  wait is a worst case. J1090 replaces it with recorded typing.
- The network here is a per-message delay in the fixture bridge (user space), not
  netem: no loss, no queueing. The lossy-link rows are J1067's.
- The server's share includes the embedded infraternal agent over a socketpair. A
  remote infraternal agent adds the QUIC leg. J1064 measured that the relay's cost is
  geography, within 0.2 ms of the model.
- The binary is j1018's static build (dev `c8c44ed6a` plus UI files). Against today's
  dev, the keystroke path differs only in a 26-line plugin-call change in
  `websocket.rs` (#556). A same-SHA build was queued at position 31 on compute01 and
  then cancelled.
