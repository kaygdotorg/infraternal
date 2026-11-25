# Architecture

This page gives an overview. `DECISIONS.md` records the decisions (numbers in
brackets). The contracts in `contracts/` are written before S1 code starts.

```
 phone / laptop ──leg A──▶ infraternal server ──leg B──▶ infraternal agent ──leg C──▶ PTY / engines
   browser, PWA,             identity, roles,              one per host              local, or SSH
   CLI, MCP                  audit, state, API,            (rootful or rootless)     on the LAN
                             routing, SQLite
                             └─ embedded agent (subprocess, `agent --fd 3`)
```

- **Leg A** (browser ↔ server): WebSocket [63]. This is where most latency and
  jitter come from: mobile networks, roaming, sleep. Streams have sequence
  numbers, so they resume without loss [11]. Predictive echo hides the round
  trip.
- **Leg B** (server ↔ agent): QUIC with a TCP/TLS fallback. Both ends are our
  code. KCP is added only if a benchmark justifies it [11]. Where both are
  blocked, the same mutual TLS runs inside a WebSocket on the server's public
  HTTPS origin (`/remote/agent`), so a reverse proxy only carries leg-B
  ciphertext (#559).
- **Leg C** (agent ↔ host): a local PTY or engine socket, or SSH to devices that
  have no agent [13].

## Processes on a host

```
init (systemd / openrc / runit / s6 / fallback)
 └─ infraternal agent            upgrades in lockstep, A/B slots [17]
     └─ session shim (one per PTY)  rarely changes; keeps sessions across agent upgrades [13]
         └─ $SHELL
```

On Linux, a system server that shares `/var/lib/infraternal` with the
infraternal agent puts its state in the private `server/` child [395].
The shared base retains the infraternal agent's install paths and traversal.
The systemd start job owns migration and verifies the new server before it
retires the recorded originals. [Server CLI and recovery](CLI.md)

## Plugin anatomy [15][16]

| Part   | Language   | Does |
|--------|------------|------|
| agent  | Rust crate | the work: PTY, engine calls, metrics |
| server | Rust crate | permissions, persistence, routing, audit |
| ui     | TypeScript | views inside the shell (tree, tabs, palette) |

You define each action once (schema, permission, handler). The API, CLI, MCP
and UI adapters come from that definition.

## Repo layout

```
crates/        server, db (SQLite access, D379), agent, shim, protocol, plugin-api, plugins/*
apps/tracer    the product UI (TypeScript); its build is the `web/` folder the server serves (`--web-root`), and it holds the browser tests
apps/release-signer  the release signing service
docs/user      user docs, published at /docs and shown in the app's Docs view (D317)
packages/protocol  the browser side of the wire protocol: codec and stream decoder (TypeScript)
packages/ui    shared tokens and components (vendored from calternal until @kayg/ui exists)
contracts/     protocol, plugin and action specs (written before code)
scripts/       verify (quick | iterate | fast | nightly | integration | browser | latency | bench), release/ (build, publish and deploy)
```

Planned, not in the tree yet: `apps/website` (infraternal.com) and `apps/docs`
(D44). Commercial-licensed features live in their own repository,
`kayg/infraternal-enterprise`, never here (D277).
