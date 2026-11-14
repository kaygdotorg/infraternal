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
  code. KCP is added only if a benchmark justifies it [11].
- **Leg C** (agent ↔ host): a local PTY or engine socket, or SSH to devices that
  have no agent [13].

## Processes on a host

```
init (systemd / openrc / runit / s6 / fallback)
 └─ infraternal agent            upgrades in lockstep, A/B slots [17]
     └─ session shim (one per PTY)  rarely changes; keeps sessions across agent upgrades [13]
         └─ $SHELL
```

## Plugin anatomy [15][16]

| Part   | Language   | Does |
|--------|------------|------|
| agent  | Rust crate | the work: PTY, engine calls, metrics |
| server | Rust crate | permissions, persistence, routing, audit |
| ui     | TypeScript | views inside the shell (tree, tabs, palette) |

You define each action once (schema, permission, handler). The API, CLI, MCP
and UI adapters come from that definition.

## Repo layout (target)

```
crates/        server, db (SQLite access, D379), agent, shim, protocol, plugin-api, plugins/*
apps/website   infraternal.com (SvelteKit static)
apps/docs      docs at /docs (Astro Starlight)
apps/web       the product UI (SvelteKit, embedded in the server binary)
packages/ui    shared tokens and components (vendored from calternal until @kayg/ui exists)
ee/            commercial-licensed features (multi-user management)
contracts/     protocol, plugin and action specs (written before code)
scripts/       verify (fast | integration | browser | bench), deploy, sync
```
