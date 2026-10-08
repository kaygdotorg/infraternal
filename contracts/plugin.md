<!-- Public plugin, action, event and stream contract [3,15,16,29]. -->
# Contract: plugins and actions

Status: draft for #10. Implements DECISIONS 3, 15, 16 and 29.

## 1. What a plugin is

A plugin is a feature (ssh, metrics, docker, …) delivered as three parts that
ship together and share one id:

| part   | crate or package                         | runs in              |
|--------|------------------------------------------|----------------------|
| agent  | `infraternal-plugin-<id>` (feature `agent`)  | infraternal agent    |
| server | `infraternal-plugin-<id>` (feature `server`) | infraternal server   |
| ui     | `apps/web/src/plugins/<id>`              | browser / PWA        |

Plugins are compiled in (DECISIONS 15). The server and agent each hold a
static registry, built from the list in `crates/infraternal/src/plugins.rs`.
There is no dynamic loading. The interface below is versioned
(`plugin-api` major version), so a WASM host can wrap it later without
changes to the plugins.

## 2. The descriptor

Each plugin exports one `PluginDescriptor`. It is const data: no I/O, no side
effects.

```rust
pub struct PluginDescriptor {
    pub id: &'static str,            // "ssh": lowercase, [a-z0-9-], unique
    pub api: u16,                    // plugin-api major version it was built against
    pub actions: &'static [ActionDef],
    pub events: &'static [EventDef],
    pub streams: &'static [StreamDef],
    pub settings: Option<SchemaRef>, // shown as a form in the UI
    pub tree: Option<TreeDef>,       // nodes it adds under a host in the sidebar
}
```

## 3. Actions: define once, adapt everywhere (DECISIONS 16)

An action is the only way to change state or read it. Each adapter (HTTP API,
CLI, MCP, the UI search capsule, the Apple apps later) is **generated** from
the action definition. No adapter has a hand-written handler.

```rust
pub struct ActionDef {
    pub id: &'static str,         // "ssh.session.open": <plugin>.<noun>.<verb>
    pub summary: &'static str,    // one line; used by CLI help, MCP and the search capsule
    pub input: SchemaRef,         // from a Rust type: serde + schemars
    pub output: SchemaRef,
    pub target: Target,           // Global | Host | Session | …: what permissions are scoped to
    pub effect: Effect,           // Read | Write | Destructive
    pub permission: &'static str, // "ssh.open": what a role grants
    pub dry_run: DryRun,          // Unsupported | Supported | Required
    pub opens: Option<&'static str>, // a StreamDef id if the action returns a live stream
}
```

Core transport actions are defined by the wire contract rather than a plugin
descriptor. In S1, `terminal.open` uses the schema in wire.md §3.1 and is
authorized for the authenticated user before the request reaches an
infraternal agent.

Rules:

- `Effect::Destructive` requires `DryRun::Required` (DECISIONS 28).
  - MCP: the generated tool takes `dry_run: true` first. The real call must
    include the `plan_id` from a dry run made in the last 5 minutes.
  - UI: a fresh passkey tap.
  - CLI: `--yes`, or an interactive confirm.
- Each call is audited: who (user, device, adapter), the action, the
  target, the input digest, dry-run or not, and the result. The audit write
  happens before the side effect, and its outcome is updated after it.
- An action is idempotent when it can be (for example, `close` on a closed
  session succeeds). Otherwise, its definition says so.

Generated adapters, for `ssh.session.open`:

| adapter | shape |
|---------|-------|
| HTTP    | `POST /api/v1/actions/ssh.session.open` (JSON body = input) |
| CLI     | `infraternal ssh session open --host <id> [--json]` |
| MCP     | tool `ssh_session_open` with the input JSON Schema |
| UI      | an entry in the search capsule: "Open terminal on …" |

The build writes `contracts/generated/actions.json`: every action with its
schemas. The TypeScript client, the CLI and the MCP server come from this
file. A test fails if the file is stale.

## 4. One path for every call

```
adapter ──▶ server: authenticate ─▶ authorize (role × host tags × permission)
                 ─▶ audit (pending) ─▶ plugin server part
                       └─(if host work)─▶ agent: plugin agent part ─▶ result
                 ─▶ audit (done) ─▶ adapter
```

- The plugin server part may answer by itself (for example, `hosts.list`) or
  send a `PluginCall` to the agent of the target host over the wire protocol
  (contracts/wire.md).
- The agent part only accepts calls that the server signed (DECISIONS 9).
  It never authorizes on its own. It trusts the server.

## 5. Events: one route

State changes are events: `host.added`, `agent.connected`,
`ssh.session.exited`, …. Each plugin declares its events with a schema. One
event bus on the server fans events out to:

- the UI (a live subscription per tab, filtered by permission),
- the CLI (`infraternal events --follow`),
- MCP (resource subscriptions),
- notifications (ntfy, gotify; later the APNs relay).

The UI never polls. Live counts in the sidebar tree come from events.

The core Mesh inventory is not a plugin, but its live view uses the same
control-stream `Subscribe`/`Event` frames. Subscribe with
`{"topic":"mesh","tag"?:string}` to receive an initial filtered snapshot,
revision invalidations, and a resync snapshot if the bounded change buffer
overflows. Authorization is checked for each viewer. The event shapes and
tag-filter behavior are specified in [contracts/mesh-api.md](mesh-api.md).

## 6. Streams

Some actions return a long-lived stream instead of a value: a terminal, a log
tail, live metrics. A `StreamDef` declares its frame types and whether it is
resumable. Terminal streams are resumable by byte offset (contracts/shim.md
§4, contracts/wire.md).

## 7. Settings and tree

- `settings` is a JSON Schema. The UI renders it as a form, so each plugin is
  configurable in the UI without UI code (DECISIONS 29: "everything
  configurable in the UI").
- `tree` adds nodes under each host in the sidebar (for example, ssh adds
  "Sessions (3)"), with a count that comes from events.

## 8. Versioning

- `api` must match the major version of `plugin-api` in the binary. All
  plugins are compiled in, so a mismatch is a build error and never a runtime
  error.
- Action ids, event ids and schemas are a public API, because users script
  against the CLI and MCP. A breaking change needs a new action id
  (`.v2`). The old id stays for one minor release, with a deprecation
  warning.
