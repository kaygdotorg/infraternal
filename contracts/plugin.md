<!-- Public plugin, action, event and stream contract [3,15,16,29]. -->
# Contract: plugins and actions

Status: target contract for #10; the implemented Mesh binding is specified below. Implements DECISIONS 3, 15, 16, 28, 29, 198, 201 and 202.

## 1. What a plugin is

A plugin is a feature (ssh, metrics, docker, …) delivered as three parts that
ship together and share one id:

| part   | crate or package                         | runs in              |
|--------|------------------------------------------|----------------------|
| agent  | `infraternal-plugin-<id>` (feature `agent`)  | infraternal agent    |
| server | `infraternal-plugin-<id>` (feature `server`) | infraternal server   |
| ui     | `apps/web/src/plugins/<id>`              | browser / PWA        |

Plugins are compiled in (DECISIONS 15). The server and agent each hold a
static registry. The current server composition is in
`crates/infraternal-server/src/plugins.rs`; implementations live under
`crates/plugins/`.
There is no dynamic loading. The interface is versioned in `crates/infraternal-plugin-api`. Sections 2–7
describe the target adapter interface; the implemented version-1 socket
binding below declares its supported fields explicitly.

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
  - UI: inside the 15-minute admin window that one passkey tap opens (D333).
  - CLI and API keys: inside the key's scope, no further tap; the dry run
    comes first (D333).
  - Per-action-tap actions (`fresh_passkey`: key creation or widening, admin
    role changes and CA setup, recovery-key and passkey changes, account
    deletion, turning these rules off) need their own tap for every run and
    are never key-callable. Each tap is bound to the one action and parameters
    on screen, is single use and expires after 120 s (D336,
    `contracts/keywrap.md`). The 15-minute window never covers them.
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

A plugin subscription is identified by its `sub_id` on one authenticated
socket. Repeating `Subscribe` with that ID replaces the previous generation
in its existing bounded slot; normal topic and authorization checks still
apply, and replies from the replaced generation are discarded. An error event
can withdraw a subscription without closing the socket. A stateful viewer
recovers by repeating the same ID to request its topic's initial snapshot,
coalescing retries with positive, capped backoff rather than allocating new
IDs. Canvas-specific revision and pending-intent rules are in wire §Account
canvas layout (#250).

The Mesh coordinator is the `mesh` plugin server feature. Its live view uses the same
control-stream `Subscribe`/`Event` frames. Subscribe with
`{"topic":"mesh","tag"?:string}` to receive an initial filtered snapshot,
revision invalidations, and a resync snapshot if the bounded change buffer
overflows, or a visible live node reaches its expiry deadline. Authorization is checked for each viewer. The event shapes and
tag-filter behavior are specified in [contracts/mesh-api.md](mesh-api.md).

## 6. Streams

Some actions return a long-lived stream instead of a value: a terminal, a log
tail, live metrics. A `StreamDef` declares its frame types and whether it is
resumable. Terminal streams are resumable by byte offset (contracts/shim.md
§4, contracts/wire.md).

Native `WireStreamDef.capability` is the leg-B capability and must not alias its
reserved core bits 0–7 (bits 6 and 7 are path backup and path proof). The additive optional `browser_capability` declares a
different leg-A bit when the browser extension already has one. If absent, the
browser uses the native bit and descriptor JSON is unchanged. A declared browser
bit is a single extension bit (at least bit3); browser advertisement and admission
use that same projection. Native provider/transport negotiation always uses the
native field. Both identities must be unambiguous within a descriptor/provider
set. This metadata starts no work and does not identify a particular feature in
core dispatch [D16,D198]. For desktop, the frozen values remain browser8/native64
(contracts/wire.md §9); enabling a feature never changes its wire numbers.

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

## 9. Implemented Mesh socket binding (version 1)

`crates/plugins/mesh` owns the coordinator storage API, strict action and
subscription parsers, scoped watches, and expiry timers. The implementation
uses `crates/infraternal-plugin-api`; core WebSocket dispatch owns only the
generic host, session authority and opaque encoded reply delivery. The sole
Mesh reference in server composition registers its implementation.

The binary and server crate expose a default `mesh` Cargo feature. Building
`infraternal` with `--no-default-features` excludes both the plugin and its
policy library. The plugin's `server` feature requires an existing server
role; construction and enabling can never initialize a server [201]. A future
node-side component uses the same plugin id and its `agent` Cargo feature.
That component is not implemented by this coordinator change. Existing
shipped Mesh database migrations remain immutable compatibility history,
including when the feature is excluded.

The pure descriptor declares all 16 frozen Mesh action ids, summaries,
step-by-step instructions, input/output contract type references, permission
requirements and effects, plus topics, settings schema, role dependencies
and defaults. Type references identify the Rust types in `api.rs` and the
frozen Mesh contract. The CLI adapts these declarations into its shared action
registry: action ids become command paths, instructions become help and skills,
and effects retain destructive dry-run guidance. Generated skills include the
original input/output references and exact permission alternatives. Node-side
host-facts descriptors use the same adapter with host-scoped authority.
Hosted CLI commands return the shared unavailable result until an authenticated
CLI device-session transport exists; the server UI keeps the working handlers.
MCP generation is not implemented. Discovery reads these declarations even while
the feature is disabled. The plugin API's `socket-host` Cargo feature contains
its async reply queues and transactional freshness helper; pure descriptors,
node-side routing and CLI contracts do not pull Tokio or SQLx.

Control-stream calls are:

| Action | Input | Authority | Result |
|---|---|---|---|
| `plugins.list` | `{}` | unlocked authenticated session | `actions`, and `plugins` containing `descriptor` and `enabled` |
| `plugins.set_enabled` | `{"plugin":"mesh","enabled":false}` | fresh owner session | `plugin` and `enabled` |

Both reject unknown fields, duplicate fields and wrong field types; control
frames are bounded to 1 KiB. Mesh keeps its existing 64 KiB frame limit.
Runtime switches persist per host role and plugin in SQLite and restore before
serving sockets. Descriptor defaults apply only without a saved override.
Unreadable settings prevent startup. Enabling saves before admitting work and
starts no worker. The first admitted action or view starts one bounded ordered
worker per socket. Disabling invalidates buffered replies, aborts all registered
workers and joins them before waiting for the settings writer, then saves
before acknowledging success. This ordering cancels pending inventory writes
without waiting behind them. A failed save restores the previous enabled
state lazily. Owner/fresh authority is rechecked inside the writer transaction
after lock waits [28]. Disabled calls are refused; unanswered in-flight calls
receive one error result, leaving no Mesh worker, watch or timer running.

Existing views receive a final plain `forbidden` event on disable or worker
exit. Already-buffered successful calls settle on normal worker exit before
unanswered calls fail. Distinct feature epochs and worker generations reject
old replies, including after reusing a call id. Never-reused view generations
prevent an old withdrawal from ending a replacement with the same subscription
id. Core checks this typed lifecycle metadata without parsing snapshot JSON.
Only declared plugin topics are routed to workers; `auth.*` topics remain core
owned regardless of descriptor claims. The control worker remains available
to re-enable compiled features.
