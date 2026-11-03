<!-- Control-plane JSON contract for Mesh nodes, tags, named grants, roles and subscriptions [154,163,164,180,187]. -->
# Contract: Mesh API

Status: additive v1 JSON contract for #108. The control plane stores and
authorizes inventory; WireGuard configuration and packet forwarding remain in
the later data-plane slice. The shared policy representations come from
`infraternal-mesh`.

## 1. Calls and results

Mesh actions use `Call` on control stream 0 (contracts/wire.md §4). The
`actionId` is one of the names below and `input` is its JSON object. A success
uses `Result { ok: true }` with the listed JSON value. A failure uses
`Result { ok: false }` with `{"error":"..."}`. Unknown fields are rejected.

| Action ID | Input | Success value | Required action |
|-----------|-------|---------------|-----------------|
| `mesh.list` | `MeshFilter` | `MeshSnapshot` | Any assigned Mesh management action grants view access, subject to its tag scopes. |
| `mesh.node.enroll` | `{"name":string,"public_key":[u8;32],"host_id"?:string}` | `{"node_id":u64,"revision":u64}` | Global `mesh.manage_nodes` |
| `mesh.node.observe` | `{"node_id":u64,"last_rtt_us"?:u64\|null}` | `{"revision":u64}` | `mesh.manage_nodes` covering every current node tag |
| `mesh.node.rename` | `{"node_id":u64,"name":string}` | `{"revision":u64}` | Global `mesh.manage_nodes` |
| `mesh.node.delete` | `{"node_id":u64}` | `{"revision":u64}` | `mesh.manage_nodes` covering every current node tag |
| `mesh.tag.create` | `{"name":string}` | `{"revision":u64}` | `mesh.manage_tags` |
| `mesh.tag.rename` | `{"name":string,"new_name":string}` | `{"revision":u64}` | `mesh.manage_tags` |
| `mesh.tag.delete` | `{"name":string}` | `{"revision":u64}` | `mesh.manage_tags` |
| `mesh.tag.member.add` | `{"tag":string,"node_id":u64}` | `{"revision":u64}` | `mesh.manage_tags` scoped to `tag`, or global `mesh.manage_tags` |
| `mesh.tag.member.remove` | `{"tag":string,"node_id":u64}` | `{"revision":u64}` | `mesh.manage_tags` scoped to `tag`, or global `mesh.manage_tags` |
| `mesh.grant.create` | `MeshGrantCreate` | `{"grant_id":u64,"revision":u64}` | `mesh.manage_grants`, covering every endpoint's tag scope |
| `mesh.grant.move` | `MeshGrantMove` | `{"revision":u64}` | `mesh.manage_grants`, covering the old, new and retained endpoints |
| `mesh.grant.delete` | `{"name":string}` | `{"revision":u64}` | `mesh.manage_grants`, covering both existing endpoints |
| `mesh.grant.rename` | `{"name":string,"new_name":string}` | `{"revision":u64}` | `mesh.manage_grants`, covering both existing endpoints |
| `mesh.role.define` | `MeshRoleDefinition` | `{"revision":u64}` | Global `mesh.manage_roles` |
| `mesh.role.assign` | `{"user_id":string,"role":string}` | `{"revision":u64}` | Global `mesh.manage_roles` |

`MeshFilter` is `{"tag"?:string,"cursor"?:{"revision":u64,"offset":usize}}`. IDs are positive integers no
greater than SQLite's signed 64-bit maximum. A node public key is exactly 32
nonzero bytes; private keys are never accepted by this API.

### Authenticated host binding (#173, D164/D166/D235)

An optional `host_id` is a canonical lowercase hyphenated UUID of an existing,
unrevoked `remote_hosts` identity. Global `mesh.manage_nodes` authorizes its
binding to the new mesh node. Enrollment records that binding and clears that
host's mesh removal tombstone in the same transaction; duplicate bindings are
refused. A missing or revoked remote host is refused without a revision change.

Legacy key-only enrollment remains unbound inventory. Its public key never
permits an authenticated host to attach to that node or inherit its grants.
Automatic joining allocates a fresh identity when no host binding exists; a
conflicting public key or retained removal tombstone is refused. An already
bound host retains its mesh node identity and addresses across key rotation.
The reserved server identity is bound only through the trusted server channel.

## 2. Shared policy and inventory shapes

Endpoints and port policies use mesh-core's serde representation:

```json
{"Node":7}
{"Tag":"prod"}
"All"
{"Ports":[{"protocol":"Tcp","number":443},{"protocol":"Udp","number":53}]}
```

`MeshGrantCreate` is
`{"name":string,"from":Endpoint,"to":Endpoint,"both_ways":boolean,"ports"?:TrafficPolicy}`.
Omitting `ports` means `All`. An explicit `ports: null` is refused as `invalid input`
before any grant or revision is committed. A `Ports` list must be nonempty and each port
must be in 1..=65535. `None`, user endpoints, and endpoints that do not exist
are not accepted for a grant. `both_ways` permits new connections to be
initiated from either end. `MeshGrantMove` is
`{"name":string,"side":"from"|"to","endpoint":Endpoint}` and retains the
grant name and traffic policy.

A listed grant is `{"name":string,"arrow":{"id":u64,"from":Endpoint,"to":Endpoint,"both_ways":boolean,"ports":TrafficPolicy}}`.
Its numeric ID is server inventory identity. Layouts refer to grants by name
only (D180).

`MeshNode` is `{"node":{"id":u64,"public_key":[u8;32],"host":string,"tags":string[]},"live":boolean,"last_seen":i64|null,"last_rtt_us":u64|null}`.
`last_seen` is Unix seconds and never decreases when observations admitted
before writer waits commit out of order. `live` is true when the newest
successful observation is within the 30-second live window. RTT is in
microseconds.
`MeshTag` is `{"name":string,"members":u64[]}`; member IDs are sorted.
`MeshSnapshot` is `{"revision":u64,"nodes":MeshNode[],"tags":MeshTag[],"grants":MeshGrant[],"next_cursor"?:{"revision":u64,"offset":usize}}`.
The snapshot is permission-filtered and read from one consistent database
transaction.

## 3. Names, roles and authorization

Node, tag, grant and role names are 1–63 lowercase ASCII letters, digits or
hyphens; a name cannot start or end with a hyphen. A host name is one such
single label. Node IDs are monotonically allocated and never reused after
deletion or restart (D180); the allocation high-water mark is persisted apart
from live inventory. Tag and grant names are stable references in layout documents.

For an automatically named bound host, the source order is a person's name,
the server name, a valid machine name from the host's bootstrap destination,
the last valid hostname from admitted-host inventory, then an unnamed label.
An IP address is not a machine name. The reported hostname yields to every
other host's bootstrap name, including hosts without a Mesh node. When
inventory learns a hostname after attach, the node is renamed and its new
revision is sent to live subscribers without another attach. Existing
`mesh-<host UUID>` placeholders are migrated to unnamed labels. The API shape
and `host` field remain unchanged (#236).

A view contains only the machines its viewer may see (the viewer's role scope),
and each appears under its real name, the one DNS answers to. A machine outside
the viewer's scope has no node, no tag membership and no grant in the view, and
no stand-in name: no `unnamed-<id>` label is derived for any viewer (D327, D329,
#331). The stored `unnamed` labels above belong to machines whose name is not
known to anyone.

The only assignable Mesh role actions are `mesh.manage_nodes`,
`mesh.manage_tags`, `mesh.manage_grants` and `mesh.manage_roles`. A role has a
nonempty `actions` array and optional nonempty `scopes` array of existing tag
names. `MeshRoleDefinition` is
`{"name":string,"actions":string[],"scopes"?:string[]}`. Omitting `scopes`
means instance-wide authority. Explicit `scopes: null` is refused as `invalid
input` before any role, revision or audit is committed; it never becomes global
authority. A role granting
`mesh.manage_roles` is global and cannot have tag scopes. Node enrollment and
node rename and role management are global actions; node observation and delete
can use `mesh.manage_nodes` scoped to tags. Node names occupy one globally unique
namespace. Rename checks global authority before looking up any name, so callers
without it receive `denied` for both a hidden occupied name and an unused name
(#236). Global node managers may move automatic name holders aside, including
reported hostnames hidden in their inventory view; hand-chosen names still
conflict. A scoped role, even combined with global authority for a different
action, cannot rename nodes. A scoped node edit must cover every
current node membership; an untagged node requires a global node-management
role. Tag membership changes require `mesh.manage_tags` on the destination
tag and every current node membership; untagged hosts require global access.
Checks use pre-edit memberships so an editor cannot claim an out-of-scope host.
A tag endpoint requires that tag; a node endpoint requires every current
membership. Creating, moving, deleting or renaming a grant requires
`mesh.manage_grants` covering every tag of every touched endpoint [211].
Moving includes the old, replacement and retained endpoint. An untagged node
endpoint requires global grant-management authority.

Owners bypass role checks. Other users need an assigned role. Any assigned
Mesh management action grants inventory view access, narrowed by its scopes;
there is no separate `mesh.view` permission (D187). A filtered list or
subscription requires access to the requested tag. Role scopes also filter
which changes a live subscription reveals. Permission checks are repeated for
each operation and live invalidation. Membership edits notify viewers of every
pre-edit host tag and the edited tag. Cascading tag renames also notify viewers
of the other tags on affected hosts, because node tag metadata changes.

Browser node/tag/grant deletion, membership removal, grant endpoint moves, and
role definition/assignment require a passkey tap within the browser's
15-minute admin window (D28, D333: one tap starts 15 minutes of admin actions). Freshness is checked at admission and
again inside the writer transaction, immediately before commit using the
SQLite clock. Waiting for the writer cannot extend the confirmation window.
If confirmation expires, the result says `confirm with your passkey again`;
inventory, revisions and audit roll back together and the multiplexed socket
remains usable. Reads and observations do not require fresh confirmation.

Every successful edit, including a liveness observation, advances the shared
monotonic revision and records an audit row in the same SQLite transaction
(D154 G9). Deleting a node also removes its memberships and grants that use
it. A tag cannot be deleted while a grant references it. A grant rename
preserves its numeric identity. Concurrent edits serialize through SQLite;
the returned revision identifies the committed edit.

## 4. Mesh subscriptions

Send `Subscribe` on control stream 0 with
`{"topic":"mesh","tag"?:string}`. The `sub_id` identifies the live
subscription. The server checks current authorization and sends an `Event`
with that `sub_id`:

```json
{"type":"snapshot","snapshot":MeshSnapshot}
{"type":"changed","revision":u64}
{"type":"resync","snapshot":MeshSnapshot}
{"type":"error","error":"forbidden"}
```

Authoritative `snapshot` and `resync` events apply even at the currently shown
revision: liveness expires with time without a database edit. Older revisions
and delayed list replies at an already delivered revision never replace them.
Earlier paged results and failures are dropped after any newer complete view,
including a completed invalidation refresh. They cannot replace equal-revision
liveness, publish an error or clear newer pending refresh work. Incoming
authoritative snapshots and resyncs also supersede earlier page work.

The initial event is a permission-filtered snapshot. A `changed` event is an
invalidation; the viewer reloads `mesh.list` with the same tag filter. An explicit
subscription tag limits scoped invalidations for every viewer, including owners
and global roles. Instance-wide changes invalidate every authorized view. If a
subscriber falls behind the bounded change buffer, the server sends a fresh
filtered `resync` snapshot. Each view also schedules the earliest visible
live-node deadline from the complete filtered inventory, before paging.
Membership and role changes recompute this deadline for newly visible hosts,
including watches which previously had no live-node timer. At
that deadline it sends a `resync` at the current revision, even with no edit
or subsequent request. This derived expiry changes neither revision nor audit.
A timed resync may arrive between continuation results; authoritative resyncs
supersede page assembly as described above. Invalid filters, denied access, missing tags and
storage errors produce sanitized `error` events (`invalid input`, `forbidden`,
`not found`, `conflict`, or `mesh unavailable`) and do not expose SQL details.
A server `error` ends that subscription. Clients withdraw publication before
notifying the view; an earlier in-flight list cannot republish inventory or
a replacement error afterward. A new watch is required to retry.
Mesh database work runs separately from shared terminal/control dispatch. Each
socket admits one active request and four queued requests, with four buffered
replies and at most 32 Mesh subscriptions. At most two Mesh operations run
across sockets, reserving deployed SQLite pool capacity for authority reads. Saturation returns `mesh unavailable`
without waiting for queue capacity. Closing the socket cancels pending Mesh work.

Reusing a `sub_id` ends its previous Mesh subscription at admission, before the
replacement filter is checked. Every replacement refusal, including oversized
input and queue or subscription saturation, leaves that ID unsubscribed. Earlier
queued watches, in-flight snapshots and buffered events cannot revive it or
publish after the refusal. Other subscription IDs remain active; a new
`Subscribe` is required to retry the refused ID. The 32-subscription admission
bound includes queued watches. Closing the WebSocket ends its subscriptions;
v1 has no separate unsubscribe frame.

JSON examples for each action, representative results and event forms are in
`contracts/vectors/mesh/manifest.json`.

List input accepts an optional `cursor: {revision, offset}`; snapshots include
`next_cursor` only when another bounded page is needed. The offset counts
objects in stable nodes, tags, then grants order. Every page checks the caller's
current permissions. A cursor for an older revision restarts at offset zero;
clients discard the previous revision before assembling the restart. Future
revisions and invalid offsets are refused. A single object that cannot fit
produces a sanitized service error. The global wire codec retains its existing 4 MiB limit. Every Mesh frame,
including mux/frame headers, is at most 64 KiB so terminal frames interleave
between pages. Paging reserves 1 KiB for the fixed envelopes and cursor.
Input frames above that scheduling limit are refused before Mesh work begins.

Subscription snapshots and resyncs use the same pages. The typed client follows
continuations through `mesh.list` with the same tag filter, then publishes a
complete snapshot. Small inventories keep their existing shape and one request.
Clients bound continuation work and stop issuing continuation calls when a newer
authoritative event supersedes an assembly or the subscription is withdrawn.
Already-issued calls may settle; obsolete results never restart continuation work.

## Plugin ownership [198,201]

The coordinator belongs to `crates/plugins/mesh` as the `mesh` server feature,
behind the optional Cargo feature of the same name. The core discovers its
actions and routes opaque bytes through the shared plugin host. Discovery,
runtime switching, role dependencies and the future node-component naming
are specified in [the version-1 plugin binding](plugin.md#9-implemented-mesh-socket-binding-version-1).
The Rust `infraternal-server::mesh_api` module is a feature-gated compatibility
re-export; the implementation and parsers live in the plugin crate.
