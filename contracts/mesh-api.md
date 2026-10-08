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
| `mesh.node.enroll` | `{"name":string,"public_key":[u8;32]}` | `{"node_id":u64,"revision":u64}` | Global `mesh.manage_nodes` |
| `mesh.node.observe` | `{"node_id":u64,"last_rtt_us"?:u64\|null}` | `{"revision":u64}` | `mesh.manage_nodes` covering every current node tag |
| `mesh.node.rename` | `{"node_id":u64,"name":string}` | `{"revision":u64}` | `mesh.manage_nodes` covering every current node tag |
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

`MeshFilter` is `{}` or `{"tag":string}`. IDs are positive integers no
greater than SQLite's signed 64-bit maximum. A node public key is exactly 32
nonzero bytes; private keys are never accepted by this API.

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
Omitting `ports` means `All`. A `Ports` list must be nonempty and each port
must be in 1..=65535. `None`, user endpoints, and endpoints that do not exist
are not accepted for a grant. `both_ways` permits new connections to be
initiated from either end. `MeshGrantMove` is
`{"name":string,"side":"from"|"to","endpoint":Endpoint}` and retains the
grant name and traffic policy.

A listed grant is `{"name":string,"arrow":{"id":u64,"from":Endpoint,"to":Endpoint,"both_ways":boolean,"ports":TrafficPolicy}}`.
Its numeric ID is server inventory identity. Layouts refer to grants by name
only (D180).

`MeshNode` is `{"node":{"id":u64,"public_key":[u8;32],"host":string,"tags":string[]},"live":boolean,"last_seen":i64|null,"last_rtt_us":u64|null}`.
`last_seen` is Unix seconds. `live` is true when the last successful
observation is within the 30-second live window. RTT is in microseconds.
`MeshTag` is `{"name":string,"members":u64[]}`; member IDs are sorted.
`MeshSnapshot` is `{"revision":u64,"nodes":MeshNode[],"tags":MeshTag[],"grants":MeshGrant[]}`.
The snapshot is permission-filtered and read from one consistent database
transaction.

## 3. Names, roles and authorization

Node, tag, grant and role names are 1–63 lowercase ASCII letters, digits or
hyphens; a name cannot start or end with a hyphen. A host name is one such
single label. Tag and grant names are stable references in layout documents.

The only assignable Mesh role actions are `mesh.manage_nodes`,
`mesh.manage_tags`, `mesh.manage_grants` and `mesh.manage_roles`. A role has a
nonempty `actions` array and optional nonempty `scopes` array of existing tag
names. `MeshRoleDefinition` is
`{"name":string,"actions":string[],"scopes"?:string[]}`. A role granting
`mesh.manage_roles` is global and cannot have tag scopes. Node enrollment and
role management are global actions; node observation, rename and delete can
use `mesh.manage_nodes` scoped to tags. A scoped node edit must cover every
current node membership; an untagged node requires a global node-management
role. Tag membership changes require `mesh.manage_tags` on the destination
tag and every current node membership; untagged hosts require global access.
Checks use pre-edit memberships so an editor cannot claim an out-of-scope host.
A tag endpoint's scope is
that tag; a node endpoint's scopes are its current memberships. A scoped grant
role must cover each endpoint's scope group, so an untagged node endpoint
requires a global `mesh.manage_grants` role.

Owners bypass role checks. Other users need an assigned role. Any assigned
Mesh management action grants inventory view access, narrowed by its scopes;
there is no separate `mesh.view` permission (D187). A filtered list or
subscription requires access to the requested tag. Role scopes also filter
which changes a live subscription reveals. Permission checks are repeated for
each operation and live invalidation.

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

The initial event is a permission-filtered snapshot. A `changed` event is an
invalidation; the viewer reloads `mesh.list` with the same tag filter. If a
subscriber falls behind the bounded change buffer, the server sends a fresh
filtered `resync` snapshot. Invalid filters, denied access, missing tags and
storage errors produce sanitized `error` events (`invalid input`, `forbidden`,
`not found`, `conflict`, or `mesh unavailable`) and do not expose SQL details.
Reusing a `sub_id` replaces its existing Mesh filter. Closing the WebSocket
ends its subscriptions; v1 has no separate unsubscribe frame.

JSON examples for each action, representative results and event forms are in
`contracts/vectors/mesh/manifest.json`.
