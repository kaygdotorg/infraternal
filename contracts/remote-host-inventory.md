<!-- Admitted terminal-host inventory over the existing mux, #194; D16/D178/D198/D214. -->
# Admitted terminal hosts

The remote crate declares the `remote.host` server feature. It reads the
existing enrollment ledger and bootstrap coordinates; it creates no separate
host inventory. It can be removed with the remote build feature and switched off
through the generic plugin runtime. Its node and socket workers are cancelled
when it is switched off.

`remote.host.list` accepts an object with an optional canonical lowercase UUID
`after` cursor. Input is at most 1,024 bytes; unknown fields and positional arrays
are refused. The account comes only from the authenticated socket. The read uses
the terminal admission checks in `websocket::terminal_actor`: matching `owner_id`
and an absent host revocation tombstone. Unredeemed invitations are excluded.
Certificate expiry does not hide a host that is offline.

The result is `{ hosts: [...], next: UUID | null }`. Each host has `id`, `name`,
`online`, and nullable `user`, `os`, `address`. UUIDs are routing authority; names
are presentation. Existing bootstrap destinations supply users and addresses;
a rootful installation uses `root`. The first valid hostname reported by an
admitted host is retained on its inventory row. A valid machine name from the
bootstrap destination takes precedence; an IP-only destination uses the
retained hostname. When neither source gives a name, the display name is
`unnamed`. The name and address fields keep their existing shape. The last
collected public OS is retained on the bootstrap row; missing facts do not clear
retained hostnames or OS values. Online means the admitted actor has a complete live session
census; it is never inferred from a saved browser window or a certificate alone.

Pages are ordered by UUID, contain at most 128 hosts, and reserve a 60 KiB JSON
budget inside the 64 KiB mux frame. Continue from the last delivered UUID when a
page is truncated by either limit. A cursor selects position only; it cannot
select an account or enlarge access.
There is no total host-count cutoff: offline admissions are independent of live
transport capacity. Clients continue through every bounded page before publishing
the complete inventory.

`Subscribe { topic: "remote.hosts" }` receives `{ type: "changed" }`, including
one initial invalidation that closes the read/subscribe race. Notification is
coalesced after durable admission and revocation, and after connectivity or cached
hostname and OS changes. The event carries no host or account data. The existing plugin
subscription slots, generation stamps, socket authority watchdog and cancellation
apply. Read and outbound queue admission stay inside one live-authority operation.
There is no polling timer.

After sign-in, the canvas opens the first terminal before loading the inventory
module. Nonempty painted terminal text starts inventory; a silent attached session
has a one-shot one-second grace followed by two animation frames. A terminal
that cannot open starts inventory for recovery. This is not a polling timer. Every welcome invalidates the previous read generation. Complete,
validated pages replace the sessions adapter in one notification; incomplete or
superseded pages cannot partially replace it. The client subscribes only after a
successful read, so an older server never receives an unsupported subscription.
A refused read or withdrawn feature clears remote admission; a transient network
failure retains the last complete snapshot until reconnect. Disposal fences every
pending result and unsubscribes. Offline hosts remain in the existing host list
with their state, and palette actions route by UUID.

The toolbar and the palette receive the same `SessionService` adapter through
`cx.adapters.sessions`. `hosts()` exposes `{ id, name, user?, os?, online? }`,
including offline hosts; `onChange(listener)` signals complete inventory,
connectivity and removal updates. A new-window consumer opens with
`cx.win.open(host.id)`, which routes through `sessions.open(id)` using the admitted
UUID. Names can collide and are never the identity to select. The host-choice UI
for New window remains designer work; this data path introduces no new surface.

Palette rows stay synchronous. Canvas action dispatch is loaded on first
selection from `palette-actions.on-demand.ts`, fenced by canvas disposal, so
dispatch costs no sign-in transfer and remains within the unchanged D188 budgets.

An undelivered host removal stays in this inventory with optional
`state: "pending"` and `online: false`. A removal response acknowledges the
committed denial as `state: "pending"` (“revoked, cleanup pending”); it does not
claim the infraternal agent has persisted cleanup. Once that durable receipt
commits, final retirement removes the host from inventory. When no individually
unrevoked certificate has remaining validity, the next read instead exposes
`state: "retired-unreachable"`. That terminal delivery status retains the
unconfirmed denial, including after restart; it never grants access or invents a
receipt. Other hosts omit `state`, preserving the existing inventory shape.

Clients retain these status rows and show pending or retired-unreachable in the
existing host list, without shell, removal or privilege actions. The CLI reports pending for an accepted removal whose cleanup has not completed. See
`docs/operations/login-revocation-backpressure.md` for delivery bounds and the
operator action when cleanup certificates expire.

## Facts of one host: `remote.host.facts` (#410)

A window's machine details describe the window's own host, never the server.
`host.facts.read` on the browser socket answers only for the server's own agent
and takes no host. `remote.host.facts` takes exactly `{ "host_id": UUID }`
(canonical lowercase, at most 256 bytes; unknown fields and arrays are refused)
and returns what that host's infraternal agent reports for `host.facts.read`
with live figures. It has no API scope: it is a browser action.

The host must pass the same predicate as `remote.host.list` (the account's own,
not revoked, admitted, no pending retirement). Otherwise the answer is
`{"error":"host unavailable"}`, the same for a host that does not exist and a
host of another account. An admitted host whose agent is not connected, or does
not answer within 5 seconds, is `{"error":"host offline"}`. The server's own
facts are never returned in place of either. Live reads do not write inventory
rows; the connection observer retains the host's name and system separately.

The details panel says "Can't be read while this machine is offline" for
`host offline` and "Not known yet" until the first answer.
