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
are presentation. Existing bootstrap destinations supply names, users and
addresses; a rootful installation uses `root`. A host enrolled without bootstrap
coordinates uses its UUID as the label and does not invent a login or address.
The last collected public OS is retained on the bootstrap row; missing facts
remain absent. Online means the admitted actor has a complete live session
census; it is never inferred from a saved browser window or a certificate alone.

Pages are ordered by UUID, contain at most 128 hosts, and reserve a 60 KiB JSON
budget inside the 64 KiB mux frame. Continue from the last delivered UUID when a
page is truncated by either limit. A cursor selects position only; it cannot
select an account or enlarge access.

`Subscribe { topic: "remote.hosts" }` receives `{ type: "changed" }`, including
one initial invalidation that closes the read/subscribe race. Notification is
coalesced after durable admission and revocation, and after connectivity or cached
OS changes. The event carries no host or account data. The existing plugin
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
