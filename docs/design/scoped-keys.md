<!-- Design note: scoped API keys and the join permission (D342, D343), issue #340. -->
# Scoped API keys and the join permission

Status: design, not built. Issue: [#340](https://git.kayg.org/kayg/infraternal/issues/340).
Sources: D333, D336, D337, D339, D342, D343, D235, D237, D239, D318 and D340.
It builds on the API-key code on `apikey-actions-303` (#303, not merged yet)
and on the `infraternal up` machine join that is on `dev` (#263).

There is no separate "setup key" type (D342). An API key gets one more
scope, **join**, and that scope has its own settings. A machine that runs
`infraternal up <server> --setup-key=…` with such a key joins without an
approval tap (D337), because the passkey tap was made once, when the key
was created, and that tap was bound to the key's exact settings (D336, D342).

Every place where no decision covers a choice is marked **Open question
Qn**, with options and a recommendation. The same questions are posted on #340.

## 1. What exists today

| Piece | Where | State |
|---|---|---|
| `api_keys(token_hash PK, user_id, device, scopes JSON, renewed_at, expires_at, dead)` | migrations 0001, 0034, 0035 | dev |
| Sliding inactivity end: `server_settings.api_key_lifetime_days` (1–365, default 30), renewed at most once an hour | `auth/devices.rs` | dev |
| `hard_expires_at`: the lifetime approved with the key, 24 h by default, at least 1 h, at most the inactivity policy (D333) | 0044 | #303 |
| Keys from before D333 end at most 24 h after the upgrade (D337) | 0047 | #303 |
| Grantable scopes: `hosts:read`, `hosts:write`, `sessions:read`, `status:read`, `terminal:connect`, `actions:dry-run` | `device_start_for` | #303 |
| Per-action tap bound to one action, single use, 120 s (`TapAction`, D336) | `auth/action_tap.rs` | #303 |
| Key creation only through device approval: the CLI asks (`sign-in --scope`), a browser approves with a tap | `device-start` / `device-approve-*` / `device-redeem` | dev + #303 |
| Change audit `api_action_audit`, read counts per key and minute `api_read_audit` | 0043, 0046 | #303 |
| `api-list` and `api-revoke` endpoints (no UI list yet); the key's public id is its `token_hash` | `auth/http.rs` | dev |
| Machine join by approval: `up` sends a `join_machine` request with the machine-key fingerprint; the owner taps; `device-redeem` returns a 10-minute receipt bound to that machine key | `up.rs`, `devices.rs`, `remote_http.rs::issue_approved_machine_join` | dev |
| Source caps on pending approvals (IPv6 /64, /56, /48 = 5, 16, 32; IPv4 /32, /24 = 5, 32; 1024 server-wide), kept in memory only | `devices.rs` `SOURCE_CAPS` | dev |
| Ceremony pools: anonymous per network, per person (5), with eviction (J174) | `webauthn.rs`, `devices.rs` | `signin-pools-263-j174` |

Two facts shape the design:

- A key is a 256-bit random bearer secret, stored only as its hash. The hash
  is the row's primary key and its public id. Lookup is one indexed read.
- `api_authorize` opens a writer transaction (`BEGIN IMMEDIATE`) on every
  call so that expiry, renewal and revocation are serialised. That is
  acceptable for actions. It is not acceptable as the first thing an
  unauthenticated join request does (see §4.3).

## 2. Data model

### 2.1 Keys and scopes

The key stays one row in `api_keys`. New columns:

| Column | Meaning |
|---|---|
| `name` | What the person called it ("ci runners"). Keys from device approval keep using `device` as their name. |
| `created_at` | Issue time. NULL for keys from before this change. |
| `origin` | `device` (approved from a CLI or MCP request) or `settings` (created in Settings › Access › Keys). |
| `never_expires` | 1 when the creator chose no expiry (D343). Then `hard_expires_at` is NULL. A CHECK keeps the two consistent, so after 0047 a NULL end can never mean "an old key with no cap". |
| `last_used_at` | The last successful use, in minutes, written at most once a minute. The list shows it. |

The scopes stay a JSON array of strings. One new grantable scope is added:

- **`hosts:join`**: may enrol new machines, with the settings in §2.2.

**Open question Q1: the scope's name.** Options: (a) `hosts:join`, next to
`hosts:read` and `hosts:write`; (b) `machines:join`, which matches the
user-facing word; (c) `join`. **Recommendation: (a).** The other scopes are
named by resource, the UI never shows the raw name (it says "Join new
machines"), and the CLI and MCP already use `hosts`.

**Open question Q2: may one key hold `hosts:join` and other scopes?** D342
says "no separate key type", so the model allows it. But a join key usually
ends up in a CI secret store or in a cloud-init file, which is where it is
most likely to leak. If it also holds `hosts:write`, a leak lets the
attacker remove machines as well as add them. Options: (a) allow any mix;
(b) a key with `hosts:join` may also hold read scopes but no write scope;
(c) a key with `hosts:join` holds nothing else. **Recommendation: (b) for
now.** It is still one key type, one table and one list. The create sheet
says why when someone ticks both. It can be loosened later without a
migration.

### 2.2 The join permission's settings

A key with `hosts:join` has exactly one row in a new table, `api_key_join`,
keyed by the key's hash:

| Field | Default | Decision |
|---|---|---|
| `reusable` | no: one-time | D342 |
| expiry | 24 h (the key's `hard_expires_at`) | D342; no expiry allowed (D343) |
| `assign_to` | the creator | D342 "user to assign" (see Q3) |
| `tags` | none | D342 "tags to assign" |
| `ephemeral` | no | D342 |
| `ephemeral_after` | see Q7 | not decided |
| `max_uses` | 1 when one-time; none when reusable | see Q4 |
| `uses` | 0 | counter |
| `modes` | `system` and `user` | see Q5 |
| `settings_digest` | SHA-256 of the canonical settings | binds the creation tap (§3) |

The settings never change after creation. Changing them means creating a new
key and revoking the old one (Q19). That keeps "the tap approved exactly
these settings" true for the key's whole life.

Access is never stored on the key. A joined machine reaches what the grants
and policies give its tags and its assigned owner, the same as any other
machine (D342: "access will be determined by our grants"; D237: ownership is
a label, never access).

**Open question Q3: what "user to assign" can name.** `remote_hosts.owner_id`
is NOT NULL today, and D237 says an administrator makes a machine *shared*
by tagging it, which removes person links. Options: (a) only the creator in
the community edition, and any person in EE (multi-user management is EE,
D334); (b) also "Shared (nobody)", which needs at least one tag and a
nullable owner or a `shared` flag on the host; (c) creator only, with no
field. **Recommendation: (a) plus (b).** "Me" is the default. "Shared" is
what a fleet of CI runners or servers is. "Another person" appears only in EE.
For (b), use a `shared` flag on `remote_hosts`, so that `owner_id` keeps
meaning "who added it" for audit and stays NOT NULL.

**Open question Q4: a use limit between one and unlimited.** D342 names
"reusable or one-time". A count ("at most 20 machines") limits a leaked
reusable key. Options: (a) only one-time or unlimited; (b) one-time,
unlimited, or a number. **Recommendation: (b).** The column costs nothing,
the create sheet shows it only when Reusable is on, and "20 runners" is a
real request.

**Open question Q5: which install modes a key allows.** On dev, `up` joins
only as a root system service. D339 holds back a root install requested by
an AI agent through MCP until the owner taps. With `up --setup-key` the
person on the machine runs sudo themselves, so the key only authorises the
join, not the root install. Options: (a) any mode; (b) a per-key choice:
system, user or both; (c) user mode only unless the key says otherwise.
**Recommendation: (b), with both ticked by default.** A key for laptops can
then refuse root installs. D339 still applies to MCP-started installs.

### 2.3 What the host row gains

`remote_hosts` gets:

- `joined_with_key`: the hash of the key that enrolled it. It is NULL for
  machines that joined by approval or by SSH add-host. It stays when the key
  is revoked (D342), so "remove machines joined with this key" and "last
  machine that joined" work. When the key row is purged at the end of audit
  retention, this column is set to NULL.
- `ephemeral_after`: seconds offline before automatic removal, or NULL.
- `shared`: per Q3 (b).

Tags are applied to the host's mesh node in the same transaction as the
join, through the existing `mesh_tag_members` path, so a grant applies from
the machine's first packet, never a moment later.

**Open question Q6: a tag that no longer exists when a machine joins.**
Options: (a) refuse the join and say which tag is missing; (b) join without
it and record that in the audit; (c) re-create the tag. **Recommendation:
(a).** A CI job fails loudly instead of producing machines that silently
lack the access they were meant to get. (c) would bring back a tag that an
administrator deleted on purpose.

### 2.4 Ephemeral machines

An ephemeral machine is removed after it has been offline for
`ephemeral_after` (D342). Removal is the same as removing a host:
`revoked_at` is set, the mesh trigger retires the node, the node's
certificates are revoked, the name is freed for reuse (D339 suffixes), and an
audit row says why ("removed: offline for 1 h, joined with key ci runners").
The infraternal agent is not uninstalled, because it is unreachable. If the
machine comes back, its credentials are refused and it must join again.

Mechanics, which follow from the performance budget of zero idle wakeups (D41):

- The clock for "offline" starts when the machine's leg-B connection closes.
  It is cancelled when the machine reconnects.
- The server keeps one timer, set for the earliest pending removal. It has no
  per-host timers and does not poll. With no ephemeral machine offline, it
  never wakes.
- After a server restart, every ephemeral machine gets a full window counted
  from when the server came up. A server that was down for a day must not
  remove every runner the moment it starts.
- A machine with a terminal that someone is watching is not removed: it is
  online by definition.

**Open question Q7: the default offline time before removal.** Options:
(a) 10 min; (b) 1 h; (c) 24 h; (d) no default, the creator must choose.
**Recommendation: (b) 1 h, with choices of 10 min, 1 h, 24 h and 7 days.**
1 h survives a reboot, a network blip or a slow image pull, and it still
cleans up a CI fleet within the hour.

## 3. Creating a key

Creating any key with `hosts:join`, or with no expiry, or any key at all in
Settings, needs a passkey tap bound to its exact settings (D333, D336,
D342). A new tap kind is added beside `TapAction::ApproveKey`:

```
TapAction::CreateKey { settings_digest }
```

`settings_digest` is the SHA-256 of a canonical encoding of the name, scopes,
expiry (or "never") and every join setting. The page shows those settings in
plain words. The tap's challenge covers the digest. The server recomputes it
from the submitted settings and spends the tap only if the two match. A tap
made for "one-time, 24 h" therefore cannot create "reusable, never".

There are two ways in:

1. **Settings › Access › Keys › New key** in the browser (§6). The secret is
   shown once on the page, after the tap.
2. **From the CLI or an AI agent**, through the existing device-approval
   flow: `infraternal keys create …` (§7) sends the settings, prints a
   link and a short code, and waits. The approval page shows the same
   settings and asks for the bound tap. A key never starts a tap action
   (#303), so a key alone can never create another key.

The approval request carries the settings in `approvals.request_json`, with a
new kind `create_key`. SQLite cannot widen a CHECK in place, so adding the
kind rebuilds `approvals` (as 0040 did for `remote_join_tokens`).

**Open question Q8: does a key's secret ever reach an AI agent?** Through
MCP, an AI agent can ask for a join key, and the owner taps the request on
the approval page. Options: (a) the secret goes back to the AI agent in the
MCP result, where it ends up in the AI provider's transcript; (b) the
secret is shown only on the approval page, and the person pastes it where it
belongs; (c) the local CLI adapter writes it to a file the AI agent named,
mode 0600, and the MCP result returns only the path and the key's public id.
**Recommendation: (b) for MCP over HTTP and (c) for the local CLI.** A join
key in a transcript is a leaked join key.

The key's lifetime choices (D333, D343): 1 h, 24 h (default), 7 days, 30
days, 90 days, 1 year, Never. Today the inactivity policy caps the approved
lifetime. With "Never" allowed, that cap is replaced as described in Q9.

**Open question Q9: what "no expiry" does to the inactivity end.** Every key
today also dies after `api_key_lifetime_days` (30) without use. A join key
for a fleet image may go unused for longer than that, and it would then die
without warning. Options: (a) "Never" means no hard end and no inactivity
end; (b) "Never" means no hard end, but the inactivity end still applies;
(c) "Never" keys follow a separate inactivity setting. **Recommendation:
(a), and an Inbox reminder for a no-expiry key that has not been used for 90
days.** The person chose "Never" with a tap, so a quiet death would be
surprising. The reminder covers the forgotten key. The inactivity policy
stays for keys that do have an end, and it no longer caps the choices.

**Open question Q10: a recognisable secret format.** The secret is 32 random
bytes in base64url today. Options: (a) keep it; (b) add a fixed prefix and a
short checksum, for example `ifk_` + 43 characters + a 6-character checksum,
so secret scanners and our own CLI recognise a key, and the CLI rejects a
mistyped or truncated key before any network call. **Recommendation: (b) for
new keys.** Old keys keep working. The hash is taken over the whole string,
so lookup is unchanged.

## 4. Joining with a key

### 4.1 The command

```
infraternal up <server> --setup-key=env:NAME
infraternal up <server> --setup-key=file:PATH
infraternal up <server> --setup-key=-            # read from stdin
```

Only these three forms exist (D343). A value without `env:`, `file:` or `-`
is refused with "pass the key with env:NAME, file:PATH or -", and the value is
never echoed back. Reading:

- `env:NAME` reads the variable and removes it from the environment of every
  child process, including the sudo helper. The helper receives the
  credential on stdin, as it does today.
- `file:PATH` reads at most 4 KiB, follows no symlink owned by another user,
  and refuses a world-writable file. It does not delete the file: a
  reusable key's file is often a mounted secret that other machines share.
  (`up` without a key does delete its own machine-key file, J161 P3-1; that
  is a different file.)
- `-` reads stdin until EOF, at most 4 KiB, and trims one trailing newline.

**Open question Q11: a group- or world-readable key file.** Container and
orchestrator secret mounts are often mode 0644. Options: (a) refuse; (b)
warn and continue; (c) accept silently. **Recommendation: (b) for readable
files and refuse world-writable ones.** Refusing would break the usual way
these files arrive, while a writable file lets someone else swap the key.

### 4.2 The flow

The flow differs from the approval join only in how the receipt is obtained.

1. `up` finds sudo and systemctl and creates the machine key, exactly as
   today (`prepare_machine_join_key`, `take_join_key`).
2. It no longer needs a terminal. The terminal rule exists because the
   approval code is a live capability shown on screen. A key join shows no
   code, so it works under CI, cloud-init and `--json`.
3. It sends `POST /auth/machine-join` with `Authorization: Bearer <key>`
   and the same body as today's `join_machine` request: host id, hostname,
   mode, execution uid and machine-key fingerprint.
4. The server runs the checks in §4.3, then, in one transaction: counts the
   use, creates the `remote_hosts` row (owner or shared, `joined_with_key`,
   `ephemeral_after`), applies the tags, and issues the receipt through the
   same `issue_approved_receipt_in` path, bound to the machine key's digest,
   10 minutes.
5. The response has the same `JoinInvitation` shape as `device-redeem`, so
   `validate_invitation`, `encode_handoff` and the root helper are reused
   unchanged.
6. The output and `--json` envelope are as today, plus `joined_with_key` (the
   key's name and public id, never the secret).

What the key join does **not** do: it links no local account to any person.
D235 says a link always needs the person's own passkey, and that root,
system and shared accounts are never person-linked. A key-joined machine
therefore has machine identity only (D235). The approval join still links
the account that ran `up`, because a person tapped for it.

**Open question Q12: when a one-time key's use is spent.** If the network
drops after the server issued the receipt and before the machine enrolled,
a key spent at issue time is gone, and the machine never joined. Options:
(a) spend at issue time, and let a retry with the same host id and machine
key get the same receipt while it is live; (b) also give the use back when
the receipt expires unredeemed; (c) spend only when enrolment completes.
**Recommendation: (a) plus (b).** Only the exact machine key can redeem the
reserved receipt, so a thief gains nothing during the 10 minutes. (c) lets
two machines race through the same one-time key.

**Open question Q13: may a key take over a machine that belongs to another
server?** D337 allows a takeover only when the old install is not
working, and needs proof of ownership when it is. A key join runs without a
person watching. Options: (a) a key join refuses any machine that has
another server's install; (b) it follows D337 automatically when the old
install is broken; (c) as (b), but only with an explicit `--take-over` flag.
**Recommendation: (c).** A CI image rebuilt from a snapshot that carries a
stale install is the common case. The flag keeps that intentional, and the
audit row records it.

### 4.3 Server checks, in order

Cheap refusals come first. Nothing takes the writer lock until the key is
known to exist, and no client address is written to the database (devices.rs
rule).

1. **Per-network admission** for `/auth/machine-join`, in memory, with the
   nested networks of `SOURCE_CAPS` (/64, /56, /48; /32, /24), counted per
   minute. Unknown keys and refusals count; successful joins also count.
   The rejection is 429 with `Retry-After`.
2. **Shape**: the secret's format and checksum (Q10), the body size and the
   `join_machine` request's own `validate()`.
3. **Read-only lookup** of the key hash. An unknown hash is answered 401
   here, without a writer transaction. A flood of made-up keys then costs one
   indexed read each and never serialises behind the writer.
4. **Authorise in the writer transaction** (the existing `api_authorize_key_hash_tx`):
   not dead, before its hard end, not past its inactivity end (Q9), and
   holding `hosts:join`.
5. **The creator still holds the authority** to add machines and to assign
   these tags and this owner. Today only the owner may approve a join; EE
   roles will decide later. A creator who loses that authority, or is
   disabled, makes the key stop working (it is not revoked, so it can work
   again if the authority returns).
6. **Join settings**: uses left (Q4), mode allowed (Q5), every tag still
   exists (Q6), the assigned person still exists and is active.
7. **Per-key rate**: at most 10 joins in a burst, then 1 per 6 s
   (Q14).
8. **The host id is new**, or it is the retry of this key's own reserved
   receipt (Q12). A takeover follows Q13.
9. **Name**: the reported hostname, with D339's fallback and collision suffix.

The response does not say which check failed beyond four classes the CLI
needs for D303 exit codes: refused (bad, revoked, expired key, or no
permission), exhausted (no uses left), throttled, unavailable. The audit row
records the exact reason.

**#263 sign-in pools.** A key join creates no approval row and no passkey
ceremony. So it never takes a slot from `MAX_PENDING_APPROVALS` (1024), the
anonymous ceremony pool or the per-person pools (J174). A flood of key joins
therefore cannot lock the owner out of signing in or approving an `up`, and
a flood of approvals cannot block key joins. The per-network admission for
key joins is its own budget, separate from the approval budget. A
**reusable** key cannot be used as a cheap way to fill the host table: the
per-key rate, the use limit and the per-network budget bound it, and every
join is audited and shown in the list.

**Open question Q14: the rate limits.** Options for the per-key limit:
(a) 10 in a burst, then 1 every 6 s (600 an hour); (b) a setting on each
key; (c) none, only the per-network budget. For the per-network budget:
the approval caps (5 per /64 or address, 32 per /48 or /24) per minute.
**Recommendation: (a), and the per-network budget at 4× the approval caps
(20 per address, 128 per /24 or /48, per minute).** A CI autoscaler behind
one NAT legitimately starts tens of runners at once, which the approval caps
would refuse.

## 5. Audit

Every event is one row in a new `api_key_audit` table, kept 90 days like
`api_action_audit`. Reads stay aggregated in `api_read_audit`.

| Event | Recorded |
|---|---|
| created | key id, name, scopes, join settings, expiry, creator, how (Settings, CLI, MCP), the spent tap's id |
| join | key id, new host id, hostname as reported and as named, mode, tags applied, owner or shared, uses after, source network (Q15) |
| join refused | key id if known, reason, source network (Q15); counted per key, reason and minute, like reads, so a flood cannot push out real rows |
| revoked | key id, by whom, how |
| machines removed with key | key id, host ids, by whom |
| ephemeral removal | host id, key id, offline time |
| creator lost authority | key id (first refusal only) |

**Open question Q15: storing where a join came from.** The approval code
keeps client addresses in memory only and never writes them to the
database. But "a key used from many networks" (§9.4) can only be seen if
the network is recorded, and D235's connection log already records "from
where". Options: (a) store nothing; (b) store the enclosing /24 or /48 only;
(c) store the full address. **Recommendation: (b).** It answers "how many
networks" and "is this one of ours" without keeping individual addresses,
and it follows the 30-day connection-log retention, not 90 days.

**Open question Q16: tell the owner about joins.** Options: (a) nothing
beyond the list and the audit; (b) an Inbox item per key, batched to one
item per key every 10 minutes ("4 machines joined with ci runners"); (c) an
Inbox item only for the first join from a network the key has not used
before. **Recommendation: (b) plus (c) as the item's highlight.** It is
quiet for a fleet and loud for a leak.

## 6. Settings › Access › Keys

Described in words; the design grill and mockups come next (PROCESS §8).
Every key lives in this one list (D343). Signed-in browsers are a different
list (Settings › Account, #224), not keys.

**The list.** Each row: the key's name; its scopes as chips in plain words
("Read machines", "Change machines", "Join machines", "Open terminals"); for
a join key, its uses ("1 of 1", "12 of 20", "37 machines"); the last machine
that joined, as a host chip with a relative time; and the expiry ("in 23 h",
"Never", "Ended 2 days ago"). "Never" uses a small mark of its own, not a
coloured dot. Revoke is a row action. On a phone, a row has two lines (the
name and scopes, then use and expiry), and its actions open from the row.
Rows follow the shared Settings-row edges, with keys left and values right
(TASTE).

**Grouping and filters.** TASTE says "group automatically instead of
asking", and that one field filters instead of modes. D343 asks for chips in
the list, and the brief for filter chips.

**Open question Q17: filter chips or natural groups.** Options: (a) filter
chips above the list (All, Join, Sign-in, No expiry, Ended); (b) natural
groups in a fixed order (Join keys, then Sign-in keys, then Ended), and one
filter field that understands words like "join", "never" and a tag or
machine name, shown as chips inside the field; (c) both. **Recommendation:
(b).** It follows the TASTE rows already agreed and still gives one-tap
narrowing. Ended keys stay visible, collapsed, until their audit is purged.

**Opening a row** shows its facts as key/value rows: created by and when,
origin (this browser, the CLI on `mbp`, an AI agent), scopes, every join
setting in plain words, the networks it joined from (Q15), and the list of
machines that joined with it, as host chips. Below them are two destructive
rows (TASTE: "a destructive action is a row"):

- **Revoke key**: "No new machine can join with it. Machines that already
  joined stay." It runs inside the 15-minute admin window (D333) and asks in
  its own row.
- **Remove machines joined with this key (N)**: "Removes N machines and
  uninstalls their infraternal agent where they are online." Its
  confirmation lists the machines first, as the dry run does (D28), and marks
  any machine with an open terminal. It is offered on revoked keys too.

**Open question Q18: the tap rule for removing many machines.** D339 puts
removing one host in the browser under the 15-minute admin window. Removing
"all 40 machines from this key" is the same action 40 times. Options:
(a) the admin window is enough; (b) a fresh tap bound to the exact list of
hosts when the count is above a threshold (for example 5); (c) always a
fresh tap. **Recommendation: (a), with the dry-run list in the confirmation.**
D339 already chose the window for host removal, and the list makes the scope
visible.

**New key** opens a sheet, with one job (TASTE: no settings inside a flow):

1. Name.
2. What it can do: a short list of scopes as option rows. "Join new
   machines" reveals its settings under it: Reusable (off) and, when on, "At
   most N machines" (Q4); Assign to (Me / Shared, plus a person in EE, Q3);
   Tags (a chip field of existing tags); Install as (Service / User, Q5);
   Remove when offline (off, or after 10 min, 1 h, 24 h or 7 days, Q7).
3. Expires: 24 h by default, then the choices in §3.
4. One sentence that says the result, for example "One machine can join in
   the next 24 hours. It will be shared, tagged ci, and removed after 1 hour
   offline."
5. **Create key** asks for the passkey tap bound to these settings.

After the tap the sheet shows the secret once, which copies on press (TASTE:
"only real values copy", no copy button), and ready commands with the
server filled in and the key in a variable, never inline:

```
INFRATERNAL_SETUP_KEY=… infraternal up https://<server> --setup-key=env:INFRATERNAL_SETUP_KEY
```

Closing the sheet forgets the secret. The page never shows it again.

Every action is also in the palette (TASTE: "everything you can do is
findable in search"): "New key", "Revoke key ci runners", "Remove machines
joined with ci runners".

**Open question Q19: editing a key.** D333 lets someone widen a key with a
tap. Options: (a) keys never change, so you create a new one and revoke the
old; (b) narrowing (fewer uses, a sooner end, removing a scope) without a
tap, and widening with a bound tap. **Recommendation: (a) in the first
slices, (b) later if it is asked for.** It keeps one tap equal to one set of
settings for the key's whole life, and it keeps the audit simple.

## 7. CLI and MCP

One definition per action in the action registry, and thin adapters (D318).
Scopes for key management:

| Action | Scope | Notes |
|---|---|---|
| `keys.list` | `keys:read` (new) | no secrets; ids are hashes |
| `keys.revoke` | `keys:write` (new) | narrowing only, no tap (D333 lists only creating and widening) |
| `keys.create` | none: always a device-approval request (§3) | the key cannot create a key |
| `hosts.remove --joined-with <key>` | `hosts:write` | a dry run first and its review token (D28, #303) |
| `hosts.join` | `hosts:join` | the server side of `up --setup-key`; not an MCP tool |

CLI:

```
infraternal keys list [--join] [--json]
infraternal keys show <id|name>
infraternal keys create --name ci --join [--reusable [--max-uses 20]]
    [--expires 24h|7d|…|never] [--tag ci]… [--shared] [--mode system|user]
    [--ephemeral 1h] --output file:PATH
infraternal keys revoke <id|name> [--yes]
infraternal hosts remove --joined-with <id|name> [--dry-run] [--yes]
infraternal up <server> --setup-key=env:NAME|file:PATH|-
```

`keys create` prints the approval link, code and QR code, waits for the tap,
and writes the secret to the `--output` file with mode 0600. It never prints
the secret. `--output -` writes to stdout only when stdout is not a terminal,
for piping into a secret store.

MCP gets `keys_list`, `keys_revoke`, `keys_request` (answers "approval
needed" with a code and a link, the D339 shape) and the dry run of `hosts_remove`
with `joined_with`. A secret never travels through MCP (Q8). The AI agent
can wait on the request like it waits on a root install (D339).

**Open question Q20: new key-management scopes.** Options: (a) `keys:read`
and `keys:write` as above; (b) only `keys:read`, and revoking only in the
browser; (c) fold them into `status:read` and `hosts:write`.
**Recommendation: (a).** An AI agent that notices a leak should be able to
revoke at once. Revoking can only narrow access.

## 8. Migrations

On dev the migrations go up to 0040. #303 adds 0043–0048. 0041 and 0042 are
taken on `trust-285-a`, and `mesh-ssh-s1-j175` also uses 0041, so those two
already collide. This work lands after #303 and takes the next free numbers
at merge time. Every migration is additive; no shipped
migration is edited.

1. `api_keys`: `name`, `created_at`, `origin`, `never_expires` with
   `CHECK (never_expires = 0 OR hard_expires_at IS NULL)`, `last_used_at`.
   Existing rows: `origin = 'device'`, `never_expires = 0`, `created_at`
   NULL.
2. `api_key_join` (§2.2), keyed by the key's hash, `ON DELETE CASCADE`.
3. `remote_hosts`: `joined_with_key` (`ON DELETE SET NULL`),
   `ephemeral_after`, `shared` (Q3), plus an index on `joined_with_key` for
   the per-key machine list and bulk removal.
4. `approvals` rebuilt to add the `create_key` kind (§3).
5. `api_key_audit` (§5), plus the per-minute table for refused joins.
6. The grantable-scope list in code gains `hosts:join`, `keys:read` and
   `keys:write`. That is code, not SQL.

Each migration gets a test that runs it on a copy of a production-shaped
database (like `remote_migration_tests.rs`), checks that every old key still
authorises with its old scopes, and checks that the migration's own number
does not collide with the branch it merges into.

## 9. Existing keys

- They keep their scopes, name (`device`), inactivity end and the 24-hour
  end that #303 gives keys from before D333 (D337). This change touches none
  of that.
- They appear in the list under Sign-in keys, with "Created: before this list"
  where `created_at` is NULL.
- None gets `hosts:join`. None becomes "Never". Either change would widen a
  key, which needs a new key with its own tap (Q19).
- `api-list` gains fields; it removes none. A released CLI that parses
  `api-list` keeps working.

## 10. Threat model

### 10.1 A leaked join key

What the attacker can do: enrol machines they control, as many as the key's
uses and rate allow, until its end or its revocation. Each machine gets the
key's tags and owner, and therefore whatever the grants give those.

What stops them:

- Logins: a key-joined machine has machine identity only and no person
  links (D235). It cannot log in as anyone on another machine unless an
  administrator granted that machine identity.
- One-time and 24 h are the defaults (D342), so most leaked keys are already
  used or dead.
- Each join is audited with its network (Q15), shown in the list, and sent to
  the Inbox (Q16). Revoke plus "remove machines joined with this key" undoes
  it in two actions.
- Join keys hold no write scope (Q2).

What remains: network reach. The community default network policy allows
everything (D228), so a machine that joins can reach every mesh machine's
open ports, whatever its tags.

**Open question Q21: key-joined machines and the allow-all default.**
Options: (a) they get the same default as any machine; (b) they get only
what their tags' grants give, never the allow-all default; (c) a per-key
choice, "Can reach: everything / only what its tags allow", defaulting to
the second. **Recommendation: (c).** A leaked key then gives an attacker only
the access the key's tags were meant to have, and a home setup can still
choose "everything" with one tap at creation time.

A hostile hostname ("db-prod") gets D339's suffix and a "joined with key ci
runners" fact in its details card. The name alone never grants anything.

### 10.2 A leaked key with no expiry

The same as §10.1, but with no end in time: it works until it is revoked,
its creator loses the authority, or (Q9 b or c) it goes unused.

Mitigations: creating it takes a tap that names "Never"; the list marks it
and can show only those keys (Q17); the Inbox reminds about a no-expiry key
that has been unused for 90 days (Q9); the per-key rate and use limit still
apply; rotation means creating a new key and revoking the old one, and the
machines that joined stay.

### 10.3 Replay

- **The key itself** is a bearer secret. It is only accepted in the
  `Authorization` header over TLS, never in a URL, query, argv (D343) or log.
  Captured traffic is protected by TLS, as for every key.
- **A join request** replayed with the same host id gets the same receipt
  (Q12), and that receipt is bound to the machine key's digest. Without the
  machine's private key the replay gains nothing. A replay with a new host id
  is a new use, so it is bounded by the uses, the rate and the audit.
- **The creation tap** is bound to the settings digest, single use and lasts
  120 s (D336). It cannot be replayed to create a wider key, or a second key.
- **The receipt** lasts 10 minutes, works once and only with the exact
  machine key (as for approval joins today).

### 10.4 A key used from many networks

A reusable key for an autoscaling fleet legitimately joins from many cloud
networks. Using a key from many networks is therefore a signal, not proof of
a leak.

- The audit keeps the enclosing network of every join (Q15). The row's
  facts show "joined from N networks" and list them.
- The first join from a new network is highlighted in the Inbox item (Q16).
- The per-network and per-key limits bound a burst from anywhere.

**Open question Q22: limiting a key to certain networks.** Options: (a) no
network limit; (b) an optional "Only from" list of address ranges on each
key; (c) a limit to the first network the key was used from. **Recommendation:
(a) in the first slices, and (b) as a later slice if the owner wants it.**
It is cheap to add because the check sits next to the per-network admission,
but no decision asks for it, and a wrong range would break CI silently.

## 11. Slices

Estimates are for one job, without queue time. Each backend slice gets its
break-it review (PROCESS §9). Slices 2 to 5 touch auth and get the strictest
one.

| # | Slice | Depends on | Estimate |
|---|---|---|---|
| 0 | Owner answers Q1–Q22 | this note | — |
| 1 | Schema and scopes: migrations 1–3 and 5 of §8, `hosts:join`/`keys:*` grantable, `never_expires` semantics in `api_authorize`, `last_used_at`, `api-list` fields | #303 merged | 1 day |
| 2 | Creation with a bound tap: `TapAction::CreateKey`, settings digest, `create_key` approval kind (migration 4), Settings create endpoint, one-time reveal | 1 | 1.5 days |
| 3 | `/auth/machine-join`: checks §4.3, per-network and per-key limits, shared receipt issuance, tags in the same transaction, reserved one-time use (Q12), audit | 1, 2 | 2 days |
| 4 | `up --setup-key`: the three input forms, environment scrubbing, no terminal needed, `--json`, D303 exits; real root run in a throwaway clone and a join against the test server | 3 | 1 day |
| 5 | Ephemeral removal: one timer, restart grace, removal through the host-removal path, audit | 3 | 1 day |
| 6 | Revoke and "remove machines joined with this key": per-key host list, bulk dry run and removal, admin window | 3 | 1 day |
| 7 | Settings › Access › Keys UI: design grill and mockups, then list, groups or filters, create sheet, reveal, row facts, destructive rows, palette entries; production-build screenshots at phone and desktop sizes with alignment checks | 1, 2, 6 | 3 days plus design rounds |
| 8 | CLI `keys …` and MCP tools through the registry, `keys create --output` | 2, 6 | 1 day |
| 9 | Inbox items for joins and unused no-expiry keys (Q9, Q16) | 3 | 0.5 day |

Total: about 12 job-days, plus review rounds and design rounds. Slices 4,
5 and 6 can run in parallel after slice 3. Slice 7's design grill can start
as soon as the owner answers Q17 and Q18, while slices 1 to 3 are being built.

## 12. Performance

- A refused join with an unknown key costs one indexed read and an in-memory
  counter, and no writer transaction (§4.3).
- A successful join adds one writer transaction to what the approval join
  already does, and no extra round trip for the machine: one request
  replaces the start, the wait and the poll, so a key join is faster than
  an approval join by the whole human wait.
- Ephemeral cleanup costs zero idle wakeups (§2.4).
- Key-join latency (request to receipt) is measured on the perf VM in slice
  3, at 1, 50 and 500 concurrent joins, against the approval join's
  redemption.
