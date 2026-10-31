<!-- Frozen local shim protocol and additive restart-safe input negotiation [13][17][41]. -->
# Contract: session shim ↔ infraternal agent

Status: draft for #10. Implements DECISIONS 13 and 17.

This interface is **frozen** from v1. A new infraternal agent must be able to
talk to every shim that an older agent started, because a shim can live for
weeks across many agent upgrades. Changes are additive only (§7).

## 1. Role

A shim is one small process per terminal session. It owns:

- the PTY master and the child process (the user's shell),
- the terminal state (screen, cursor, modes, scrollback),
- an output ring buffer addressed by byte offset.

The agent owns everything else: auth, routing, many viewers, the network. When
the agent restarts or upgrades, every shim keeps its shell alive. The new agent
reattaches to the shims.

Why the shim holds the terminal state, not the agent: a resume snapshot must
show the exact screen. If you replay a byte ring buffer, this can only work
when the buffer goes back to the last full redraw. That point can be hours
ago for a full-screen program. tmux keeps the state in its server for the
same reason. The cost: the shim includes a VT parser. We accept this,
because a VT parser changes rarely and does not depend on our protocol.

## 2. Process model

- The shim is the same static binary, in the hidden mode `infraternal __shim`.
  A running shim keeps running the code it started with. New sessions start
  shims with the new code. Only §4 must stay compatible.
- **A shim must survive a restart of the agent service.**
  - systemd (rootful): the agent unit uses `KillMode=process`, and each shim
    runs in its own transient scope (`infraternal-session-<id>.scope`). A
    restart of the agent does not kill the shim.
  - systemd --user (rootless): the same, in the user manager.
  - Other init systems: double fork + `setsid`, and the shim reparents to
    PID 1.
  - The installer tests this: it restarts the agent with a canary session
    open, and the canary must survive (contracts/bootstrap.md).
- The shim drops privileges to the target user **before** it execs the
  shell. A rootful agent can start sessions as any user. A rootless agent can
  only start sessions as itself.

## 3. Rendezvous

- Socket: `$STATE/sessions/<session-id>.sock`. `$STATE` is
  `/run/infraternal` (rootful) or `$XDG_RUNTIME_DIR/infraternal` (rootless).
  The directory mode is 0700. The socket mode is 0600.
- On accept, the shim checks the peer with `SO_PEERCRED`. The peer uid must be
  the agent's uid (or root). Any other uid is refused.
- The shim accepts **one** agent connection at a time. A new connection
  replaces the old one (this handles an agent that crashes and does not
  close the connection). Fan-out to many viewers happens in the agent.
- When an agent starts, it lists `$STATE/sessions/*.sock`, connects to each
  socket, and reads `Hello`. A socket that refuses the connection is stale:
  the agent removes it.

## 4. Framing (v1, frozen)

The protocol is a byte stream over the Unix socket. Each frame:

```
u32 le  length of (type + payload)
u8      type
...     payload
```

The maximum frame length is 1 MiB. A larger frame is a protocol error: close
the connection. Integers are little-endian. `seq` is a u64 byte offset into
the PTY output stream since the session started.

| type | direction     | name       | payload |
|-----:|---------------|------------|---------|
| 0x01 | shim → agent  | `Hello`    | u16 version, u64 caps, 16-byte session id, u32 pid, u16 cols, u16 rows, u64 created_unix_ms, u64 head_seq, u64 ring_start_seq |
| 0x02 | agent → shim  | `Attach`   | u64 caps (what the agent understands) |
| 0x10 | agent → shim  | `Input`    | bytes to write to the PTY |
| 0x11 | shim → agent  | `Output`   | u64 seq, bytes |
| 0x12 | agent → shim  | `Resize`   | u16 cols, u16 rows, u16 px_w, u16 px_h |
| 0x13 | agent → shim  | `ReadFrom` | u64 seq. The shim sends `Output` from seq if seq ≥ ring_start_seq; otherwise it sends `Snapshot`. |
| 0x14 | agent → shim  | `SnapshotRequest` | (empty) |
| 0x15 | shim → agent  | `Snapshot` | u64 seq, bytes: VT sequences that repaint screen, scrollback tail, cursor and modes, valid at seq |
| 0x16 | agent → shim  | `Signal`   | u8 signal (allow-list: INT, TERM, HUP, KILL, WINCH) |
| 0x17 | agent → shim | `SequencedInput` | u64 input offset, bytes (cap bit 0) |
| 0x18 | shim → agent | `InputAck` | u64 exclusive written input offset (cap bit 0) |
| 0x19 | agent → shim | `InputStateRequest` | empty (cap bit 0) |
| 0x1A | shim → agent | `InputState` | u64 exclusive written offset, u64 exclusive accepted offset (cap bit 0) |
| 0x1B | agent → shim | `SelectWriter` | u32 nonzero writer identity (cap bit 1; see additive section) |
| 0x1C | shim → agent | `SnapshotWithFlags` | u64 seq, u8 flags, bytes VT (cap bit 2; see additive section) |
| 0x1D | agent → shim | `SelectSharedWriter` | u32 existing nonzero writer identity (cap bit 4; see additive section) |
| 0x20 | shim → agent  | `Exited`   | i32 status or −signal, u64 final_seq |
| 0x21 | agent → shim  | `ExitAck`  | (empty). Optional acknowledgement after `Exited`; closes this peer. |
| 0x7F | both          | `Error`    | u16 code, utf-8 message |

Rules:

- **Flow control.** The shim reads the PTY only while the agent keeps up. If
  the agent stops reading, the shim stops reading the PTY. The kernel then
  applies backpressure to the program, as a real terminal does. Output is
  never dropped while the agent is connected.
- **No agent connected.** The shim keeps reading the PTY, updates the
  terminal state, and appends to the ring (default 8 MiB, overwrites the
  oldest data). A program never blocks because no one is watching.
- **Exactly once.** The agent tracks the last seq that it forwarded. After a
  reconnect, it sends `ReadFrom(last_seq)`. Thus, no byte is lost or sent two
  times while the bytes are in the ring (DECISIONS 41: no lost bytes on
  resume).
- **Signal after exit.** An allowlisted signal after the PTY exits is a no-op;
  unsupported signals are still refused. This preserves ordered exit delivery
  when host uninstall races shell exit (#87).
- **Exit delivery and retirement (owner brief #151, round 2).** After PTY
  drain, unowned shims flush `Exited` to data viewers and retire promptly.
  An ownership-only connection (cap bit 3) retains the final output independently
  of an output link's 250 ms credit-starvation detach. Release ownership after
  ordered leg-B delivery or when the window closes. Ownership links cannot
  backpressure the PTY or select writers. All legacy layouts remain unchanged.
  Retention ends at 600 seconds from child exit even if an owner or output peer
  stalls. Before that forced retirement, write the frozen `Exited` frame as a
  mode-0600 `.ended` record in the private runtime sessions directory. An attach
  to the retired session returns ordered `terminal.exited` with status/final_seq
  with additive `retired: true`, followed by final Close 4404 (wire §4), without
  claiming a final repaint. Ordinary drained exits retain exact cursor equality;
  saved exits may have `final_seq` beyond the delivered cursor and never advance it.
  Runtime records survive infraternal agent restarts, not a host reboot; they
  contain no shell output. D178 still preserves detached *running* shells.

## 5. Budgets (from DECISIONS 41)

- Shim idle RSS < 4 MiB plus the scrollback (default 10 000 lines).
- `Input` → write to the PTY in < 0.2 ms p99 on the shim side.
- `Snapshot` of a 200×60 screen in < 2 ms.

## 6. Security

- The shim never parses data from the network. Its only peer is the local
  agent, after the `SO_PEERCRED` check.
- `unsafe` is allowed only in the PTY and syscall module of
  `infraternal-shim`. Each block has a `SAFETY:` comment, and a second
  reviewer audits it.
- The fuzz target `shim_frame_decode` covers the §4 decoder.

## 7. Evolution

- `version` stays 1. New features are bits in `caps`. A side sends a new
  frame type only if the peer announced the matching cap bit.
- An unknown frame type from a peer that announced no caps is a protocol
  error.
- Removing or changing a v1 frame is not allowed.

### Capability bit 0: SEQUENCED_INPUT (#20)

A supporting shim advertises bit 0 in Hello; Attach selects it. Frames
0x17–0x1A are valid only after selection. Existing v1 layouts stay unchanged.
With bit 0 selected, legacy Input is refused: mixing unsequenced bytes would
make the input cursors ambiguous. Caps-zero Attach retains legacy behaviour.

The shim owns exclusive accepted and written input cursors and its bounded
input queue (at most 1 MiB; a request exceeding available space disconnects
without accepting bytes). Check offset + byte length for u64 overflow before
mutation. Trim bytes below accepted, refuse gaps, and advance accepted only
when queueing the remaining suffix. Duplicate requests return the current
written acknowledgment without queueing again. Advance written only by actual
successful PTY writes. Ack may coalesce to the latest written offset; it needs
no unbounded queue. State requests return both cursors. On a selected writer's
data link, a state reply may subsume the standalone Ack. Its written cursor
remains authoritative acknowledgment progress even when requested only for
liveness; consumers must not discard it or acknowledge the accepted cursor.
Cursors and queued
input survive peer loss; reconnecting infraternal agents query state and replay
safely, including after a crash between input send and Ack. This guarantee
does not cover a shim or host crash. Caps-zero shims cannot give PTY-write
acknowledgments; the infraternal agent must expose that limitation.

### Approved leg-B terminal boundary (#20)

`terminal.open` input is `{ "uid": u32, "cols": u16, "rows": u16 }`;
output is `{ "session_id": "UUID" }`. Reject zero dimensions, more than
200,000 cells, and a different uid in rootless mode before launching a shim.
Exit is a wire Event on the terminal mux stream, sub_id 0, JSON
`{ "type": "terminal.exited", "session_id": "UUID", "status": i32,
"final_seq": u64 }` (saved runtime records add `"retired": true` as described
in §4). The embedded infraternal agent uses the inherited
socketpair for leg B; its trusted spawning server owns the channel. This
introduces no listener or mTLS bypass.

### Capability bit 1: MULTI_WRITER (#34; remaining #28 acceptance)

Bit 1 requires bit 0. A supporting shim advertises both in Hello; a new
infraternal agent selects both in Attach, then sends `SelectWriter` (0x1B,
exactly one little-endian u32 identity). Identity zero is reserved for legacy
bit-0 peers. Select a nonzero identity exactly once, before state, input or
resize requests. Existing v1 frame layouts and caps-zero behavior are unchanged.
The parser fuzz target also decodes this additive fixed-length frame.

Each selected writer has independent accepted/written offsets. A new device
starts at zero; reconnecting the same identity retains both cursors. The daemon
uses its monotonic server-assigned leg-B stream id, never an untrusted browser
identity. There are at most 32 simultaneous peers and 512 retained nonzero
writer identities per surviving shim, plus legacy identity zero. Refuse a new
identity at capacity without evicting existing cursors. Legacy identity zero
keeps replacement semantics; replacing the same nonzero identity disconnects
its former peer. A shim lacking bit 1 is refused for multi-device attachment;
it cannot safely impersonate independent writers.

All writers share the existing at-most-1-MiB input byte queue. Bounded ownership
segments associate each queued byte with its writer; actual partial PTY writes
advance only those owners' written offsets. Duplicate trimming and gap/overflow
refusal remain per writer. Output and its ring cursor remain shared. Slow
viewers recover from the ring or Snapshot without preventing a credited viewer
from receiving live output. Newly accepted input selects that peer's remembered
geometry [74]; duplicate input does not steal the active geometry.

### Capability bit 2: APPROXIMATE_SNAPSHOT (#26)

A supporting shim advertises bit 2 in Hello; Attach selects it. The additive
frame `0x1C SnapshotWithFlags` is shim → infraternal agent and contains
`u64 seq, u8 flags, bytes VT repaint`. Bit 0 of flags means approximate; all
other flag bits are reserved and must be zero. The type, sequence, flags and
VT payload together remain within the frozen 1 MiB frame limit. `Snapshot`
0x15 and every other v1 layout remain unchanged. Never send 0x1C unless bit 2
was selected; receiving it without selection is a protocol error.

Recovery sends `ReadFrom(last_forwarded_seq)` first. If that offset remains in
the ring, replay it exactly once, including after credit starvation; do not
replace retained bytes with a Snapshot. If the ring no longer covers it, try
the faithful bounded Snapshot. If it cannot be represented or fit, a selected
peer gets a bounded best-effort visible repaint with flags bit 0 set. It may
omit history, inactive screen, semantic content, hidden modes, links, parser
carry or cells beyond the bound. The sequence is the same captured head used
for the repaint, and subsequent raw output starts there. Approximation must
never be described as lossless. A Snapshot limitation never closes the live
session's relay stream.

Caps-zero/bit-0-only peers continue to receive Error(1) for capacity limits or
Error(2) for faithful restoration gaps, with an accurate UTF-8 reason. The
infraternal agent parks a legacy limited reconnect and reports availability;
credit or terminal input/resize can retry it without a spin loop or Close.
No approximation is sent to an unnegotiated peer.

On leg B, before forwarding an approximate repaint in the existing Snapshot
frame, send an ordered Event (sub_id 0):
`{"type":"terminal.snapshot","session_id":"UUID","seq":u64,"approximate":true}`.
This is additive JSON event data; the binary Snapshot layout is unchanged.
Count each actually forwarded approximate repaint in the process counter
`approximate_snapshots_total`; a pending repaint does not increment it twice.
Legacy rejection is reported as a `terminal.snapshot_unavailable` Event with
session identity and sequence, preserving the live mux stream.

### Capability bit 3: SESSION_OWNER (#151, round 2)

Hello advertises bit 3; an ownership-only Attach selects exactly bit 3.
This link has no writer or output cursor and accepts no PTY/input requests.
An `InputStateRequest` on this link receives `InputState(0,0)` solely as an
ownership-installation barrier; these zeroes are not writer cursors.
It remains open for one owning window across data-link replacements; socket
closure releases ownership. An infraternal agent only opens it when advertised.
Old shims retain their negotiated behavior. The maximum 32 peer sockets includes
ownership links. Only exited shims use the one-shot 600-second retention timer;
running idle shims have no timer. The hidden shim startup option may shorten
this bound for deterministic real-PTY tests, but cannot increase it.

### Capability bit 4: SHARED_WRITER (#129, D215)

Bit 4 requires bits 0 and 1. A supporting shim advertises all three; Attach
selects them before the fixed-length `SelectSharedWriter` (0x1D, little-endian
u32). Select exactly once before state, input or resize. Zero, an unknown
writer, an unselected capability and malformed payloads are refused without
changing another peer or allocating a new writer identity.

An ordinary peer and a shared peer may coexist for the same durable writer.
Their accepted/written cursors, input queue and duplicate trimming are shared;
output cursors and socket backpressure are independent. Replacement disconnects the
previous peer only within the same ordinary/shared mode. Ordinary `SelectWriter`
semantics, caps-zero behavior and the 32-peer/512-writer bounds remain unchanged.
Shared selection cannot change remembered geometry. Only newly accepted input
selects its remembered geometry; replayed input cannot steal it.

A parked shared peer queries the authoritative input state but does not request
output until `ReadFrom` or `SnapshotRequest`. If only parked shared peers remain,
the shim continues draining the PTY into its bounded terminal state and ring as
when detached. Such peers are input/Ack subscribers, and cannot alone impose
viewer backpressure. Ordinary peers retain the existing flow-control behavior.

The authenticated infraternal agent chooses the identity from the existing
server-assigned native writer binding. This capability grants no browser-selected
identity, new session authority or guarantee across a shim/host crash.

SHARED_WRITER also negotiates queue deferral for an ordinary native writer
selected with SelectWriter; it does not change ordinary replacement semantics.
A valid sequenced frame whose unseen suffix
cannot fit the shared input queue waits without changing accepted/written
cursors, geometry or ownership segments. Acceptance remains atomic. Each live
peer retains at most one complete bounded frame and at most one 16-KiB socket
read suffix; later frames remain ordered behind the deferred frame. The shim
stops reading that peer, continues PTY writes and other peer requests, and gives
the oldest deferred request priority over fresh input requiring queue space.
Duplicate input requires no space. Overlap is recalculated against the durable
writer cursor before acceptance.

Dropped deferred peers release their live-peer storage immediately. Only their
unaccepted data is discarded: accepted bytes remain in the surviving queue,
and the server retains input until a durable written Ack permits replay to
advance. Malformed ranges and invalid ordering remain refusals. Peers without
SHARED_WRITER retain their existing capacity-refusal behavior. The accepted
queue stays at most 1 MiB; deferred payload belongs to at most 32 live peers,
never to the 512 retained writer identities. Decoder allocation capacity and
per-peer read storage are additional to that accepted-byte bound.

Reserved queue space remains unavailable to fresh input from any peer. Ordinary
ReadFrom, InputStateRequest, Resize and duplicate input continue while another
peer waits. A legacy peer requesting new input against reserved capacity keeps
its existing refusal behavior. Completing a deferred request releases its FIFO
ticket; a trailing request that must wait receives a new ticket behind existing
waiters.

## Reply input extension [D307, #160]

Capability bit 5 (`QUERY_REPLIES`) permits additive frame `0x1E QueryReply`,
whose body is 1–1024 server-arbitrated reply bytes. It has no typing offset.
Existing v1 layouts and input cursors are unchanged. The infraternal agent
selects this capability only when advertised by the surviving shim; otherwise
it refuses marked replies rather than sending them as typing and emits the
once-per-attachment `terminal.query_replies_unavailable` notice (wire.md).

The shim admits replies to the existing bounded PTY queue under a reserved
internal writer (`u64::MAX`, outside the u32 peer-writer namespace). Queue segments retain
that ownership through partial PTY writes. Reply bytes never advance a
viewer's typing cursor, select the active writer or change terminal geometry.
The trusted server arbitrates identity, syntax and expiry before forwarding;
the shim validates capability and size before queue admission. Replies are
best effort and never replayed after link replacement.

### Explicit saved-shell close (D314, #251)

Capability bit 6 (`CLOSE_SESSION`, value 64) permits zero-payload `CloseSession`
(opcode `0x1F`). It is legal only after selecting that capability in Attach.
It requests SIGHUP of the shim-owned shell process group, including when a
foreground job has a different group. Existing Signal semantics stay unchanged.
An already reaped child is a no-op; the shim never signals a recycled PID.
The request has no acknowledgement: delivery is not proof of process exit.
Old shims must receive no such frame; callers report an upgrade/recreate fix.
