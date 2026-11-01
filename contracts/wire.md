<!-- Multiplexed wire framing, resume cursors and bounded flow control [12][41][81]. -->
# Contract: wire protocol (leg A and leg B)

Status: draft for #10. Implements DECISIONS 10, 11, 12, 17, 41, 63 and 64. The
numbers come from the transport spike (#12, `spikes/transport/RESULTS.md`).

## 1. Transports

| leg | transport | stream multiplexing |
|-----|-----------|---------------------|
| A (browser ↔ server) | WebSocket (WSS, or WS behind a TLS-terminating reverse proxy) | our mux (§3) |
| B (server ↔ agent)   | QUIC (quinn, BBR), mTLS; TCP + TLS 1.3 mTLS fallback | QUIC: native streams. TCP: our mux. |

- Leg A is WebSocket only (DECISIONS 63). WebTransport only helped on lossy
  links (#12: burst p99 216 ms against 489 ms at 1% loss). It would cost a
  public certificate in the app, a UDP port for browsers and Safari risk.
  The codec and the mux do not depend on the transport, so WebTransport can
  come back later without changes to the frames.
- Ports (DECISIONS 64): leg B uses one server port (default 7443, UDP for
  QUIC and TCP for the fallback). Leg A uses the reverse proxy, or the same
  port with the server's own certificate when there is no proxy. Managed
  hosts open no inbound ports.
- Passkeys need a secure context, so leg A is always HTTPS for the browser.
  A reverse proxy can do the TLS.
- Head-of-line blocking on leg A is a known cost. Predictive local echo
  (in the SSH plugin) hides the round trip, and §6 catch-up keeps a stalled
  stream from replaying a flood.

## 2. Frame codec

One codec for all legs and transports. The spike chose it: decode ~4.6 ns in
Rust and ~290 ns in JS, against 35–2570 ns for prost (#12).

```
varint  len      length of (type + body), LEB128, max 4 MiB
u8      type
...     body
```

- Integers in bodies are little-endian, fixed width, unless the table says
  varint.
- Every `varint` is an unsigned 32-bit LEB128 value in shortest form; decoders
  reject non-canonical encodings. This applies to frame lengths, mux stream ids,
  and the lengths before UTF-8 strings. The frame-length limit is checked before
  buffering or allocating from the declared size.
- Examples: `80 00` is a redundant encoding of zero; `ff ff ff ff 10`
  overflows u32. Both are protocol errors, including at nested string sites.
- A decoder never allocates from a length before it checks the length
  against the limit. A frame over the limit is a protocol error. Close with
  code `FRAME_TOO_LARGE`.
- The fuzz target `wire_frame_decode` covers the decoder (DECISIONS 40).

## 3. Mux (leg A, and leg B over TCP)

On a transport that has no native streams, each frame is wrapped:

```
varint  stream_id
frame   (§2)
```

On leg A every stream is muxed. Stream 0 is the control stream. Odd ids are opened by the client, and even
ids by the server. On leg B over QUIC, the native stream gives the id, and frames
are not wrapped.

### 3.1 Embedded agent over a local socketpair (S1, issue #19)

The server starts its own infraternal agent as `<self> agent --fd 3` and passes
one endpoint of a Unix socketpair as descriptor 3. This is a local process
channel, not a network leg: the inherited socketpair is its trust boundary,
so it does not use mTLS. Both processes still exchange the v1 `Hello` frame
and use the shared codec. Because a Unix socketpair is a byte stream, frames
use the leg-B mux envelope: stream 0 is control, and the server opens even
terminal stream ids. The protocol remains transport independent.

On leg A, the server sends Hello first and then receives the client's Hello on
stream 0. A new client leaves caps bit 0 clear; the server sends a fresh
Welcome. A client resuming a connection sets caps bit 0 (`RESUME_NEXT`), sends
Resume immediately after Hello on stream 0, and receives a refreshed Welcome
only after the token is validated. No other Hello capability bit changes this
ordering. This removes ambiguity between a new connection and a resume request.

The core `terminal.open` action is a control-stream `Call` whose JSON input is
`{"cols":u16,"rows":u16,"px_w":u16,"px_h":u16}` and whose successful JSON
result is `{"session_id":"<32 lowercase hexadecimal characters>"}`. The
server records the returned session id for the authenticated user before it
returns the result to the browser. A terminal `AttachTerm` then names that
session on a server-opened even stream to the embedded infraternal agent.

The browser tracer also calls `ssh.session.open` with `{}` or an optional
`host_id`. Omission chooses the embedded host at 80x24; its result uses a
canonical hyphenated UUID. Explicit remote hosts are denied until the host
inventory path exists. The legacy core action and its result spelling above
remain available. Both actions enforce the authenticated user's ownership.

The trusted server adapts either action to the leg-B daemon request
`terminal.open` with `{ "uid": u32, "cols": u16, "rows": u16 }`: uid is the
server's effective uid, never browser supplied. The daemon returns a canonical
hyphenated UUID; the server accepts that or its legacy lowercase 32-hex spelling.
Pixel dimensions are carried by later Resize frames, not daemon-open input.

For private bootstrap proof (#169), leg B accepts optional `readiness: true`.
It selects a fixed non-login `/bin/sh` command that waits for a newline, prints
`infraternal-ready` and exits. No executable or shell text is accepted. Enrolled
uid checks and terminal.open plugin admission are unchanged; ordinary opens omit
the field and continue to use the target login shell. The private probe has a
10-second absolute shim lifetime. Bootstrap retains its session id before
attachment and finishes its fixed read through a separate writer on every exit,
waiting for terminal.exited or session-gone. Cancellation cleanup precedes SSH
service rollback. A lost transport still reaches the shim deadline; ordinary
user terminals acquire no deadline or cleanup behavior.

## 4. Frames

Ranges: `0x00–0x0F` connection, `0x10–0x2F` terminal hot path, `0x30–0x3F`
control (JSON bodies), `0xF0–0xFF` upgrade handshake (**frozen forever**,
leg B only, contracts/bootstrap.md §4).

| type | name | body | notes |
|-----:|------|------|-------|
| 0x00 | `Hello` | u16 version, u64 caps, varint+utf8 client info | first frame on stream 0, each side |
| 0x01 | `Welcome` | 16-byte connection id, 32-byte resume token, u32 resume window seconds | server → client |
| 0x02 | `Resume` | 16-byte connection id, 32-byte resume token | client → server, instead of a new session |
| 0x08 | `Ping` | u64 nonce, u64 sent_us | any side; the UI shows the latency |
| 0x09 | `Pong` | u64 nonce, u64 sent_us | |
| 0x0F | `Close` | u16 code, utf8 reason | |
| 0x10 | `Input` | u64 in_seq, bytes | keystrokes; in_seq = byte offset of the first byte |
| 0x11 | `Output` | u64 out_seq, bytes | PTY output; out_seq = shim byte offset (contracts/shim.md) |
| 0x12 | `Resize` | u16 cols, u16 rows, u16 px_w, u16 px_h | |
| 0x13 | `Ack` | u64 in_seq_acked | server → client: input that is now written to the PTY |
| 0x14 | `Credit` | u32 bytes | client → server: permission to send more output |
| 0x15 | `Snapshot` | u64 out_seq, bytes | screen repaint valid at out_seq |
| 0x16 | `AttachTerm` | 16-byte session id, u64 last_out_seq, u64 last_in_seq | opens or resumes a terminal stream |
| 0x17 | reply-marked `Input` | u64 query_seq, bytes (1–1024) | additive D307 extension; no typing cursor |
| 0x30 | `Call` | u32 call_id, varint+utf8 action id, JSON input | contracts/plugin.md §3 |
| 0x31 | `Result` | u32 call_id, u8 ok, JSON output or error | |
| 0x32 | `Subscribe` | u32 sub_id, JSON filter | events (contracts/plugin.md §5) |
| 0x33 | `Event` | u32 sub_id, JSON event | |

The core Mesh inventory uses `Subscribe` and `Event` on control stream 0 with
the additive JSON contract in contracts/mesh-api.md. It does not allocate new
frame IDs or change the frozen frame codec.

`Close` on stream 0 closes the connection. On a nonzero mux stream it retires
only that logical stream; code 1000 is a normal detach. This lets a socketpair
peer release one terminal attachment while keeping the user's session alive.
After any host/server terminal-stream close, the server discards already-in-flight
Input (including reply-marked Input), Credit and Resize until the viewer's own
Close or a replacement AttachTerm. Retirement metadata stays bounded by the
attachment limit; unknown streams still fail admission. A viewer sends Close
only after introducing that stream with AttachTerm, never for a local window
that left before attachment (#250).

Code 4404 on a terminal stream (reason `session ended`) is final: the session
no longer exists on its host, either because its shim is gone or because the
account never had it. The server and the infraternal agent send it in answer
to `AttachTerm`, never as a transport failure, and keep the connection and
every sibling stream up. Frames the viewer had already sent on that stream are
dropped until its own `Close`. A viewer that receives 4404 does not attach to
that session again. A verified saved exit may precede it on the same ordered
stream as `terminal.exited` with `status`, `final_seq` and optional `retired: true`
(shim §4). That status does not advance the viewer cursor or claim a final repaint;
the viewer presents it in its ended state. Every other stream close is transient and may be retried
(#158).

The embedded infraternal agent sends a complete `Event` on control stream 0
with `sub_id: 0` and `{"type":"terminal.sessions.snapshot","session_ids":[UUID...]}`
once after connect/reconnect discovery and thereafter only when its live-shim
set changes. New or adopted shims register process-exit readiness in one shared
kernel queue (Linux pidfd, macOS kqueue EVFILT_PROC/NOTE_EXIT); an exit, including
SIGKILL, removes the shim even without an attached terminal stream. Rendezvous
removal also triggers an identity check. Where pidfd_open is unavailable,
identity checks run only at connect/reconnect and open/close/exit events. There
is no periodic census or idle timer (D81). Census queue pressure is retried on
queue capacity, preserving the ordered open fence below. The server reconciles open
local `terminal_sessions` rows against each snapshot and closes rows whose shim
is absent; it never signals a shim to exit. On leg A, an authenticated browser
may `Subscribe` with `{"topic":"terminal.sessions"}`. The server sends an
account-filtered full snapshot as an `Event` on control stream 0 using that
subscription's `sub_id`, then pushes a new snapshot after every reconciliation
or persisted session change. `session_ids` contains only open persisted rows
whose shim is live. An optional `ended_sessions` array carries `{session_id,
status}` for at most the 128 most recently closed local rows with a saved exit
status. This bounded sidecar lets an already-open window stop retries as soon
as its row is retired while retaining the saved status; ended IDs never appear
in `session_ids`. Superseded unviewed status records are released on the device;
windows already opened there retain their ended state. The browser resubscribes after each Welcome and does not
expose cached local rows until the first snapshot arrives. Before a
complete census arrives, and whenever the agent link is lost, the server pushes
`{"topic":"terminal.sessions","type":"terminal.sessions.unavailable"}`.
This hides cached rows while the inventory is unverifiable and does not mark
them ended or close their database rows. After the agent reconnects, its next
complete snapshot restores surviving shims and reconciles stale rows.

Census Events and open Results share one ordered control lane on leg B. The
census containing a newly registered session must precede its successful open
Result; older censuses cannot overtake that Result. Reconciliation acquires the
database writer before copying the latest census, and leg-A inventory reads
acquire their database connection before copying it. This keeps a census that
waited for storage from retiring a row persisted after it was captured. A new
local browser record waits for its first positive census before absence can
retire it; cached rows receive no such protection. An explicit saved exit or
final Close remains conclusive even before that positive census, and no later
census may revive a finally closed ID.

Bodies of control frames are JSON. They are not on the hot path, and JSON
lets the HTTP API, CLI, MCP and the wire share one schema per action. Terminal
frames are binary, because they carry each keystroke and each output chunk.

## 5. Resume without lost or duplicated bytes (DECISIONS 41)

- Input and Output byte ranges must have an exclusive end representable as
  u64. Consumers check `seq + payload_length` before dispatch (`checked_add`
  in Rust, an explicit u64 maximum in TypeScript). The codec reads fields but
  does not perform sequence arithmetic. Snapshot repaint length never advances
  `out_seq`; it represents screen state valid at that sequence.
- **Output.** The client keeps `last_out_seq`. After a drop, it sends
  `Resume` and then `AttachTerm(last_out_seq)`. The server asks the agent,
  and the agent asks the shim with `ReadFrom`. The client gets the bytes
  from exactly `last_out_seq`, or a `Snapshot` if the ring has wrapped.
- **Replay fence.** For each leg-B attach, the agent captures the shim's
  `Hello.head_seq`. Replayed raw Output ends at that cursor; if an Output frame
  crosses it, the agent splits the frame and sends an ordered
  `terminal.replay_complete` Event before forwarding later live output. Its
  JSON is `{"type":"terminal.replay_complete","session_id":"UUID","out_seq":"u64 decimal","cols":80,"rows":24}`.
  `cols` and `rows` are additive optional u16 fields (1..65535, at most
  200,000 cells), present together on new producers. They describe the shim's
  screen geometry captured for this replay **before** the attaching viewer's
  own Resize is applied, not that viewer's requested size. A later attach
  captures the current geometry, including changes made by another viewer.
  Primed links refresh their capture when the delivered cursor starts replay,
  rather than reusing the size from their earlier priming handshake. Captured
  geometry stays fixed until that replay's completion, including credit pauses.
  Older producers omit both fields; clients then retain their existing
  silence/repaint behavior. Unknown JSON fields are ignored by older clients
  under D63. No binary frame layout or capability bit changes.
  Snapshot bytes are always silent. If a repaint advances beyond the current
  fence, the fence advances to that Snapshot's `out_seq` and the Event follows
  the repaint; otherwise the original fence remains until replay reaches it.
  The browser suppresses VT replies while restoring replayed output or any
  Snapshot, then allows replies from live output. The decimal string preserves
  the full u64 cursor.
- **Input.** The client keeps keystrokes that are not acknowledged. After a
  resume, it resends from the server's `in_seq_acked`. The server drops
  bytes below the offset that it already wrote. Thus, a keystroke is never
  lost and never typed two times.
- **Writer authority (#28).** Input ranges belong to a durable pair of
  authenticated connection id and odd client stream id, pinned to one owned
  session. Distinct devices can start at zero without sharing acknowledgements.
  SQLite retains each writer's full unsigned Ack. A monotonic, never-reused even
  leg-B stream id represents that writer across connection/supervision reconnects;
  output offsets still belong to the session. The backend must deduplicate by
  writer identity and return its authoritative Ack on AttachTerm before replay.
  A connection retains at most 32 writer identities, including detached streams.
  The current implementation preserves this identity only during connection
  resume. After the resume window, pending input needs a separate durable writer
  capability: blindly replaying it with a new writer can duplicate accepted input.
  This longer-drop contract gap remains recorded on #28. The merged daemon now
  selects independent shim writers (contracts/shim.md bit 1); real shared PTY
  tests cover independent Acks and full-range replay across daemon crashes.
- **Window.** A connection can resume for `resume window seconds` (default
  120). After that, the client opens a new connection and attaches by
  session id. The session itself lives in the shim, without a time limit.
- Target: < 300 ms from network return to a usable terminal (DECISIONS 41).

## 6. Flow control and catch-up

- The client grants output with `Credit` (initial value 1 MiB). The server
  stops forwarding output when the credit is used up. Thus, a slow phone
  never makes the server buffer without limit.
- **Catch-up by snapshot.** If a stream stays without credit for more than
  250 ms while new output arrives, the server stops forwarding bytes. When
  credit returns, it sends one `Snapshot`. The user sees the current screen
  at once, and does not wait for megabytes of a flood that scrolled away.
  (The full output stays in the scrollback in the shim.)
- **Snapshot credit.** A Snapshot is indivisible and bounded by the leg's
  frame limit (the shim leg permits at most 1 MiB including type and sequence).
  With positive usable credit, one Snapshot may exceed the remaining credit
  by at most its own payload length. Record the excess as repaint debt. Future
  Credit repays debt before permitting raw Output or another Snapshot. Snapshot
  byte length consumes credit but never advances `out_seq`; the supplied
  sequence identifies the screen state. Zero usable credit never sends a repaint.
- An unfunded repaint or raw suffix must detach from the shim after the same
  250 ms pending-output deadline. Partial debt repayments must not extend that
  deadline. While detached, the PTY progresses independently; after debt is
  repaid and usable credit returns, obtain a fresh Snapshot. Do not reconnect
  on partial repayments or run an idle catch-up timer.
- **Command isolation.** Each browser attachment has one cancellable Input/Resize
  FIFO bounded to eight requests and `MAX_FRAME_LEN + 128` wire bytes, counting
  the currently blocked request as well as queued requests. Admission never
  waits for durable input Ack. Output Credit bypasses this FIFO; Input and Resize
  keep their mutual order. When full, retire only that attachment with Close
  1013, absorb its trailing Input/Resize/Credit until Close or reattach, cancel
  its pending forwarding worker, and keep dispatching sibling/control frames.
  The viewer reattaches and replays unacknowledged Input using shim-owned
  accepted/written cursors (§5); a refused command never implies acceptance.
- The embedded actor retains unspent credit, subtracting accepted Output and
  Snapshot payload bytes. After a leg-B reconnect it sends AttachTerm and then
  restores only the remaining credit. Snapshot repaint bytes do not advance the
  output sequence.
- A full attachment output queue retires that attachment (Close 1013), allowing
  the browser to reconnect from its last consumed offset. It never waits for a
  stalled reader in the shared actor. Stream Close remains local even when its
  consumer has already dropped; control Close is echoed normally.
- Leg B uses QUIC flow control plus the same credit idea between the server
  and the agent.

## 7. Authentication

- WebSocket admission reserves the 16-per-user and 256-global permits at
  upgrade, including sockets without Hello. Hello/Resume and incomplete wire
  frames have five-second completion deadlines; writes are bounded at one
  second. After Hello, an empty receive buffer has no idle-read deadline.
  Active terminal routes use the bounded liveness probes in §9 [D265];
  these supersede the former zero-idle-probe rule. An unused host route has
  no probe timer. The former thirty-second idle-read deadline caused periodic
  disconnect/reconnect work.
  Axum reassembles RFC WebSocket fragments internally; unseen post-Hello
  fragments are bounded by the 4 MiB message/frame limit, admission permits,
  and live authority expiry/revocation, rather than an idle-read timer. A begun
  mux frame retains its five-second deadline across transport pings and select
  cancellation. Pre-Hello/Resume remains bounded even for unseen fragments.
  Disconnect releases permits. Revocation wakes idle sockets without polling;
  each dispatch checks current session authority and expiration.
- Leg A: the WebSocket upgrade carries the session cookie
  or a device API key. The server checks the key before it accepts `Hello`.
  Every `Call` is then authorized for each action (contracts/plugin.md §4).
- Leg B: mTLS. The agent pins the server CA, and the server checks the agent
  certificate against the host record. The channel is the server's
  signature: an agent accepts `Call` frames only on this channel
  (DECISIONS 9). Upgrade binaries also carry their own Ed25519 signature
  (contracts/bootstrap.md §4).

## 8. Versioning

`Hello.version` is 1. New features use `caps` bits. A side sends a new frame
type only if the peer announced the matching cap. Frames `0xF0–0xFF` never
change.

### Native leg-B parked fallback (#129, D215)

These capabilities apply only to the enrolled infraternal-agent/server channel,
independently of browser resume. Existing frame layouts remain frozen.
`REMOTE_STANDBY` is server Hello bit 4. The server advertises
`REMOTE_PRIMED_WRITERS` (bit 5) together with bit 4 and the existing native
writer-binding bit 1. Both peers negotiate bits 5 and 1; the client need not
advertise the server parking capability (bit 4). The existing mTLS,
certificate ledger, host identity and execution-uid checks apply before any
request. No request contains a caller-selected host or writer identity.

On a proven fallback control channel, `Call(0, "transport.standby", {})` parks
the connection without replacing the host actor. The supporting server returns
`Result(0, true, {})` and a cached Hello. Basic parking waits for the client's
Hello before normal admission; it owns no terminal relay or plugin worker.
There is at most one parked connection per host and 1,000 across the listener;
initial handshake permits are released after ledger admission. Revocation or
expiry retires the parked connection.

With native bit 5 negotiated, the same request may contain
`{"prime":true}`. The client sends its Hello immediately, permitting native
writer preparation while the active transport remains live. Later
`Call(0, "transport.activate", {})` activates this authenticated connection
without a new handshake or a second Hello. Activation rechecks ledger authority
and belongs to the existing host actor. Standby and activation JSON are exact
objects bounded to 64 bytes: duplicate/unknown fields, arrays and trailing
objects are refused. TCP and peers without bit 5 retain basic parking.

For each authenticated native writer binding, an ordered canonical
`Call(0, "transport.prime", {})` immediately before AttachTerm selects shared
shim-writer intent. This marker is permitted only after bit 5 negotiation; an
unmarked stream retains ordinary writer behavior even after control activation.
The shared writer first returns its authoritative InputAck and remains without
an output subscription. `Call(0, "transport.cursor", {"out_seq":u64})` starts
or changes that subscription; its exact object is bounded to 64 bytes and is
valid only on a marked stream. Cursor updates never reset input ownership.
Existing Credit, Input, Resize and Close frames retain their layouts.

Shared relays reuse the existing session/writer identity, durable shim input
cursors and bounded output credit. The actor retains unacknowledged input once;
replay trims acknowledged prefixes and never converts a path switch into a new
writer. Malformed requests retire their own stream. Owned supervisors and
preparation/write tasks are cancelled on link retirement, component down or
actor shutdown; the parked transport grants no additional session authority.

### Native leg-B encrypted path copies (#201, D215, D263)

`REMOTE_PATH_BACKUP` is additive Hello bit 6, advertised by native peers.
It permits bounded copies of existing encrypted QUIC datagrams to the retained
enrolled path while that same connection uses a plugin-proposed mesh path.
The client enables copies only after the authenticated server Hello announces
bit 6; the server enables a trusted peer lease only after the admitted client
Hello announces it. Legacy peers keep their previous behavior. Cached native
standby Hello also announces support. Frame layouts and protocol version remain
unchanged, and no capability replaces mTLS, ledger admission or writer binding.

The transport reuses its existing recent history, bounded to 64 datagrams and
64 KiB of ciphertext per peer. One clock belongs to each endpoint socket,
never a detached task. Ordinary mesh-to-enrolled copies each become eligible
10 ms after their original transmission; another entry's earlier deadline
must not copy younger entries early. Each endpoint receive poll permits at
most 32 copy send calls, shared across peers. A segmented send call can carry
multiple UDP datagrams. Due work beyond this budget remains pending for the
next poll. Successful copies are not scheduled again; socket backpressure
retains pending work within the same bounded history.

Returning to enrolled makes retained mesh originals eligible for bounded
recovery. A completed return consumes its original once, including when the
send budget is exhausted; a later route change must not re-arm completed
returns. Pending returns retain their backpressure deadlines. Withdrawing
bit 6 cancels negotiated copies while preserving pending legacy enrolled
recovery. Retiring a peer lease cancels its remaining work; retiring the last
lease releases the clock and cache.

#### Bounded dual reply (#201)

The additive clarification proposed on #201 is implemented in the remote
plugin; release acceptance remains pending on that issue. It changes no frame
layout, version, capability bit or authority.

For negotiated bit 6 peers, an enrolled primary reply remains immediate.
The same encrypted datagram may additionally be sent to the admitted mesh
alternative without changing that primary route. This alternative is eligible
immediately, rather than adding a second 10 ms delay; ordinary mesh-to-enrolled
copies retain their individual 10 ms deadlines. Both kinds of copy share the
existing bounded history, endpoint clock and 32-send budget, within the same
64-datagram / 64-KiB limits. Redundant alternative admission must not evict or
displace pending enrolled-return work; backpressure must not discard that
recovery work.

Unknown mesh coordinates remain dormant. A withdrawn capability cancels
negotiated alternatives while preserving pending legacy enrolled returns.
Component removal or lease retirement cancels its alternative work, and a
retired lease must never select a replacement socket. Alternative replies
create no new connection, stream, writer or admission authority.

Receivers deliver every datagram to QUIC for authentication and packet-number
deduplication. A bounded ciphertext-suffix cache filters recent duplicate
routing hints, including differently batched GRO input. A suffix collision
keeps a route hint rather than admitting or dropping data. A duplicate mesh
original received after its enrolled copy must not promote the primary route;
the alternative reply does not change this rule. The mesh liveness
probe requires that physical path's own session-authenticated response.
Authenticated enrolled copies and unrelated mesh UDP cannot jointly prove mesh health.

#### Session-bound physical path proof (#201)

`REMOTE_PATH_PROOF` is additive native Hello bit 7. Both regular and parked
native greetings advertise it. A client keeps an enrolled path in place until
the server advertises support; the server allocates responder state only after
admitting a client that advertises the bit. Withdrawal retires mesh selection.

The native UDP socket accepts a fixed 45-byte probe envelope alongside QUIC:
`0x80 "ip1"`, direction byte (`0` request, `1` response), big-endian `u64`
sequence and a 32-byte HMAC-SHA256 tag over the preceding 13 bytes. In QUIC
long-header interpretation, prefix plus direction selects unsupported versions
`0x69703100` or `0x69703101`; valid negotiated QUIC packets cannot share it. The existing
QUIC session exports 32 key bytes with label `EXPORTER-infraternal-path-v1`
and empty context. Exporter bytes are cleared after native key import.
This adds no terminal frame, protocol version, connection, writer or authority.

A server responder is registered only for an admitted live QUIC connection.
Its key lease is independent of mesh routing leases, so enrolled proofs keep
working after mesh disable. Alternative tuples resolve only through admitted
peer leases. Replies use the actual receiving socket and local address, never
a replacement socket or a UDP-learned arbitrary destination. Connection/key
retirement removes the responder; an older lease cannot erase its replacement.
Up to four admitted connection keys may share an exact UDP tuple during queued
replacement; cancelling any one removes only that key. The registry retains at
most 10,000 exact tuples, matching native host admission's existing bound.

A client accepts only the outstanding sequence, response direction, valid MAC
and exact probed physical source tuple. Each new challenge advances the socket's
sequence; retransmission preserves both sequence and first successful-send
clock. Replies cannot answer another direction or session, and an accepted
reply cannot refresh health twice. Backup copying never copies these probes.
Datagram aggregation preserves each independent envelope. Unknown formats,
wrong lengths and invalid authentication do not advance health.

The response allowance follows this physical path's authenticated smoothed RTT
and variation, with its configured scheduling margin and measured local timer
lateness. A single-tuple connection reuses ordinary adaptive QUIC health;
connection-wide counters are insufficient when distinct tuples are normalized.
Probe work is owned by the selected path's existing future and stops when it
is cancelled. Older peers that cannot answer keep enrolled service rather than
satisfying a mesh proof with ambiguous connection-wide progress.

## 9. Route liveness (D265, #199)

Use the existing `Ping`/`Pong` layouts in both directions. With active terminal
routes the server probes the browser control stream, the shared infraternal
daemon control stream and each attached terminal stream. Terminal-stream Pong
on leg B follows the selected shim writer's existing `InputStateRequest` fence;
a daemon control reply alone never establishes session readiness. One shim
fence may be in flight per data link and is discarded when that link is parked.

A selected writer's state fence can also carry written-input progress
(shim contract, capability bit 0). Forward newly advanced progress through the
existing terminal Ack before its correlated Pong, including when output is
parked. Unchanged fences remain Pong-only: they do not add repeated Ack frames
or storage work. Merely accepted input is never acknowledged as written.

Local send-queue pressure alone never retires a connection or terminal for a
liveness probe (#234). Skip a scheduled Ping before issuing its correlation
when the bounded FIFO has no room; skipping never starts or renews a reply
deadline. A best-effort Pong or terminal-command Ping may likewise be omitted
at capacity. Outstanding correlated replies retain the timeout below. Reliable
control replies defer their producers until bounded FIFO capacity returns,
preserving ordering, including the census-before-open-result fence. Actual
transport errors and closed writers still retire their connections.

When both peers advertise Hello caps bit 2 (`VIEWER_VISIBILITY`), the viewer
may send a control-stream
`Event` with `sub_id = 0` and at most 128 JSON bytes:
`{"topic":"connection.visibility","hidden":true}` (or `false`). This is a
transport notice, not a subscription or plugin action. A hidden page may be
suspended indefinitely: pause browser probes and discard outstanding probe
correlations, retaining the socket, terminal streams and writers. Authentication
expiry, revocation and resource bounds still apply. When visible, restart the
unknown-RTT lease without reusing probe IDs; old replies cannot train its RTT.
If the transport ended during suspension, wait until visible before reconnecting.
The notice cannot preserve a socket when the operating system closes it; use the
ordinary resume window, then a fresh attach if that capability is refused (#244).

Probe replies echo nonce and timestamp. Only a new correlated reply renews a
route deadline; ordinary traffic, unsolicited replies and stale sockets do not.
Startup, pending input and recent link doubt keep browser probes pipelined
with bounded state. A healthy idle browser may keep one probe in flight and
pace its next sample from the correlated answer. Waiting or issuing a request
never renews an outstanding deadline. Detecting a broken direction does not
first wait for another full request/response cycle. The initial RTT is
unknown and retains the bounded two-second startup grace. Correlated replies
initialize `srtt = RTT`, `rttvar = RTT / 2`; subsequent samples update
`rttvar = 3/4 × rttvar + 1/4 × abs(srtt − RTT)` before
`srtt = 7/8 × srtt + 1/8 × RTT` ([RFC 6298 §2](https://www.rfc-editor.org/rfc/rfc6298.html#section-2) estimator).
The browser response allowance follows the host formula below (#244). A proven
foreground browser route doubts its first miss and retires after two consecutive
allowances without a correlated reply; startup still has a two-second grace.
Host routes (the primary host link and its terminal streams) carry ordered
replies that one lost packet holds back for about one more round trip, so
their allowance is `clamp(2 × srtt + 4 × rttvar + 75 ms, 250 ms, 2 s)` [D300].
On the primary host link a first miss only marks the route doubtful: the
link, its streams and writers stay. Each settled stream of a viewer that set
browser Hello caps bit 1 (`LINK_DOUBT_NOTICES`) receives
`{"type":"terminal.link_doubt","session_id":"UUID"}`. The viewer shows that
the link may be reconnecting and changes nothing else: live output is not
replay, so it keeps answering terminal queries and sending input, and the
server keeps its Ack checks strict. A correlated reply within a second
allowance clears the doubt; the same streams then receive
`terminal.link_recovered`, which clears only that indicator and is never a
replay fence. A doubt belongs to its link: once the link is retired or
replaced, the streams receive `terminal.reconnecting` and only the
replacement's own `terminal.replay_complete` confirms them. Viewers without
bit 1 receive neither notice. A stream whose queue was full when doubt began
is told on a later tick of the same episode. The link is retired only after
the second consecutive allowance passes without a reply. A link that has never
answered retires at its startup grace. A link whose doubt recovered while its
allowance sat at the 2 s ceiling raises no further doubt (its delay is the
path, not a loss) until a reply brings the allowance below the ceiling; it
still retires after two allowances. Viewers ignore terminal notice types they
do not know.
The floor tolerates a 150 ms scheduler/main-thread stall on a healthy low-RTT
route, rather than confusing local load with peer loss. A settled quiet link
therefore doubts silence at that floor; browser and primary host links retire
after two allowances, plus at most one probe interval (26 ms). Above the floor
they follow measured RTT and jitter. This extends the
owner-approved #199 scheduling exception to D265's approximate one-RTT detection;
reusable/fresh connection recovery budgets remain D265/D267. Renewed monitoring
on a replacement route relearns both estimates; jitter decays with healthy
replies. Liveness traffic must not drive the latency pill or terminal painter
at the probe frequency. Initial unpainted windows remain connecting; previously
confirmed windows are monitored continuously through reconnect and replay.

The server's sampled browser-control route may likewise keep one probe in
flight. Its idle fallback gap remains 26 ms; the response allowance begins
when a probe is actually issued, including after a late local callback.
An already-ready control reply
may carry the next eligible probe in the same write, retaining separate frame
boundaries. Application progress may briefly retain the faster cadence;
content-free proofs cannot keep that activity window alive. An answered route
has no response deadline until another probe is actually issued. Restarting
monitoring on the same socket must not reuse an earlier probe identifier.

A stalled session attachment is rebound on the server while retaining its
browser stream and durable writer. It retains acknowledged and unacknowledged
input; ordinary retirement still closes only that terminal stream. A stalled
browser route becomes disconnected before the
client requests WebSocket closure: an intermediary need not deliver a close
event. Replacement sockets ignore all late events from the retired route. A
shared daemon link is replaced independently of graceful child reaping; session
shims remain alive. Before automatic rebinding, each retained stream receives
`{"type":"terminal.reconnecting","session_id":"UUID"}` on its Event channel.
The window stops advertising readiness and holds input in its existing bounded
queue; the replacement's painted `terminal.replay_complete` fence confirms
readiness and releases that input on the same writer. Individual terminal
rebinding uses Close/Attach on leg B with the existing offsets and unspent credit;
a shared-link replacement already replays its retained attachments. Neither
path requires another client attach round trip. None of these paths ends a
session or bypasses authority
expiry/revocation. An existing local session does not require the CA to be
unlocked; connection readiness follows painted, session-bound replay rather
than inventory membership.

The client's first WebSocket message contains Hello and, when resuming, its
adjacent Resume. Resume capabilities never enter URLs or HTTP headers. Measure
reused/resumed paths against RTT + 50 ms, and fresh TCP/TLS/upgrade paths against
4 × RTT + 50 ms (D267), through real TLS on the pinned VM. Preserve the last screen and
keep input typed during recovery. Logs, screenshots and measurements belong on
the issue [D262].

## 9. Desktop video extension [D104,D200,D208,D232; #146]

Leg A advertises `DESKTOP_VIDEO` (caps bit 4) before desktop messages. Leg B
advertises the desktop native lane on bit 8; bits 0–7 remain reserved for core
transport capabilities (writer binding, renewal, server paths, standby,
priming, path backup and path proof). The extension
is additive; v1, terminal framing and frozen upgrade messages are unchanged.
Leg A remains WebSocket; the two QUIC delivery candidates apply to leg B.
Neither delivery mode has a default: opening selects it explicitly for measurement.

| type | name | body (little endian) |
| ---: | --- | --- |
| 0x40 | AttachDesktop | 16-byte session UUID, u8 delivery (0 reliable, 1 datagram) |
| 0x41 | Video | u64 sequence, u64 capture_ns, u8 keyframe (0/1), Annex-B access unit |
| 0x42 | VideoSize | u16 width, u16 height, u16 density_milli |
| 0x43 | VideoInput | u8 input kind, binary fields below |
| 0x44 | VideoRepair | u64 last_sequence |
| 0x45 | VideoFragment | 16-byte session UUID, u64 sequence, u64 capture_ns, u8 keyframe, u32 total, u32 offset, fragment bytes |

Video sequence starts at 1 and never decreases within a session. `capture_ns`
is the Mac host's monotonic capture-request clock, converted to nanoseconds;
it is not the server clock. Cross-machine latency measurements must record
clock-offset estimation and uncertainty; subtracting unrelated clocks is invalid.
Keyframes include SPS/PPS and IDR. Access units are nonempty and at most
4 MiB minus 42 bytes, reserving room for the fragment header inside §2.
Size is even, 2–4096 per side, at most 4 megapixels, density 1000–4000.

Input coordinates are unsigned millionths of the current output frame (including letterbox bands),
0–1,000,000 inclusive; the host maps to its verified geometry. Modifiers use
helper-contract bits 0–3. Mouse (kind 0): u32 x, u32 y, u8 button (0–2),
u8 state (0–2), u8 modifiers. Scroll (kind 1): u32 x, u32 y, i32 dx,
i32 dy, u8 modifiers. Key (kind 2): u16 keycode (0–127), u8 down (0/1),
u8 modifiers. Release (kind 3) has no additional fields and releases held
remote inputs in order on the reliable control lane. Text (kind 4): u32 Unicode
scalar, at least U+0020, excluding U+007F–U+009F, surrogates and values above
U+10FFFF. Printable keyboard input uses the source layout text; shortcuts
retain physical key codes and release the key selected at keydown. Control
(kind 5): u8 active (exactly 0/1), originated only by server control-lease
transitions; browser-origin control visibility messages are refused. Taking
control shows the native indicator before input, and retirement hides it.
The native helper remains
the authority on D208's local input
pause. Input is never replayed after a connection drop. Only one authorized
viewer controls a session; taking control is an explicit handover.

The server holds the session independently of viewers and checks live grants
for view and control. At most five viewers attach. It retains the latest IDR
and one pending access unit, sharing immutable bytes between viewers. A new
viewer receives the cached IDR immediately, requests a fresh IDR and waits for
it before consuming current deltas. Replaying a stale IDR followed by a current
P-frame is forbidden. A viewer that misses a sequence discards deltas until IDR.

Reliable mode has one pending frame at the sender and a bounded in-flight
write. A stale pending frame is dropped; its dependent deltas are discarded
until IDR. Once any bytes of a reliable frame are written it must be completed
or its dedicated video stream reset: partial-frame cancellation cannot splice
the next frame into it. Control and input use an independently driven reliable
control direction; they are never queued behind video writes.

Datagrams contain one complete §2 VideoFragment frame without mux. Fragment
payload is exactly 1024 bytes except the final tail; offsets are multiples of
1024. Each encoded fragment also fits the negotiated QUIC datagram size.
All offsets are validated before allocation. A receiver binds the UUID to the
already authorized session and retains one bounded assembly. A newer sequence
or a 250 ms active assembly deadline drops an incomplete frame and coalesces
VideoRepair on the reliable control stream. Duplicate identical fragments are
idempotent; conflicting fragments and metadata are errors. Idle
receivers have no repair timer. A skipped delta forces IDR recovery; an IDR
supersedes prior incomplete frames. No unbounded retransmission backlog.

Path selection consumes the same measured relay/direct observations as terminals.
The server session and grant authority remain stable across path changes.
This production base lacks terminal direct transport/signalling; the desktop
relay and path interface must not advertise working direct delivery until that
integration exists. The canvas view is outside this slice and needs an approved
mockup before product UI work.

## Account canvas layout [178,180,183,245,248] (#243)

The `canvas` server plugin uses control stream 0 only. Account identity always
comes from the authenticated socket, never from JSON. Disabling the plugin
withdraws its subscriptions and cancels its workers. It needs an existing server.

`Subscribe {"topic":"canvas.layout"}` sends
`{"type":"canvas.layout.snapshot","revision":N,"initialized":true|false,"document":DOC}`
then ordered `{"type":"canvas.layout.operation","revision":N,"op_id":ID,"intent":INTENT,"noop":false}`
events, using the requested subscription ID. When `noop:true`, advance the
revision without applying the intent; a reconnect snapshot need not carry
historical close tombstones. DOC is exactly the v1
`infraternal.canvas` document (`apps/tracer/src/canvas/model/document.ts`), with
its revision set to N. Cameras, focus, terminal content and credentials are
excluded. Reconnect resubscribes and receives a fresh canonical snapshot.
A reader overtaken by compaction gets another snapshot rather than a partial
history. Apply Results and events may interleave; deduplicate by revision.
An error/withdrawal event, a skipped revision, or a receipt ahead of the client's
canonical head requires a replacement snapshot. Repeat Subscribe with the same
subscription ID so its generation replaces the existing bounded server slot.
Coalesce recovery retries with positive, capped backoff and stop when history
catches up or a valid snapshot arrives. Pending intents retain their original
operation IDs and input across resubscription (#250).

`Call canvas.layout.apply` input is `{op_id,base_revision,intent}`. IDs are
nonempty strings of at most 200 UTF-16 code units; op_id is unique per account
across both actions. Reusing it with different input returns an error. An exact
retry returns its original `{revision}` even after log compaction. Future base
revisions fail; stale revisions are reduced against current state. Each accepted
intent (including a no-op against a closed window) consumes one revision.
Server commit order decides edits of the same field; unrelated window fields
survive. No client clocks are consulted. Stable window IDs cannot be reused
after close. Close removes every membership and permanently beats move/resize.

INTENT is one of (optional fields may be omitted):

- `{type:"view.add",view:VIEW}`: add an empty v1 view (tiled or graph). An existing
  ID of the same kind/layout type is a no-op, preserving its metadata and contents.
- `{type:"view.update",view_id,cell?:{x,y},name?}`: update only supplied view metadata.
- `{type:"target",window_id,target:TARGET}`: change the reference in every membership;
  newly referenced sessions must belong to the account, exactly as for open. A closed
  window stays closed.
- `{type:"view.remove",view_id}`: remove a view; its windows stay in other views.
- `{type:"open",view_id,column_id,window:WINDOW,after?:WINDOW_ID}`: add a v1
  window reference; create a missing column at the end with weight 1.
- `{type:"split",view_id,anchor_id,axis:"right"|"down",column_id,window:WINDOW}`:
  divide the anchor's occupied bands (D212), preserving neighbours above and
  below. Right halves an existing span or adds a half-weight column; down
  inserts a shared row band. New IDs are client chosen.
  This action never opens a terminal: first obtain a session reference using
  the existing terminal action. Retry that action separately as its contract allows.
- `{type:"close",window_id}`: close all memberships without ending the session.
- `{type:"move",view_id,window_id,column_id,after?:WINDOW_ID}`: move the existing
  membership; a missing destination column is appended. A missing neighbour
  means append (including a neighbour concurrently closed); null/omitted means
  prepend. No array indexes are accepted.
- `{type:"resize",window_id,height?,span?,rows?,row?}`: update only supplied
  non-null sizing fields in every membership. Null means omitted, preserving the
  existing value (or its absence), on both server and browser. Canonical document
  sizing fields are always numbers when present; they never contain null.
- `{type:"weight",view_id,column_id,weight}`: set one column's relative weight.
- `{type:"membership.add",view_id,column_id,window_id,after?:WINDOW_ID}`:
  reference an existing window in another view, preserving its stable ID.
- `{type:"membership.remove",view_id,window_id}`: remove only this membership.
- `{type:"pin",view_id,node_id,position?:{x,y}}`: set a graph pin; omit position
  to unpin. Graph references reveal no host configuration.

Open, move and membership.add may include `column_after: COLUMN_ID | null`.
It affects only a missing destination column: null inserts at the beginning, a
known ID inserts after that column, and an omitted or missing ID appends. Existing
columns retain their position. This lets a drag create a column at either edge
without publishing array indexes.

Session targets must name a terminal session owned by this account (including
ended sessions); references confer no host or session access. Duplicate window
IDs in a view and differing targets for the same ID are rejected. Documents
and intents reject unknown fields. Bounds: 64 views, 64 columns per view, 256
window memberships total, 256 graph pins per view, 200 UTF-16 code units per string;
cell coordinates ±1000, graph coordinates ±100000, column weights 0.1–10,
height 0.05–10000, span/rows 1–64, row 0–64. Snapshot documents are at most
48 KiB; apply inputs at most 8 KiB. Log checkpoints occur every 128 revisions,
retaining only the latest checkpoint and at most 127 following operations.
Durable receipts and closed IDs are limited to 65536 each per account; reaching
a limit refuses new writes without losing existing idempotence or tombstones.

`Call canvas.layout.initialize {op_id,document:DOC}` is the sole whole-document
exception: a one-time migration from old local storage, never a save method.
The first transaction initializes the account's head. A later import adds only
windows whose target identity is absent from every canonical view. Session
identity is host plus session ID (stable host IDs take precedence when both
references carry one); Settings uses its section, and logs/containers use host.
Names and other presentation metadata do not create a new target. New windows
keep their relative column order, weights and heights, appended to the existing
same-kind tiled view. A new tiled view is created only when it has new windows;
window-less views and existing graph pins are never imported again. An import
that adds nothing returns the current revision without a layout event.

Historical `Recovered: <name>` views are folded by the same rule only when an
existing view has that base name and kind. Their removal is committed as a normal
snapshot revision on load or the next write, so all devices converge. Unrelated
user-named views are preserved. When repair and an accepted edit commit together,
their normal revision steps may share the final snapshot boundary; no operation
tail crosses the replacement of historical window IDs. Repair does not rewrite
documents in a migration.
Migration 0030 backfills a transactional receipt counter so quota admission stays
constant in the number of historical receipts, including no-op imports.

The result is `{revision}`. Retrying the same op_id is idempotent, including a
no-op import; the receipt quota counts calls rather than layout revisions. If
bounds or ownership checks fail the transaction rolls back and the browser must
keep its local document for a later retry/export. Initialization and repair events
use a canonical snapshot, since imported IDs are assigned by the server. The
client keeps its original local document until success, then treats it only as a
drawing cache.
Errors are Result `ok:false` with `{"error":"invalid canvas operation"}`;
no account existence or foreign ownership detail is exposed.

## Reply-marked Input [D307, #160, #206]

Hello capability bit 3 (`TERMINAL_QUERY_REPLIES`) advertises the v1 reply
extension. A browser sends 0x17 only to a server advertising it; legacy 0x10
Input is unchanged and always means ordinary input. The TypeScript Input model
adds optional `replyTo`; Rust names the distinct layout `InputReply`.

`query_seq` identifies the opening ESC byte in the session's absolute Output
cursor. It is not a typing offset. Replies consume no typing credit or cursor,
are not replayed by browsers, and are never reclassified as typing. The server
timestamps output ranges before delivering them, accepts the first renderer response
within one second of the opening ESC, and drops duplicate, unknown, expired or
empty or oversized responses with content-free diagnostics. This window
covers more than three default 300 ms round trips and bounds stale responses,
including queries split across output frames. A new query has a new identity,
even when its bytes match an older query. Query state survives viewer reconnect.

The renderer is authoritative about which output produces a response. Neither
side matches request kinds or response contents. Generic control boundaries
split browser renderer writes so identities survive different viewers' paint/credit
chunking, including multiple requests in one transport frame. They classify no
request kinds and retain no control contents. A string interrupted by another
ESC sequence uses the newer opening ESC identity. The server parses no terminal
grammar: the timestamp of the output byte identified by `query_seq` determines
the deadline, even when the request completes in a later output frame. Replay
and fan-out never renew that timestamp.

Only output creates timestamped ranges (at most 64 per session); accepted replies
create bounded claims (at most 64 live positions per session, 4,096 sessions).
Unknown marked input creates neither. Evicting the oldest output range refuses
replies to its positions. A full claim table refuses new replies until expiry;
it never evicts a live claim and thereby reopens an accepted position. Styling
controls consume no claims, so they cannot displace a pending query.
Replies take a separate bounded lane to the shim so discarded replies cannot
leave gaps in keyboard input cursors or select the answering viewer's geometry.
On the browser leg, replies retain their wire order relative to Input/Resize
through both forwarding queues. Each attachment reserves up to 64 reply slots
of at most 1,024 bytes each, separately from the existing eight keyboard slots
and wire-byte budget. Full or expired reply admission drops only the reply;
it never retires the writer. The shared host dispatcher likewise reserves
64 reply slots separately from its eight Input/Resize slots, while preserving
one FIFO and the existing accumulated-Credit barriers. Output Credit still
bypasses the browser FIFO.

A surviving pre-extension shim cannot accept reply bytes without changing typing
cursors or geometry. On the first marked reply to such a session the infraternal
agent sends `terminal.query_replies_unavailable` with its `session_id`; the
server validates and forwards it only in response to marked input, so an old
browser never receives this new notice. The browser says to open a new shell.
Ordinary legacy Input remains available. No session is automatically ended.

### Layout session incarnation (#250, D312)

Hello capability bit 4 (`16`) requests an additive Welcome suffix: a length-prefixed
43-byte base64url `session_incarnation`. The label is opaque and non-secret; it is
stable only for the authenticated browser session, including reconnects and server
restarts. Authenticated HTTP session responses include the same label so the tab
binds its store before its first WebSocket handshake. It is separate from both
bearer and resume credentials. Keep it in RAM;
never put it in logs, URLs or browser storage.

Every `canvas.layout.apply` and `canvas.layout.initialize` request carries
`session_incarnation` beside its existing fields. Before receipt lookup or mutation,
the server compares it with the calling session. Missing or mismatched labels receive
`ok=false`, `{"error":"layout session changed","reason":"layout_session_changed"}`.
This refusal does not reveal another account or session. On Welcome, a tab drops its
old queue without sending if the incarnation changed; it reports lost edits with the
existing not-saved notice. Account-only binding is insufficient because signing out
and signing back into the same account revokes the original lifetime too.
