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
| 0x30 | `Call` | u32 call_id, varint+utf8 action id, JSON input | contracts/plugin.md §3 |
| 0x31 | `Result` | u32 call_id, u8 ok, JSON output or error | |
| 0x32 | `Subscribe` | u32 sub_id, JSON filter | events (contracts/plugin.md §5) |
| 0x33 | `Event` | u32 sub_id, JSON event | |

`Close` on stream 0 closes the connection. On a nonzero mux stream it retires
only that logical stream; code 1000 is a normal detach. This lets a socketpair
peer release one terminal attachment while keeping the user's session alive.

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
- **Command isolation.** Each terminal command queue is bounded (eight slots
  in the embedded infraternal agent). When full, retire only that attachment
  with Close, cancel its shim link, and keep dispatching sibling/control frames.
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
  frames have five-second completion deadlines; transport reads have a
  thirty-second liveness deadline and writes are bounded at one second.
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
