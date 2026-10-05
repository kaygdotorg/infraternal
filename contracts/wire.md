# Contract: wire protocol (leg A and leg B)

Status: draft for #10. Implements DECISIONS 10, 11, 12, 17 and 41. The
numbers come from the transport spike (#12, `spikes/transport/RESULTS.md`).

## 1. Transports

| leg | first choice | fallback | stream multiplexing |
|-----|-------------|----------|---------------------|
| A (browser ↔ server) | WebTransport (HTTP/3) | WebSocket (WSS) | WT: one QUIC stream per logical stream. WS: our mux (§3). |
| B (server ↔ agent)   | QUIC (quinn, BBR), mTLS | TCP + TLS 1.3, mTLS | QUIC: native streams. TCP: our mux. |

- With 1% loss, the spike measured WT burst p99 at 216 ms and WS at 489 ms
  (TCP head-of-line blocking). Native QUIC streams also keep a flood in one
  terminal from delaying keystrokes in another.
- Auto mode on leg A: try WT. If the connection or the first stream does not
  open in 5 s, use WS. Remember the result for each origin for 24 h. (Safari
  26.4 has a bidi-stream report; see #12.)
- **WT and passkeys need a secure context.** The page must be served over
  HTTPS with a certificate that the browser trusts. The `serverCertificateHashes`
  pin is only a dev convenience. The TLS story is an S1 grill item.

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
- A decoder never allocates from a length before it checks the length
  against the limit. A frame over the limit is a protocol error. Close with
  code `FRAME_TOO_LARGE`.
- The fuzz target `wire_frame_decode` covers the decoder (DECISIONS 40).

## 3. Mux (only on WS and TCP)

On a transport that has no native streams, each frame is wrapped:

```
varint  stream_id
frame   (§2)
```

Stream 0 is the control stream. Odd ids are opened by the client, and even
ids by the server. On WT and QUIC, the native stream gives the id, and frames
are not wrapped.

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

Bodies of control frames are JSON. They are not on the hot path, and JSON
lets the HTTP API, CLI, MCP and the wire share one schema per action. Terminal
frames are binary, because they carry each keystroke and each output chunk.

## 5. Resume without lost or duplicated bytes (DECISIONS 41)

- **Output.** The client keeps `last_out_seq`. After a drop, it sends
  `Resume` and then `AttachTerm(last_out_seq)`. The server asks the agent,
  and the agent asks the shim with `ReadFrom`. The client gets the bytes
  from exactly `last_out_seq`, or a `Snapshot` if the ring has wrapped.
- **Input.** The client keeps keystrokes that are not acknowledged. After a
  resume, it resends from the server's `in_seq_acked`. The server drops
  bytes below the offset that it already wrote. Thus, a keystroke is never
  lost and never typed two times.
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
- Leg B uses QUIC flow control plus the same credit idea between the server
  and the agent.

## 7. Authentication

- Leg A: the HTTP upgrade (WS) or the CONNECT (WT) carries the session cookie
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
