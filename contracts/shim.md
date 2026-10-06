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
| 0x20 | shim → agent  | `Exited`   | i32 status or −signal, u64 final_seq |
| 0x21 | agent → shim  | `ExitAck`  | (empty). The shim deletes its socket and exits. |
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
- **Exit is kept.** The shim keeps `Exited` until it gets `ExitAck`, so an
  agent restart cannot lose the exit status.

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
