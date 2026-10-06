<!-- Records the concrete #20 interface proposal; this is not a shipped contract. -->
# Shim input crash safety proposal (#20)

The infraternal agent lane cannot implement the job's PTY-write acknowledgment
and exactly-once input across its own restart with the frozen shim v1 fields.
This proposal is recorded on #20. Shared implementation is outside this lane's
ownership and awaits authorization or a change from the shim lane.

## Failure evidence

`crates/infraternal-shim/src/session.rs::handle` accepts v1 Input into a bounded
queue, then attempts a PTY write. Neither that write nor subsequent partial
writes generate an acknowledgment. Hello reports output offsets only.

Consider a crash after the infraternal agent sends input but before it answers
the server. On reconnect, these cases are indistinguishable on v1:

1. The shim wrote the bytes to the PTY. Replaying them types twice.
2. The shim never received the bytes. Discarding them loses input.

A local file storing an offset does not fix this: neither the PTY write nor
socket acceptance can be committed atomically with that file. A socket write
also cannot justify a wire Ack, whose contract means **written to the PTY**.

## Additive negotiated messages

Reserve shim capability bit 0 (`SEQUENCED_INPUT`). Keep every v1 frame and its
layout unchanged. A supporting shim advertises it in Hello; the infraternal
agent selects it in Attach. These new frames are accepted only after selection:

| Type | Direction | Payload | Meaning |
|---|---|---|---|
| `0x17` | infraternal agent → shim | u64 input offset, bytes | Sequenced input |
| `0x18` | shim → infraternal agent | u64 exclusive written offset | PTY-write acknowledgment |
| `0x19` | infraternal agent → shim | empty | Query input state |
| `0x1A` | shim → infraternal agent | u64 exclusive written offset, u64 exclusive accepted offset | Surviving input cursors |

The shim owns both cursors and its existing bounded input queue. It checks
`seq + len` for overflow, trims bytes below its accepted offset, refuses gaps,
and advances the accepted offset only when queueing bytes. It advances the
written offset by the actual successful PTY write length. Duplicate requests
return the current acknowledgment and never requeue bytes. Querying state on
reattach distinguishes already-written input from input still queued.

An acknowledgment can be coalesced to the latest written offset; no unbounded
acknowledgment queue is necessary. The shim retains cursors after peer loss.
An infraternal agent restart, including a crash between sending input and
receiving its Ack, can replay safely because deduplication happens in the
surviving shim. This does not promise PTY persistence after a shim or host crash.

Caps-zero shims remain compatible with their frozen v1 messages. They cannot
provide the stronger input guarantee; the infraternal agent must expose that
limitation rather than invent a PTY-write Ack.

## Other leg-B details proposed on #20

- `terminal.open` input: `{ "uid": u32, "cols": u16, "rows": u16 }`;
  output: `{ "session_id": "UUID" }`. Reject zero dimensions, more than
  200,000 cells, and a different uid in rootless mode before launching a shim.
- Terminal exit uses the existing wire Event on the terminal mux stream, with
  `sub_id = 0` and JSON `{ "type": "terminal.exited", "session_id": "UUID",
  "status": i32, "final_seq": u64 }`. There is no wire Exited frame today.
- The initial leg-B transport is the inherited socketpair; no network listener
  or mTLS bypass is introduced. The spawning trusted server owns that channel.

## Current lane status

The current lane implements the offset/credit state, safe inherited-socket IO,
secure shim rendezvous discovery and scope/detached launch helpers. Eleven
checks exercise those pieces, including a real shim with an isolated login
profile, exact output offsets after disconnect/discovery, and resize.

The CLI is still a stub. No daemon relay loop or in-memory session registry is
wired yet. In particular, the state-machine starvation test does not establish
a production flood catch-up path, and helper reconnection does not establish
an infraternal agent process restart. The requested daemon RSS, input p99 and
throughput measurements remain outstanding. Do not treat a green fast gate or
these helper checks as completion of the tracer bullet.
