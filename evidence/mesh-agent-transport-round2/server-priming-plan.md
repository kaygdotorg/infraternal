<!-- Implementation ownership and invariants for server priming, D215/#129. -->
# Server native priming implementation plan

Goal: keep one authenticated native fallback and up to128 existing terminal writers ready, hedge retained input once after200ms without duplicate browser credit, and promote with authority recheck. Existing QUIC/TCP basic standby remains compatible.

Spec: owner-approved #129 proposal plus parent task messages; REMOTE_PRIMED_WRITERS bit5; Call0 transport.standby {"prime":true}; immediate client Hello; per-bound-terminal transport.cursor {"out_seq":u64}; control0 transport.activate {}.

Ownership: server remote_standby/remote_link/remote_accept/remote_runtime/embedded and dedicated new modules/tests here. Parent owns plugin API cap and agent/client/daemon/cursor. Shim/sessions are separately owned. Existing linked worktree mesh-agent-transport; scratch targets only round2. No engine/profile/budget changes, commit/push only after parent coordination; parent final fast gate.

- [ ] Real-mTLS failing test first: bounded primed request must return negotiated parking, consume client Hello without replacing generation, then activate without second greeting. Include legacy compatibility, malformed/duplicate JSON, revoke/expiry and refused secondary ownership.
- [ ] remote_standby: strict bounded standby options; RAII identity parking moves into RemoteLink for primed mode, old {} wait unchanged; authority checks cover parking/activation.
- [ ] remote_link/runtime: primed native marker and owned activation signal; only existing admitted same-uid host may prime, one secondary; admission waiter updates generation and attaches plugins after actor promotion, never awaiting plugin joins inside actor turn.
- [ ] embedded priming module: owned asynchronous handshake/zero-credit attachment setup for <=128 existing writer IDs; primary remains responsive. Cache first authoritative Ack per writer without acknowledging browser input. New writers after promotion remain ordinary. Shadow-only errors retire shadow only.
- [ ] Hedging: when active Input remains unacknowledged200ms, send per-writer cursor, bounded <=16KiB credit and existing retained suffix on ready shadow; no extra input payload retention. Dedup output against actor delivered cursor before consuming browser credit; process shadow Ack only after durable-state validation.
- [ ] Promotion: strict control activation, authority ledger recheck, transfer ready shadow to primary without reattach flights or duplicate Hello; handoff admission waiter; RAII owns cancellation/parking through queue admission and promotion.
- [ ] Targeted red/green transport+actor tests, strict touched clippy/fmt, real-PTY proof with parent/shim ownership; no benchmark/build overlap. Full final verification belongs to parent.
