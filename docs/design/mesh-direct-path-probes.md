# Direct-path RTT probes (#220, J1194)

**Status:** implemented on `j1194-direct-rtt-probes` · **Rules:** D185, D313 Q5, D81

The mesh chose between a direct path and a relay without measuring the direct one: a pair was
relayed only when its handshake did not follow the endpoint (`relay_path::direct_failed`), and
once relayed it never looked at the direct path again. A direct path that works but is slow was
never compared with a faster relay, and a direct path that opened later was never returned to.
The path rule (`infraternal_mesh::path_choice`) already knew `Path::Direct`; it lacked samples.

## What it does

- **Probes from the WireGuard port.** A probe leaves through a clone of the engine's own bound
  send socket, so it uses the NAT mapping the pair's data uses. Its answer comes back to the
  engine's receive socket and is consumed by the receive guard (`handshake_admission`) before
  GotaTun sees it. No GotaTun change is needed.
- **Wire.** 12 bytes: kind (`0xF2` ping, `0xF3` pong), three zero bytes, a big-endian 64-bit
  token. WireGuard message types are 1 to 4, so a probe is never ciphertext. A pong is the same
  size as its ping, so a probe cannot amplify.
- **Who answers.** Only a ping whose source is a known endpoint of an installed peer is answered
  (configured or confirmed, the guard's existing list), at most 64 pongs a second. A stranger
  gets silence, as `WireGuard` itself gives. An answer counts only from the endpoint the ping
  went to and with the ping's token.
- **No idle wakeups (D81).** Nothing runs on a schedule. The path owner asks for the next round
  (`want_round_in`); the receive task, which runs for every inbound batch anyway, compares one
  atomic with the clock, and only for a batch that carries a data packet longer than a keepalive
  (keepalives and rekey handshakes do not count). When a round is due it wakes the owner once.
  The only timer is the 2 s loss timeout of a probe that is in flight.
- **Rate.** One round a second while a decision is open, one every 5 s once every window is
  sustained and steady. A sample that leaves the margin around the median reopens the decision at
  the fast rate at once. A peer that never answered (an older node, a path that never opened) is
  pinged every 5 s and never judged slow: lost probes count only after a first answer.
- **The rule is unchanged.** `max(5 ms, 15 %)` margin, a sustained window of 5 samples spanning
  3 s, at most one move per 10 s, direct wins inside the margin. The direct path is one more
  candidate in the same comparison as the relays.
- **Standby relays.** A pair on the direct path requests relay links only when some relay's own
  QUIC round trip (free, no probe) plus the margin is below the newest direct round trip. A relay
  path is at least as long as this node's leg, so otherwise the direct path cannot lose and the
  links would cost relay state for nothing.
- **Moving.** To a relay: the existing publish (endpoint to the shim, session kept). Back to
  direct: the engine endpoint returns to the peer's own endpoint through the same endpoint-only
  update, and the route budget is re-derived. While the ends disagree for a moment, a pair on the
  direct path answers a peer that already moved to a relay on its best standby link, so nothing is
  black-holed.

## Measured

`scripts/mesh-direct-path-proof.py` with the `relay_fixture` example, on dev-02 (aarch64 build
host, debug build, not perf evidence), in `unshare -Urnm` namespaces with `tc netem` delays by
destination. Two nodes and two relays on one bridge; the phases alternate "direct fast" (direct
20 ms, relay 80 ms) and "relay fast" (direct 80 ms, relay 20 ms), 40 s each, three cycles, one
echo every 0.2 s as traffic, both ends sampled each second. The same fixture with
`RELAY_FIXTURE_NO_DIRECT_PROBES=1` is the behaviour before this change.

| | with probes | before |
|---|---|---|
| phases on the faster path after settling | 6 of 6 | relay-fast phase never moves |
| decision latency per transition (both ends on the better path) | 9, 9, 12, 13, 12 s | never |
| wrong-choice samples after settling | 0 of 370 | 80 of 80 in the relay-fast phase |
| switches | one per transition, no flapping | none |
| direct probes sent in a 30 s idle window after the traffic stopped | 0 | 0 |

The latency is the steady probe interval (a change is seen within 5 s) plus a fresh five-sample
window of the unchanged rule (about 5 s). A 2 s steady interval would save about 3 s at one more
12-byte ping every 2 s per busy pair; the rule's own numbers are not touched. A simulation of the
pair state (40 seeds, 15 % jitter) agrees: a 80 ms direct path loses to a 20 ms relay within
6 s of samples and the reverse never moves; a relay only 10 % faster than the direct path moves
a pair off direct about 1.3 times an hour under 10 % jitter, which is the rule's documented
behaviour (J1105).

Not done (follow-ups): the macOS engine's socket factory does not install probes yet (such a
node never answers and is never judged slow, so it only misses the feature); `RelayPaths` is
still driven only by the relay fixture, so wiring `watch_direct` into the production agent loop is
the step that turns the measured choice on for real nodes.

## Where the code is

| Piece | File |
|---|---|
| wire, answers, rate and wake | `crates/plugins/mesh/src/direct_probe.rs` |
| receive-guard hook | `crates/plugins/mesh/src/handshake_admission.rs` |
| probes of the bound port | `crates/plugins/mesh/src/gotatun_node.rs` |
| direct candidate in the pair rule, standby relays | `crates/plugins/mesh/src/relay_path.rs` |
| netns + `tc netem` proof | `scripts/mesh-direct-path-proof.py` with the `relay_fixture` example |
