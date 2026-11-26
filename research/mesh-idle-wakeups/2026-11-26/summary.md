# Mesh idle wakeups after connect, and offline peers (#260, J1253)

Follow-up to J1234 (`../../many-peer-hub/2026-11-25/summary.md`, fix 6 and the offline-peer note). Harness:
`../harness/` (J1234's hub test ported to current dev, J1234's peer simulator, and `idle.py`, which prints wakeups,
datagrams and timer events per window). The hub is the production `Node` in a network namespace; no default route,
nothing in the host namespace.

- Base: origin/dev `3f5f9bb30` (GotaTun pin `a0be34f8`), hub binary built at `aa543f503` (dev plus research files).
- Head: `4d5b26f80` (GotaTun pin `0853f42b`, fork branch `j1253-idle-timers-v2`).
- Attribution: dev-02 (aarch64), `perf record -e sched:sched_waking` and the engine's timer trace events
  (`attribution/`, `variants/`).
- Before/after: infraternal-perf-01 (x86_64), a `perf-run --root` hold of 66 minutes and a 9-minute repeat hold,
  steal 0 (`perf/`, `perf/machine-state/`). Binaries sha256: base `719c1ffa…`, head `e736bbb2…`, peersim `6443b331…`.

## Where the wakeups come from

| J1234 saw | Cause (measured) |
|---|---|
| 26/s (1,000) and 65/s (4,096) from ~30 s after sessions come up | The hub's own 25 s persistent keepalive to every connected peer: 4,096 / 25 = 164 datagrams/s, and 0.4-0.5 wakeups per datagram. It does not stop (480 s run: 24-83/s throughout), apart from a re-handshake wave every 180 s, when a session with only keepalives expires (peaks of 150-350/s on dev-02). |
| "Quiet from ~55 s after the last traffic" | Not quiet: traffic synchronises every peer's keepalive timer, so the keepalives leave in one burst per 25 s with silence between. J1234's third after-load window fell between two bursts. `afterload` windows alternate between 0 and 40-190/s. |
| 305/s in the 20 s after applying 4,096 offline peers with endpoints | Handshake retries: every 5 s per peer for 90 s (18 initiations each), then the engine gives up and goes quiet. |
| (not in J1234) offline peers with candidate addresses | The node's candidate walk spawned one waiting task (5 s deadline) per peer per step: 650-2,600 wakeups/s for 45 s at 4,096 peers with two candidates. |
| Settled 0.35-0.5/s | The Linux worker's 15 s endpoint-scan fallback, and the 30 s route inventory recheck. The Mac worker scanned every 250 ms (found by reading the code; no Mac run). |
| Session expiry, cookie rotation | Not material: slot expiry shows up only as the re-handshake wave above; no cookie events. |

**What a wakeup is made of.** In the three recordings made while datagrams were leaving (two connected, one offline),
82-94% of wakeups are the UDP socket's write-space event
(`attribution/wake-sources.txt`): each sent datagram is freed (`sock_wfree`), and because tokio registers the mesh
socket for `EPOLLOUT` as well as `EPOLLIN`, that wakes the parked worker, which finds nothing to do. The timer task's
own deadline wake is 0.5-6%. So wakeups follow datagrams sent, not timers fired.

## What was changed

1. Engine: handshake retries to a peer that only keepalives wait for back off 5, 10, 20 s (6 initiations instead of
   18 before the same 90 s give-up). Data waiting for the peer, or a forced handshake, restores the 5 s retry. The 20 s
   cap stays under the 30 s a connection tracker keeps an unanswered UDP mapping.
2. Engine and node: candidate-walk and readdress handshakes go out in one `rehandshake_all()` call, without waiting.
3. Engine and node (Linux and macOS): a confirmed-endpoint change signal replaces the 15 s (Linux) and 250 ms (macOS)
   scan timers.

The 25 s persistent keepalive is unchanged.

## Measured and rejected: coalescing the keepalive timers

A one-second (and five-second) grid for persistent keepalives, and batching one timer pass's sends (through the
buffered writer, or straight to the socket with `sendmmsg`), were built and measured on one binary with switches (fork
branch `j1253-wake-experiments`; 4,096 connected peers, 60 s each, dev-02, one run per variant):

| Variant | wakeups/s |
|---|---|
| neither (as dev) | 64 |
| grid 1 s | 75 |
| batched | 76 |
| grid 1 s + batched | 80 |
| batched to the socket | 74 |
| grid 1 s + batched to the socket | 82 |
| grid 5 s + batched to the socket | 72 |

None helps (the spread is run-to-run noise or slightly worse), for the reason above, so neither is in the pin. The
first perf-VM hold with the grid and batching in the engine agreed: 113/s against 83/s at 4,096 connected peers. The
engine already has one timer queue for all peers (J1111); there was no second wheel to merge.

## Before and after (perf VM, means over the whole window)

Wakeups are voluntary context switches per second over every thread of the hub. "sent" counts UDP datagrams the hub
sent. Offline runs last 180 s from the snapshot apply (90 s attempts, then 90 s settled).

| Scenario | Peers | wakeups/s base | head | CPU % base | head | sent base | head |
|---|---|---|---|---|---|---|---|
| offline | 1,000 | 34.2 | 13.3 | 0.78 | 0.28 | 16,607 | 5,702 |
| offline | 4,096 | 172.8 | 57.2 | 3.37 | 1.12 | 72,023 | 23,382 |
| offline, 2 candidates | 1,000 | 132.3 | 31.3 | 1.72 | 1.12 | 17,000 | 12,726 |
| offline, 2 candidates | 4,096 | 697.8 | 162.7 | 13.71 | 11.37 | 74,993 | 58,220 |
| offline, settled (t >= 120 s) | 1,000 | 0.57 | 0.22 | | | 0 | 0 |
| offline, settled (t >= 120 s) | 4,096 | 0.53 | 0.03 | | | 0 | 0 |
| connected, silent (200 s) | 1,000 | 21.0 | 19.6 | 0.14 | 0.13 | 8,497 | 8,497 |
| connected, silent (200 s) | 4,096 | 78.7 | 88.5 | 0.87 | 0.84 | 40,848 | 40,843 |
| realistic peers (150 s) | 1,000 | 34.9 | 31.8 | 0.09 | 0.08 | 4,041 | 4,043 |
| realistic peers (150 s) | 4,096 | 86.5 | 87.8 | 0.28 | 0.26 | 20,011 | 23,560 |
| after traffic (90 s) | 1,000 | 22.7 | 19.1 | 0.06 | 0.07 | 4,000 | 4,000 |
| after traffic (90 s) | 4,096 | 54.8 | 55.3 | 0.27 | 0.19 | 16,384 | 16,384 |
| peers send 25 s keepalives (90 s) | 1,000 | 23.1 | 22.9 | 0.12 | 0.12 | 823 | 856 |
| peers send 25 s keepalives (90 s) | 4,096 | 39.7 | 40.3 | 0.36 | 0.30 | 7,676 | 7,582 |

Highest 10 s window: offline 4,096 364 -> 310/s (the first window, before the back-off starts); with candidates
2,584 -> 821/s.

- **Offline peers:** 61-77% fewer wakeups over the 180 s, and nothing sent on either build from t = 100 s.
  From t = 120 s the head's mesh threads did not wake once at 4,096 peers; what is left (0.03/s) is the 30 s route
  inventory recheck's own thread (`mesh-route-repair`, #489). At 1,000 peers the head's mesh threads woke 11 times in
  those 60 s (source not traced; a 200-peer recording on dev-02, `attribution/windows-offline-200-settled.jsonl`, had
  none). The base's mesh threads woke 27-32 times in the same window (it still has the 15 s scan; not traced either).
- **Connected peers: not fixed, and slightly higher at 4,096.** The datagrams are the same; the head woke more in all
  three paired runs of the silent-connected cell (first 100 s: 71.4 against 66.9, then 73.3 against 65.6 and 72.3
  against 67.8; +7 to +12%; CPU equal or lower). Not seen at 1,000 peers, after traffic, or with peer keepalives. The
  cause is not isolated: no timer or datagram differs, and 82-94% of these events are per-datagram write-space wakeups,
  whose count depends on whether the other worker has parked again.
- **Candidate walks still cost CPU** (11-14% for 45 s at 4,096): each step installs addresses one device write at a
  time (not changed here).

## Pins

- Fork: `retries_to_an_offline_peer_back_off_and_stop`, `queued_data_ends_the_back_off` (mock clock),
  `offline_peers_leave_no_timer_deadline_after_giving_up` (200 peers, real clock), and the confirmed-signal and
  `rehandshake_all` tests.
- Node: `an_idle_node_with_offline_peers_never_wakes` (200 peers, real engine and worker, 0 wakeups in 16 s after the
  give-up; with a 15 s timer put back into the worker it fails with 3 wakeups). It does not include the route-repair
  thread.

## Follow-ups

1. **Drop the write-space wakeups** (orchestrator to schedule): register the Linux mesh socket for readability only and
   wait for writability only after `EWOULDBLOCK`. About 200 lines in the fork; a data-path change, so it needs a
   throughput and p99 benchmark. Expected: most of the remaining idle wakeups at every peer count (82-94% of events).
2. Install a walk step's addresses in one device write.
3. `SourceWatch` in the handshake admission guard now only duplicates the engine's change signal; removing it takes work
   off the receive path (security-sensitive file, own review).
4. Other mesh unit tests still configure documentation-range endpoints on real engines in the host namespace; only the
   two touched here were moved to loopback.

## Limits

- Peers are simulated (boringtun) behind a veth; write-space wakeups per datagram will differ on a real NIC, where
  transmit completions can be batched.
- One run per cell on the perf VM (the connected 4,096 cell has two repeats, `perf/repeat-*`); variants on dev-02 ran once
  each, and the first offline variant shared the host with another of this job's runs.
- macOS: compiled and linted from Linux only.
