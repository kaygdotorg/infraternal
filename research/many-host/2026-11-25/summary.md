# Many-host and terminals-per-host rerun, 2026-11-25 (J1220, #562)

Base: origin/dev `824340500` (has J1164 single-writer open writes, J1181 open-burst queueing, J1190 snapshot-first reconnects) plus the J1057 many-host fixture (`7b68395d3`, never built before this job) and a 25-line retry patch to it (`fixture-retry.patch`). Binaries: static x86_64 musl release with line tables, built on compute01 (`/mnt/build/targets/j1220`, deleted after).

## Method

- **Perf VM, through `perf-run`** (cpus 1-3, 6 GiB, lock, egress guard; loopback only, no private or documentation addresses). Raw output and the CSV are beside this file. The server (the `many_host_server_fixture` test process, memory-only CA) and every infraternal agent and shim run **on those same 3 CPUs**. In production the hosts are other machines, so the "server CPU" columns are the server's own and the latency columns are inflated at the top rows (see "What the numbers mean").
- N hosts are enrolled with a real invitation and a real `infraternal agent join` each. One account then opens T terminals per host (round-robin over hosts), 8 opens in flight, in sockets of 28 (D214's interim pool). Each terminal is a remote shell turned into raw `cat`, so **key-to-echo is wire Input → wire Output** (server + link + agent + shim + pty).
- 20 typists (one terminal each, spread over hosts, 8 keys/s, 15 s) while every other terminal sits attached and visible and idle. "Idle (visible)" is 15 s with every terminal attached and visible. Then one socket is dropped and its terminals re-attached (reattach = Attach sent → Attached ack).
- SQLite lock waits: separate runs under a seccomp-bpf `strace -f` of `nanosleep`, `fsync`, `fdatasync` (the busy handler sleeps with `nanosleep`). Those runs are slow on purpose and not used for timing.
- Profile: `perf record -e cpu-clock -F 499 -g` (the VM has no PMU) over the 200 hosts × 2 terminals point, as root, server and agents dropped to `claude`. Flat: Rust release without frame pointers.

## Results (run `A`, `C`, `D`; CSV: `results.csv`)

| hosts | term/host | terminals | server RSS MiB | all-process mem MiB | server CPU idle (visible) % | server CPU typing % | open p50/p99 ms | attach p50/p99 ms | key p50/p99/max ms | reattach p99 ms |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 1 | 35.4 | 42.2 | 0.53 | 1.0 | 54.4 / 54.4 | 23.5 / 23.5 | 0.71 / 1.06 / 7.48 | 2.7 |
| 1 | 8 | 8 | 32.2 | 52.6 | 0.93 | 3.3 | 11.5 / 79.3 | 24.2 / 24.7 | 0.61 / 0.79 / 9.27 | 5.6 |
| 1 | 32 | 32 | 34.9 | 105.0 | 1.6 | 7.0 | 11.3 / 52.9 | 24.6 / 31.5 | 0.62 / 1.69 / 7.53 | 18.0 |
| 1 | 128 | 128 | 35.9 | 303.3 | 4.73 | 10.4 | 12.8 / 44.8 | 25.5 / 34.5 | 0.68 / 1.58 / 7.41 | 22.0 |
| 2 | 128 | 256 | 45.1 | 608.6 | 9.4 | 15.3 | 13.7 / 40.5 | 26.2 / 33.6 | 0.67 / 3.07 / 8.67 | refused at 3 hosts (below) |
| 3 | 128 | 384 | 44.8 | 872.4 | 14.13 | 20.5 | 14.4 / 36.4 | 27.8 / 37.4 | 0.73 / 3.48 / 8.48 | refused at 3 hosts (below) |
| 12 | 32 | 384 | 46.5 | 876.2 | 16.33 | 22.4 | 13.9 / 42.2 | 28.9 / 40.3 | 0.85 / 2.57 / 8.45 | 32.0 |
| 50 | 1 | 50 | 43.3 | 324.4 | 13.4 | 19.3 | 13.4 / 68.3 | 26.6 / 35.9 | 0.78 / 2.44 / 8.69 | 36.1 |
| 50 | 8 | 400 | 53.2 | 1057.8 | 27.73 | 34.1 | 14.9 / 36.9 | 33.2 / 47.7 | 1.14 / 3.13 / 9.16 | 60.4 |
| 50 | 9 | 450 | 53.2 | 1161.4 | 29.67 | 35.9 | 14.2 / 41.5 | 33.2 / 48.7 | 1.33 / 3.61 / 9.63 | 65.8 |
| 200 | 1 | 200 | 67.7 | 1204.6 | 46.27 | 53.0 | 17.6 / 52.9 | 35.7 / 65.1 | 2.34 / 5.44 / 12.29 | 94.1 |
| 200 | 2 | 400 | 71.5 | 1592.2 | 57.8 | 64.2 | 24.1 / 97.0 | 48.9 / 116.3 | 4.41 / 11.84 / 17.5 | 228.7 |

- **Server RSS** is the server process only. **perf-run scope memory** is every process of the run (server, agents, shims, shells, page cache of the 160 MB binaries), taken at the end.
- p99 over 300 to 2,400 keystrokes per row; max is the single worst key. The D375 own-overhead row is **8.3 ms p99**.
- 3 hosts × 128 reattach was refused (see finding 4); that row's other columns are from run `D`, which skipped the reconnect phase.
- Not reachable from one account: 50 × 32, 200 × 8 and every 128-per-host shape past 3 hosts (finding 2). Those rows are in the CSV as `failed`.

## D214 / D375 budgets: where things leave them

| budget | result |
|---|---|
| **D214 bound, 128 terminals on one host** (`MAX_TERMINAL_STREAMS` = 4 MiB / 32 KiB) | holds: 1, 2 and 3 hosts × 128 all attach, 0 refusals, attach p99 34-37 ms, key p99 1.6-3.5 ms |
| **Terminals per account** | **leaves the budget at 480-512.** One socket carries at most 32 terminal streams (`MAX_ATTACHMENTS`, `websocket.rs:112`; a 33rd is closed with "stream limit") and one account holds at most 16 sockets (`MAX_USER_CONNECTIONS`). D214 says the 32-per-socket limit goes. 200 hosts × 128 (25,600) cannot be opened by one account at all. |
| D375 own overhead, key p99 ≤ 8.3 ms | holds in every row but one: 0.8-3.6 ms up to 450 terminals on 50 hosts. **Leaves at 200 hosts × 2 terminals: 11.8 ms p99** (17.5 ms max), with agents and shims taking 177% of the 3 CPUs beside the server's 64% |
| D375 reconnect, typable on a resumed link: 1 RTT + 50 ms (loopback RTT ≈ 0) | holds to 12 hosts × 32 (32 ms p99); **leaves at 50 hosts × 8 (60 ms), 200 × 1 (94 ms), 200 × 2 (229 ms)** |
| D375 idle infraternal agent < 15 MB RSS | **18.5 MiB RSS per remote-joined agent** (anon 3.0 MiB; the rest is the shared binary's resident pages). Not re-split here; J1034 measured 10 MB for the local agent |
| Server memory | flat and small: 35 MiB at 1 host, 71 MiB at 200 hosts + 400 terminals (about 0.16 MiB per host, 25 KiB per terminal) |
| Memory per terminal | about 2.1-2.4 MiB (1.7 MiB anon: shim and shell, on the host, not on the server). 450 terminals use 1.16 GiB. The 6 GiB scope would hold about 2,300 |
| D81 idle, no viewer | server 0.0-0.2% CPU; 12 wakeups/s at 1 host, 49/s at 200 hosts (0.25 per host) |
| SQLite write-lock waits (strace) | **gone**: 1 busy sleep at 1 × 32, 10 sleeps (9 ms total) at 50 × 8 over about 90 s; J1034 counted 2,092 in 12 s on the old base |

## What the numbers mean

1. **The server's cost is idle probing, not typing.** Server CPU with every terminal visible and idle: 0.5% (1 × 1), 4.7% (1 × 128), 14% (3 × 128), 16% (12 × 32), 28-30% (50 × 8-9), 46% (200 × 1), 58% (200 × 2). Typing from 20 terminals adds at most 7 points. A fit of about **0.2% of a core per host with a visible terminal plus 0.03% per terminal** reproduces the rows (200 × 2: 40 + 12 = 52, measured 58). It goes with the probes: every attached terminal route is probed every 25 ms (**41 shim wakeups/s per terminal in every row**, same as J1034), plus the host link's own timers. 450 visible terminals on 50 hosts mean 18.6k shim, 12.9k agent and 2.3k server wakeups/s while nobody types.
2. **The profile says all of that lands on one server thread.** Of all samples (200 × 2), the server's `runtime::remote` thread has 22.9% (the agents and shims 63%, the driver 6%, bash 6%, `db-writer` 0.18%, `sqlx-sqlite-worker` 0.44%). It is the only server thread with real load, so the server's remote path is **single-threaded**: at 100% of one core it stops scaling. The fit puts that at roughly 400 hosts that each show one terminal. 15% of the samples are in the server binary and 6.4% in the kernel (UDP send/receive, nftables, conntrack on loopback). Within the binary the profile is flat: quinn `ConnectionDriver::poll` 0.59%, `process_payload` 0.28%, `populate_packet` 0.22%, tokio notify/waker (0.43 + 0.25 + 0.20%), `embedded::run_actor` 0.41%, **`remote_guard::AuthorityGuard::cancelled` 0.35% and `::permits` 0.22%** (polled per packet), `remote_link::pump` 0.18%. No SQLite symbol is in the top 40 (`perf/srv-thread-sym.txt`).
3. **Attach has a floor of about 24 ms** in every row (23.5-25.5 ms at 1 host, any terminal count), the same as the 25 ms probe period, while an open takes 11-14 ms. I did not trace it; a wait for the next probe tick is the obvious suspect.
4. **Reattach at the host bound is refused.** After 3 hosts × 128 attached (384, 12 sockets), dropping one socket and attaching its 28 terminals on a new one gave "the host could not accept the terminal attachment" for the first streams and the rest hung (60 s timeout). The old socket's streams were still counted when the new ones arrived. On 1 host × 128 the same step worked (22 ms p99), so it is a race with the release of the old socket's streams. That is the shape of a reconnect after a network change.
5. **Enrolling a host while others are connected answers 503 at random** (see `fixture-retry.patch` and the retries column in `raw/`): 50 hosts, 3 of 3 first runs failed between host 2 and host 21, and with the retry 3 retries at 50 hosts, 18 at 200 hosts × 1, 10 at 200 × 2, 0 at 12 hosts and below. Likely cause (read, not proved): `remote_http.rs` begins a deferred transaction, reads, then writes (`pool.begin()` for sessions; only the API-key branch uses `BEGIN IMMEDIATE`), and SQLite refuses a deferred read-then-write after another writer committed (`SQLITE_BUSY_SNAPSHOT`, which the busy timeout does not wait out); the handler turns it into 503.
6. **Opens run at 27-32 per second** with 8 in flight (J1164's local-session figure was about 85 per second with 16 in flight; here every open also crosses the host link). p50 11-24 ms, p99 37-97 ms, no `resource_unavailable` refusals in any run.

## Compared with the last run

There is no earlier many-host run: J1057's fixture was committed untested on 2026-11-21. The nearest records are J1034 (2026-11-21, local sessions on `ae96a4d34` / `163034fbd`) and J1164:

| | J1034 (local sessions) | this run |
|---|---|---|
| key p99, 100 sessions, 20 typists | 1.41-2.20 ms (fix); 7.6-20.6 ms (base) | 1.58 (1 × 128), 2.57 (12 × 32), 3.61 (50 × 9) |
| shim wakeups per visible idle terminal | 41/s | 41/s |
| server RSS | about 60 MiB flat to 1,000 sessions | 35-71 MiB (remote hosts only) |
| SQLite busy sleeps under typing | 2,092 in 12 s (base) | 10 in about 90 s |
| idle, no viewer | 3.8 wakeups/s | 12/s at 1 host, 49/s at 200 |

## Follow-up fixes, ranked by impact (not built)

1. **Reach D214's intent: lift the 32-streams-per-socket limit (`MAX_ATTACHMENTS`) and decide the 16-sockets-per-account limit.** One account tops out at 512 attached terminals, so the 128-per-host bound can only be used on 4 hosts. D214 says no arbitrary caps and bytes buffered per connection as the bound. Decision for kayg (D214); recommendation: raise the per-socket count to the per-host bound (128) and keep the byte limits.
2. **Enrol 503: begin the invitation transaction with `BEGIN IMMEDIATE` (session branch too).** One line plus a test; production-visible whenever a host is added while others are connected.
3. **Put more than one thread behind the remote hosts.** One `runtime::remote` thread carries every host link and is the scaling ceiling (about 400 hosts with a visible terminal each, extrapolated). Move the host links to a multi-thread runtime or shard them by host, then rerun 200 and 400 hosts.
4. **Cut the idle cost: one probe per host link instead of one per attached terminal (25 ms each), and none for terminals that nobody sees.** It is 18.6k shim + 12.9k agent wakeups/s at 450 terminals and most of the server's CPU. It touches D265/D300's link-death numbers, so it needs the owner's choice of what a hidden or detached route must still prove.
5. **Release a closed socket's terminal streams before refusing a new attach on the same host** (finding 4), so a reconnect at the bound works.
6. **Find the 24 ms attach floor** (finding 3): trace Attach → Attached with timestamps on the server, link and agent.
7. **Per-packet authority polling** (`AuthorityGuard::cancelled` and `::permits`, 0.57% of the thread's samples): check once per link state change rather than per packet.
8. **Agent RSS 18.5 MiB against D375's 15 MB**: split anon from shared pages and say which the row means.
9. **Harness:** the fixture and the extended driver (`measure.py`) live outside the repo's `scripts/` for now; the fixture branch `j1057-many-host-fixture` plus `fixture-retry.patch` rebuild it. The D375 "flooding terminal adds at most 8.3 ms" row is not measured here (no flood phase yet), nor is a second account (needed to go past 480 terminals).

## Caveats

- Agents, shims, driver and server share 3 CPUs, so the high rows (200 hosts) overstate the latency a real deployment sees; the server-side CPU columns do not suffer from that. A second run with the agents on another machine would separate them.
- One account, loopback, fixture hosts (no real SSH, no network RTT). All connections here are QUIC links to the same server.
- Single run per point (no repeats) because the perf lock was queued for about 8 hours in total; point-to-point steps are far larger than the noise seen in repeated points (1 × 32 appears in runs A and B).

## Files

- `results.csv`: one row per point (set A first run and second run, C, D; B is the strace set with lock waits). `raw/*.jsonl`: the driver's full JSON per point (all percentiles inputs, per-window CPU and wakeups, memory). `raw/B-*.strace.json`: lock-wait counts.
- `measure.py` (driver), `matrix.sh` (runs points under `perf-run`), `profile.sh` (`perf record` run), `strace_count.py`, `to_csv.py`. `perf/`: top symbols of the server thread, the agents and the per-process split.
- `fixture-retry.patch`: the change to `crates/infraternal-server/src/remote_many_host_tests.rs` (J1057's fixture, branch `j1057-many-host-fixture`) that retries a refused invitation and counts the retries.
- Rerun: build the CLI and the server test (`--features remote`, musl release) as in J1057's issue comment, copy both to the perf VM with `scripts/` and `crates/infraternal/tests/profile`, then `perf-run -- bash matrix.sh X "50:8 200:2"`.
