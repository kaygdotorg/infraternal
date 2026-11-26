# Remote host links and server threads (J1246, #562)

Question (from J1220, `research/many-host/2026-11-25/` on branch `j1220-many-host`): one server thread,
`runtime::remote`, carried every remote host link (22.9% of all samples at 200 hosts × 2 terminals),
so the remote path looked single-threaded with a ceiling of about 400 hosts. Can the links be spread
over more than one thread?

## Answer: the shipped server already spreads them; the single thread was the fixture's

- J1057's fixture `many_host_server_fixture` was a plain `#[tokio::test]`, which is tokio's
  **current-thread** runtime. The server ran inside the test process, so every host link, quinn
  driver, HTTP and WebSocket task shared libtest's thread.
- libtest names that thread after the test: `runtime::remote_demo_tests::many_host::many_host_server_fixture`.
  Linux cuts `comm` to 15 bytes, which gives **`runtime::remote`**.
- The shipped server is built on `tokio::runtime::Runtime::new()` (`crates/infraternal/src/main.rs`).
  That is the multi-thread runtime, with one worker per CPU the process may use. Its workers are
  named `tokio-rt-worker`. Nothing on the remote path pins work to one thread: no `LocalSet`, no
  `spawn_local`, no dedicated current-thread runtime. DECISIONS has no rule that puts the server on
  one thread. D379's single SQLite writer is a separate thread, and it is unchanged.
- The fixture now builds the same runtime as `main.rs` by default (commit `afdd8bfee`).
  `INFRATERNAL_MANY_RUNTIME=current` keeps the old shape, so both run from one binary.

## Method

- Binaries: static x86_64 musl release with line tables, built from `afdd8bfee` (origin/dev `534dff31c`
  plus J1057's fixture, J1220's invitation retry and this runtime switch). sha256: `server-test`
  `fad2be68…`, `infraternal` `62c81fa8…`.
- Perf VM through `perf-run`: cpus 1-3, 6 GiB, steal 6 of 515,140 jiffies. The server, the infraternal
  agents and the shims share those 3 CPUs, so the production runtime has 3 workers.
- J1220's driver `measure.py` (J1057 + J1220), extended with each server thread's CPU
  (`server_thread_cpu`, from `/proc/<pid>/task/*/stat`) in the idle-visible and typing windows. It
  also logs a control-stream Close's reason.
- `run-all.sh`: two rounds, each with production then current, at 50 × 8 and 200 × 2. That is
  8 points in one lock slot. One account, 20 typists at 8 keys/s for 15 s; every other terminal is
  attached, visible and idle.
- `table.py raw/*.raw` writes `results.csv` and the table below.

## Results

| runtime | round | hosts × term | server CPU idle / typing % | busiest server thread (idle) % | busy threads | server wakeups/s (idle) | key p50 / p99 / max ms | attach p99 ms | reattach p99 ms | invitation 503 retries |
|---|---|---|---|---|---|---|---|---|---|---|
| current | 1 | 200 × 2 | 58.4 / 64.0 | 59.8 | 1 | 3,103 | 4.57 / 11.68 / 17.2 | 127.9 | 258.0 | 12 |
| current | 2 | 200 × 2 | 56.1 / 62.2 | 57.4 | 1 | 3,133 | 4.69 / 11.71 / 17.9 | 126.0 | 248.2 | 12 |
| production | 1 | 200 × 2 | 71.1 / 76.5 | 24.5 | 3 | 7,735 | 3.71 / **8.22** / 13.8 | 153.4 | **140.3** | 0 |
| production | 2 | 200 × 2 | 71.8 / 76.4 | 24.7 | 3 | 7,930 | 4.11 / **10.12** / 14.5 | 165.0 | **114.6** | 0 |
| current | 1 | 50 × 8 | 27.6 / 33.9 | 27.8 | 1 | 2,219 | 1.17 / 3.44 / 9.0 | 48.7 | 60.0 | 2 |
| current | 2 | 50 × 8 | 28.1 / 34.6 | 28.3 | 1 | 2,257 | 1.21 / 3.77 / 11.9 | 47.9 | 58.1 | 3 |
| production | 1 | 50 × 8 | 39.5 / 46.3 | 13.5 | 3 | 9,106 | 1.15 / 3.73 / 8.4 | 51.5 | 54.9 | 0 |
| production | 2 | 50 × 8 | 39.3 / 46.4 | 13.3 | 3 | 8,876 | 1.15 / 2.61 / 8.4 | 50.2 | 53.2 | 0 |

The current rows reproduce J1220's (50 × 8: 27.7 / 34.1%, key p99 3.13 ms; 200 × 2: 57.8 / 64.2%,
key p99 11.84 ms, reattach p99 229 ms).

## What it means

1. **There is no one-core ceiling in the shipped server.** On the production runtime the load spreads
   evenly over the 3 workers (24.5 / 24.3 / 24.3% at 200 × 2). The busiest thread carries 13-25% instead
   of 28-60%. The ceiling is the machine's cores, not one core.
2. **Spreading costs CPU.** Total server CPU is 12-13 points higher at both shapes (+43% at 50 × 8,
   +23% at 200 × 2), and the server wakes 3-4× as often (7.7-9.1k vs 2.2-3.1k wakeups/s). Moving
   work between workers costs this: cross-thread wakes and parking and unparking workers. The work
   itself is the per-terminal route probes (J1220 finding 1). The current-thread rows understate
   what the shipped server costs.
3. **D375 rows, shipped runtime:**
   - Key p99 (8.3 ms): passes at 50 × 8 (2.6-3.7 ms). At 200 × 2 it sits at the line, 8.2 and 10.1 ms
     in the two rounds; current-thread gives 11.7 ms. The server competes for the same 3 CPUs with
     about 178% of infraternal agents and shims, so a deployment where the hosts are other machines
     sees less.
   - Reconnect typable (1 RTT + 50 ms, loopback RTT ≈ 0): 53-55 ms at 50 × 8 (current 58-60 ms) and
     115-140 ms at 200 × 2 (current 248-258 ms). It still misses at both shapes. The probe period
     (J1220 findings 3 and 4: the 24-25 ms attach floor) dominates it, not the threading.
4. **The invitation 503s disappear on the shipped runtime** (0 retries in 4 runs vs 2-12 on
   current-thread). The race J1220 read in `remote_http.rs`, a deferred transaction upgraded after
   another writer committed, still exists in the code. It is just much less likely when the HTTP
   handler does not wait behind 200 links' traffic on the same thread. `BEGIN IMMEDIATE` remains the
   fix.
5. **Per-packet authority checks** (`AuthorityGuard::cancelled` / `permits`, 0.57% of the old
   thread's samples) are not worth touching in auth code for that share. Unchanged.

## Not changed, for the owner

- Per-terminal route probes every 25 ms (41 shim wakeups/s per terminal) are most of the idle cost
  on every runtime. Reducing them is the D265/D300 question J1220 raised. Not changed here.
- Runtime tuning that might win back part of the 12-13 points (worker count, the global-queue or
  event interval, or sharding host links by thread) is a threading decision. Not measured, not
  changed.

## Caveats

- One VM, 3 CPUs shared by the server, the agents and the shims. One account, loopback, fixture
  hosts. Two rounds per point.
- An indicative run on compute01 (shared, load 10-27) also lost a few browser sockets to an empty
  WebSocket Close, on both runtimes (and J1220's `A-second-run` shows 4). The perf VM runs show none
  in 8 runs, so this is a starved-host effect. It is listed as a follow-up, not chased here.

## Files

- `raw/*.raw`: the driver's full output per point (the last line is the JSON); `results.csv`.
- `measure.py`, `matrix.sh`, `run-all.sh`, `profile.sh`, `table.py`.
- To rerun, build the CLI and the server test with `--features remote` as in J1057's #562
  comment, copy them with `scripts/` and `crates/infraternal/tests/profile` to the perf VM, then run
  `perf-run -- bash run-all.sh`.
