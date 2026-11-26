# Exact repaint on a same-size terminal reopen

J1270 · 2026-11-26 · base `98e6adda1080c9a991345f508efd6eb95c59c098` · [#521](https://git.kayg.org/kayg/infraternal/issues/521)

Prefer an exact-only Snapshot when a fresh, same-size reopen requests
bytes from before an applied resize. This restored the wrapped and
alternate screens that today's small and 1 MiB replays left wrong.
Healthy small reloads already reached the correct frame at the same
time and spent less CPU with raw replay.

## Current replay policy

On this base, `ReadFrom` already attempts an exact Snapshot when a retained
backlog is **strictly greater than 1 MiB**. A refusal returns to raw replay.
A cursor older than the ring takes the existing recovery path. The proposed
change only matters when today's policy would choose raw replay and some of
the bytes it would replay predate a successful change in rows or columns.
The fixture compares the deployed selection, forced raw and forced exact
with the same exact-only fallback as #583. [#583](https://git.kayg.org/kayg/infraternal/issues/583)

## How often replay crosses a resize

The six checked-in PTY recordings deliberately exercise resizing during a
shell session. At each record boundary, model a new browser attaching from
cursor zero at the current size. Count the cut when an applied geometry
change follows some of the output that would be replayed.

| Recording | Sampled cuts | Changed sizes | Replay crosses a resize | More output since resize |
|---|---:|---:|---:|---:|
| Bash, one-line prompt | 348 | 4 | 185 | 181 |
| Bash, multiline prompt | 334 | 4 | 185 | 181 |
| Bash, long edits | 418 | 6 | 213 | 207 |
| Zsh, right prompt | 329 | 4 | 176 | 172 |
| Zsh, long edits | 420 | 6 | 214 | 208 |
| Fish | 401 | 4 | 227 | 223 |
| **Total** | **2,250** | **28** | **1,200** | **1,172** |

All 28 applied size changes follow output. At 1,172 of the 1,200 exposed
cuts (97.7%), at least one more PTY write has already arrived. A predicate
that checks whether the resize was the last event would miss those cuts.
Compare the attach cursor with the byte offset of the last applied
geometry change instead. The recordings supply an exposure count under a
resize-heavy workload. They provide no estimate of production reopen
frequency. The existing Snapshot counter tracks approximate outcomes and
does not provide a denominator for this case. [Corpus counts](https://git.kayg.org/kayg/infraternal/issues/521#issuecomment-105726)

## Method

- A release build of the real infraternal agent and per-session shim, with a
  disposable switch at the shim's `ReadFrom` policy, ran a real PTY per cell.
  The generated stream fills primary scrollback with short logs or styled,
  wrapped text. The alternate-screen fixture enters a full-screen view after
  filling the primary buffer. Cases start at 80×24. In the resize cases
  the original viewer applies 60×24 and the PTY writes again before the
  fresh viewer attaches at 60×24 from output cursor zero. The controls
  keep 80×24 throughout.
- A socket-pair relay imposes 50 ms RTT with zero jitter. It exposes the
  PTY protocol directly. Time to replay completion starts on Attach and
  includes the 1 MiB + 64 KiB opening grant and the fixture's credit refunds.
  Byte counts are terminal payloads. Host CPU is the sum of daemon and
  shim thread run time from Linux `schedstat` during the reload. The central
  relay, TLS and HTTP page startup are outside this fixture.
- Chromium replays the actual frame arrival intervals into the shipped
  Ghostty WASM and canvas renderer. The reference uses the real raw bytes
  at their original geometry and applies the recorded Resize at its byte
  offset. The metric stops at the renderer's write callback once all
  viewport cells and the cursor match that reference. The comparison
  clips the reusable cell array to the current grid after a resize.
  The canvas uses the bundled Maple Mono font. Browser paint and
  network clocks come from two runs, and credit in the wire capture is
  refunded on receipt. This measures the first correct canvas draw for a
  ready terminal. [HTML rendering steps](https://html.spec.whatwg.org/multipage/webappapis.html#update-the-rendering)
- The serializer timer re-creates each shim state from the same captured
  bytes and recorded Resize. It times 101 calls to `Terminal::snapshot`
  after warming the state. This isolates generation and excludes frame
  encoding and socket transport.

## Payload, host CPU and wire time

perf-01, AMD Ryzen 7 3700X, CPUs 1–3 under `perf-run`. The relay
self-test measured 50.69 ms median RTT (31 samples). The matrix recorded
378 reloads, seven measured repetitions after one warmup per policy,
shape, history size and resize condition. There were zero stolen jiffies
during the 141-second run. Each row below is a same-size reopen after the
previous viewer resized and received more output. Times and CPU are medians.

| Surface | Backlog | Payload bytes, raw → exact | Serialize (µs) | Host CPU, raw → exact (ms) | Replay complete, raw → exact (ms) |
|---|---|---:|---:|---:|---:|
| Logs | Small | 8,105 → 13,167 | 128 | 0.213 → 0.413 | 50.45 → 50.67 |
| Wrapped | Small | 8,279 → 12,550 | 124 | 0.213 → 0.471 | 50.45 → 50.72 |
| Alternate | Small | 8,898 → 15,021 | 142 | 0.291 → 0.464 | 50.49 → 50.72 |
| Logs | About 1 MiB | 1,047,444 → 22,917 | 226 | 1.950 → 0.551 | 52.60 → 50.80 |
| Wrapped | About 1 MiB | 1,047,639 → 24,194 | 239 | 2.165 → 0.526 | 52.69 → 50.78 |
| Alternate | About 1 MiB | 1,048,237 → 24,771 | 243 | 1.781 → 0.513 | 52.47 → 50.77 |
| Logs | About 5 MiB | 5,242,775 → 22,917 | 230 | 9.820 → 0.598 | 254.92 → 50.85 |
| Wrapped | About 5 MiB | 5,242,935 → 24,194 | 239 | 10.182 → 0.560 | 302.73 → 50.82 |
| Alternate | About 5 MiB | 5,243,568 → 24,771 | 241 | 9.919 → 0.572 | 302.57 → 50.82 |

All 18 fixture states exported an exact Snapshot, including the
alternate screens. At small backlogs a Snapshot added 4.3–6.1 kB and
0.17–0.26 ms of host CPU in the resize rows. At about 1 MiB, it cut payload
by 97.6–97.8% and host CPU by 71–76%. Under the deployed policy the
three 5 MiB cases already sent identical Snapshot payloads with a
50.77–50.83 ms replay fence. Those rows quantify the cost avoided by
the existing 1 MiB threshold.

[Raw wire, CPU, serializer and machine-state receipts](https://git.kayg.org/kayg/infraternal/issues/521#issuecomment-106087)

## First correct frame at 50 ms RTT

The browser pass used headless Chromium 149 at its normal frame cadence.
A correct frame matches the live-resize reference for the visible grid
and cursor. Each entry is a median of seven measured reloads. “None”
means all seven finished replay with the wrong viewport and no correct
frame appeared.

| Surface | Backlog | Forced raw (ms) | Forced exact (ms) | Deployed (ms) |
|---|---|---:|---:|---:|
| Logs | Small | 67.5 | 67.5 | 67.6 |
| Wrapped | Small | None | 67.6 | None |
| Alternate | Small | None | 67.5 | None |
| Logs | About 1 MiB | 67.6 | 67.5 | 67.6 |
| Wrapped | About 1 MiB | None | 67.5 | None |
| Alternate | About 1 MiB | None | 67.5 | None |
| Logs | About 5 MiB | 267.5 | 67.6 | 67.5 |
| Wrapped | About 5 MiB | None | 67.6 | 67.6 |
| Alternate | About 5 MiB | None | 67.5 | 67.5 |

The exact candidate reached the reference in all 63 resized trials.
With no resize, all controls matched across the three policies. Raw
small and 1 MiB controls already reached the correct frame in roughly
67.6–67.8 ms. The 5 MiB forced-raw controls reached it much later, with
deployed policy already using the exact path.

Of the 1,200 resize-crossing cuts in the real shell corpus, 376 (31.3%)
showed a different visible grid or cursor with raw replay. Another
output write had already arrived in 352 of those 376 mismatches
(93.6%). A last-event predicate would miss those failures. Fish accounts
for 121 mismatches in this corpus. Its OSC 133 state is a documented
serializer refusal, so the exact-only policy cannot promise a repair
for that shell. [#521 serializer corpus](https://git.kayg.org/kayg/infraternal/issues/521)

[Raw frame timing, corpus oracle, harness and canvas captures](https://git.kayg.org/kayg/infraternal/issues/521#issuecomment-106093)

## Decision for the next slice

Use the byte offset of the last successfully applied change to rows or
columns to decide whether a fresh viewer at the same size needs an
exact Snapshot. A replay cursor earlier than that offset crosses
geometry. Subsequent writes advance the head without clearing that
condition. When the serializer refuses, use the existing exact-only
fallback. Retain the existing backlog threshold and the established
paths for an out-of-ring cursor or a viewer at a different size.

An unconditional Snapshot spends another 0.17–0.26 ms of host CPU and
4.3–6.1 kB for the small resize fixtures, and the small no-resize
controls showed no earlier frame for that work. It also gives a fresh
viewer a bounded history tail of up to 256 rows. Leaving the policy
as-is preserves the four below-threshold states whose wrapped or
alternate screen finished wrong. The resize boundary provides a
conservative trigger. The plain log controls show that some replays
cross the boundary and still draw correctly.
