<!-- Records reproducible local session admission, retirement and memory evidence for #151 and D214. -->
# Session bounds and retirement

Host admission belongs to the enabled host facts plugin. `host.memory.configure`
sets `terminalMemoryFloorMiB` (default 256) and `terminalMemoryFloorPercent`
(default 5). The floor is the larger of these values, using MemTotal and
MemAvailable from the existing collector. Equality admits; missing memory data
refuses safely. Disabling the plugin removes its admission check. Session counts
never substitute for available memory.

Public refusal JSON adds `reason` to the legacy `error` field. Low memory also
carries nonnegative `available_mib` and `session_count`. Reasons are
`host_memory_low`, `host_memory_unavailable`, `invalid`, `resource_unavailable`
and `unavailable`. Server routing preserves known reasons and hides internal
errors. The tracer renders fixed public copy and opens the existing sessions
picker through the shared toast action. The picker currently lists browser-known
sessions; the orchestrator owns the separate background-session view.

`host.facts.read` adds `sessionCount` and `backgroundSessionCount` when trusted
runtime context exists. Bootstrap collectors omit them. Background means no
attached terminal window, even if credit starvation has disconnected its shim
link. Counts are process-identity checked on control reads and refreshed by
socket deletion events, with no idle timer or per-session descriptor.

## Measurement

Run locally from the repository root under the required weighted scope:

```sh
systemd-run --user --scope -p CPUWeight=10000 python3 scripts/measure-session-memory.py --binary /absolute/path/to/infraternal --sessions 200
```

The harness owns all children and measures `/proc/<pid>/smaps_rollup` PSS,
private dirty and private clean. It fills each real shell with 12,000 rows and
waits for its output marker before sampling. A fresh daemon also recovers all
200 real shims, admits session 201, and drops back to 200 when its shell exits.

Initial branch measurement at source a7a0ff7b, static binary 19,620,768
bytes, infraternal-dev, 8 cores, 32,803,748 KiB RAM, 80x24 terminals:

| Phase / role | Total PSS KiB | Total private dirty KiB | Mean PSS KiB | Mean private dirty KiB |
| --- | ---: | ---: | ---: | ---: |
| Empty / shim | 216,928 | 212,928 | 1,084.64 | 1,064.64 |
| Empty / shell | 122,120 | 118,876 | 610.60 | 594.38 |
| History / shim | 3,616,604 | 3,612,604 | 18,083.02 | 18,063.02 |
| History / shell | 134,160 | 130,876 | 670.80 | 654.38 |

Empty combined PSS: 339,048 KiB. History combined PSS: 3,750,764 KiB.
Load averages started 13.13/41.39/34.73 and ended 18.92/41.74/34.92.
There was no artificial CPU load. Each shim had one thread; its resident stack
was 52 KiB, and writable ELF mappings accounted for 908 KiB of private dirty
memory. History allocation dominates scale. The 8 MiB ring is lazy; retained
terminal history has its existing 17 MiB cap. Separating the shim executable
could trim relocation pages, but requires an independently measured architecture
choice rather than substituting an unapproved terminal engine.

The release relay measurement `terminal_stream_memory_at_200` uses actual local
relay futures with authenticated Unix peers, without PTYs. At load
10.43/12.43/19.25, private memory grew from 4,160 to 5,148 KiB: 988 KiB for 200
streams, or 5,058 bytes each, including paired fixture overhead. A relay future
was 1,704 bytes. This is transport metadata evidence, not a shell measurement.
The connection allowance is 32 KiB per stream within a 4 MiB metadata reserve.
Full payload buffers remain separately bounded by frame, queue and transport
byte budgets; stream IDs retain their u32 protocol range.

## Backend review

- The daemon refreshes liveness before admission and host facts reads. Socket
  deletion refreshes without polling. PID reuse is rejected by the kernel
  process birth clock; zombies have no executable link. Secure socket ownership/
  mode checks and caller execution-UID checks remain in the existing connection path.
- Exit delivery is ordered through the writer acknowledgement. No-viewer shells
  retire without waiting for a discovery peer; delayed credit retains a bounded
  final frame and the closed connection instead of reconnecting to a dead socket.
- Memory settings reject unknown/duplicate fields, oversized input, overflow and
  percentages above 100 before replacing the policy. Refusal decoding is bounded
  to the existing 32 KiB control budget. Unknown reasons become generic guidance;
  tracer counters must be nonnegative safe integers.
- Server routing preserves existing session freshness, revocation and host
  ownership checks before and after opening. Internal IO/database errors remain
  generic; no shell content, credentials or diagnostic text enters refusal copy.
- No new dependency, terminal engine, timer or UI material is introduced. Shared
  toast actions preserve pointer/keyboard activation for the existing picker.
  Production screenshots are review artifacts; visual quality requires the
  orchestrator's independent review.

Repeat with final lifecycle tracking: 200 streams increased private memory from
4,072 to 5,076 KiB (1,004 KiB, 5,140 bytes/stream); future size 1,728 bytes;
load 33.38/29.37/26.00. The 32 KiB allowance remains over six times this cost.
The real-session repeat at 24216c32 is preserved in `measurement-200.json`.

## Parser fuzzing

The production memory policy decoder, process birth parser and public refusal
decoder passed coverage-enabled ASan fuzzing: 2,372,685 executions in 46 seconds,
cov=2,049 / ft=6,838, no crashes. Seeds cover valid defaults/refusals,
negative counters, overflow, duplicate fields, invalid percentages, and live/dead
process records with unusual command bytes.

```sh
CARGO_PROFILE_RELEASE_LTO=false cargo +nightly-2026-10-01 fuzz run terminal_admission /absolute/path/to/corpus -- -max_total_time=45 -max_len=32769
```

The release-profile LTO attempt failed to link sanitizer coverage globals.
Disabling LTO only for this fuzz command produced the instrumented run; the
production release profile remains unchanged. On Nix, use the existing make and
Perl shell and pinned Zig PATH as for repository verification.

## Stable process identity regression

A proc directory inode can be recreated without the process exiting. A failing
regression modeled this by preserving the actual process stat record and exe
link in a new proc view: the old inode guard dropped the live session. Registry
identity now uses the kernel stat field 22 birth tick, with the existing PID,
socket and executable checks. The parser bounds input at 4 KiB and supports
spaces, parentheses and non-UTF8 command bytes. Zombie/dead states, missing
fields and numeric overflow fail closed. All three lifecycle tests pass.

## Final static build and scale check

The final lifecycle binary is 19,656,320 bytes on x86_64 musl, static PIE and
stripped, with no interpreter. ARM musl is 17,533,960 bytes, static and stripped,
with no interpreter. The process-identity correction adds 3,936 x86 bytes.
Both exceed the historical fixed size baseline; D205 permits this reported size
exception. No dependency was added to the production graph.

`measurement-final-200.json` preserves binary SHA256, load and all raw rows.
At 200 empty sessions, shim/shell PSS totals were 217,152 / 122,187 KiB and
private dirty totals were 212,952 / 118,868 KiB. After 12,000 rows per session,
PSS totals were 3,576,532 / 134,202 KiB; private dirty totals were
3,572,332 / 130,868 KiB. Recovery counted 200 background sessions, admission
created session 201, and shell exit retired it within one second back to 200.
Initial load was 12.31/11.42/16.24; the filled-history sample was
22.11/13.50/16.81. No artificial CPU load was generated.

The separate zero-RTT comparison (`facts-latency-200.json`) isolates network
delay: 101 host-facts reads with 200 real sessions, weighted CPU scope, no own
build/browser during sampling. Median before/after the birth check was
2.521 / 3.999 ms; maximum was 8.613 / 13.941 ms. Load was
14.76/13.04/15.77 and 17.20/13.86/15.95. The observed median increase is
1.478 ms per 200-session control read. This bounded on-request cost avoids
incorrect lifetime identity without an idle timer or per-session descriptor;
typing does not run these checks. Load differences limit causal attribution.

Production base `0d93a502` rebuilt with the same locked release/musl settings is
19,613,216 bytes: this branch grows by 43,104 bytes (0.22%). The historical size
maximum is already exceeded by the base. Measured x86 increments by logical set:

| Set | Bytes added | Resulting bytes |
| --- | ---: | ---: |
| Shim retirement `730dd3bd` | 3,136 | 19,616,352 |
| Admission API `a58e071b` | 96 | 19,616,448 |
| Memory policy `a7a0ff7b` | 4,320 | 19,620,768 |
| Discovery `fe362c97` | 1,920 | 19,622,688 |
| Host count wire `a82ec0d9` | 1,088 | 19,623,776 |
| Daemon lifecycle `24216c32` | 18,272 | 19,642,048 |
| Typed refusal routing, stream-bound expression and fuzz target | 10,336 | 19,652,384 |
| Stable birth identity `4540e157` | 3,936 | 19,656,320 |

UI, fixture, harness and documentation commits add no native release code.
The metadata expression and fuzz target do not change the native graph: the
10,336-byte set comes from preserving typed refusal errors through routing.
The ARM size is reported absolutely; no ARM baseline delta is claimed.
