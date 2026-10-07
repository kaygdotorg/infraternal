<!-- Merged Ghostty VT integration evidence and reviewer handoff for #22/#26/#34; decisions 13,40,41,74,81,94. -->
# Ghostty VT integration on the dev box

This checkout merges reviewed `vt-ghostty` head `565105f` into deployed dev
`0c47cd4` with a two-parent merge `d583114`. Nothing was pushed or deployed.
The owner selected this engine on #22; this integration makes no library choice.
`DECISIONS.md` is unchanged. A later no-ff merge `6a350e9` incorporates dev
`7d2d0a5`, including reviewed snapshot/Unicode ordering, setup checks and layout tolerance.

The deployed writer capability remains bit 1 and SelectWriter remains type 27.
Approximate recovery uses bit 2 and SnapshotWithFlags type 28. Borrowed decoding,
independent writer Acks, trusted terminal-open, replay ordering, detached controls,
indivisible repaint credit, output pauses and refused-resize retirement survive.
The merge body explains why the old snapshot credit-debt oracle was superseded.

Measurements below use this shared x86_64 dev box, eight CPUs, Intel Core
i9-9900K at 3.60 GHz as exposed by the host, not the pinned performance VM
(`machine.txt`). Each evidence log records its machine/load where applicable.

| Measurement | Result | Evidence under `target/integrate2-evidence/` |
| --- | --- | --- |
| Raw full infraternal-agent/shim/PTY LF flood | 14.921 MB/s, 14.230 MiB/s, 50 MiB exact, zero substitutions | `ghostty-raw-flood.log` |
| Raw CRLF / printable flood | 19.623 / 80.632 MB/s | `ghostty-raw-flood.log` |
| Native authenticated server full-path flood, accepted combined run | 50 MiB exact, zero substitutions, 11.873 MB/s (repeats 12.606 and 12.730) | `native-final-7.log`, `native-final-4.log`, `native-final-6.log` |
| Native 500-key probe, accepted combined run | paint p99 17.2 ms, echo p99 2.382 ms, resume 94.4 ms | `native-final-7.log` |
| Input seq129 loss and replay | 500/500 painted, no Ack129 reconnect loop, paint p99 18.8 ms | `native-final-4.log` |
| Shared native PTY open idle | 0 activations / 620.002 s, server RSS 16312 KiB | `native-final-4.log` |
| 32 writers/viewers × 200 inputs | 6400 exact inputs, 614400 delivered bytes, Ack p99 4.377 ms | `multi-scale-static.log` |
| 128 full-history sessions and 8 MiB rings | daemon RSS 5496 KiB; shim RSS sum 4209752 KiB | `scale-128-static.log` |
| 128 simultaneous socket recoveries × 10 | p99 58.404 ms, max 58.594 ms; load 14.95 | `scale-128-static.log` |
| Two-device reconnect/reload under stress-ng CPU8 | 20/20 exact shared-input and restoration replay; resume median 106.99 ms, max 189.67 ms | `native-final-4.log` |
| Native abrupt stop/restart | 24/24; exact replay of 4710396 payload bytes | `agent-functional-final.log` |
| Infraternal agent/shim idle | 0 scheduled slices / 2.2 s; daemon RSS 5176 KiB | `agent-functional-final.log` |
| Fuzz owned/borrowed shim parser and stream splits | 1144058 runs in 61 s, no sanitizer failure | `fuzz-shim.log` |

The user-supplied Alacritty baseline is 4.58 MiB/s; it was not remeasured here.
The native reconnect harness (`reconnect-final.log`) passes faithful raw replay,
one ordered approximate notice/repaint, and legacy mask-3 parking/retry without
a second approximation. The corrected full native functional run
(`native-final-6.log`) passes setup, sign-in, real PTY output, two independent
device Acks, reload/resume, logout revocation, and browser gap recovery with a
visible approximation and live stream. Its flood repeats at 12.730 MB/s.
Attach-before-Credit permits an output-paused notice before the funded repaint;
the oracle counts approximation notices separately rather than all Events.
`geometry-green-repeat.log` records 20/20 last-typist geometry runs. Timing
repeat failures remain visible: final4 direct echo p99 5.404 ms versus its 5 ms
gate; final6 paint p99 31.0 ms and echo p99 6.050 ms. Final5 direct echo timed
out; the harness now records content-free frame/Ack/sample counts on failure.
The final combined run (`native-final-7.log`) exits 0 with functional and all
performance budgets PASS: paint p99 17.2 ms, native echo p99 2.382 ms, resume
94.4 ms and full-path 11.873 MB/s. Earlier failures remain for review; no timing
threshold was relaxed. The 20-run CPU8 stress and 620-second idle evidence use
the identical production implementation, with only the later harness oracle
correction for the permitted output-paused notification.

Tests first reproduced terminal-open Ping stream refusal, idle RTT intervals
(103 activations/10 s), lost submitted Input sequence129 reconnect loops,
ordered recovery Event retirement, and premature healthy-viewer retirement
on immediately-ready output bursts, and a detached render queue that prevented
Attach after Welcome (painted 16384/16454 bytes in the failing browser test).
Owned output now drains while disconnected before declaring the painted cursor.
The fixed build completed all 20 repeated native two-device stress trials. Exact red logs remain in the evidence folder. Healthy-viewer scheduling retains
a 256-frame bound and nonblocking isolation. Native output is also rejected
before queueing if it exceeds remaining negotiated credit (maximum 8 MiB).
At default 1 MiB credit, 128 unique buffered streams measured 145164 KiB RSS
and dispatch p99 0.032832 ms (`actor-queue-128.log`); the hard payload ceiling
is 128 × 8 MiB = 1 GiB plus bounded notices and metadata. The native repeat harness paces
extra auth reads within the existing 30/source/minute admission policy; it does
not weaken limits or substitute source addresses. Input-loss injection is isolated
on the fresh probe writer so repeat/reload references remain meaningful.

Self-review covers auth B1/S1/S2/N1 and shim/wire ownership, trusted UID,
per-writer partial-write Ack/dedup, capability negotiation, bounded queues,
reserved flags and lengths, native handle retirement, ordered credit/repaint,
and recovery notice session binding. The existing authenticated socket watchdog
also guards forwarded notices. No auth/secret policy or engine FFI changed.
Physical iPhone/Safari and independent visual/security review remain external.
`docs/PROCESS.md` is absent; the supplied Definition of Done and available
review checklists were followed. Screenshots are from production assets and
provided for independent review without a self-assessment of visual quality.

Final checks: the full browser suite on unique port 4441 passes 21/21
(`playwright-accepted.log`); the exact requested Nix fast command passes all
six Rust gates and 7 protocol tests, 34390 assertions, 134 streams and 11439
schedules with zero divergences (`complete-fast.log`). `bun run check` passes
(`detached-client-check.log`). Production screenshots are retained under
`target/integrate2-evidence/screenshots/`.
