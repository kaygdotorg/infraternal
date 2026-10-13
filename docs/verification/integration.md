<!-- Merged dev evidence for the first deploy: real native auth, PTY writers, static binaries and idle budgets [9][13][41][74]; #34/#28. -->
# First-deploy integration

Work is local to dev; nothing was pushed or deployed. Required no-ff merges,
each with a green fast gate before the next: t-server e4809d4 → f5ea2c9,
pinned t-web 845c293 → 9e82c28, t-web-auth 58040df → 6f4214e.
The server merge retains the real embedded `agent --fd 3` socketpair [9],
adds both wire-contract sides, and keeps main synchronous so the shim forks
before any runtime exists in its own process. Later fixes are separate module, regression,
benchmark and documentation commits. Full gate output and final head are on
[issue #34](https://git.kayg.org/kayg/infraternal/issues/34).

## Real-engine evidence

The retained browser fixture uses the optimized static binary, fresh private
storage, built production tracer, real server WebSockets and real shim PTYs.
A pipe-only test TLS proxy gives Chromium a native HTTPS/WebAuthn origin; it
uses native sockets, not intercepted WebSocket timing. Capabilities, cookies,
private test TLS keys, passkeys and recovery words are never logged or saved.
Two native sign-ins issue distinct cookies for separate browser contexts using
the same virtual resident credential. This proves independent device sessions,
not physical Safari/iPhone interoperability.

Native owner setup, sign-in, typing/output, reload of the same public session,
a second signed-in device, independent Ack zero after the first writer Ack ten,
exact input in both viewers, and logout socket revocation pass. Only the public
session id persists in tab storage/URL; it confers no authority. The trusted
server selects effective uid and character dimensions for daemon-open requests.
Explicit remote host ids remain denied until host inventory is integrated.

Reproducible commands (from the repository root unless noted):

```sh
nix shell nixpkgs#binutils nixpkgs#file nixpkgs#gnumake nixpkgs#perl -c scripts/verify fast
nix shell nixpkgs#gnumake nixpkgs#perl -c scripts/verify browser
cd apps/tracer && TRACER_TEST_PORT=4391 bun x playwright test
# Return to the repository root after the browser suite rebuilds the tracer.
bun scripts/browser-auth/check-merged.mjs
MERGED_OPEN_IDLE_SECONDS=620 bun scripts/browser-auth/check-merged.mjs
python3 scripts/verify-server-idle.py --binary target/x86_64-unknown-linux-musl/release/infraternal
python3 scripts/verify-agent-multi.py --binary target/x86_64-unknown-linux-musl/release/infraternal
python3 scripts/verify-agent-writer-size.py --binary target/x86_64-unknown-linux-musl/release/infraternal
python3 scripts/verify-agent-multi-scale.py --binary target/x86_64-unknown-linux-musl/release/infraternal
python3 scripts/verify-agent.py --binary target/x86_64-unknown-linux-musl/release/infraternal
python3 scripts/verify-agent-flood.py --binary target/x86_64-unknown-linux-musl/release/infraternal
```

The default browser-test port remains 4173. Another worktree's server occupied
it during this job; TRACER_TEST_PORT selects an isolated localhost port in both
the test runner and test double without stopping unrelated processes.

Browser checks use Playwright 1.61.1 / Chromium 149.0.7827.55. Keep the tracer
assets stable during real-browser verification; run its build/test suite first.
The fixture copies the production assets into its private run directory so
a concurrent rebuild cannot replace modules during a native ceremony.
Safe production mobile setup/login and terminal/probe screenshots from the
historical run were removed under D262. Fresh screenshots belong under
`$HOME/.cache/codex-scratch/integration/evidence/screenshots/` and should be
attached for review, without visual-quality approval by the job. No arbitrary
failure screenshots or traces
capture auth/recovery ceremonies. The inherited onboarding screenshot helper
captured browser-generated recovery words even against the test double; its
recovery grid and setup-token input are now masked, and this job's earlier
recovery screenshots were removed.

## Measurements and bounds

Local x86_64 Linux host, eight virtual cores on Intel i9-9900K @ 3.60 GHz
(KVM); this is not the pinned perf VM [42].
Historical load and full-output receipts were removed under D262; fresh runs should retain them under `$HOME/.cache/codex-scratch/integration/evidence/`.
Do not extrapolate one-session numbers to all users or global live streams.

| Probe | Result |
| --- | --- |
| Earlier isolated native-browser 500-key paint baseline, all 500 complete | p50 14.00 ms, p99 16.40 ms; resume 93.10 ms |
| Earlier isolated real leg-A/server/daemon/shim/PTY echo baseline, 500 keys | p50 1.130 ms, p99 1.903 ms |
| Final static native functional acceptance, 500/500 keys and logout | PASS; paint p50/p99 15.00/62.30 ms, resume 156.10 ms; timing gate FAIL |
| Final static raw server echo, 500 exact bytes | p50/p99 1.015/19.920 ms; 5 ms p99 budget FAIL on loaded host |
| 32 simultaneous writers/viewers × 200 distinct inputs | 6400 Acks; p50 0.473 ms, p99 2.825 ms; 0.413 s |
| Full-peer exact output | 19200 bytes per viewer, 614400 delivered bytes, identical order and exactly 200 tokens per writer |
| Full-peer process RSS | daemon 6212 KiB, shim 9732 KiB; load 3.92/3.30/4.64 |
| Real daemon crash replay | 24 abrupt stops, all four stop positions × six; 4710396 payload bytes exactly once |
| Shared-device crash replay | independent Acks; both full acknowledged ranges replayed after SIGKILL; exactly 37 bytes including the new fence |
| Last typist [74] | real stty reports A 24×80 and B 40×120 in both viewers |

The 32-peer probe uses bounded initial 1 MiB credit per viewer (19200 bytes
used). Refunding every tiny output frame saturated the deliberate eight-command
queue in the faster optimized build; the fixture was corrected, with no queue
limit or exact-output assertion relaxed. Server writer admission/lookup at its
512-retained-writer capacity remains measured in `fix-round.md`.

Before TCP_NODELAY, the same real 500-key debug echo measured p50/p99
48.021/68.082 ms. The fix matches the existing TLS acceptor; after it, debug
3-viewer echo measured 3.705/12.033 ms. A concurrent-renderer static sample was
1.971/15.121 ms. Isolated server-overhead timing closes browser viewers after
the complete UI/device proof; the production paint probe separately includes
rendering. These loaded-host failures remain visible, not perf-VM evidence.

The idle canary observes scheduler activations of every live thread, not coarse
CPU ticks. The first fresh static server scheduled four times in 620.001 s due
to SQLx's default 600-second pool reaper. Local SQLite now retains at most eight
connections without idle/lifetime reaping; no engine or library changed. Both
short static canaries pass with zero activations (no session and shared idle PTY).
The fresh static server now has zero activations over 620.004 s (load
4.07/3.53/4.25), versus four over 620.001 s before the fix. The first full
native two-viewer observation found another timer: 7761 activations in 620.002 s,
with both clients reconnecting every 30 s. A new real socket regression failed
before the fix and now answers Ping after 31 quiet seconds. Empty post-Hello
reads now wait without a timer; begun mux frames still have five-second
completion deadlines, and admission/expiry/revocation/write bounds remain.
An unfinished RFC fragment cannot hide committed logout (real regression passes).
Axum-hidden post-Hello RFC fragments are now bounded by size, permits and live
authority rather than the former idle-read timer; that draft-contract change was
proposed on #34 before implementation. The final long two-viewer retest is
recorded on #34. Initial retests kept both viewers connected but observed one
activation in 620.004/620.015 s. Timestamped events at 273.991 s and 264.405 s
tracked the startup health connection's late EOF, not periodic server work.
The corrected fixture sends Connection: close for that probe and checks procfs:
zero established backend connections before the no-session window, exactly the
two intended WebSockets before shared idle. A controlled no-auth/no-PTY
reproduction observed one activation at 299.091 s / 310.007 s when its pooled
health connection closed. The corrected final static native run observed zero
activations / 620.002 s with both signed-in devices connected (RSS 13696 KiB).
The independent final no-session 620.002 s observation also had zero activations.
The threshold remains zero.
Alacritty remains the VT engine; credited/starved 50 MiB flood results are
reported on #34 and are nonblocking for this integration. The credited
50 MiB run completed at 1.738 MiB/s (52,429,168 total bytes in 28.763 s;
daemon RSS 6068 KiB, load 16.29/7.23/5.48). Concurrent unrelated builds
loaded this eight-core host; this is measured protocol/PTY/Alacritty throughput,
not a renderer or pinned-perf-VM result. The earlier combined benchmark timed
out at its 20-second flood observation; the separate diagnostic keeps the
actual throughput visible without changing any production budget. A subsequent
run validated every one of the 50 MiB payload bytes: 0.874 MiB/s (57.210 s;
daemon RSS 6048 KiB, load 33.87/17.07/9.37). Both loaded-host samples are kept.

The full 14-case browser suite passed all 12 functional/renderer cases on three
loaded-host runs. The latest unchanged timing gates failed: paint p99 38.7 ms
(limit 20 ms), setup render upper bound 1189.4 ms (limit 1000 ms), actual FCP
p99 527.3 ms. Eight-core load reached 27–28; a two-second CPU sample had 0%
idle. A loaded native run also stopped at Ack129 and repeatedly reconnected; another
failed to replay on device-A restoration. The complete later native run passed
every functional/revocation assertion, including all 500 exact raw echo bytes.
These failures remain recorded and require a quiet CPU window; no
threshold, sample count, case or renderer corpus was removed. The retained
native fixture finishes both-device logout before its per-browser paint probe
(one active frontend) and collects all performance failures before exiting
unsuccessfully, so slow timing does not suppress later functional evidence.
Required final Playwright and timing acceptance remains blocked on that resource
window; this checkpoint is not a completed deployment handoff.

## Self-review and remaining boundaries

Checked the auth review areas B1/S1/S2/N1 in `auth.md` and the shim/wire safety
and budget invariants: trusted uid, origin/cookie predicates, ownership before
attachment, post-commit revocation, unsigned per-writer Ack, actual partial PTY
writes, duplicate/gap/overflow refusal, bounded memory, legacy frame preservation,
capability negotiation and last-typist geometry. Real failing oracles preceded
the boundary, reload, delayed-Ack and periodic-idle fixes. Additive SelectWriter
has a frozen-byte regression, all split schedules and malformed-length checks;
the existing shim fuzz target covers owned/borrowed decoding and stream splits.
The sanitizer/libFuzzer campaign completed 1,138,785 runs in 61 s without a
crash (coverage 567, features 1599).

The surviving shim retains at most 32 live peers and 512 nonzero writer identities
plus legacy zero. Its input queue is globally at most 1 MiB; ownership segments
are bounded by queued bytes. Per-peer pending frames and decoders are bounded by
MAX_FRAME; do not treat the measured small-input RSS as their worst-case memory.
The daemon remains limited to 128 live streams, eight queued commands per stream,
eight shared writer slots and one pending output frame per terminal task.

Remaining #28 multi-device PTY acceptance is proved within the existing writer
identity/resume contract. Unacknowledged input beyond the 120-second connection
resume window still needs the previously recorded durable writer capability;
this additive choice remains with the owner. Shim/host crashes are outside the
PTY-write deduplication guarantee. Physical iPhone/Safari and independent security
and visual review remain external; this job does not claim those checks.
`docs/PROCESS.md` is absent in this checkout, so its referenced §2 checklist
could not be read; the supplied Definition of Done and available area review
checklists were followed.
