<!-- Records run8 pinned o1 network findings, cold CLI proof, isolated transport diagnostics and remaining #78 work. -->
# Remote infraternal agents: run 8

Phase 1 remains incomplete. Nothing was pushed or deployed; the job did not
merge into dev. Dev integration is `ec40b6d` (dev `5e483ed`) followed by `40737a8`
(dev `f63307e`). Older browser comparisons below apply only to the first merge.

## Atomic history

| SHA | Change | Full fast proof |
| --- | --- | --- |
| 7bb98ef | Pinned rootless o1 harness and installation cleanup | [host harness](remote-agents/run8-gate-host-harness.log) |
| 1b4e140 | Retained public trust, cold-locked signing source | [trust loader](remote-agents/run8-gate-startup-source.log) |
| 8089901 | Explicit normal CLI remote listeners and service options | [CLI activation](remote-agents/run8-gate-cli-startup.log) |
| 408667b | Real TLS negative tests and normal CLI cold restart | [startup tests](remote-agents/run8-gate-startup-tests.log) |
| f170adb | Retained authority cancellation on revocation/expiry | [authority source](remote-agents/run8-gate-revocation-core.log) |
| eb29a72 | Session-authorized HTTPS revocation and cancellation-safe commit | [revocation API](remote-agents/run8-gate-revocation-api-source.log) |
| b23cecb | Real QUIC, HTTP cancellation and normal CLI revocation tests | [revocation tests](remote-agents/run8-gate-revocation-api-tests.log) |
| fb1b4ed | Rootless o1 proof through separately pinned TCP forwards | [o1 harness](remote-agents/run8-gate-o1-relay.log) |
| 40737a8 | Latest dev predictive input/renderer fixes | [dev merge](remote-agents/run8-gate-merged-f633.log) |
| dcad48c | Revocation API and generation-bound retirement contract | [contract](remote-agents/run8-gate-lifecycle-contract.log) |
| fa78142 | Release revoked/expired host registry slots | [runtime](remote-agents/run8-gate-retirement-source.log) |
| eec1621 | Real mTLS retirement/replacement tests and 1,000-host diagnostic | [retirement tests](remote-agents/run8-gate-retirement-tests.log) |

The startup is deliberately partial: standalone HTTPS uses the retained
internal issuer for join and remote mTLS. It validates the server leaf/key and
public-origin SAN, refuses missing/unsafe trust without regeneration, and loads
no CA signing key. Administrator envelopes/passkey unlock and update IPC remain
unimplemented. The existing memory policy/handoff interface is preserved.

## o1: pinned TCP relay proof; direct connectivity blocked

The owner authorized first-use trust on #78. The test fetched the ed25519 SSH
host key through NetBird and pinned it in its dedicated known_hosts with strict
checking enabled. Fingerprint:
`SHA256:uMAQHBbZ/cuo8T3nCMhAu30Y2XPSenXqlLYkSiJF9ww`.
No default/global known_hosts was changed.

The rootless aarch64 binary was hash-verified on o1, uid 1002. Four isolated
installation attempts were completely removed (processes=0, data/state absent).
The initial join could not register. Independent Python TCP probes on o1,
while the dev server listened at 10.69.69.125, timed out:4701 in 3006 ms and7443
in 3003 ms. The updated harness refuses unreachable ports before issuing an
invitation. [Raw network/cleanup evidence](remote-agents/run8-o1-network.log).

Direct connectivity remains blocked. A diagnostic route through pinned NetBird
SSH remote TCP forwards proved a real rootless o1 terminal without changing
network policy or using monitor01. Two forwards in one NetBird SSH connection
incorrectly routed both ports to the first backend; independent labelled probes
reproduced it twice. Separate strict SSH connections per port route correctly.
The trusted operator fixture privately advertises its forwarded loopback endpoint
while retaining issuer/SAN verification, host-generated key and one-time token.
This is actual TCP/mTLS routing through o1, not direct UDP/QUIC acceptance and
not the product SSH bootstrap adapter. No o2 proof ran.

At `fb1b4ed`, the aarch64 static binary was 15998184 bytes, SHA256
`ae23f392d7638686a9adc9ea4cbded1b457e5a9a12d059ac0803ce1b3d566663`.
Its uid was1002; o1 load0.27/0.22/0.19, dev load0.81/1.58/1.72, 8 dev CPUs.
The shorter test-only state namespace preserves all128 random UUID bits and
makes the shim socket path98 bytes rather than113 (Linux sun_path cap108
including NUL). The path admission regression failed before this fixture fix.

| Measurement | Real o1 TCP-relay result |
| --- | --- |
| Join to first terminal | 3230501 us |
| Command RTT, 25 samples p50/p99 | 197048/201628 us |
| Single-byte echo, 25 samples p50/p99 | 193924/197947 us |
| Authoritative terminal output | 5401 contiguous bytes, zero loss/duplication |
| Daemon idle | 0 scheduler activations /10.000s, 10828 KiB RSS, 1 thread |
| Desktop keydown-to-glyph, 25 samples p50/p99 | 197.90/215.50 ms |
| Phone viewport keydown-to-glyph, 25 samples p50/p99 | 198.20/208.70 ms |

The byte probe fences authoritative shim Acks and uses distinct ASCII keys;
three durable writers were independently acknowledged. It is a short diagnostic,
not a general chaos byte oracle. RSS ×1000 nodes is10828000 KiB across hosts;
only one daemon was measured and separate shim/server costs are excluded. The
browser used real production assets and HTTPS/WSS/PTY routing, with inspection
hooks only. Its isolated CA required browser HTTPS test trust; join and remote
mTLS verification remained enabled. The phone viewport is Chromium, not physical
Safari certification. All proof installations were removed: zero processes and
absent data/state directories. Subsequent dev UI changes require fresh browser
measurements; these numbers apply to the recorded tree.

[Unedited o1 proof and cleanup](remote-agents/run8-o1-tcp-relay-browser.log).
Production screenshots supplied for owner review:
[desktop](remote-agents/run8-o1-relay-screenshots/desktop.png),
[phone viewport](remote-agents/run8-o1-relay-screenshots/iphone.png).

## Real normal-CLI cold restart

At408667b, the initial fixture enrolled a separate rootless static CLI and
opened a real PTY through HTTPS/WebSocket, the remote registry and QUIC.
The fixture stopped, then the actual static normal server CLI started from
retained public issuer and server-leaf files. The CA private key remained only
in the initial fixture's memory; it was never persisted. An in-process fixture
must wait for QUIC close-drain port release before launching a replacement;
that fixture fix did not alter a production deadline.

The replacement re-admitted the existing host and reattached its original
terminal in 343154 us; a command round trip took6370 us. All348 observed output
bytes had contiguous offsets. This short test is not a general chaos byte oracle.
Locked join returned403, minted no certificate and kept its invitation usable.
Load8.79/9.11/16.14 on infraternal-dev (8 logical CPUs).
[Actual static-process proof](remote-agents/run8-normal-cli-cold-proof.log).
Trust loader and CLI tests each passed 3/3 with real OpenSSL.

## Immediate revocation and retained expiry authority

`f170adb` retires both transport directions on ledger revocation and the admitted
certificate's monotonic expiry. Real TCP regressions failed before the fix;
real idle QUIC cancellation now passes. The registry and actor reject new
Open/Attach operations while existing streaming input uses event/deadline checks,
without a SQLite lookup for every key. Certificate expiry cannot be extended by
wall-clock rollback during admission.

`eb29a72` adds the bounded owner revocation API, including current session and
ownership checks inside its SQLite transaction. The router and listeners share
one event scope. A failed-first cancellation test exposed a SQLite worker commit
whose caller never resumed to publish cancellation. A process-owned commit and
notification finalizer fixes that race. Cancellation before authorized mutation
still rolls back. This adds no healthy-idle polling worker.

The normal static CLI cold-lock proof at `b23cecb` reattached in241607 us, command
RTT2682 us,340 contiguous bytes; revocation took1408 us over HTTPS, with browser
refusal1057 us after commit. The300 ms observation saw zero new Acks and both
shims remained alive. Load1.63/1.75/2.22. These are small local tests, not host
chaos acceptance. [Normal CLI revocation](remote-agents/run8-revocation-normal-cli.log).
Authenticated removal/uninstall and live renewal are not implemented.

Optimized guard component measurement:1000 retained guards added636 KiB
(.636 KiB/guard). One million permits checks took37421544 ns (37.4 ns/check;
empty loop524784 ns);100 operation ledger reads took9038 us (90.38 us average).
Load4.06/4.75/6.99. This excludes actor/transport/daemon memory and is diagnostic.
[Guard component measurement](remote-agents/run8-guard-bookkeeping.log).

## Fresh D167 diagnostics

Locked optimized current infraternal-agent test build at 408667b, CPUWeight10000;
no own build/browser overlap. Each transport measured 25 admitted mTLS handshakes
through a fixed300 ms-RTT userspace relay, then retained1000 actual connection
pairs. These are combined client/server transport deltas, excluding whole-host
registry, daemon, shim and PTY costs; they are not pinned performance acceptance.

| Transport | p50/p99 handshake | KiB per pair | Actual 1000-pair delta | Connection CPU ticks | Load |
| --- | --- | --- | --- | --- | --- |
| QUIC/BBR | 455323/457055 us | 67.700 | 67700 KiB | 82 | 3.77/6.71/13.94 |
| TCP/TLS | 758030/760230 us | 69.964 | 69964 KiB | 278 | 2.66/5.57/12.87 |

The initial TCP runs exhausted the inherited soft descriptor limit 1024; the
unchanged1000-pair diagnostic passed with soft limit 8192. Raw
[QUIC](remote-agents/run8-transport-quic.log),
[TCP](remote-agents/run8-transport-tcp.log) and
[initial descriptor exhaustion](remote-agents/run8-transport-tcp-fd-limit.log).

A separate local rootless static CLI proof measured 14628 KiB full-daemon RSS,
2 threads, zero scheduler activations/10.001s, join-to-terminal100758 us and
command RTT6376 us at load2.38/5.23/12.52. Estimate at 1000 nodes:
14628000 KiB across hosts. Only one daemon was measured, its separate shim/server
are excluded, and this is not a concurrent1,000-daemon proof.
[Local idle and terminal proof](remote-agents/run8-local-idle-proof.log).
Live renewal CPU/RSS/bytes remain unmeasured because no live renewal path exists.

## Registry retirement at the 1,000-node design point

The failed-first real TCP/mTLS regression exposed a retained revoked actor and
its capped registry slot. The cleanup at `fa78142` uses the existing revocation
signal and one certificate deadline; each accepted replacement owns a fresh
generation and cancels its old waiter. A weak registry reference prevents a
retention cycle. Ordinary socket loss preserves offset-recovery state. Only
in-memory actors/attachments retire; durable tombstones and shims remain.
[Failed-first regression](remote-agents/run8-retirement-before.log).

Optimized infraternal-dev diagnostic, 8 CPUs, CPUWeight10000, soft FD8192, no own
build/browser overlap:1,000 actual signed TCP/mTLS hosts, corresponding live
server actors and client peers. Client credentials, listener and ledger were
allocated before the baseline. This delta includes both transport ends and
server actors; it excludes PTY/shim/full-daemon memory and is not pinned acceptance.

| Implementation | Actual 1,000-host delta | Per host | Local handshake+Hello p50/p99 | Load | Entries after revocation |
| --- | --- | --- | --- | --- | --- |
| Before cleanup | 128308 KiB | 128.308 KiB | 2665/4233 us | 4.23/3.77/2.99 | 1000 |
| With cleanup | 128836 KiB | 128.836 KiB | 2232/4065 us | 2.94/3.41/3.22 | 0 |

Cleanup adds528 KiB across1,000 hosts (.528 KiB/host); all1,000 durable
revocations and cleanup completed in154318 us. The differing shared host load
limits the handshake comparison. The active tests cover slot release, retained
actor refusal, and an old expiry failing to remove a freshly renewed/reconnected
identity; that replacement test does not demonstrate automatic live renewal.
[Registered regression gate](remote-agents/run8-gate-retirement-tests.log).
[Baseline](remote-agents/run8-registry-baseline.log),
[cleanup comparison](remote-agents/run8-registry-after.log).

Fresh isolated transport refresh after the lifecycle experiment (unchanged
infraternal-agent/protocol/lockfile source since408667b, same optimized artifact):
QUIC at300ms RTT,25 handshakes p50/p99454762/456677 us; actual1,000 pairs added
67668 KiB (67.668 KiB/pair),85 connection CPU ticks, load2.21/3.03/3.10.
TCP p50/p99757112/758451 us;1,000 pairs69964 KiB (69.964 KiB/pair),181 ticks,
load1.46/2.45/2.88. These transport-only numbers exclude retained actors and
are separate from the registry measurement above. Raw
[QUIC refresh](remote-agents/run8-transport-quic-final.log),
[TCP refresh](remote-agents/run8-transport-tcp-final.log).

## Browser result after the dev merge

The full merged production suite at `ec40b6d` was red:51 passed,21 skipped,
7 failed (13.3min), port4701 and CPUWeight10000. The earlier interrupted suite
is not evidence. No own build/performance measurement overlapped the completed
suite. [Full browser log](remote-agents/run8-browser-merged.log).

The UI, protocol and mock-server sources are byte-identical to merged dev
`5e483ed`. A separate source snapshot ran the failing files with the same scope
and port. Five failures reproduce on dev: motion169px versus expected190px,
phone/desktop sign-in snapshots, reconnect p99 (branch962.2ms/dev979.0ms versus
900ms), and access setup/first-paint flow. Setup render upper bound p99 is
1815.7ms on branch and1821.1ms on dev versus1000ms; the final failing assertion
in that case is a missing setup control, not that reported timing metric.
[Dev comparison](remote-agents/run8-browser-dev-comparison.log).

The other two full-suite failures were request refusals at `::1:4701` in
mobile-scroll/Unicode fixtures. Both pass separately on dev and both pass on
an unchanged branch retry (2/2); the full-suite red result remains recorded.
[Dev mobile check](remote-agents/run8-browser-dev-mobile.log),
[branch retry](remote-agents/run8-browser-ipv6-retry.log). No threshold, snapshot
baseline or skip condition was changed. Neither this comparison nor a green
fast gate certifies the required browser budget.

Production core-screen screenshot test passes1/1. Images are supplied for
independent visual review; they show the merged production tracer, not o1:
[desktop paper](remote-agents/run8-screenshots/tracer-core-1440x900-paper-sidebar-closed.png),
[desktop ink](remote-agents/run8-screenshots/tracer-core-1440x900-ink-sidebar-closed.png),
[phone paper](remote-agents/run8-screenshots/tracer-core-393x852-paper-sidebar-closed.png),
[phone ink](remote-agents/run8-screenshots/tracer-core-393x852-ink-sidebar-closed.png).
[Capture gate](remote-agents/run8-browser-screenshots.log).

## Browser result on dev f63307e production assets

The new merged full suite was red:59 passed,22 skipped,7 failed (15.7min),
port4701/CPUWeight10000; no own build/host performance overlap. The later Rust
regression source additions did not change browser production assets. The
renderer, predictive input, shared overlay, build and test backend match dev
`f63307e` byte-for-byte. [Full suite](remote-agents/run8-browser-f633.log).

An isolated dev snapshot ran the seven failing cases under the same scope and
port:5 failures reproduce (motion190px versus169px, both sign-in snapshots,
reconnect branch1060.8ms/dev1010.9ms versus900ms, and access screens). Setup
render upper-bound p99 was1853.6ms on branch and1906.2ms on dev versus1000ms;
the final access failure was a missing setup control. Prediction CPU p99 was
5.5ms on the branch full suite versus the2ms budget, while the isolated dev run
passed at0.9ms. [Matching dev comparison](remote-agents/run8-browser-dev-f633.log).

The layout-change case failed with a test-backend socket hangup; it passes on
dev and on an unchanged branch retry. Palette filtering remains unresolved:
full suite0.144ms/input and retry0.177ms/input versus0.13ms; the isolated dev case
passed. [Branch retry](remote-agents/run8-browser-f633-retry.log). This variation
is not a proven remote-code regression or performance acceptance. No threshold,
skip or screenshot baseline was changed; the browser gate remains red.

Positive diagnostics: predicted glyph p9913.5ms passes17ms, returning sign-in
p994307.4ms passes5000ms, and50MB prediction off/on median throughput2.67/2.83MB/s
(+5.81%) passes the5% regression budget. These are production tracer measurements
against the browser test backend, not the real o1 path. Completion load was
2.88/3.05/2.59 on infraternal-dev (8 CPUs).

Fresh production core captures pass3/3, including phone/desktop UI-font choices.
Images are supplied for independent review, not assessed for visual quality:
[desktop paper](remote-agents/run8-f633-screenshots/tracer-core-1440x900-paper-sidebar-closed.png),
[desktop ink](remote-agents/run8-f633-screenshots/tracer-core-1440x900-ink-sidebar-closed.png),
[phone paper](remote-agents/run8-f633-screenshots/tracer-core-393x852-paper-sidebar-closed.png),
[phone ink](remote-agents/run8-f633-screenshots/tracer-core-393x852-ink-sidebar-closed.png).
[Capture log](remote-agents/run8-browser-f633-screenshots.log).

## Author review and remaining acceptance

Checked bounded/no-follow trust reads, owner/mode/regular-file checks, actual
leaf chain/SAN/key verification, fail-closed cold signing, absence of CA-key
regeneration/persistence or argv unlock secrets, service-option preservation,
real TLS/PTY routing, fixture cleanup and unchanged dependencies/licenses.
Auth B1/S1/S2/N1 principles were applied; no new parser or crypto engine was
introduced. The retained authority revocation/expiry findings now have failed-first and real
TCP/QUIC regression evidence. Review also checked current owner/session checks,
request cancellation around the SQLite commit, shared runtime event scope,
generation-specific cleanup after successful queue admission, weak map ownership,
cancellation of superseded waiters and release at1,000 actual TLS hosts,
unchanged join shape, real remote-host UID, byte/Ack probes and complete cleanup.
Live renewal and production administrator unlock findings remain open.

Still required: encrypted per-administrator CA envelopes/passkey adapter and
notifications, issuer overlap/rotation, half-life live renewal with atomic host
identity replacement and load costs, authenticated removal/uninstall, enforced
fail-closed lease, direct o1/o2 connectivity and rootless chaos, complete
fleet-scale evidence and independent security/device review.

The unregistered inherited `crates/infraternal-agent/src/remote_lease.rs` is not
lease enforcement. Scratch/build/evidence directories are not commit contents. No production
private CA material or invitation was persisted or logged by these fixtures.

## Historical fast gate after the first dev merge

Exact requested Nix gate, CPUWeight10000, TRACER_TEST_PORT4701, exit0.
[Unedited full output](remote-agents/run8-gate-merged-docs.log). Verbatim:

```text
+---------------------------+--------------+
| Rust gate                 | Result       |
+---------------------------+--------------+
| fmt                       | PASS         |
| VT native fmt             | PASS         |
| clippy                    | PASS         |
| test                      | PASS         |
| cargo-deny                | PASS         |
| static builds             | PASS         |
+---------------------------+--------------+

PT_INTERP: absent; size: 19005488 bytes (baseline 18982128 + allowance 262144 = max 19244272)
PT_INTERP: absent; size: 15950856 bytes (baseline 15934232 + allowance 262144 = max 16196376)

7 pass
 0 fail
 34390 expect() calls
Ran 7 tests across 2 files. [2.60s]
```


## Latest implementation fast gate

The exact requested Nix gate at `eec1621` passes with both new retirement
regressions registered, CPUWeight10000 and TRACER_TEST_PORT4701, exit0. Completion
load3.56/2.26/2.24. The previous runtime-only gate used the original test inventory
and is separately retained. No static size baseline changed.
[Unedited full test gate](remote-agents/run8-gate-retirement-tests.log). Verbatim:

```text
+---------------------------+--------------+
| Rust gate                 | Result       |
+---------------------------+--------------+
| fmt                       | PASS         |
| VT native fmt             | PASS         |
| clippy                    | PASS         |
| test                      | PASS         |
| cargo-deny                | PASS         |
| static builds             | PASS         |
+---------------------------+--------------+

PT_INTERP: absent; size: 19077936 bytes (baseline 18982128 + allowance 262144 = max 19244272)
PT_INTERP: absent; size: 16015544 bytes (baseline 15934232 + allowance 262144 = max 16196376)

7 pass
 0 fail
 34390 expect() calls
Ran 7 tests across 2 files. [2.56s]
```


## Evidence checkpoint fast gate

The report and cited production screenshots also pass the exact requested Nix
fast gate on the unchanged implementation/test tree, CPUWeight10000, port4701,
exit0. Completion load5.49/2.86/2.25. Dev remains `f63307e`, already merged.
[Unedited full checkpoint output](remote-agents/run8-gate-evidence.log). Verbatim:

```text
+---------------------------+--------------+
| Rust gate                 | Result       |
+---------------------------+--------------+
| fmt                       | PASS         |
| VT native fmt             | PASS         |
| clippy                    | PASS         |
| test                      | PASS         |
| cargo-deny                | PASS         |
| static builds             | PASS         |
+---------------------------+--------------+

PT_INTERP: absent; size: 19077936 bytes (baseline 18982128 + allowance 262144 = max 19244272)
PT_INTERP: absent; size: 16015544 bytes (baseline 15934232 + allowance 262144 = max 16196376)

7 pass
 0 fail
 34390 expect() calls
Ran 7 tests across 2 files. [2.91s]
```
