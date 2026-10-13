<!-- Records run 7 size investigation, gated remote-runtime slices, real local proof and remaining #78 acceptance. -->
# Remote infraternal agents, run 7

> Raw screenshots, logs and receipts referenced by this report were removed under D262. The
> recorded results remain; new outputs belong in job scratch and should be attached to the
> relevant issue with the `issue-attach` helper.

Phase 1 remains incomplete. This run commits the configured-server local
remote path and stops before real-host proof because o1 is not trusted in the
server's known_hosts. No SSH/key scan, host installation, push, deployment or
merge back occurred. `git merge dev` reports already up to date (dev e19c4eb).
Issue #78 is the record; #34 now includes the exact rootless identity path.

The running server supplied a trusted `RemoteService` serves invitation/join,
registers admitted outgoing hosts and routes browser terminals through the
existing terminal actor with enrolled uid and durable server writer ids.
The operator CLI supports private-stdin join/run and private atomic no-replace
identity publication. Browser/session host authority is durable and rechecked.
Missing or foreign remote hosts never fall back to the local server host.

**Normal CLI server startup still calls `serve` without a `RemoteService`.**
Current administrator/passkey envelopes, encrypted XDG CA storage and default
startup wiring are not delivered. The test server uses the explicitly trusted
memory-only administrator fixture adapter. The local configured-server proof
is not complete production enrollment acceptance or an o1/o2 demonstration.
Enrollment HTTPS must chain to the invitation's pin; separately configured
browser-facing HTTPS trust needs explicit integration, not a verification
bypass. The stable API shape remains in `contracts/remote.md` for #87.

## Atomic history and fast gates

| Commit | Logical step | Exact full fast log under remote-agents/ |
| --- | --- | --- |
| 33bd23a | Measured size baseline/rationale only | run7-gate-baseline.log |
| a4d1c65 | Existing HTTP test dependencies | run7-gate-test-deps.log |
| baf36bb | Operator join/run module | run7-gate-operator.log |
| ac03ab0 | Coupled private bridge/registry/actor/browser integration | run7-gate-runtime-green.log |
| bed97b3 | Security, transport and real-browser proof fixtures | run7-gate-proof.log |

Every row exited0: all six Rust rows PASS, production tracer check/build and
transfer budget PASS, protocol7pass/0fail,134streams/11,439schedules with zero
divergences. A source-splitting attempt caught an unused test-only listener
helper in Clippy; the helper moved with the fixtures before the full green
runtime rerun. No test threshold was relaxed. A mistaken `--lib` CLI test
selection was corrected to the binary target; all five new security tests pass.

Both complete binaries are stripped/static without PT_INTERP: x86
18,982,128 bytes and ARM15,934,232 bytes. Baselines record those exact measured
values with the unchanged262,144-byte allowance. The requested growth target
was missed; [the size report](remote-agents-run7-size.md) supplies dev/head
bloat, symbols, duplicate trees, ELF deltas, before/after provider performance
and the rejected OpenSSL-reuse candidate. No second-provider change remains.

## Local real-engine evidence

Machine: infraternal-dev, i9-9900K, eight visible cores, Linux6.12.111+deb13,
32GB RAM. CPUWeight10000 scopes, no own build/benchmark overlap. Server harness
is debug; host CLI is the actual static optimized artifact. Local RTT0.
One sample per transport is not a reconnect or join distribution.

| Check | QUIC | Forced TCP fallback |
| --- | ---: | ---: |
| Join to usable terminal | 108,918us | 225,479us |
| Command echo | 7,086us | 5,572us |
| Full host daemon idle RSS | 13,384KiB | 12,980KiB |
| Scheduler activations /10s | 0 | 0 |
| Threads | 2 | 2 |
| Process absence in restart sample | 688,031us | 787,490us |
| Recovery after replacement process starts | 33,593us | 133,751us |
| Contiguous delivered output bytes through restart | 1,313 | 614 |
| Surviving shim during restart /after cleanup | 1 /0 | 1 /0 |

Evidence: `run7-demo-quic-browser.log` and `run7-demo-tcp.log`. Both use the
real HTTPS router, a separate rootless operator process and real PTY. The
foreign owner is refused before creating a session. The QUIC proof has three
distinct durable writers, independently acknowledged. Snapshot/approximate
recovery continues through the existing actor; these short live-PTY runs do
not certify ring-gap recovery under remote chaos. Continuous output offsets
and replay checks are not a fleet or packet-loss claim.

The full-daemon RSS extrapolations at1,000 are13,384,000/12,980,000KiB. These
are estimates spread across hosts, not a concurrent1,000-process measurement.
Transport diagnostics separately retain1,000 **combined client/server pairs**:
QUIC delta67,712KiB (67.712KiB/pair); TCP69,964KiB (69.964KiB/pair). They
exclude full daemon/host-registry/PTY state. The size report records repeated
low-load samples, CPU ticks and all scope limitations; neither number is
isolated server memory per complete enrolled host.

RTT300, optimized transport n25: QUIC handshake p50/p99
454.630/456.372ms; TCP758.136/760.225ms. First protocol Hello:
QUIC455.714/457.639ms; UDP-blocked fallback868.090/871.162ms. These are fixed
300ms relay diagnostics, not the jittered full-browser profile, full session
open, pinned performance certification or live renewal. The exact50MiB
transport test checks all application bytes, but its userspace UDP relay
retransmits; no clean-link throughput claim follows. Live renewal CPU/RSS/bytes
and real-host reconnect p50/p99 are still unmeasured.

## Production browser evidence

The local real remote path uses production Ghostty assets, not mocked HTTP,
WebSocket or terminal traffic. `mock=1` enables existing renderer inspection
hooks only. Browser trust exceptions apply only to the memory-only fixture CA;
the operator verifies its pin and hostname. Fixture authority stays in memory
and private stdin; no traces, storage-state files or request logs are captured.
The Ed25519 internal CA and host key remain unchanged; the browser-facing test
leaf uses the already supported P-256 certificate for Chromium compatibility.

Desktop/iPhone enter-to-observed-glyph:72.937/73.228ms (Playwright observation).
The renderer's n25 keydown-to-glyph p50/p99: desktop15.00/17.80ms;
iPhone14.40/29.70ms. P99 exceeds17ms. Chromium iPhone viewport emulation is
not physical iPhone or Safari evidence. Screenshots are attached for human
review; this report makes no visual-quality approval claim:

- Desktop
- iPhone viewport

The full production suite on TRACER_TEST_PORT4701 exits1: **47 passed,
21 skipped,6 failed (13.9m)**. The six failed cases, rerun against archived dev
`e19c4eb` under the same CPUWeight10000 scope and port, all fail there too.
No job-owned build/performance measurement overlaps either browser run.
`git diff dev -- apps/tracer packages/ui packages/protocol
scripts/latency_proxy.py` is empty; these tests use the unchanged Node test
double and renderer, not the newly added Rust remote service.

| Failed check | Branch | Dev comparison | Unchanged requirement |
| --- | ---: | ---: | ---: |
| Tooltip width | 169px | 169px | 190px |
| Glyph/bar alignment, DPR1/2/3 | fail at all3 | same failures | exact pixel assertions |
| Mock browser reconnect p99, n20 | 978.7ms | 995.3ms | 900ms |
| Setup render upper bound p99, n30 | 1,563.7ms | 1,533.7ms | 1,000ms |
| Sign-in render upper bound p99, n30 | 1,850.0ms | 1,859.8ms | 1,000ms |

Low-load samples are embedded in both logs (branch near0.1–0.45, comparison
near0.56–0.78 during glyph cases). Evidence: `run7-browser-full.log` and
`run7-browser-dev-comparison.log`. This is a **red browser gate**, not an
exception or new acceptance claim. No thresholds, test assertions or UI source
were changed to hide it. The branch's all-case fast gate remains green.

## Trust boundary and remaining work

`run7-o1-trust.log` records the read-only prerequisite. NetBird's help specifies
`~/.ssh/known_hosts` and strict checking by default; `ssh-keygen -F` finds no
records for10.69.69.51, o1 or[10.69.69.51]:22. **Owner kayg must confirm the
fingerprint/provision trusted known_hosts before the o1 step.** No untrusted
host key was accepted, and nothing was installed on o1/o2 to clean up.

Outstanding phase1: production administrator envelopes/unlock/role rewrap/
notifications and startup; CA rotation overlap; half-life live renewal without
session interruption; immediate active revocation and contact-driven removal;
operator uninstall; integrated fail-closed lease; rootless o1/o2 chaos and
real-host/reconnect/renewal/performance acceptance. The inherited
`remote_lease.rs` prototype is unregistered and does not enforce a runtime lease.

## Author review

Checked bounded CSR/invitation/response handling and existing CSR fuzz target;
verified authority before backend selection and again at publication; enrolled
uid, durable writer binding, raw wire/Snapshot/recovery reuse; private stdin,
no secret diagnostics, private fsynced no-replace identity; bounded handshake
and transport queues; fixture lifetime and authenticated shim cleanup; unchanged
licenses and dependency versions; exact static builds and budget rationale.
Auth B1/S1/S2/N1 review principles from `docs/verification/auth.md` were applied:
transaction authority rechecks, bounded admission, trusted test-only unlock and
real TLS/PTY engines, isolated modules. CA envelope/administrator integration,
remote cancellation/lease edges and full lifecycle need further review.
Historical production screenshots were removed under D262. Fresh screenshots
belong in job scratch and should be attached for independent review; security
review and physical-device validation remain external. No approval or budget-
certification claim follows from the green fast gate.

## Final fast gate

The requested Nix command under CPUWeight10000/TRACER_TEST_PORT4701 exits0.
Full unedited output follows the role header in `remote-agents/run7-gate-final.log`;
the final source also includes the five operator security tests and both real
TLS/QUIC admission tests. Summary verbatim:

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

7 pass
 0 fail
 34390 expect() calls
Ran 7 tests across 2 files. [2.24s]
```
