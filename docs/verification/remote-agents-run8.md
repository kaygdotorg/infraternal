<!-- Records run8 pinned o1 network findings, cold CLI proof, isolated transport diagnostics and remaining #78 work. -->
# Remote infraternal agents: run 8

Phase 1 remains incomplete. Nothing was pushed or deployed; the job did not
merge into dev. The required merge from dev is `ec40b6d` (dev `5e483ed`).

## Atomic history

| SHA | Change | Full fast proof |
| --- | --- | --- |
| 7bb98ef | Pinned rootless o1 harness and installation cleanup | [host harness](remote-agents/run8-gate-host-harness.log) |
| 1b4e140 | Retained public trust, cold-locked signing source | [trust loader](remote-agents/run8-gate-startup-source.log) |
| 8089901 | Explicit normal CLI remote listeners and service options | [CLI activation](remote-agents/run8-gate-cli-startup.log) |
| 408667b | Real TLS negative tests and normal CLI cold restart | [startup tests](remote-agents/run8-gate-startup-tests.log) |

The startup is deliberately partial: standalone HTTPS uses the retained
internal issuer for join and remote mTLS. It validates the server leaf/key and
public-origin SAN, refuses missing/unsafe trust without regeneration, and loads
no CA signing key. Administrator envelopes/passkey unlock and update IPC remain
unimplemented. The existing memory policy/handoff interface is preserved.

## o1: identity pinned, network proof blocked

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

No o1 terminal, join time or keystroke time is claimed. No o2 proof ran. #78
records the required o1-to-dev TCP4701 and TCP+UDP7443 reachability, or owner
approval for a monitor01 scratch listener. No monitor01 action was taken.

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

## Author review and remaining acceptance

Checked bounded/no-follow trust reads, owner/mode/regular-file checks, actual
leaf chain/SAN/key verification, fail-closed cold signing, absence of CA-key
regeneration/persistence or argv unlock secrets, service-option preservation,
real TLS/PTY routing, fixture cleanup and unchanged dependencies/licenses.
Auth B1/S1/S2/N1 principles were applied; no new parser or crypto engine was
introduced. The independent review findings on #78 remain open: live authority
revocation/expiry, live renewal, and production administrator unlock. This run
addresses normal CLI listener activation and existing-host cold routing only.

Still required: encrypted per-administrator CA envelopes/passkey adapter and
notifications, issuer overlap/rotation, half-life live renewal with atomic host
identity replacement and load costs, immediate revocation and authenticated
removal/uninstall, enforced fail-closed lease, o1/o2 rootless proof/chaos, complete
fleet-scale evidence and independent security/device review.

The unregistered inherited `crates/infraternal-agent/src/remote_lease.rs` is not
lease enforcement. Scratch/build/evidence directories are not commit contents.

## Fast gate after the dev merge

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
