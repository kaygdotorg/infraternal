<!-- Final auth recheck fixes, regression evidence and self-review for #29 [23,24,28,40]. -->
# Final auth recheck

## Shared cookie responses

At server `e4809d4`, the extended
`review3_completion_and_cleanup_are_transaction_bound` failed on the completion
response's `Set-Cookie` header (0 passed, 1 failed). Both ported reviewer probes
also failed against production client `58040df` and the real Rust/SQLite fixture:
delayed completion replaced B's pending cookie; delayed cleanup cleared B's
active cookie while its database row remained valid.

Completion, authenticated action responses and logout now emit no
cookie headers. Existing transaction checks and atomic pending-row predicates
remain the authority boundary. Server expiry slides; browser expiry is measured
from cookie issuance, so an identity response cannot restore an earlier login.
Ordinary explicit logout revokes its database row without clearing the shared jar.

The Rust regression covers both login orders, mismatch and consumed ids, pending
reload reads, active identity reads, cleanup after another login succeeds, and
cookie-neutral successful cleanup. Native production browser probes hold an
accepted completion or cleanup response, replace the shared jar in a second tab,
and release the reply. Both probes reload B before release, then
keep B's original 401/200 status respectively and preserve that state on reload.
No UI implementation changed; no visual-quality claim is made.

Reproduce with the client production dist directory as the sole positional
argument (contains no capabilities):

```sh
bun scripts/browser-auth/review4-response-race.mjs ../t-web-auth/apps/tracer/dist
bun scripts/browser-auth/review4-cleanup-direct.mjs ../t-web-auth/apps/tracer/dist
```

The optional `TRACER_BROWSER_AUTH_BIN` selects a scratch-built `browser_auth`.
Capabilities and recovery words remain in browser/private IPC memory; these
probes produce pass/fail summaries, no screenshots, traces or body logs.

Self-review used the auth B1/S1/S2/N1 checklist in `docs/verification/auth.md`:
exact Origin and cookie/id binding, live pending predicates, replay denial,
foreign attempts leave both rows unchanged, response ordering, no secrets in
files/logs/argv, real verifier/SQLite/native WebCrypto coverage, and module and
invariant comments. No schema, dependency, parser or foundational engine changed.
Full gate output and completed commit SHAs are recorded on #29.

Release scale evidence on Linux 6.12.111 x86_64, eight i9-9900K KVM vCPUs:
1 owner, 2 passkeys, 1,024 pending ceremonies, 200 samples per measurement;
load 3.37/5.14/6.73. Discoverable challenge p99 20 us; signed finish including
browser binding and transaction id p99 600 us. Pending inline storage remains
136 bytes/unit × 1,024 = 139,264 bytes (heap/hash-table allocations excluded);
RSS 13,124 → 14,580 KiB. Local SQLite memory/verifier paths only, not phone,
network, disk or slow-host evidence. Cookie-neutral responses add no SQL query.

## Terminal connect budget

The real Unix backend regression failed before the fix (0 passed, 1 failed in
10.41 s): a valid ten-second open had already received the five-second failure.
`TERMINAL_CONNECT_TIMEOUT` now gives open a 60-second budget, as required by the
owner task when no earlier SSH connect budget exists. Attachment waits retain
their five-second bound. Handshake, authority-read and close deadlines, revocation
notifications, busy-only 25 ms checks, and post-await SQL predicates are unchanged.

The ordinary regression measures a live ten-second reply (10,003 ms) and logout
while another ten-second open is pending (socket close 1,508 us, no late success
or terminal row). The retained no-reply regression waits up to 61 s to observe
the connect deadline, rejects late success and services the next Ping.

`review4_slow_open_at_user_capacity` exercises all 16 allowed sockets for one
owner in release mode, with ten-second Unix backend replies and real SQLite. Run
it without concurrent compilation:

```sh
cargo test --release --locked -p infraternal-server review4_slow_open_at_user_capacity -- --ignored --nocapture
```

Busy authority work remains at most 40 periodic reads/second per pending socket:
16 per user × 40 = 640 reads/second; at the 256-process socket limit, 10,240
reads/second if every socket is busy. The longer deadline changes maximum wait
duration, not per-socket polling rate. Idle sockets still do no periodic reads.
The capacity test measures the single-owner 16-socket case; it does not claim a
256-socket multi-user benchmark or real SSH slow-host evidence.

Capacity result on the same eight-vCPU host: all 16 live opens succeeded in
10,005 ms; revoking 16 pending opens closed every socket in 2,728 us, with zero
late success frames and zero terminal rows. Whole release probe 20.12 s; load
immediately afterward 4.14/5.21/6.14. These are local control/SQLite measurements.

## Final gates

Final server fast: 55 tests passed, 4 release measurements ignored; fmt, clippy,
test, cargo-deny and both static builds passed. Native auth: 4 isolated Chromium
149.0.7827.55 scenarios passed. Both production cookie-race probes passed. The
1,024-pending auth and 16-socket connect release measurements were run explicitly.

Client source remains `58040df`, untouched. Its production Playwright suite ran
from a disposable archive. Only the archive's fixture/config port changed from
4173 to 4187 after a shared-port collision; assertions, browser flags and
production source were unchanged. Final result: 4 passed (45.4 s), 500 painted
keys p99 16.20 ms (<20 ms), resume 78.50 ms (<300 ms). Earlier runs measured
26.7/25.4/20.4 ms under shared load; none was accepted or had its threshold raised.
No UI visual-quality judgment is part of these server changes.

Final fast summaries, verbatim (complete output is on #29):

```text
| fmt                       | PASS         |
| clippy                    | PASS         |
| test                      | PASS         |
| cargo-deny                | PASS         |
| static builds             | PASS         |

 7 pass
 0 fail
 34390 expect() calls
```
