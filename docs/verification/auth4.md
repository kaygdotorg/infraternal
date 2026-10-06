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
