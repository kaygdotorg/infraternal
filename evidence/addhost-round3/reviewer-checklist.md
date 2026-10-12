<!-- Author security and lifecycle checklist for host provisioning round 3, #169. -->
# Author checks

- V1 retains the listed address and user when a typed port overrides the saved port. Existing components and visuals are unchanged; the independent production-address regression is retained.
- V2 accepts only an empty regular receipt with one link, exact owner, mode0600, private owned mode0700 stage and the exact acquisition journal. Nonempty foreign receipts and links remain refused. Real generated-shell tests cover rollback and retry.
- V3 preserves numeric Join71/72 but keeps payload failures within the Join recovery boundary. Installer ownership classification remains for fixed installer scripts.
- V4 records the retirement intent in the invitation transaction. Failure synchronously fences the exact host record before cleanup awaits; an owned writer survives caller deadlines, retries only SQLite BUSY/LOCKED and pool admission timeouts, and atomically retires the record with intent consumption. Startup consumes unfinished intents before listeners start. Completed prior host records have no intent and cannot be retired by the helper.
- Owner/session/uid, root consent, certificate generation and actor checks remain. SQLite failures preserve the cancellation fence and durable intent; no generalized deletion or trust replacement is introduced.
- The unchanged review contention regression and additional real-file two-connection BUSY test both pass. Startup, exact ownership and completion regressions preserve prior host records.
- No parser or foundational dependency is added. Migration23 is additive and retains foreign-key/integrity checks. The existing fuzz targets remain; no new instrumented campaign is claimed.
- Secrets remain in pipes/scoped memory; instrumentation prints only classified setup steps, numeric measurements and public counts. Raw SSH output is not logged. Only disposable fixtures were modified; owner live state was untouched.
- Functional mode preserves byte, Ack, terminal exit and24-stop assertions while refusing all performance-counter calls in its regression harness. Default performance-mode limits are unchanged.
- All accepted time/CPU/RSS evidence comes from the pinned VM under the shared lock. Prior shared-host timing claims are superseded. Browser27/27 functional replay uses unique4331 and retains the production screenshot for independent visual assessment. No author visual verdict or physical-iPhone claim.
- No feature or library is duplicated; no release profile or historical static-size limit is changed. Gate failure at size is reported under D205 with exact deltas; TypeScript is checked separately because the dispatcher stops at that row.
