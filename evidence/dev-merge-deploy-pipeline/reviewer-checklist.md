<!-- Records integration self-review of signed recovery and deployment tooling for #188. -->
# Integration self-review

- Merge includes both current dev ancestry and reviewed deploy tooling; every test function in the overlapping dev modules remains.
- Signed MANIFEST/VERSION admission, exact immutable execution bytes, the pre-shutdown probe, root-only CA transfer, late recovery and anonymous subprocess launch remain intact. No trust predicate, timeout, size budget, dependency or release profile changed.
- Staging trust remains a non-default feature requiring a fresh public build key. Both production static gates scan the final ELF and retain D244 memory protection checks after a D243 size refusal.
- R5 strips only the final kernel label from a zero-link running inode during relative invocation capture. Absolute service aliases and raw pathname bytes remain intact. Existing actual PATH and atomic-install/memfd regressions pass; actual linked and unlinked literal-suffix filename replays pass too.
- Complete deploy admission authenticates the actual separate architecture payloads and server. Alias/web restoration failures cannot skip retained signed process rollback. A mixed/locked/dead rollback requires operator recovery, and the live database is never overwritten.
- Web-only deployment cannot record a candidate as the running executable. The builder signs, publishes and deploys nothing; its exact-head gate, capacity admission, lock lifetime and durable completion receipts remain.
- The staging runner builds locally, deletes its private signer before transfer, and uses a fresh private VM directory/unit/data/CA/runtime. Transfer/extraction precede the shared measurement lock; wait is 3600 seconds. The native proof holds the lock, stops its own unit, and directory cleanup follows release.
- Administrator session and CA material stay in memory/private pipes. No credential store, production signer, owner fixture, production host, tag or dev/main update is used.
- Functional logs are build-host diagnostics, not timing evidence. Only the named perf VM supplies listener/transaction measurements; sample brackets and worst actual spacing qualify p50/p99.
- No UI change, screenshot quality judgment, foundational engine choice, service installation or issue closure belongs to this integration.

Final exact-head verification and VM receipts are recorded on #188; adjacent evidence retains the failing-first recovery test and completed integration checks.
