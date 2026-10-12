<!-- Records the author integration checklist for production backmerge #169. -->
# Integration checklist

- Merge parents must be dev d93056ef and production 61bdbd9f; round-two add-host fixes are outside this ancestry.
- Preserve dev action definitions, compile-out features, asynchronous plugin worker/admission, signed payload resolver, CA handoff and current decision records.
- Preserve production fixed private readiness command and cleanup before rollback; readiness is a boolean, never arbitrary command input.
- Keep enrolled/effective UID, terminal cell/input bounds and plugin admission before launch.
- Preserve event-driven shim lifetime census, queue-capacity retry and open-result FIFO fencing alongside asynchronous plugin events.
- Keep capability invalidation and census availability as distinct watches. Decoder regression must prove that plugin control notices are retained.
- Diagnostics include signed-payload step labels and classified numeric status only; remote text remains withheld.
- Ordinary PTY retention, exit status, replay fences, authenticated saved status and terminal-input response ordering remain unchanged by conflict resolution.
- Reuse production UI changes in shared components; attach fresh production-build screenshots for independent/owner review without a visual-quality verdict.
- scripts/verify.d/rust.sh and docs/PROCESS.md must be byte-for-byte identical to dev. D243 budget is never raised.
- Verify fmt, strict all-target workspace Clippy, workspace real-engine tests, tracer type/tests/build/transfer, functional browser cases and final fast gate. Timing gates require the perf VM; access refusal is recorded, no build-host performance claim.
- Normalize only the shipped successful production migration checksum from 20 to 22 under an immediate transaction; retain dev 20/21, reject unknown/dirty/colliding histories and preserve owner data.
- Preserve production exponential backoff for greeted links that immediately close; paused-clock tests exercise the actual actor without host timing claims.
- Functional daemon mode must omit CPU/RSS sampling, while retaining all 24 data/ack/exit/restart assertions and unchanged performance-mode thresholds.
- Only this task branch may be pushed; no deployment or dev/main update.
