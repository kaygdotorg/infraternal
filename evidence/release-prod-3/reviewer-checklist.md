<!-- Records the production integration review of private readiness and retained PTY lifecycle for #169. -->
# Production integration review

- Imported ancestry is exactly the four logical commits b45ec594, 95f27ef5, a33c9f73 and b800019c. Commit64d4e213 and its budget changes are excluded.
- Daemon opens preserve production input-size, enrolled/effective-uid and terminal-cell validation, plugin admission, resource policy and typed refusal. Readiness is an optional boolean, not an executable or command argument.
- Private PTYs use fixed non-login `/bin/sh`, authenticated attachment input and confirmed output. Completion and the absolute10-second bound retire without an ended record. Ordinary PTYs retain their exit ceiling, owner control link, output drain and authenticated saved status.
- Poll keeps the existing immediate nonblocking post-exit drain; otherwise it selects the earliest applicable deadline, rounding upward. A live ordinary PTY has no deadline and no added idle wakeup.
- CLI keeps production early dumpability, in-memory CA intake, queued reload/signal policy and exit-retention override. The old main-length allowance is unnecessary after production split dispatch and is omitted.
- Automatic cleanup retains the exact attempt before attachment and finishes it before SSH rollback, including cancellation. Diagnostics retain only public numeric status and allowlisted metadata; raw remote output is not logged.
- Rootless defaults and explicit root consent remain unchanged. No new dependency, engine, release profile, budget, server role or deployment action.
- UI extends the existing Details disclosure. Production screenshots are attached for independent review; no author visual-quality judgment or physical iPhone claim.
- Existing failing-first #169 regressions are retained. Required merge gates and fresh real-PTY readiness/cleanup evidence are linked from the final README. Prior branch evidence is not substituted for fresh results.
