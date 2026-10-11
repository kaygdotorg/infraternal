<!-- Indexes public regression and shipping proof artifacts for mesh integration #129. -->
# Mesh integration evidence

[Verification narrative](../../docs/verification/mesh-integrate.md) explains
scope, measurements and gate qualifications. `provenance.json` records the
shipping source and binary. The final branch-head gate is quoted verbatim on
issue #129 after this documentation commit.

- `r6-red.log`: unchanged reviewer budget test failing before the fix.
- `r6-before.json`, `r6-after.json`, `r6-after-1.log`: shipping scale comparison.
- `restart-red.log`, `restart-green.log`: actual SIGKILL recovery regression.
- `kernel-results.json`, per-case logs, `kernel-after-run.log`: all 26 real-kernel cases.
- `namespace-results.json`, ingress/transit/fallback logs: seven additional both-backend namespace proofs.
- `production-*.json`, load files: shipping daemons and production coordinator at 1,000 peers/node.
- `bulk-kernel.log`, `journal-retry.log`: primitive and durable-write retry proofs.
- `cli-ownership-gate3.log`: CLI feature isolation, Clippy and ordinary tests.
- `merge-fast5.log`: full merge milestone gate, known static-size failure only.
- `final-ts.log`: tracer/protocol tests, production build and transfer budget.
- `gate-profile.toml`, `run-kernel.py`: recorded local gate configuration and namespace runner.

Raw logs/JSON are immutable output artifacts; this index supplies their roles.
No private key or credential is part of the evidence.
