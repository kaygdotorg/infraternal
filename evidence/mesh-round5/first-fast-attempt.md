<!-- Full resumed gate attempt and unchanged isolated comparison for #173, D242/D243. -->
# First resumed full gate

The attempt began at `94342e78`; evidence-only commits advanced the branch during compilation. Rust production/test sources remained unchanged. Native qualification, serial tests, umask 022 and the private target follow the recorded procedure; only the three-sample RTT setup is routed to the locked authorized VM.

Formatting, native formatting, CLI compile-out, workspace Clippy and dependency-license checks pass. The shipping shim suite is 23 passed / 1 failed: `attached_backpressure_and_detached_progress`, at `crates/infraternal/tests/shim.rs:207`, reports an output head below its minimum. The identical immutable case passes immediately in isolation (1 selected, 1 passed). No cause or waiver is inferred from that success; a complete exact-head rerun follows. No assertion, deadline or production source was changed.

Static x86_64 is 22,408,144 bytes, with PT_INTERP absent, versus the unchanged 16,404,816-byte D243 ceiling. The script stops the static row there, before ARM qualification, and Rust failure prevents its subsequent TypeScript stage. No TypeScript source is changed in this round. The size limit is not raised.

Complete stdout/stderr: `resume-fast.log`; isolated comparison: `attached-backpressure-isolated.log`.

Full-log SHA256: `b7189537a54a99c971533fde351b183802e58d53ea5c1d003fb6d19fd8afbd28`.
