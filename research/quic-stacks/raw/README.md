<!-- Role: Describes the raw measurements and repetition context committed beside the report. -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Raw data

The `*.csv` files hold the exact rows emitted by the benchmark binary. `*-*.log` files preserve command output, including network emulation qdisc counters and failed attempts; trailing whitespace in command output was trimmed. `run-context.csv` records timestamp, host load, and the soft file-descriptor limit before each repetition. `size-binaries.csv` records the stripped static musl release/LTO executable sizes. `first-pass/` preserves the initial matrix; its README explains why those measurements are excluded from the final report. `diagnostics/` holds one-off harness checks, excluded from five-run summaries.
