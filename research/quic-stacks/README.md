<!-- Role: Entry point for the QUIC stack research artifact and its reproduction steps. -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# QUIC stack research

`REPORT.md` contains the comparison and recommendation. `raw/` contains the five measured repetitions, host load records, static binary sizes, and the command output used to produce them.

## Reproduce

Run `harness/build-musl.sh` to build the baseline, both candidate size probes, and the benchmark binary as optimized static x86_64 musl executables with LTO. The build uses the installed Rust musl target, Zig 0.15.2 for cross-compiling OpenSSL and other C dependencies, GNU make, and Perl. Build outputs go to `$HOME/.cache/codex-scratch/quic-research/target` by default; override with `CARGO_TARGET_DIR` or `QUIC_RESEARCH_SCRATCH`.

Run `harness/run-benchmarks.sh` to perform five repetitions for each scenario. Each run writes to a new UTC timestamped directory under `raw/run-*`; pass a new directory explicitly to choose another location. The script refuses an existing output directory to preserve the committed matrix and keep logs paired with their CSVs. It records load average and the soft file-descriptor limit before each run, and places each benchmark command in a user systemd scope with `CPUWeight=10000` and a soft `RLIMIT_NOFILE` of 8,192. The higher per-process limit lets the 1,000-connection client hold its UDP sockets concurrently. Delayed and loss runs use a rootless user/network namespace and `tc netem` on loopback: 150 ms ±15 ms per direction with uniform jitter, and 1% loss per egress for loss runs. The host `infraternal-dev` is the only benchmark host used.

The harness generates an ephemeral mutual-TLS identity in memory. The memory probe sends the identity to its server child over a pipe; credentials are never written to disk, argv, or benchmark output.
