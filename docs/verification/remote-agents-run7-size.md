<!-- Explains measured static growth and rejected crypto-provider reuse for remote infraternal agents, #78. -->
# Remote infraternal agent size investigation, run 7

This is local diagnostic evidence, not pinned performance acceptance or proof
that phase 1 is complete. The measured feature source is the inherited run 6
enrollment/operator/runtime prototype. No QUIC engine, TLS primitive, release
profile, dependency version or timing threshold was changed.

Machine: infraternal-dev, i9-9900K, eight visible cores. Optimized measurements
ran sequentially in CPUWeight10000 scopes, with no concurrent job-owned builds.
The paired provider run recorded load averages 0.09–0.18 (one-minute). Retained
memory includes **both** connection endpoints, not 1,000 complete daemons.

## Static attribution

`cargo bloat --release --target x86_64-unknown-linux-musl -p infraternal
--crates -n60` compares archived dev `e19c4eb` with complete feature source.
The matching `--filter 'quinn|rustls|ring|infraternal'` runs expose symbols.
Bloat attribution is approximate with LTO and native archives.

| Crate | Dev | Complete feature | OpenSSL-provider candidate |
| --- | ---: | ---: | ---: |
| openssl_sys | 1.9 MiB | 1.9 MiB | 1.9 MiB |
| std | 1.0 MiB | 1.3 MiB | 1.3 MiB |
| infraternal_server | 545.0 KiB | 682.8 KiB | 683.6 KiB |
| tokio | 319.1 KiB | 448.1 KiB | 448.1 KiB |
| quinn_proto | absent | 431.4 KiB | 434.3 KiB |
| rustls | absent | 352.6 KiB | 319.7 KiB |
| ring (Rust attribution) | absent | 243.9 KiB | 48.6 KiB |
| infraternal_agent | 88.9 KiB | 249.5 KiB | 250.0 KiB |
| infraternal | 107.3 KiB | 202.4 KiB | 202.0 KiB |
| rustls_openssl | absent | absent | 45.0 KiB |
| total .text | 10.8 MiB | 12.9 MiB | 12.7 MiB |

The exact feature section deltas are .text +2,267,752 bytes, .rodata
+292,416, .data.rel.ro +58,816, .eh_frame +175,772, .eh_frame_hdr +21,744,
.data +4,000 and .bss +32. ring also contributes native archive symbols
outside its Rust attribution; those estimates must not be added as exact
non-overlapping crate totals. Shared Tokio/std/router code becomes reachable
when the CLI calls the outgoing supervisor and the server calls the transport.

`cargo tree -d -e normal` has no duplicate Quinn, Rustls or OpenSSL versions.
The existing auth RNG versions and Quinn's rand0.10 differ; pinning incompatible
APIs or downgrading the transport to remove that small dependency was rejected.

Stock Quinn0.11.12 exposes Rustls ring/aws-lc backends. Its Rustls adapter and
Retry/reset/token machinery retain ring even with a custom CryptoProvider.
Disabling unused defaults is already the configuration. A native OpenSSL-only
QUIC backend would require a maintained implementation/fork or a different
foundational engine; that is an owner decision, not a size-gate workaround.

## Reuse experiment

The uncommitted MIT rustls-openssl0.4.2 adapter reused the already linked
OpenSSL version. Default features, TLS1.2 and post-quantum defaults were off;
the existing TLS1.3 cipher order and X25519/P256/P384 group order were preserved.
The experiment adds no new primitive and was removed after measurement.

GNU-strip copies of bloat's diagnostic binaries are 15,966,288 bytes (dev),
18,980,784 (feature/ring) and 18,586,256 (candidate). The 394,528-byte saving
still leaves +2,619,968 bytes over dev, above the requested +1.5 MB target.
These diagnostic copies are distinct from the canonical cargo-build artifacts
used by the static gate (their strip metadata differs slightly).

| Optimized local diagnostic | Ring | OpenSSL candidate |
| --- | ---: | ---: |
| 1,000-pair connection CPU, paired runs (ticks) | 97 / 94 | 182 / 193 |
| QUIC RTT300 handshake p99, paired n25 runs (ms) | 456.361 / 456.465 | 457.798 / 458.998 |
| Memory delta at 1,000 pairs, paired runs (KiB) | 67,680 / 67,724 | 60,688 / 60,648 |
| TCP RTT300 handshake p50 / p99, n25 (ms) | 758.136 / 760.225 | 757.021 / 759.030 |
| Local exact 50 MiB, n3 (ms) | 491.515 / 521.909 / 516.507 | 449.244 / 444.983 / 431.478 |
| RTT300 exact 50 MiB, n1 (s) | 76.570 | 74.624 |
| RTT300 exact 50 MiB CPU (ticks) | 328 | 253 |
| RTT300 QUIC first Hello p50 / p99, n25 (ms) | 455.714 / 457.639 | 457.065 / 458.837 |
| RTT300 UDP-blocked TCP first Hello p50 / p99 (ms) | 868.090 / 871.162 | 866.264 / 868.606 |

The repeat confirms increased connection CPU and slightly higher QUIC
handshake latency. Bulk transfer is faster and memory smaller, but the
connection regression rejects this change under D41 and the job's requirement
to preserve performance. The accepted provider therefore remains unchanged.
Reducing the mandatory Rustls state machine or replacing the engine was not
silently chosen. The target cannot be met by removing duplicate crate versions
or by this stock-provider reuse configuration.

The bulk fixture checks all 52,428,800 application bytes and completion ACK;
zero missing/duplicated **application bytes** is not zero packet loss. The
userspace UDP relay incurs burst loss/retransmission with this kernel's socket
limits. Earlier one-reactor attempts timed out. The final isolated fixture
uses two workers to schedule host/server/relay separately; successful runs
still do not certify clean-link throughput. Handshake numbers exclude session
open, reconnect-to-output and live renewal. No renewal-cost claim follows.

## Evidence

The commit cites the following source-free logs under `remote-agents/`:
`run7-dev-bloat.log`, `run7-head-bloat.log`, `run7-candidate-bloat.log`,
`run7-dev-filter.log`, `run7-head-filter.log`, `run7-dev-duplicates.log`,
`run7-head-duplicates.log`,
`run7-dev-sections.log`, `run7-head-sections.log`, `run7-ring-perf.log`,
`run7-candidate-perf.log`, `run7-paired-perf.log`,
`run7-ring-bulk-workers.log`. Canonical static sizes and the baseline rationale
are recorded below after the normal locked release build;
`run7-final-static-build.log` contains the canonical build output and
`run7-static-identities.log` records sizes, hashes and static-link checks.

## Canonical baseline rationale

The normal locked release build produces 18,982,128 bytes x86 and
15,934,232 bytes ARM (both static, stripped, no PT_INTERP). Relative to the
previous baselines 16,142,672/13,555,672, growth is 2,839,456/2,378,560 bytes.
The baseline-only commit records these target-specific measured feature sizes;
the existing 262,144-byte allowance and release profile remain unchanged.
Its exact source tree excludes all inherited feature work while running the
gate; later implementation commits must independently pass the same gate.

This is a justified increase for the reachable mandatory QUIC/TLS protocol,
transport supervision, and integration with the existing actor; it is **not**
a successful elimination of the second TLS state machine. The measured
OpenSSL reuse option cannot meet the target even before its CPU regression.
No arbitrary extra headroom or engine substitution is hidden in the baseline.
The task explicitly permits remaining explained growth after measurement;
the reported target miss and future engine choice remain visible to the owner.
