<!-- Role: Evidence-based comparison of Quinn/rustls/ring with OpenSSL native QUIC. -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# QUIC stack comparison

| Property | Measurement |
|---|---|
| Issue | [kayg/infraternal#88](https://git.kayg.org/kayg/infraternal/issues/88) |
| Benchmark date | 2026-10-08 |
| Host | `infraternal-dev`, x86_64, 8 logical CPUs, Debian 13, kernel 6.12.111 |
| OpenSSL | 3.6.3, current vendored product version used for this comparison |
| Rust stack | Quinn 0.11.12, rustls 0.23.45, ring 0.17.14 |
| Build | release, LTO, one codegen unit, stripped, static x86_64 musl |

## Recommendation

Retain Quinn + rustls + ring for the infraternal QUIC transport, with BBR configured explicitly. Across this harness it cut loopback fresh mutual-TLS handshake time by 80%, reduced measured 1,000-connection idle RSS by 37%, and delivered 23–24x the OpenSSL throughput on the configured 300 ms / 1% loss path. It also fits the Tokio server API directly and exposes 0-RTT and path migration controls. OpenSSL native QUIC's clear advantage is image size when OpenSSL is already linked: only 1,696 added bytes versus Quinn's 1,796,968 bytes. Its loopback stream throughput was comparable, and its four-stream median was 8% higher.

Confidence: **moderate**. Handshake, loopback throughput, and memory results are stable across five runs. The impaired-path qdisc was configured for 1% loss, but its packet counters recorded 0.16–0.26% loss in Quinn runs versus 1.02–1.07% for OpenSSL; the throughput gap is compelling but is not a controlled same-realized-loss comparison. The result is also from one 8-core host with 1 MiB transfers, not a production-scale 1,000-session throughput workload. Keep D41's stack choice for now; before treating the loss ratio as a capacity number, repeat with matched deterministic packet loss and a larger transfer. This report measures candidates and does not change a foundational decision.

## Measurement summary

| Criterion | Quinn + rustls + ring | OpenSSL native QUIC | Evidence / interpretation |
|---|---:|---:|---|
| Added static binary bytes over OpenSSL TLS baseline | 1,796,968 B | 1,696 B | Baseline 5,190,400 B; OpenSSL's static TLS link already pulls QUIC objects, so its delta is marginal size, not the full QUIC engine size |
| Fresh mutual-TLS handshake, loopback | 955 µs [948–1,020]; 1.901 ms CPU/connection | 4,883 µs [4,605–6,296]; 7.977 ms CPU/connection | Median of five per-run medians; Quinn's median within-run p95 was 1,353 µs vs 13,982 µs |
| Fresh mutual-TLS handshake, 300 ms RTT ±30 ms | 311.723 ms [277.245–315.592]; 2.352 ms CPU | 886.331 ms [867.227–888.265]; 5.528 ms CPU | One fresh connection per run; actual qdisc delay and packet counters are in each raw log |
| Resumed 0-RTT echo | Loopback 1.212 ms [1.153–1.978]; delayed 603.050 ms [580.079–979.928] | Unsupported by native QUIC API | Quinn accepts early data; this harness waits for complete mTLS authentication before echoing it, so these are not pre-auth application-latency results |
| Stream throughput, 1 stream | Loopback 56.370 MiB/s, 2.896 CPU s/Gbit; delayed/loss 0.515 MiB/s, 5.076 CPU s/Gbit | Loopback 55.509 MiB/s, 3.376 CPU s/Gbit; delayed/loss 0.022 MiB/s, 39.969 CPU s/Gbit | 1 MiB; medians of five runs. Delayed path qdisc drop rates differed; see loss caveat below |
| Stream throughput, 4 streams | Loopback 52.587 MiB/s, 3.368 CPU s/Gbit; delayed/loss 0.536 MiB/s, 5.573 CPU s/Gbit | Loopback 56.808 MiB/s, 3.633 CPU s/Gbit; delayed/loss 0.022 MiB/s, 76.693 CPU s/Gbit | 1 MiB total across four bidirectional streams; medians of five runs |
| Multiplexed bidirectional streams | Supported | Supported | Both stacks passed 1- and 4-stream harness workloads; see throughput and loss results |
| Server RSS per idle connection at 1,000 | 43,978 B [43,958–46,080]; 41.94 MiB at 1,000 | 69,767 B [69,660–69,865]; 66.53 MiB at 1,000 | Independent server-child RSS, baseline subtracted |
| Incremental RSS per active stream at 1,000 | 647 B [585–663]; 0.62 MiB at 1,000 | 6,447 B [6,430–6,463]; 6.15 MiB at 1,000 | One bidirectional stream per connection; active totals are about 42.56 MiB vs 72.68 MiB |
| Congestion control | BBR explicitly configured | NewReno in OpenSSL 3.6.3; no BBR selector exposed | Quinn defaults to Cubic unless configured |
| Connection migration | Quinn supports peer path changes and exposes local-address-change handling | OpenSSL API describes peer address changes “where supported”; no migration control API was found | Migration was not exercised by this harness |
| Tokio integration | Native async API | Synchronous SSL API plus blocking or application-driven event loop; native listener calls require thin FFI | Harness uses Quinn async APIs and an OpenSSL FFI shim |
| Server maturity | Established async server API | Native server listener added in 3.5.0; about 18 months old at benchmark date | Publicly supported and documented; upstream does not label it production-ready |
| License | AGPL-compatible permissive dependencies | Apache-2.0 OpenSSL license; AGPL-compatible | Package and dependency license files |

## Method

The baseline and candidate size probes use one source file, the same Rust release profile, the same static musl target, and the same OpenSSL 3.6.3 static libraries. The baseline touches the TLS API that the existing product already links. The Quinn candidate adds the Quinn endpoint, BBR configuration, rustls, and ring code paths. The OpenSSL candidate adds native QUIC client/server methods and listener setup to the same baseline. All executable files are stripped. The probes omit application code and runtime certificate provisioning; the separately measured handshake uses the same ephemeral mutual-TLS identity for both stacks.

Every timing and throughput result has five repetitions. Each loopback handshake repetition contains 1,000 fresh mutual-TLS connections; delayed-path handshake repetitions contain one connection each to isolate the one-round-trip path. Throughput transfers 1 MiB total over one or four bidirectional streams. CPU is process user+system CPU accumulated by the co-located client and server for that workload. `CPUWeight=10000` is set on every build and benchmark invocation. Per-run load averages are in `raw/run-context.csv`; the server memory test reports server-child RSS rather than combined client/server RSS.

The delayed path is implemented inside a fresh rootless network namespace. `tc netem` applies 150 ms ±15 ms uniform delay to loopback egress, producing a 300 ms ±30 ms round trip, with an additional configured 1% random loss for the loss runs. The exact qdisc readback and packet counters are retained in the raw logs. Across the five transfer runs per case, qdisc counters observed 14/5,342 dropped packets (0.26%) for Quinn one-stream, 9/5,611 (0.16%) for Quinn four-stream, 90/8,417 (1.07%) for OpenSSL one-stream, and 87/8,543 (1.02%) for OpenSSL four-stream. This means the impaired-path throughput measurements did not experience equal realized loss and must be read with that limitation. The benchmark scope sets `RLIMIT_NOFILE` to 8,192 so its client can keep 1,000 UDP sockets open; the actual limit is recorded per run. Across all 80 measured invocations the host load averages ranged 1.16–4.03 (1 min), 2.01–2.95 (5 min), and 4.26–5.62 (15 min) on 8 logical CPUs.

The benchmark uses OpenSSL 3.6.3 because that is the product's currently vendored version. This is a performance comparison, not a recommendation to ship that unpatched release. OpenSSL 3.6.4 and 3.6.5 contain QUIC server fixes listed in the version-specific advisory pages; release builds must use an updated patch release.

## Raw measurements

The committed CSV files preserve every repetition. The summary table above uses the median of five per-run medians and the min–max range across those five repetitions. Throughput and memory rows have one measured value per process invocation; their reported spread is the five-run min–max. Throughput numbers below include that spread for each stack and scenario. CPU/Gbit is the co-located client and server's combined user+system CPU divided by transferred bits, not a server-only rate.

### Binary size

| Candidate | Stripped static binary | Added bytes over TLS baseline |
|---|---:|---:|
| Minimal TLS baseline | 5,190,400 B | — |
| Quinn + rustls + ring | 6,987,368 B | 1,796,968 B (1.71 MiB) |
| OpenSSL native QUIC | 5,192,096 B | 1,696 B |

The OpenSSL figure is marginal to the already-linked OpenSSL TLS baseline. Inspection of the static archive showed that the baseline's OpenSSL objects already reference and pull in QUIC implementation objects. It should not be interpreted as the standalone size of OpenSSL's QUIC engine. The earlier issue #78 size probe reported a +2.84 MB Quinn stack under a different probe and build; it is not directly comparable with this stripped Release/LTO measurement.

### Latency, throughput, CPU, and server memory

| Workload | Quinn + rustls + ring | OpenSSL native 3.6.3 |
|---|---:|---:|
| Loopback fresh mTLS, time per connection | 955 µs [948–1,020]; p95 median 1,353 µs | 4,883 µs [4,605–6,296]; p95 median 13,982 µs |
| Loopback fresh mTLS, CPU per connection | 1.901 ms [1.870–2.094] | 7.977 ms [7.552–9.486] |
| 300 ms RTT fresh mTLS | 311.723 ms [277.245–315.592] | 886.331 ms [867.227–888.265] |
| 300 ms RTT handshake CPU | 2.352 ms [1.895–2.538] | 5.528 ms [4.839–6.825] |
| Resumed 0-RTT echo, loopback | 1.212 ms [1.153–1.978] | Not supported by native QUIC API |
| Resumed 0-RTT echo, 300 ms RTT | 603.050 ms [580.079–979.928] | Not supported by native QUIC API |
| 1 stream, loopback | 56.370 MiB/s [44.583–66.560]; 2.896 CPU s/Gbit [2.656–3.916] | 55.509 MiB/s [40.056–73.654]; 3.376 CPU s/Gbit [2.410–3.999] |
| 4 streams, loopback | 52.587 MiB/s [46.587–58.170]; 3.368 CPU s/Gbit [3.057–3.617] | 56.808 MiB/s [50.148–65.424]; 3.633 CPU s/Gbit [3.411–4.458] |
| 1 stream, 300 ms RTT / configured 1% loss | 0.515 MiB/s [0.420–0.518]; 5.076 CPU s/Gbit [4.775–5.821] | 0.022 MiB/s [0.020–0.025]; 39.969 CPU s/Gbit [37.025–42.998] |
| 4 streams, 300 ms RTT / configured 1% loss | 0.536 MiB/s [0.445–0.587]; 5.573 CPU s/Gbit [4.769–7.142] | 0.022 MiB/s [0.021–0.023]; 76.693 CPU s/Gbit [71.808–77.093] |
| 1,000 idle connections, server RSS per connection | 43,978 B [43,958–46,080] | 69,767 B [69,660–69,865] |
| Additional RSS per active stream and connection | 647 B [585–663] | 6,447 B [6,430–6,463] |

Handshake and 0-RTT values are the median of each run's median, with the displayed range across five runs. Loopback handshake CPU is total process CPU divided by 1,000 new connections; delayed handshake CPU is for one connection. The table reports per-run median throughput and process CPU per Gbit. Each raw CSV has the unrounded values. The actual qdisc drop counters are reported under Method and retained in each `throughput-300ms-loss1-*.log`.

## Stack trade-offs

### Congestion control and loss

Quinn supports Cubic by default and permits explicitly selecting BBR; the harness selected BBR. OpenSSL 3.6.3's QUIC channel instantiates NewReno, and its public API did not expose a congestion-control selector. At loopback, one-stream throughput was effectively tied and OpenSSL's four-stream median was 8% higher. On the impaired path, Quinn transferred about 23–24x faster and used far less CPU per Gbit in these runs. However, although both qdiscs were configured for 1% random loss, the recorded realized packet-drop fraction was 0.16–0.26% for Quinn and 1.02–1.07% for OpenSSL. The raw result supports the observed behavior but not a precise same-loss throughput ratio. Repeat with deterministic matched loss and more bytes before using it for a capacity model. See [Quinn's transport configuration](https://docs.rs/quinn/0.11.12/quinn/struct.TransportConfig.html) and the [OpenSSL 3.6.3 QUIC channel](https://github.com/openssl/openssl/blob/openssl-3.6.3/ssl/quic/quic_channel.c).

At the measured 1 MiB size, one or four streams had similar delayed throughput within each stack. Four streams did not raise aggregate throughput on loopback; this small transfer is primarily a protocol/path check, not a saturation test. The impairment therefore indicates relative sensitivity under the observed netem conditions, not line-rate capacity or behavior at 1,000 simultaneous active transfers.

### 0-RTT and replay considerations

Quinn's rustls client/server path can negotiate and accept 0-RTT resumption when tickets are available. The measured server waits until the full mutual-TLS handshake completes before reading and echoing the early-data stream, so the recorded handshake-to-echo time does not claim that an mTLS operation can be acted on before client authentication. 0-RTT application requests remain replayable and must not trigger non-idempotent actions. Quinn documents this in [`Connecting::into_0rtt`](https://docs.rs/quinn/0.11.12/quinn/struct.Connecting.html#method.into_0rtt); see also the [QUIC TLS specification](https://www.rfc-editor.org/rfc/rfc9001.html).

OpenSSL 3.6's native QUIC API does not expose TLS 1.3 early data. OpenSSL offers a separate callback to enable early data when it supplies TLS to a third-party QUIC implementation; that is not the native OpenSSL QUIC endpoint tested here. The native API documents multi-stream support and client/server endpoints, but the `openssl-sys` crate does not bind the listener APIs used here, so the Rust server needs a small unsafe FFI layer.

### Async API and server maturity

Quinn integrates directly with Tokio through async `Endpoint`, `Connection`, and stream APIs. OpenSSL's QUIC API remains synchronous: the application selects blocking I/O or drives the event loop itself. Its thread-assisted mode starts a background event thread and consumes additional OS resources; neither mode provides Tokio futures. This makes Quinn the more natural fit for a Tokio daemon, while OpenSSL can still be integrated through a blocking worker or a custom poll/event adapter. See [OpenSSL's concurrency models](https://docs.openssl.org/3.6/man7/openssl-quic-concurrency/).

OpenSSL added QUIC clients in 3.2 and native server listeners in 3.5.0, released April 8, 2025. The 3.6 API documents a native listener and stream acceptance, but I found no upstream statement that the server is production-ready. The interface is available and actively maintained, though it is substantially newer than Quinn's server API. The [OpenSSL 3.5 release notes](https://mirror.openssl-library.org/news/openssl-3.5-notes/) also record an early server-side `SSL_accept` fix in 3.5.1.

### Security and maintenance

The benchmark pins Quinn 0.11.12, rustls 0.23.45, and ring 0.17.14. Its lockfile resolves quinn-proto 0.11.19 and quinn-udp 0.5.16. Recent Quinn advisories GHSA-53rm-773f-4q8c (stream-limit enforcement) and GHSA-wppq-2f6r-wfvm (oversized Retry token) affect quinn-proto through 0.11.18 and are fixed in 0.11.19. Other recent advisories, including GHSA-3g6h-r5qx-f6hq, GHSA-ppcp-v39w-8jq2, and GHSA-465w-v9q3-7j98, are fixed by 0.11.18; GHSA-2hv7-gw8g-gpq5, GHSA-hmxj-32vh-65vr, GHSA-qfwj-vfxf-92j2, and GHSA-4w2j-m93h-cj5j are fixed by 0.11.17 or earlier. The quinn-udp advisory GHSA-6pp4-4cxf-xf88 is fixed in 0.5.16. These are GHSA identifiers; the reviewed Quinn notices list no CVE identifier. rustls GHSA-2mjx-qc3c-rqvc is fixed in 0.23.45. The [Quinn advisory list](https://github.com/quinn-rs/quinn/security/advisories) and [rustls advisory list](https://github.com/rustls/rustls/security/advisories) show active vulnerability maintenance. The rustls project publishes a [TLS-01 audit report](https://github.com/rustls/rustls/tree/main/audit); that audit is for the TLS library, not the QUIC transport. ring publishes a [security policy](https://github.com/briansmith/ring/security/policy); I found no public independent audit specific to the Quinn QUIC engine, ring-in-QUIC integration, or the combined stack.

OpenSSL 3.6.3, the tested version, predates QUIC fixes in 3.6.4 and 3.6.5. OpenSSL 3.6.4 fixed CVE-2026-18798 (server double-free on an Initial packet), CVE-2026-14456 (unbounded incoming-channel queue), and CVE-2026-63075 (ACK-only packet retention). OpenSSL 3.6.5 fixed CVE-2026-35191 (amplification-credit accounting), CVE-2026-42772 (quadratic stream-fragment reassembly), CVE-2026-54873 (STREAM-fragment metadata memory growth), CVE-2026-75804 (missing connection-level flow control), and CVE-2026-84784 (unbounded `RETIRE_CONNECTION_ID` backlog). The official [3.6 release notes](https://mirror.openssl-library.org/news/openssl-3.6-notes/) and [3.6 vulnerability advisories](https://www.openssl-library.org/news/vulnerabilities-3.6/) describe the affected versions and fixes. CVE-2026-75804 is especially relevant at this design point: OpenSSL describes a way for an attacker to cause roughly 100 MB of QUIC receive heap per connection instead of the default 768 KiB. That is advisory analysis, not a behavior exercised by this benchmark. The native QUIC code is outside OpenSSL's FIPS module boundary. At the benchmark date, use at least the fixed 3.6.5 patch level for any follow-up OpenSSL evaluation; do not ship the tested 3.6.3 build.

Both license families are compatible with the repository's AGPL-3.0-only license: Quinn/rustls/ring use permissive licenses, and OpenSSL is Apache-2.0. Neither stack has a project-wide public QUIC audit in the sources reviewed here.

Migration is not measured. Quinn's protocol API exposes active local-address-change handling and reports peer-address changes; OpenSSL's [`SSL_set1_initial_peer_addr`](https://docs.openssl.org/3.6/man3/SSL_set1_initial_peer_addr/) page says the peer address may change during migration “where supported,” but I found no native API in the 3.6 public docs for configuring or observing migration behavior. Verify migration on the target network before depending on it.

## Sources

- [OpenSSL 3.5 final release](https://openssl-library.org/post/2025-04-08-openssl-35-final-release/)
- [OpenSSL QUIC API and feature limits](https://docs.openssl.org/3.6/man7/openssl-quic/)
- [OpenSSL QUIC concurrency models](https://docs.openssl.org/3.6/man7/openssl-quic-concurrency/)
- [OpenSSL QUIC stream acceptance](https://docs.openssl.org/3.6/man3/SSL_accept_stream/)
- [OpenSSL native listener API](https://docs.openssl.org/3.6/man3/SSL_new_listener/)
- [OpenSSL 3.6 version notes](https://mirror.openssl-library.org/news/openssl-3.6-notes/)
- [OpenSSL 3.6 vulnerability advisories](https://mirror.openssl-library.org/news/vulnerabilities-3.6/)
- [Quinn API documentation](https://docs.rs/quinn/0.11.12/quinn/)
- [rustls security advisories](https://github.com/rustls/rustls/security/advisories)
- [Quinn security advisories](https://github.com/quinn-rs/quinn/security/advisories)
- [Quinn 0.11.12 connection migration and 0-RTT API](https://docs.rs/quinn/0.11.12/quinn/struct.Connecting.html#method.into_0rtt)
- [Quinn protocol connection API, 0.11.19](https://docs.rs/quinn-proto/0.11.19/quinn_proto/struct.Connection.html)
- [Quinn releases](https://github.com/quinn-rs/quinn/releases)
- [ring security policy](https://github.com/briansmith/ring/security/policy)
- [Linux traffic-control netem behavior](https://github.com/iproute2/iproute2/blob/main/man/man8/tc-netem.8)
