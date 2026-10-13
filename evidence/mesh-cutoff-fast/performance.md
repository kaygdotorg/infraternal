<!-- Locked-VM stage timings and complete paired samples for D242, issue #173. -->
# Access cutoff at 1,000 installed peers

The final uniform default-tightening workload meets the 200 ms change-to-last-configured-node-refusing budget on both frontends. All 31 samples per frontend retain successful durable application and IPv4/IPv6 TCP/UDP refusal assertions. The budget uses the final firewall installation clock; later journal acceptance, exact state cleanup and acknowledgment remain independently measured and mandatory.

| Frontend | Before p50 / p99 | Final p50 / p99 | Budget |
|---|---:|---:|---:|
| nft | 5203.580 / 5270.969 ms | 126.197 / 157.640 ms | 200 ms |
| iptables nf_tables | 5355.854 / 5408.101 ms | 137.986 / 153.625 ms | 200 ms |

The pinned round-5 baseline is about 5.2–5.4 s; the archived round-4 result was about 6.4 s under its earlier build/harness. The paired baseline does not claim to reproduce that historical residual exactly. Its dominant cost is directly identified: 34 serial control acknowledgments per configured node at 150 ms RTT, approximately 5.1 s. The final negotiated representation sends one frame per node. Workers already fan out independently; compiler and encoder costs are small compared with those serial waits.

| Stage (per node) | nft before p50 / p99 | nft final p50 / p99 | Compatibility before p50 / p99 | Compatibility final p50 / p99 |
|---|---:|---:|---:|---:|
| New-view compilation | 0.260 / 0.599 ms | 0.241 / 0.437 ms | 0.278 / 0.627 ms | 0.233 / 0.474 ms |
| Ordinary encoder | 9.715 / 16.524 ms | 0.087 / 0.171 ms | 9.633 / 32.354 ms | 0.087 / 0.163 ms |
| Kernel inventory validation | 2.786 / 14.804 ms | 3.281 / 6.118 ms | 2.514 / 4.815 ms | 3.254 / 11.891 ms |
| Final firewall installation | 24.402 / 41.581 ms | 26.050 / 49.935 ms | 159.013 / 210.468 ms | 40.860 / 59.292 ms |
| Durable public intent | 29.781 / 46.777 ms | 34.802 / 63.323 ms | 25.025 / 43.405 ms | 32.145 / 47.144 ms |
| Exact state cleanup | 4.542 / 12.161 ms | 7.146 / 12.990 ms | 4.075 / 15.577 ms | 6.071 / 13.056 ms |
| One control acknowledgment | 152.723 / 236.217 ms | 231.899 / 289.453 ms | 152.742 / 386.238 ms | 242.927 / 373.982 ms |

Compilation rows measure the new view; workers also recompile the retained old source to form exact deltas. First-dispatch timings in `statistics.json` include shared reload, old/new views and scheduling. Encoder rows inside the compact path are its small empty-chunk construction; the entire final compact encoder costs about 0.2 ms per node. Stage quantiles are pooled across three nodes × 31 samples and are not additive. Actual frame counts, all-node clock coordinates, loads, measured underlay RTT and RSS are retained per sample. Two baseline compatibility ACK diagnostic lines are absent from parsed logs; all 3,162 changed control frames remain recorded.

| Frontend | Final durable completion p50 / p99 |
|---|---:|
| nft | 168.557 / 201.236 ms |
| iptables nf_tables | 177.711 / 204.040 ms |

Durable completion and acknowledgments exceed 200 ms in some samples; they are not relabeled as traffic refusal. No fsync, rollback, precise cleanup or timeout was removed.

The first compact candidate passed nft but compatibility p99 was 221.238 ms. Retaining unchanged raw guards reduced its firewall cost, but duplicate syntax preflight still consumed the margin. Full parallel mutations worsened completion to 307.930 ms; read-only parallel checks gave a 195.513 ms smoke sample and were rejected. The final plan omits duplicate syntax preflight only after complete owned installation and exact typed comparison proves unchanged bindings, addresses, aliases and peer identities, with each direction unchanged or becoming None. Actual full transactions remain serial and self-validating; partial failure uses existing rollback. Fences, new permissions, changed concrete port rules and other updates retain both preflights. The first final compatibility sample was 133.343 ms; the complete distribution above determines the result.

Machine: infraternal-perf-test, the named 4-vCPU/7-GB perf VM, using the shared lock and CPUWeight=10000. Three actual kernel nodes each install 1,000 keys; two receive traffic, and three actual coordinator workers use fixture channels. Public-only inventory entries fill the remaining peer count. This matches the archived workload and does not establish 1,000 simultaneously connected control workers. Fragmented changes that exceed the bounded action and legacy nodes retain the original chunk path. Every configured node contributes its successful installed-rule clock; earlier receiver-only summaries are preserved and corrected statistically from raw clocks.

Final nft maximum observed node-fixture RSS: 8,232,960 bytes; distributed ×1,000-node projection: 8,232,960,000 bytes. Three-worker coordinator RSS: 22,548,480 bytes. RSS excludes kernel peer/state allocations and does not project coordinator memory at 1,000 workers.
Final compatibility maximum observed node-fixture RSS: 8,540,160 bytes; distributed ×1,000-node projection: 8,540,160,000 bytes. Three-worker coordinator RSS: 22,503,424 bytes. RSS excludes kernel peer/state allocations and does not project coordinator memory at 1,000 workers.

Functional evidence: original final packet campaigns 340/340; exact incoming/outgoing state assertions 344/344; rollback 8/8; recovery 20/20; strict malformed-range and exact 1,000-peer namespace cases pass. After the final compatibility optimization, its 170 packet assertions, 172 state assertions, 4 rollback and 10 recovery assertions pass again. Eligibility tests refuse additions, changed rules, identities, addresses and bindings. The exact parser completes 1,000,000 final mutations without a crash.

Auth diagnosis: original dev inventory case failed 7/200 repeats, including two unexpected WebSocket closes at the same assertion. Functional inventory I/O consumed an intentionally strict authority deadline under host scheduling. The existing frozen-clock fixture makes that case pass 200/200; production deadlines and explicit deadline/revocation cases are unchanged. Complete socket and fast-gate functional suites pass with the documented native qualification.

Static linking and production trust checks pass, but the unchanged binary-size ceilings fail. Original unmodified dev x86_64 release is 22,530,608 bytes against 16,404,816. This is an unwaived gate blocker; no budget or decision is changed. See `static-size-comparison.json` and the final gate output.

Raw data, source and executable hashes, rejected candidates and reproduction commands are retained here. `statistics.json` preserves each sample, original observation and stricter derived all-node cutoff; `reproduce.md` records qualifications.
