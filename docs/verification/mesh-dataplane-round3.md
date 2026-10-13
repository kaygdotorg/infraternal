<!-- Mesh round-three repair evidence, regression chronology and reviewer checklist for #129, D165/D166/D170/D198/D205/D206/D228/D231. -->
# Mesh data plane round three

> Raw screenshots, logs and receipts referenced by this report were removed under D262. The
> recorded results remain; new outputs belong in job scratch and should be attached to the
> relevant issue with the `issue-attach` helper.

Reviewed base: `378d4055`. Production repair head: `24542436`.
The host-resize WIP `ac21cb69` was soft-reset and split into `9a7fa2ea`
(route shape/prefix recovery) and `24542436` (durable node transaction).
Earlier atomic repairs remain in the branch history.

## Regression evidence

Reviewer tests `3bfd21d9` and `7031b688` were imported unchanged as
`d9950788` and `f92c965d` before implementation. Both local-delivery cases and the operator gateway case
fail at that imported head. Five earlier R1–R3/ownership cases pass there.
Two further inventory/recovery counterexamples were added in `fc8e5927`:
unrecorded operator direct IPv4/IPv6 routes must survive, and a refused
recovery save must leave retained peers/routes intact. Both fail before wiring.

- R4: `f24951a3` and `69085ca7` exempt loopback in the final-destination
  fences for nft and nf_tables. Node-local IPv4/IPv6 listeners receive the
  expected 20-byte UDP payloads. Translated underlay ingress remains refused
  on both backends; translation does not change the incoming interface.
- R5: `38119cb0` retains the accepted snapshot's three-field format and adds
  a separate private public-address journal; `66f92379` adds checked host-prefix
  decoding. `9a7fa2ea` checks the installed direct route shape, including IPv6
  kernel normalization. `24542436` records the ownership union before mutation
  and requires both journal membership and exact shape before retirement.
  Operator gateways, onlink/multipath modifiers, unrecorded direct routes,
  foreign tables/interfaces/protocols and local/subnet routes survive.
- Restore unions journaled addresses, accepted peer addresses and retained
  kernel host AllowedIPs before orphan key removal. It proves persistence of
  the already accepted snapshot before replay. After cleanup the journal may
  be pruned before accepting the new snapshot; restart can recover either
  side of that boundary from accepted state and retained peers.
- Endpoint-only changes keep the prior validate/save/install fast path.
  Inventory uses canonical-byte caching to avoid unchanged journal fsyncs.

All ten real-kernel R1–R5/ownership/inventory cases pass at the final production
source. Each runs in a separate disposable user/network namespace under
`systemd-run --user --scope -p CPUWeight=10000`. Ordinary agent/server Mesh
checks pass: 17 library, 4 configuration, 1 settings and 5 store cases;
privileged cases are executed separately from ordinary Cargo tests.

## Liveness classification

The review named
`claude_review_watch_expires_host_made_visible_by_membership_edit`.
At the unchanged imported target it passes alone (9.78 seconds) and in the
full server sequence (169 pass, one unrelated disk-lock failure, 12 ignored,
542.68 seconds). The initial-snapshot failure did not reproduce there.
Source tracing identifies pool/authority deadlines spent on real SQLite and
socket scheduling. `16569cb3` uses the existing frozen runtime clock through
those operations and the exact SQLite `last_seen + 31` wall-clock boundary,
then explicitly advances the expiry timer. Production timers and assertions
are unchanged. Five immutable isolated repeats pass in 9.87–11.40 seconds.

A separate full sequence later reproduced a closed headroom socket at
10,000 nodes/30,000 grants (262 pass, one failure, 30 ignored, 557.33 seconds).
The original case passes alone (111.85 seconds) and in the adjacent target/dev
window (99.22/97.81 seconds, 88 pages). `e22f09a3` freezes runtime time across
real I/O and renews the existing 90-second hang bound only on observed page
progress. Inventory/frame/shared-socket checks remain intact. No longer sleep,
production deadline increase, demonstrated production ordering regression or
same-failure baseline waiver is claimed.

The resumed source-head full server sequence passes 263 cases (30 intentionally
ignored), including both repaired fixtures, in 439.05 seconds. The final
branch-head gate is recorded with its SHA on #129.

## Reviewer checklist

- Both families/backends preserve local delivery and refuse translated ingress.
- Route deletion requires positive public ownership and installed route shape;
  IPv6 universe scope/default metric normalization does not become broad ownership.
- Journaling precedes key/route/policy mutation; save refusal preserves kernel
  state; accepted intent never advances on a failed proposed configuration.
- Crash boundaries recover from journal, accepted config and retained host prefixes;
  component-off still owns teardown and starts no background work.
- Checked existing netlink parsing is reused. Prefix parser: four unit cases;
  sanitizer fuzz: 2,669,514 executions in 61 seconds, no crash.
- All dump replies, including unparsed private fields, are zeroized on early errors.
- No dependency/foundational engine, external wire/API schema, server creation,
  UI or authentication boundary changes. Module roles/invariants are documented.

## Reproduction

Raw round-three receipts were removed under D262; the report retains their
result summaries.
`red-*` captures pre-fix cases; `shape-*` confirms shape alone is insufficient;
`node-*` captures the final regression suite, targeted gates and executable hashes.
The node binaries were built before committing their unchanged sources; provenance
records both the then-current head and committed source SHA/hashes.
Clock evidence includes isolated/full runs, five immutable repeats, headroom
same-window target/dev output and distinct executable hashes. Discarded diagnostic
runs are named as such and are not passing-gate evidence.

Use the job scratch Cargo target, the short job scratch state root,
`RUST_TEST_THREADS=1`, and unique `TRACER_TEST_PORT=4293`. Build outside user
network namespaces so the existing compiler cache remains reachable. Run saved
kernel test executables with `--ignored --exact --nocapture --test-threads=1`
in their own scope and `unshare -Urn`.

The resumed shipping measurements run on infraternal-dev after the resize
(12 vCPUs, about 64 GiB); earlier pre-resize failure/phase logs are retained
for regression chronology, not a controlled performance comparison.

Shipping proofs use `scripts/mesh-agent-scale.py --binary <static-binary>
--scratch <job-scratch>` and `scripts/mesh-namespace-proof.py --binary
<static-binary> --coordinator <coordinator_fixture> --scratch <job-scratch>
--extra-members 999`. Machine/load, source and executable hashes accompany
measurements. No other host or induced CPU load is used.

## Shipping production measurements

All nine sequential proof runs pass: eight privileged library cases, five kernel
integration cases, the shipping single daemon, the shipping production-coordinator
pair, both-backend IPv4/IPv6 ingress and transit refusal, and fallback connectivity
with deny/grant/established-flow checks. Builds and this job's other tests stopped
before measurements. Other jobs remained active. Machine and executable/source
hashes are in `machine.json` and `production-provenance.json`.

| Measurement | Result |
| --- | ---: |
| Peers per shipping daemon | 1,000 |
| Single snapshot chunks | 32 |
| Snapshot including durable save and control RPC (µs) | 262,613 |
| Endpoint action including durable save (µs) | 22,848 |
| Component down (µs) | 42,516,194 |
| Single daemon RSS on/off (bytes) | 8,781,824 / 8,372,224 |
| Single on RSS × expected 1,000 nodes (bytes) | 8,781,824,000 |
| Idle CPU ticks/10 seconds, on/off | 0 / 0 |
| Two shipping daemon RSS (bytes/node) | 11,014,144 / 11,014,144 |
| Pair mean RSS × expected 1,000 nodes (bytes) | 11,014,144,000 |
| Pair idle CPU ticks/10 seconds | 0 / 0 |
| IPv4 RTT p50/p99 (ms) | 0.257 / 3.96 |
| IPv6 RTT p50/p99 (ms) | 0.275 / 6.36 |
| Direct counted 128 MiB throughput (Mbit/s) | 1069.0 |
| Join to first packet (µs) | 1,363,870 |

Single load: `34.16 31.33 30.50 24/1716 390845`. Pair load: `33.57 31.34 30.52 39/1770 393354`. Each RTT sample
receives 25/25 packets. Denied new ping/TCP, established TCP survival, granted
port/other-port refusal and component-off pass. Snapshot timing includes all
control exchanges; endpoint timing is the action's reported apply duration,
including fsync, rather than a separately timed whole RPC.

The pair is **two actual daemons, one actual direct pair and 999 additional
public inventory fixtures per daemon**. Fleet totals are extrapolations, not
1,000 simultaneously measured daemons. RSS remains below the 15 MB daemon
budget in this sample; 25-packet tails do not establish a latency budget. No
relay/WAN capacity or automatic transport-path selection is claimed.

Compared with the recorded round-two author samples, endpoint action time,
component down, pair RSS and throughput are worse. Those samples used eight
CPUs and different shared-load windows. No controlled regression or improvement
claim is made, and the worse numbers are retained. The route journal adds
positive ownership and crash-safe write ordering required by the counterexamples;
canonical-byte caching skips unchanged journal fsyncs on endpoint/policy updates.
The packet path retains the required translated-ingress fence and loopback
exception. Removing either correctness condition is not a valid trade-off.

## Rust gate and size

Source-head milestone `24542436`: `scripts/verify fast` completes with every
non-size Rust row passing; no load waiver. Full output: `verify-node.log`.
The final branch-head run is recorded on #129 with its head SHA and verbatim
gate table after the evidence commit; no production source changes follow this
milestone.

```text
+---------------------------+--------------+
| Rust gate                 | Result       |
+---------------------------+--------------+
| fmt                       | PASS         |
| VT native fmt             | PASS         |
| clippy                    | PASS         |
| test                      | PASS         |
| cargo-deny                | PASS         |
| static builds             | FAIL (1)     |
+---------------------------+--------------+
```

Static stripped x86_64 binary: **20,643,872 bytes**, no PT_INTERP; +9,312
bytes from reviewed `378d4055` (20,634,560). The increase links public ownership
serialization/journaling and checked exact-shape recovery; no dependency or
release-profile change. Existing maximum remains 16,404,816 bytes; overrun
4,239,056 bytes is the known size-row limitation (D205). The dispatcher stops
before ARM and TypeScript; no new pass is claimed for those phases.

Temporary build targets, baseline checkout and saved probe executables are
removed after the final gate. Raw text/JSON evidence above remains committed.
