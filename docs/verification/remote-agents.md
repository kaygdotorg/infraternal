<!-- Records tested remote identity/transport boundaries and incomplete phase-1 acceptance for #78. -->
# Remote infraternal agents: phase 1 checkpoint

Phase 1 is incomplete. Issue #78 is the state of record for all steps and
verbatim gates. This checkpoint resumes from `c77e7a3`; source head is
`417e1972a4f31a8cb92beee713c1c5e4af8e667e`. No push, deployment or o1/o2
installation occurred. Build scratch is retained for continuing this job.

The prepared identity layer has host/mode/uid-bound 15-minute hashed tokens,
transactional certificate publication, bounded canonical Ed25519 CSR parsing
with a fuzz target, seven-day signing, cold-locked memory key source and
process-only handoff [168]. These are library boundaries. Administrator
passkey/role adapters, encrypted envelopes and runtime endpoints remain pending.

The shared daemon now accepts authenticated channels while preserving the
existing shim relay. It checks the locally enrolled uid, requires control Hello,
rejects odd writer ids and uid substitution, and retires cancelled connections
without killing shims. Native QUIC carries raw existing frames with stable even
server writer ids distinct from QUIC ids. Its terminal path preserves Snapshot
notice ordering, input acknowledgments and byte-offset replay. These callable
paths still need the production dialer, server registry and browser routing.

The real-CLI oracle uses a rootless PTY, isolated shell startup and raw cat,
replaces 25 real quinn/mTLS connections, replays already-written input and
compares the received prefix against an independent surviving shim reader:
569 exact bytes, 26 markers once, zero duplicates. This is local evidence,
not the required rootless o1/o2 chaos matrix.

The shared output queue could stall control dispatch: a runtime RED test
expired at two seconds. A separate eight-slot reply lane now takes priority
at frame boundaries and refuses overload without awaiting capacity. The first
fix failed the unchanged real twelve-terminal saturation oracle because a
ready writer did not get polled before a reply burst filled the queue. A
full-batch scheduling yield corrected that regression without changing limits
or assertions. The real oracle compares all 2,640,000 bytes; new tests preserve
notice-before-Snapshot order. There is no new healthy idle polling.

## Atomic source steps

| Step | SHA |
| --- | --- |
| Shared daemon admission | `1e2f1b0` |
| Real mTLS admission tests | `70b9314` |
| Native borrowed codec/channel | `9e762a6` |
| Real QUIC framing/cancellation tests | `b3bb3a4` |
| Native terminal relay | `c07d8f8` |
| Real PTY reconnect oracle | `1ce3ed3` |
| Merge dev `19fe05a`, preserve deployed schema | `234686b` |
| Deployed-v11 upgrade/idempotence test | `5fe5747` |
| Control readiness fix | `cade5ad` |
| Readiness/order/queue-memory tests | `417e197` |

The merge reproduced a duplicate migration 0010 in real SQLite. Preserve
deployed recovery 0010/0011 and their checksums; the unpublished remote identity
migration is now 0012. The upgrade test retains an account and recovery audit
row, checks version uniqueness and applies the new schema idempotently.
Every source step above passed the exact fast gate in CPUWeight10000 scope;
#78 records its SHA, load and verbatim output. Latest source gate:

```text
| fmt                       | PASS         |
| VT native fmt             | PASS         |
| clippy                    | PASS         |
| test                      | PASS         |
| cargo-deny                | PASS         |
| static builds             | PASS         |
 7 pass
 0 fail
 34390 expect() calls
Ran 7 tests across 2 files. [1.97s]
```

## D167 measurements and browser result

Machine: infraternal-dev, Linux 6.12.111+deb13-amd64, x86_64,
Intel i9-9900K, eight visible cores. Debug diagnostics ran serially after this
job's builds/browser runs stopped, in CPUWeight10000 scope. TCP initially
hit inherited NOFILE1024; its successful repeat used process-local NOFILE4096.
Each linked log preserves tool output below its descriptive header.

| Measurement | p50 / p99 | Scale and cost | Proof |
| --- | --- | --- | --- |
| QUIC admission, RTT300ms, 25 samples | 460,080 / 464,893 us | 1,000 retained client/server pairs: 67,348 KiB RSS delta, 67.348 KiB/pair; 588 CPU ticks; load3.49/11.22/13.19 | [QUIC](remote-agents/run5-quic-diagnostic.log) |
| TCP/TLS admission, RTT300ms, 25 samples | 758,889 / 763,350 us | 1,000 pairs: 69,400 KiB, 69.4 KiB/pair; 266 ticks; load7.32/8.21/11.56 | [TCP](remote-agents/run5-tcp-diagnostic.log) |
| Signer, 1,000 public identities | 347 / 654 us | 39 ticks; 398,000 DER bytes; 3,184 KiB RSS delta, 3.184 KiB/identity | [Signer](remote-agents/run5-signing-diagnostic.log) |
| Added populated control lane, 1,000 queues | — | 2,892 KiB added RSS, 2,961 B/lane; 6,778 us creation/first enqueue; Message72 B | [Queues](remote-agents/run5-reply-lane-diagnostic.log) |
| Real local PTY, 25 reconnects, RTT0 | 9,379 / 14,503 us | 569 exact bytes; 26 markers once; uid1001; load8.01/8.34/11.58 | [PTY](remote-agents/run5-native-pty-repeat.log) |

Pair RSS includes both transport endpoints. Queue RSS excludes the daemon,
transport and shim. Signer cost excludes network and publication. None proves
whole connected infraternal-agent memory, live renewal or zero idle wakeups.
D170's target is 1,000 nodes, 200 terminals, 50 users, with 10,000-node headroom.

Required production browser suite, port4701: **42 passed, 21 skipped,
five failed (10.8m)**. Failures: motion, onboarding, palette navigation,
returning sign-in/terminal latency and first-paint budgets. Load reached
21.80/13.00/8.06 on eight cores. Isolated motion/terminal checks under the same
scope and port fail on archived dev `ac03b19` (three failed, one passed,4.1m)
and this branch (three failed, one passed,3.4m). Branch frontend/proxy files
match merged dev `19fe05a`. No threshold was changed; the browser gate is red.
Raw browser logs remain job artifacts referenced on #78. Production screenshots
are in tracer `test-results/`; this lane makes no visual-quality claim.

## Remaining acceptance

- Encrypted XDG CA envelopes, current administrator/passkey unlock and role
  rewrap/notification adapters, overlapping CA rotation. Proposed #34 layout:
  `$XDG_DATA_HOME/infraternal/ca/`, default `~/.local/share/infraternal/ca/`,
  private0700 directory/0600 encrypted files outside SQLite.
- Pinned operator join and enrollment endpoint, locally generated host-key
  storage, automatic QUIC-first/TLS-fallback reconnect supervisor and backoff.
- Server routing by recorded host and enrolled uid; reuse existing durable
  `terminal_writers`/`owned_writer` authority. Library framing/relay tests do
  not establish the browser/server/remote-host route.
- Half-life live renewal, atomic certificate publication without interrupting
  sessions, CPU/RSS/bytes during 50MiB output.
- Immediate active revocation, restricted authenticated removal on next contact,
  rootless operator uninstall and integrated fail-closed lease. The inherited
  `remote_lease.rs` helper is unregistered and not runtime enforcement.
- o1/o2 rootless chaos matrix, full cleanup, reconnect/byte and whole-process
  RSS/wakeup evidence. Neither host was modified in this run.
- Production integration review and required browser timing gates. Source
  self-review checked uid/writer trust, codec reuse, bounded admission/queues,
  cancellation, replay ordering and content-free errors; this is not complete
  phase-1 or independent integration review.
