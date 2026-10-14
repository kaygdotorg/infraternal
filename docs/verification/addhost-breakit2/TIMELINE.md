<!-- Describes the owned D255 timing fixture, clock boundaries and acceptance evidence (#189). -->

# Add-host prompt timeline

`timeline.py` wraps the existing disposable-target measurement. The Rust
controller serves the real bootstrap API, session WebSocket and production
web assets. The diagnostic browser entry uses the shipping provisioning
client, multiplexed connection and terminal renderer. It calls the sign-in
operation directly; wizard and camera animations are outside this measurement.
The existing multiplexed socket is established before that operation starts.

Build artifacts on the build host. Run measurements only on the perf VM under
`flock -w 3600 /var/lock/perf-bench.lock`, releasing the lock between fresh
targets. Keep the fixture's short state directory and unique container name
exclusive to this lane. Use a unique `TRACER_TEST_PORT` for each browser run.
`measure.py` takes explicit full and session images and verifies the installed
full-image digest after handover; omitting the session image is refused.

The driver uses these additional environment variables:

| Variable | Purpose |
| --- | --- |
| `ADDHOST_BROWSER_TIMELINE=1` | Enable the ignored controller's real browser path. |
| `ADDHOST_BROWSER_DIST` | Production assets plus the bundled diagnostic entry and `timeline.html`. |
| `ADDHOST_BROWSER_SCRIPT` | `addhost-timeline.mjs`, with the existing Playwright dependency available. |
| `ADDHOST_BROWSER_RUNTIME` | Bun executable on the measurement machine. |
| `ADDHOST_BROWSER_PREPARE=1` | Prepare resources and a disposable renderer with sign-in for the paired comparison. |
| `ADDHOST_TIMELINE_EVIDENCE` | Owned directory receiving public clock/packet receipts. |
| `ADDHOST_TIMELINE_TARGET` | Same unique Docker target name passed to `--container-name`. |
| `ADDHOST_TIMELINE_CAPTURE=1` | Default detailed trace: SSH interposer, target shell clocks and bounded header captures. |
| `ADDHOST_TIMELINE_CAPTURE=0` | Production SSH/shell paths; retain browser/server clocks and every acceptance assertion. |
| `ADDHOST_FAST_STEP_PROFILE=1` | Enable target shell boundaries. |
| `ADDHOST_PROMPT_BUDGET_MS=1500` | Fail after byte-integrity and installation proof when paint exceeds this post-authentication budget. |
| `ADDHOST_SSH_COMPRESSION=1` | Fixture-only compressed SSH master for a paired experiment; shipping configuration is unchanged. |

Browser records use `performance.timeOrigin + performance.now()`. Server and
SSH records use epoch milliseconds; target shell records use epoch nanoseconds.
All three processes run on the same VM clock. Header-only TCP captures record
both directions, without payloads. Target/client SSH diagnostics retain only
fixed protocol message types, not arbitrary debug text. The target wrapper also
records public shell-program byte counts. Diagnostic subprocesses add small
local overhead, so compare matched fixtures rather than treating an instrumented
trace as the uninstrumented acceptance result.

Run production-path acceptance with `ADDHOST_TIMELINE_CAPTURE=0`, leaving
`ADDHOST_FAST_STEP_PROFILE`, `ADDHOST_FAST_TCP_PROFILE`,
`ADDHOST_SSH_COMPRESSION`, `BREAKIT2_FDPASS_CANDIDATE` and
`ADDHOST_PROMPT_PIPE_BYTES` unset. The driver refuses enabled profiling or
transport experiments in this mode, verifies that the generated SSH wrapper
does not invoke the tracing interposer and that the target has no shell-clock
wrapper, then emits `PROOF production_transport_paths=true`. SSH trust,
browser paint witnesses, all 59 acknowledged input bytes, installed-image
digest verification, child exit propagation and the prompt budget are unchanged.

Report each mode separately with its artifacts and all attempted samples.
The detailed trace explains protocol flights; a matched production-path series
measures acceptance without per-command Python launches, shell-clock programs,
verbose SSH logging or packet captures. Do not subtract a guessed observer
cost from traced results or label those results as production-path acceptance.

`target-packet-headers.txt` captures the owned container's network namespace,
in addition to the bridge and browser loopback captures. Its ingress timestamp
precedes the fixture's incoming delay. `target-delivery-headers.txt` observes
the first SYN on `ifb0` after that delay (on `eth0` for undelayed LAN cases).
Label these observation points separately from target SSH application reads.
The full target capture stops after the three TCP handshake packets, before payload transfer;
the bridge capture and target SSH/shell clocks cover the remaining traffic.
Enter only that container's network namespace; no target filesystem or
unrelated process is selected.

The owner cookie and generated SSH identity travel only through child stdin.
No request headers, WebSocket bodies, terminal contents, private key or cookie
are stored. The fixture's generated public host key remains strictly pinned;
ignoring the disposable browser TLS certificate does not bypass SSH trust.

The first painted prompt triggers 30 bytes of input before handover. After the
retained setup stream reports ready, another 29 bytes are sent. Success requires
both outputs and acknowledgment of all 59 bytes on the original session. The
driver's budget check runs only after those proofs complete. Raw receipts belong
in the job cache and must be attached to #189, rather than committed here.

Two functional browser oracles run on the build host without measuring latency:
`TRACER_TEST_PORT=<unique> bun docs/verification/addhost-breakit2/renderer-disposal.mjs`
checks document handlers after disposal and a partial opening failure;
`renderer-prepare.mjs` checks single-flight preparation, resource-failure retry,
focus preservation and absence of new sockets or retained DOM/listeners.
`RENDERER_DISPOSAL_ARTIFACT` may select an earlier public renderer artifact for
the disposal oracle's negative control. Keep their output outside the checkout.

The final native gate can use `native-timing-runner.py` as Cargo's GNU test
runner (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="python3 <absolute-script>"`).
It moves the ten non-ignored real QUIC server-path cases to
the designated VM under one short lock; their assertions and deadlines are unchanged. It verifies
the copied executable's SHA-256, executes each exact case under the shared
lock, requires one executed passing test and a successful child-exit sentinel,
then executes every remaining case locally. Failure on either machine fails
the aggregate; a filtered invocation is refused.

Set `ADDHOST_NATIVE_VM_ROOT` and `ADDHOST_NATIVE_VM_STATE_ROOT` to owned paths
under `/root/infraternal-bench/`. `ADDHOST_NATIVE_VM_LOADER` and
`ADDHOST_NATIVE_VM_LIB` select the already-staged compatible GNU loader and
public runtime libraries. `INFRATERNAL_TEST_STATE_ROOT` keeps local test state
under the job's scratch directory. Other test executables pass through without
changes. This is an explicit execution-platform choice for physical timing
checks, not a skip or a different test expectation.
