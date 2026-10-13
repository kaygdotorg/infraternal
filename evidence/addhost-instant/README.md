<!-- Records D255 bridge prerequisites and explicit integration gaps for #189. -->
# D255 continuation state

Status: **partial; add-host orchestration is unchanged**. Base
26ccb33ab4d3ec8d5a545517c68cf7d52f40b121, branch addhost-instant. The
internal bridge is a tested prerequisite, not a shipped early-terminal path.
No LAN/150 ms provisioning latency or ten-fresh-target acceptance is claimed.

Implemented in separate logical commits:

- b7486463: canonical setup refusal survives a closed invitation input pipe.
  Unchanged R190-02 oracle fails before; the eight process tests pass after.
- 4c58dba3: native SSH handles configured BindAddress, BindInterface and
  restricted address families. Unchanged R190-01 contact assertions fail
  before and pass after. Default routing retains the connector.
- a63dfba1: duplex SSH command pipes own their child and unreaped process group.
- 106e131f: readiness-driven standard pipes implement the existing Channel;
  CLOEXEC prevents descriptor inheritance into later children.
- 1d374fcf: additive duplex command method on the existing SSH session trait;
  older adapters refuse it by default.
- 4f881158: bounded commands and duplex commands share the exact fail-local
  master-channel builder. No second authentication path.
- 24cdb09e: hidden __ssh-session command, compiled only with SSH and remote.
  It starts the existing shim-owned shell, publishes the session id and runs
  the existing authenticated terminal dispatcher through command pipes.
- 867a4224: real-process pipe-to-inherited-fd handover oracle. Session id and
  even writer remain unchanged; pending input executes once and output resumes.
- 5731f06d: proposed host setup event and D240/D247 compatibility contract,
  posted to #189 before code. This contract is not implemented in the router.

A module declaration ordering mistake was corrected by rewriting the
unpublished stdio commit; the earlier issue comment's later SHAs are superseded
by this list. The interrupted fmt-red gate is retained. It is not final proof.

## Evidence boundaries

The real-process oracle uses the GNU development binary and exclusive command
pipes locally, then the real inherited-fd infraternal agent. It proves shim
ownership and writer replay at this boundary. It does not exercise a real SSH
server, enrollment, provisional browser admission, background setup ownership,
installed mTLS replacement or session selection in the canvas.

primitives-test.log: 26 pass, 2 ignored. bridge-ssh-tests.log retains the full
SSH suite. primitives-clippy.log and primitives-fmt.log retain the strict
SSH/CLI checks. source-green-final.log has the native-contact assertion replay;
its concurrently added duplex code caused dead-code warnings in the separate
source-clippy-final attempt before that module was wired. The repair-only
source-clippy.log and complete primitives-clippy.log both pass. No warning
waiver was applied.

The first browser invocation lacked local pinned dependencies. Install from
apps/tracer with bun install --frozen-lockfile, then replay on unique port4997.
Functional test durations are not performance evidence. No UI is changed and
no visual quality or physical iPhone claim is made.

## Remaining integration

1. Negotiate compressed/reused payload staging and launch the shim on the same
   SSH connection; publish its session through authorized browser routing.
2. Keep background setup alive after wizard closure while retaining immediate
   revocation/component-off fencing and bounded ownership. Do not apply the
   old fresh-install rollback to a published live user session.
3. Implement host-bound retained setup events, persistent subscriptions and
   retry actions; add the contract to the test double. The proposed window id
   is supplied by the canvas and never fabricated as a session id.
4. Replace the SSH link through the existing admitted terminal actor and replay
   path, preserve writer identities, then retire SSH only after success.
5. Integrate the shared per-person real-login launcher when D240/D247 lands.
   The internal command currently uses the existing shared session launcher.
6. Run all real add-host/start-fresh/round-3 tests and measure10 fresh targets
   each on LAN/150ms RTT on VM208/shared lock. Current primitives have no
   accepted time-to-prompt or fully-joined measurements.

Recheck the real boundary from the repository root:

```sh
CARGO_TARGET_DIR="$HOME/.cache/codex-scratch/addhost-instant/target" cargo build -p infraternal
INFRATERNAL_TEST_STATE_ROOT="$HOME/.cache/codex-scratch/ahi" python3 scripts/verify-ssh-session.py --binary "$HOME/.cache/codex-scratch/addhost-instant/target/debug/infraternal"
```

Full fast gate output and final disposition are recorded on #189. Static-size
caps, dependencies, release profile and owner fixtures are unchanged. Issue
remains open; no deployment or production branch update.

## Source-head milestone gate (5731f06d)

Full scripts/verify fast exits1: fmt, VT fmt, workspace Clippy and cargo-deny
pass; test and static rows fail. Server327 pass/1 fail/39 ignored. The unchanged
mesh_calls_and_subscriptions_deliver_scoped_live_inventory assertion fails at
socket_tests.rs677, expecting a successful Result for call_id3. Exact-artifact
replay with matching target/state environment also fails. Earlier replay omitted
the target environment and closed its socket; that output is kept separately.
No timeout exemption or causal waiver is claimed.

Detached origin/dev5e383c3d passes that exact test, both before and after its
matching CLI build. This newer baseline differs substantially from the lane's
26ccb33a base; it does not establish which change causes the legacy failure.
The failed predicate must be resolved before a green completion claim.

Browser first replay29/1: missing broken.lab failure heading at the original
15s assertion. Unchanged full replay30/30 passes, including Start fresh.
Tracer check and171 source tests pass. browser-failure-details.png is a real
optimized tracer build capture with the provisioning test double; no new UI,
visual verdict or physical-device claim. Historical capture restored.

The final branch-head gate is run again after this evidence-only commit and
quoted verbatim on #189. Its separate log is retained locally; the committed
milestone transcript remains reproducible source-head evidence.
