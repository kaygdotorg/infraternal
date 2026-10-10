<!-- Records the scoped round-two implementation, real release proof and reproduction commands (#87, #78). -->
# Add-host release round two

Implementation source through `72fff910`; later commits attach reproducible evidence.
The parked `release-addhost-wip` branch was not imported. No deployment was performed.

Remove host is declared in the optional remote plugin action registry. The UI,
CLI, skill output and HTTP API use that definition. Removal requires a new
owner passkey proof bound to the host and original session, revokes access using
the existing quiescence fence, removes bootstrap inventory and its unshared SSH
pin, and requests uninstall on the existing authenticated host channel. Revoked
host identity rows remain as denial/audit tombstones because certificate and
session foreign keys reference them; they are absent from live inventory.
Unreachable hosts lose server access and receive an explicit remaining-artifacts message.

The independent uninstall helper validates the owned installation and removes
its unit, enable link, launcher and private data. It retires foreground jobs
and their login shells within the existing per-session deadline. Handler
registration survives the bootstrap lock; every action and cleanup still
refuses an unfinished installation. Automatic sign-in preserves the selected
connection's exact trust lookup. These two defects were found by the real
container run after the original unit tests passed.

Remote shell exit now reaches the browser promptly, persists its status, and
closes a cleanly exited window after its final output paints. Installation
failures identify the step and allowlisted host error. Fingerprints name their
key family and matching comparison command. Duplicate adds say already added;
sign-in and failure copy describes actual behavior. Linux process names are
set before dispatch so symlink launches report infraternal. Release packaging
ships both matching static host payloads beside the server, with checksums;
missing-payload diagnostics name the architecture and expected path.

## Real evidence

[container-pass.log](container-pass.log) records the full passing production
flow against stock Debian SSH offering RSA, ECDSA and ED25519, with no preseeded
trust: one ED25519 confirmation, rootful execution, enabled service, a 604800-second
certificate, actual terminal input/output, reload of the same session, duplicate
refusal without another certificate, shell exit without further input with durable
status 0, and fresh-passkey removal. Actual unit, enable link, binary and data
were absent; inventory and trust were deleted and certificate access revoked.

The completed functional run measured 20 confirmed echoes: p50 2.68 ms,
p99 12.00 ms, load 12.43/12.82/17.93. Separately, [echo-1000.log](echo-1000.log)
records 1000 echoes: p50 3.42 ms, p99 15.60 ms, maximum 311.49 ms, load
15.51/20.08/26.19. That earlier run stopped at the subsequently fixed duplicate
add decoder; it is latency evidence, not the final lifecycle gate. Later long
probes also encountered socket closures under shared load; no result was
silently retried or substituted. Measurements ran locally on infraternal-dev,
8 logical cores, under `systemd-run --user --scope -p CPUWeight=10000`.
The full flow's ready and terminal wall times include automated dialog waits
and passkey/password interaction; they are not directly comparable to VM system time.

Production captures are attached for independent visual review:
[host key](real-hostkey-desktop.png), [terminal](remote-terminal-desktop.png),
[reload](remote-reload-desktop.png), [desktop removal](real-remove-desktop.png),
[phone removal](real-remove-phone.png). The author review is in
[reviewer-checklist.md](reviewer-checklist.md).

Known preexisting issue outside this brief: remote details fetch local host facts.
It is recorded on #87, without importing the parked lifecycle/registry work.

## Gates and size

The final `scripts/verify fast` output is retained verbatim in `verify-fast.log`.
Its formatting, native formatting, clippy, tests and dependency policy rows pass.
The static size row fails under D205; the binaries are stripped, static and lack
PT_INTERP. TypeScript checks/tests pass separately because the size failure stops
the combined script before its TypeScript stage; see [typescript-fast.log](typescript-fast.log).
Critical JavaScript is 287065/307200 gzip bytes; deferred is 50562/51200.
The new bootstrap socket decoder regression also passes (1 test, 2 assertions).

The default 300 ms add-host browser run passed 40 of 41 cases; an idempotent
fixture reset socket failed before its cancellation test. The fresh cancellation
rerun passes, completing coverage of all 41 cases. Both original outputs are
attached: [browser suite](browser-addhost.log), [cancellation rerun](browser-cancellation-rerun.log).

The dev d82d0fb9 schema shape (14 migrations) upgrades to 19 migrations with
ownership retained and foreign keys/integrity clean. Release completeness and
all three checksums pass; incomplete bundles never publish. The production
removal decoders have a fuzz target and passed a 10000-run ordinary libFuzzer
smoke test with no panic; that run had no coverage instrumentation and is not
claimed as coverage fuzzing. No new dependency versions were introduced.

| x86 commit set | Bytes | Change |
| --- | ---: | ---: |
| d8ecd870 base | 19578400 | — |
| process/exit set | 19616096 | +37696 |
| removal/diagnostic/CLI set | 19885856 | +269760 |
| foreground retirement | 19891232 | +5376 |
| startup registration | 19891296 | +64 |
| selected trust lookup | 19892640 | +1344 |

Final x86 growth is 314240 bytes over d8ecd870. The optional remote plugin,
removal service and CLI account for most of it; existing transport/crypto engines
were reused. ARM is 17729832 bytes. The tested release bundle is
`$HOME/.cache/codex-scratch/release-addhost/round2-tested-bundle`, containing
`infraternal`, `infraternal-x86_64-musl`, `infraternal-aarch64-musl`, and `SHA256SUMS`.

## Reproduce

Use the exact owned fixture name below; never use another job's container.
Build the fixture with the included Dockerfile, then launch its real init manager:

```sh
sudo -n docker build -t infraternal-addhost-round2 evidence/addhost-round2
sudo -n docker run -d --name infraternal-release-addhost-round2 \
  --cap-add SYS_ADMIN --security-opt apparmor=unconfined --cgroupns private \
  --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
  --mount type=bind,source=/dev/pts,target=/dev/pts \
  -p 127.0.0.1::22 infraternal-addhost-round2
```

The harness checks all three public host key files and generates private sign-in
input only in memory/stdin. It changes only the container's own ptmx symlink,
never the shared host devpts permissions. Build production web output separately
from preview/browser mocks, and package both architectures with `scripts/package-release`.

```sh
TRACER_DIST="$HOME/.cache/codex-scratch/release-addhost/production-web" \
  bun run --cwd apps/tracer build
ECHO_SAMPLES=20 \
INFRATERNAL_BIN="$HOME/.cache/codex-scratch/release-addhost/round2-tested-bundle/infraternal" \
TRACER_DIST="$HOME/.cache/codex-scratch/release-addhost/production-web" \
INFRATERNAL_TEST_STATE_ROOT="$HOME/.cache/codex-scratch/a87" \
TRACER_TEST_PORT=4350 \
systemd-run --user --scope -p CPUWeight=10000 \
  bun evidence/addhost-round2/container-round2.ts
```

Omit ECHO_SAMPLES for the separate 1000-sample probe. Each browser invocation
needs its own TRACER_TEST_PORT. The harness binds its named test origin to
10.69.69.125:47591 and its remote endpoint to 10.69.69.125:47592. It disposes its
server and browser; remove the owned fixture after reviewing the result.
