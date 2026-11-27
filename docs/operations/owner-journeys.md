<!-- Run and interpret the owner journeys against the deployed test server (J1340, #621). -->
# Owner journeys after test deploys

`scripts/owner-journeys` signs in to https://test.ssh.kayg.org using compute01's
existing test-admin helper. It opens a fresh server shell at 1440 × 900 and
393 × 852 in Chromium. The probe requires a marker from the actual shell and
checks the terminal stream's bytes for Ctrl+C, the four arrows, and Ctrl+R. It
asks the sidebar to end only the session it just created. The iPhone row
exercises the phone layout in Chromium at iPhone size. Safari and physical
iPhone behavior need separate device runs.

## Test deploy hook

Run the hook from an independently reviewed checkout on compute01 with Bun on
PATH and the test-admin helper and Chromium already installed. The deploy
operator waits for the test deploy and CA unlock, then calls this hook before
promotion. Give the hook the SHA of the **deployed** build, which may differ
from the reviewed suite's checkout.

```sh
deploy.sh "$sha" test &&
  netbird ssh claude@infraternal-dev-01-compute01.vpn.kayg.org \
    "cd ~/worktrees/owner-journeys-reviewed && PATH=\$HOME/.nix-profile/bin:\$PATH \
     scripts/owner-journeys-after-deploy '$sha' \$HOME/.config/infraternal-owner-journeys.json"
```

If Bun comes from the dev shell, use `nix develop -c` before the hook.
The hook acquires one build slot. Do not wrap it in a second slot. Keep the
same fixture leases through the entire full run and restore the fixture VM
snapshots on interruption or a failed release check. The test service can
share a machine with production. The warm helper requires the running
`infraternal-test.service`, its explicit test origin and its own control socket.
Use only a signed candidate staged for that test service. Use a distinct new
version, record the version in the run output, and coordinate the switch so the
operator can still promote the intended build.

The private evidence directory is printed at launch. It contains a JSONL
transcript, a final `result.json`, and screenshots by step. The runner masks
the join code and credential fields. Raw PTY approval output stays in memory.
Publish selected screenshots and sanitized transcripts on the tracking issue.
A failed step sets exit 1. A dependent step records why it skipped. A missing
final result file means the run was interrupted.

## Fixture configuration

Keep the configuration on compute01 under its private operator-owned config
directory. Use fresh dedicated VM hostnames beginning with `owner-journey-`.
Reserve the Mac VM with the existing Mac lease and use a disposable Linux VM
with its own network and resolver. Revert or replace a tainted fixture before
using it again. Supply each SSH address as reachable **from the test server**
and pin the fingerprint through the fixture's provisioning channel. Any
optional `keyFile` holds an SSH key issued to this fixture only and must have
mode 0600. The test-admin passkey stays in its existing helper.

```json
{
  "linux": {
    "name": "owner-journey-linux",
    "ssh": "fixture@owner-journey-linux.example",
    "fingerprint": "SHA256:<pinned Linux host key>",
    "keyFile": "/home/claude/.config/owner-journey/linux-ssh-key",
    "driver": "/home/claude/infraternal-ops/owner-journey-linux"
  },
  "mac": {
    "name": "owner-journey-mac",
    "ssh": "fixture@owner-journey-mac.example",
    "fingerprint": "SHA256:<pinned Mac host key>",
    "driver": "/home/claude/infraternal-ops/owner-journey-mac"
  },
  "warmUpdate": "/home/claude/infraternal-ops/owner-journey-warm-test"
}
```

Point each host driver at the corresponding locked fixture and invoke the
reviewed `scripts/owner-journeys.d/fixture-host` on it. For example, a driver
for a disposable VM with a staged candidate and the reviewed script in its
fixture home can use the following. The PTY is needed for the real `up`
approval link, and all operations need to return the remote exit status.
Use the Mac login account with the active GUI session. Set up the fixture
account and its passwordless administrative access as part of its lease.
On the fixture, set `~/.config/infraternal-owner-journey` to the fixture's
hostname and stage the released CLI for the VM's platform at the candidate
path. Build the candidate on a build VM, or use a verified release artifact.

```bash
#!/usr/bin/env bash
set -euo pipefail
name=owner-journey-linux
pty=()
[[ $1 != up ]] || pty=(-t)
# This driver is installed by the fixture operator with these fixed paths and host.
printf -v invocation '%q ' /home/fixture/fixture-host "$1" \
  /home/fixture/releases/infraternal "$name" "${@:2}"
exec timeout 230 netbird ssh --no-browser "${pty[@]}" "fixture@$name.vpn.kayg.org" "$invocation"
```

The warm adapter takes `apply https://test.ssh.kayg.org` and invokes
`scripts/owner-journeys.d/warm-test-server` on the test service host as an
account allowed to use that test control socket. Append the absolute signed
candidate binary path and the edge version as its last two arguments. The
server CLI waits through the warm restart. The journey requires its success
message and then asks the browser for a **new** shell.

The SSH journey accepts a ready host or a clear refusal that points to
`infraternal up`. The up journey compares the code, machine name, key and
service mode before approving with the passkey. It exercises status and mesh
status, opens a shell, stops the fixture's own service so cleanup stays
pending, cancels the first Remove confirmation, then removes and forgets.
It runs the public `infraternal uninstall` command locally and checks the
installed files, services and managed network artifacts before rejoining.
Failures on existing deployed builds are findings to file, including a
missing public command or sidebar action.

## Nightly row

Schedule the following on compute01 from the reviewed checkout under the
test-admin helper's account. Use it for the unattended smoke row, separate
from the token-less dev-02 browser suite. It uses the same private evidence
format. The browser row reports the warm update and fixture lifecycle as
skipped. Use the full post-deploy invocation for those rows.

```sh
cd ~/worktrees/owner-journeys-reviewed
~/infraternal-ops/build-slot nix develop -c scripts/owner-journeys --browser-only
```
