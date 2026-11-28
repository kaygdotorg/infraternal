<!-- Operator contract for the nightly `infraternal up` join proof on compute01 [#580, J1200, J1257]. -->
# Nightly `up` join proof (#580, J1200, J1257)

`scripts/verify-up-approval-namespace` proves the `infraternal up` approval join in a
private network and mount namespace: the public HTTPS listener is up, the legacy port
7443 is blocked, and the approval page and its passkey ceremony run for real. Its
non-root CLI check needs a second uid, which only real root can provide, so the proof
is complete only when root runs it. The nightly runs it on compute01 every night.

## Who owns what

| Part | Where | Owner |
|---|---|---|
| Coordinator (`scripts/nightly-up-approval.py run`) | the operator's host, with `netbird ssh` | the infraternal orchestrator |
| Root side (clone, build, proof, cleanup) | compute01, as root, over `netbird ssh root@` | the compute01 operator |
| Build queue | compute01 reserved nightly slot, through `scripts/root-slot-hold --reserved nightly` | the claude build account |

## What a run does

1. Picks the commit: `--sha`, or the head of `dev` on the public repository.
2. Probes root on compute01. **Without root the run is skipped** (exit 77, one line
   `SKIP: root is unavailable`, and the reason is recorded). It is not run as claude:
   the non-root check would be skipped, and a pass would overstate the proof.
3. As root, clones that commit from the public repository into a fresh 0700 folder
   under `/root`, builds it there (root-owned cargo home, target and Playwright browsers)
   through the reserved nightly build slot, and runs `scripts/verify-up-approval-namespace` with the full
   check (`UP_E2E_SKIP_NONROOT` is never set).
4. Records `log.txt` and `result.json` under `~/nightly-up-approval/<UTC time>-<sha12>/`
   on the operator's host (mode 0700). Exit 0 pass, 1 fail, 77 skip.

A run fails, not passes, when the root side prints no exit marker (a clone or build
failure, or a dropped session).

## Safety

- The namespace run is its own process group (`setsid`). On exit the root side kills
  that group (`kill -TERM`, then `-KILL`) and removes its own folder. Nothing is killed
  by name.
- The host resolver is never touched (no `resolvectl`, no systemd-resolved D-Bus).
- Root runs only code from the commit it was asked for, cloned from the public
  repository, the same trust model as `scripts/tun-real-root-proof`.
- A killed run leaves its folder behind; the next run removes root-owned leftovers under
  `/root/up-approval.*` once it holds the root lock.

## Run it

```sh
python3 -I scripts/nightly-up-approval.py run --sha <40-hex commit>   # the commit to prove
python3 -I scripts/nightly-up-approval.py run                        # the head of dev
```

The fixture tests (`scripts/test-nightly-up-approval.py`) run in `scripts/verify fast`
as the `nightly up-approval run` row and reach no host.

## Schedule

The operator's systemd user timer on hd01 runs at 04:45 IST with up to ten
minutes of jitter. Install the coordinator from a revision that supports
`--reserved nightly` after the branch tested by the timer has the updated
`root-slot-hold`. See [build slots](build-slots.md) for the compute01 reserve
configuration.
