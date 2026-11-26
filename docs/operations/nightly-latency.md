<!-- Operator contract for the nightly D375 latency run on the perf VM [D375, #447]. -->
# Nightly latency run (D375, #447)

Every night the D375 latency profile (`scripts/verify latency`: the native agent
probe plus the tracer browser specs, ten p99 rows) runs on the quiet perf VM
against the head of `origin/dev`. PROCESS section 1 calls each budget a CI check;
before this, nothing ran the profile, and shared build hosts made the flood row
flap, so gate decisions come from these perf-VM runs only.

## Who owns what

| Part | Where | Owner |
|---|---|---|
| Timer and coordinator (`scripts/nightly-latency.py run`) | hd01, a systemd **user** unit of the hd01 operator account | the infraternal orchestrator |
| Build of the static x86_64 binary | compute01, through `build-slot`, fresh target per run | the compute01 build queue |
| Measurement and published tables | perf VM, as `claude`, under `perf-run`, in `~/nightly-latency/` | the perf VM operator |
| The comment on #447 | `fj` login of the hd01 operator | the orchestrator |

Why hd01 and not the perf VM: the perf VM only measures (no cargo, no sudo, no
user lingering, no Forgejo login), and compute01 cannot reach it. Only hd01
reaches both. hd01 does no building and no measuring; it moves one binary
(about 30 MB) and reads two small files.

## Schedule

`infraternal-nightly-latency.timer` fires daily at **03:30 Asia/Kolkata**, up to
10 minutes late. That is clear of the dev-02 nightlies (fuzz 02:00; browser suite
05:00, quiet window 05:30 to 07:45) and the run uses no dev-02 at all. It needs
the perf VM's lock (`perf-run` queues behind other benchmarks, so a calternal run
delays it, never overlaps it) and one compute01 build slot for the build. A
normal night takes about 25 to 40 minutes after the build; the unit gives up at 5 h.

## What a run does

1. Reads the head of `origin/dev` from the public repository.
2. Builds `infraternal` (static x86_64 musl) on compute01 in a throwaway worktree
   and target, and streams it to the perf VM; sha256 is compared at both ends.
3. On the perf VM, under `perf-run`: fetches exactly that commit (shallow),
   runs `scripts/verify latency` with `INFRATERNAL_LATENCY_BINARY` set (it measures
   the shipped bytes; the profile's own cargo build and the auth-browser functional
   check are skipped, since the perf VM has no cargo) and
   `FIRST_PAINT_PROTOCOL=http2` by default (matching production `ssh.kayg.org`;
   `FIRST_PAINT_PROTOCOL=http1` stays selectable, #573), and deletes its work files.
4. Publishes the night, atomically (see below).
5. Compares each row with the previous published night (within the same transport
   protocol, when tagged) and comments on #447 only if a row fails its gate, is
   missing, or regressed.

**Regressed** means more than 10 % worse than the previous night and worse by more than
0.5 in the row's unit (ms, MB or fps); the floor keeps a 0.6 ms row from tripping on
0.06 ms of jitter. A failing row is reported every night it fails. A night with no
numbers at all (build failed, perf VM unreachable, disk full) posts one comment saying so.
A green night posts nothing: the table is on the perf VM.

## Logs and published tables

- Coordinator log: `journalctl --user -u infraternal-nightly-latency.service` on hd01.
- Perf VM, `~/nightly-latency/published/<UTC time>-<sha12>/`: `table.md` (the D375 table),
  `rows.json` (the gated value of each row, used for the next night's comparison),
  `meta.json` (commit, gate, failing and regressed rows, machine state lines),
  `verify-latency.log` (the whole profile output) and `comment.md` when a comment was due.
  `published/latest` points at the newest complete night; the newest 30 are kept.
- Publishing follows the nightly browser suite reporter (#443): the night is written
  into a hidden staging directory, every file and the directory are fsynced, and the
  directory is renamed into place; `latest` is then replaced by renaming a fresh link.
  A reader sees the previous night or the whole new one, never half of one.
- `perf-run` also leaves its before and after machine-state files in
  `~/nightly-latency/perf-run/`.

Disk: the perf VM was 99 % full (1.6 GB free, then under 700 MB) when this was written, so a
run keeps its checkout and `node_modules` (about 0.7 GB) in `/tmp`, which is RAM-backed there,
and removes them when it ends. It needs 1.5 GB free in `/tmp` and 100 MB in the home, and
otherwise stops with exit status 3 (and one comment). What stays on disk is the published nights
(about 2 MB each) and `~/nightly-latency/browsers`, the run's own Playwright headless shell
(about 270 MB): the shared `~/.cache/ms-playwright` on the perf VM holds version 1228 while the
tracer lockfile pins 1255, so the run downloads the pinned one once and wipes the folder when the Playwright version changes.
The perf VM also lacks the shared libraries Chromium needs (libnspr4, libnss3, libgbm and twelve
more) and the run has no root, so it fetches those Debian packages with `apt-get download` and
unpacks them under `~/nightly-latency/libs` (about 8 MB), pointing `LD_LIBRARY_PATH` at them for
the run. The VM has no fonts or fontconfig setup either (Chromium aborts in Skia without one), so the
same folder holds the DejaVu font and a private `fonts.conf` named by `FONTCONFIG_FILE`. If the operator installs them system-wide, the run notices they are not missing and does not fetch.

## Operate or stop

```sh
systemctl --user list-timers infraternal-nightly-latency.timer     # next firing
systemctl --user start infraternal-nightly-latency.service         # run now (same as the timer)
systemctl --user disable --now infraternal-nightly-latency.timer   # stop scheduling
systemctl --user stop infraternal-nightly-latency.service          # abort a run in progress
```

A manual run without a comment, for a particular commit:
`scripts/nightly-latency.py run --sha <commit> --no-comment` (`--sha` also accepts a
pushed branch head, which is how a change to the profile itself is tried before it is on dev).
Stopping the unit ends the coordinator and its ssh sessions; `perf-run` releases the
perf lock when its command ends. If something is left behind, look for
`~/nightly-latency/in/` and `~/nightly-latency/work/` on the perf VM and for
`~/nightly-latency-out/` on compute01 and remove them.

## Install or update

Install on hd01, as the operator account, from a clone at the reviewed full commit.
The installer checks the checkout is at that commit, checks that `netbird`, `git` and
`fj` are on PATH, and runs two preflight checks: `build-slot --status` on compute01, and
`perf-run -- true` on the perf VM (the VM's `perf-run` takes `[--cold] [--root] [--out DIR] -- <cmd>`
and has no `status` subcommand). The perf check takes the perf lock for a moment, so while a
benchmark holds the lock it can time out after 120 s; rerun the installer then. It then writes the
program and the two units, reloads the user manager only if a unit changed, and enables the timer.
Repeating it is safe. `--no-preflight` skips both checks.

```sh
d=$(mktemp -d) && git clone -q https://git.kayg.org/kayg/infraternal.git "$d/src" \
  && git -C "$d/src" checkout -q --detach <40-hex SHA> \
  && python3 -I "$d/src/scripts/install-nightly-latency" --ref <40-hex SHA>; rm -rf "$d"
```

The coordinator ships its own installed copy to the perf VM on every run, so the
reviewed copy is the only measurement script that runs there. `scripts/verify`,
`latency_targets.py` and the tracer specs come from the commit under test.

## Switch rule

PROCESS section 6 turns the own-overhead gate from 12 ms to 8.3 ms after two consecutive
perf-VM runs at or under 8.3 ms. These nightly tables are those runs: read the own-overhead
row of two consecutive nights, then change `OWN_OVERHEAD_GATE_MS` in a change that cites them.
