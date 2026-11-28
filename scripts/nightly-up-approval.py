#!/usr/bin/env python3
"""Nightly `infraternal up` join proof on compute01, as real root when root is reachable [#580, J1200, J1257].

`scripts/verify-up-approval-namespace` runs the whole `up` approval join in a private
network and mount namespace (the page, the passkey ceremony and the agent's legacy port
7443 blocked). Its non-root CLI check needs a second uid, which only real root can give
it, so the proof is complete only when root runs it. This coordinator runs that proof
every night, and only where root is actually reachable.

Where each part runs, and why:

- `run` is the coordinator. It runs on the operator's own host (it needs `netbird ssh`
  and reads the public repository). It builds nothing and runs no test itself.
  1. Picks the commit: `--sha`, or the head of `dev` on the public repository.
  2. Probes root on compute01 (`netbird ssh <root host> true`). When root does not answer,
     the run is SKIPPED with exit status 77 and the reason is recorded. A claude-only run
     is not done instead: it would skip the very check that needs root, and reporting it
     as a pass would overstate what was proven.
  3. Feeds `ROOT_SCRIPT` to `bash -s` on root's side and keeps the whole log.
- `ROOT_SCRIPT` runs as root on compute01. It trusts only the commit id and the public
  repository, as `scripts/tun-real-root-proof` does: root clones the commit into a fresh
  0700 folder under `/root`, builds it there with a root-owned cargo home, target and
  Playwright browsers, through the reserved nightly build slot (`scripts/root-slot-hold`, so the claude
  build account keeps its queue and nothing it writes reaches root's process). Then it runs
  `scripts/verify-up-approval-namespace` with the full check. The namespace script runs in
  its own process group (setsid); the trap kills only that group and removes root's folder,
  so no server it started outlives the run. Nothing here touches the host resolver.

Exit status of `run`: 0 pass, 1 failed (or an infrastructure error after the probe),
77 skipped (root unreachable), 2 usage. Each run writes `log.txt` and `result.json` under
`--out` (default `~/nightly-up-approval/<UTC time>-<sha12>/`), readable only by its owner.

Usage:
    nightly-up-approval.py run [--sha <40-hex commit>] [--out DIR]
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True

#: The SSH target of compute01's root account, reached through netbird ssh (network auth, no keys).
ROOT_HOST = os.environ.get("NIGHTLY_UP_APPROVAL_HOST", "root@infraternal-dev-01-compute01.vpn.kayg.org")
REPOSITORY = "https://git.kayg.org/kayg/infraternal.git"
#: The same clean environment `tun-real-root-proof` gives root's side: nothing set machine-wide or by sshd.
REMOTE_ENV = "env -i PATH=/nix/var/nix/profiles/default/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C.UTF-8"
PROBE_TIMEOUT = 120
RUN_TIMEOUT = 3 * 3600
EXIT_PASS, EXIT_FAIL, EXIT_SKIP = 0, 1, 77

# Root's side. Fed to `bash -s -- <commit>` on compute01. Every line that matters for the
# trust boundary is commented where it runs; the coordinator's docstring has the overview.
ROOT_SCRIPT = r"""
set -euo pipefail
commit=$1
[[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo "pass the full 40-character commit id" >&2; exit 2; }
repository=https://git.kayg.org/kayg/infraternal.git
export PATH=/nix/var/nix/profiles/default/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root
umask 077

# One run at a time: a second run waits instead of deleting the first one's folder.
mkdir -p /root/.cache
exec 9>/root/.cache/up-approval-nightly.lock
flock 9

# Holding the lock means no other run is alive, so a folder a killed run left behind is safe to remove
# (no trap runs on SIGKILL). Only root-owned folders match.
for stale in /root/up-approval.*; do
    [[ -d $stale && ! -L $stale && $(stat -c %u "$stale") == 0 ]] || continue
    echo "removing a killed run's leftover: $stale"
    rm -rf -- "$stale"
done

work=$(mktemp -d /root/up-approval.XXXXXX)
group=
cleanup() {
    # Kill only this run's own process group (the namespace script and what it started), never by name.
    if [[ -n $group ]] && kill -0 -- "-$group" 2>/dev/null; then
        kill -TERM -- "-$group" 2>/dev/null || true
        sleep 2
        kill -KILL -- "-$group" 2>/dev/null || true
    fi
    # The agent starts terminal shims in their own process groups (setsid), so the group kill misses them
    # (J1257: a shim survived the first passing run). Kill by PID every process whose executable lives in this
    # run's folder; that path is root's own build, so nothing else can match it.
    local proc exe
    for proc in /proc/[0-9]*; do
        exe=$(readlink -- "$proc/exe" 2>/dev/null) || continue
        case $exe in "$work"/*) kill -KILL -- "${proc#/proc/}" 2>/dev/null || true ;; esac
    done
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# 1. Root fetches the commit itself, from the public repository, and checks it is the commit asked for.
git clone -q --no-checkout "$repository" "$work/src"
git -C "$work/src" fetch -q origin "$commit"
git -C "$work/src" checkout -q --detach "$commit"
[[ $(git -C "$work/src" rev-parse HEAD) == "$commit" ]] || { echo "checkout is not $commit" >&2; exit 1; }
echo "root clone at $commit in $work"

# 2. Build as root: root-owned cargo home, target, browsers and scratch. TMPDIR is set inside the dev shell,
#    not before it (J952: outside, Nix nests its temp dir and socket paths exceed SUN_LEN).
export CARGO_HOME=/root/.cache/up-approval-cargo CARGO_TARGET_DIR=$work/target CARGO_BUILD_JOBS=4
export PLAYWRIGHT_BROWSERS_PATH=/root/.cache/up-approval-playwright
export scratch=$work/tmp
mkdir -p "$CARGO_HOME" "$PLAYWRIGHT_BROWSERS_PATH"
cd "$work/src"
python3 scripts/root-slot-hold --reserved nightly --keep-fd 9 nix develop -c bash -c '
    set -euo pipefail
    mkdir -m 700 -p "$scratch" && export TMPDIR=$scratch
    cd apps/tracer && bun install --frozen-lockfile && bun run build
    bun x playwright install chromium
    cd ../.. && cargo build --locked --package infraternal
' > "$work/build.log" 2>&1 || { tail -40 "$work/build.log" | cat -v >&2; exit 1; }
# The debug binary: apps/tracer/real/up-approval.spec.ts asserts INFRATERNAL_BIN is $CARGO_TARGET_DIR/debug/infraternal.
binary=$CARGO_TARGET_DIR/debug/infraternal
[[ -x $binary ]] || { echo "no release binary at $binary" >&2; exit 1; }
[[ -d $work/src/apps/tracer/dist ]] || { echo "no tracer dist in $work/src" >&2; exit 1; }
echo "built $commit as root: $(stat -c '%s' "$binary") bytes"

# 3. The full proof, as root (no UP_E2E_SKIP_NONROOT: the script then runs its non-root CLI check).
#    setsid makes the namespace script a process group of its own, so the trap can kill exactly its children.
export INFRATERNAL_BIN=$binary TRACER_DIST=$work/src/apps/tracer/dist
setsid nix develop -c bash -c 'mkdir -m 700 -p "$scratch" && export TMPDIR=$scratch \
    && exec timeout --kill-after=60 1800 bash scripts/verify-up-approval-namespace' > "$work/proof.log" 2>&1 &
group=$!
if [[ $(ps -o pgid= -p "$group" | tr -d ' ') != "$group" ]]; then
    echo "the namespace run is not its own process group" >&2
    kill -TERM "$group" 2>/dev/null || true
    exit 1
fi
status=0
wait "$group" || status=$?
cat "$work/proof.log"
echo "UP_APPROVAL_NIGHTLY_EXIT=$status commit=$commit"
exit "$status"
"""


def utc_now():
    """The current UTC time, timezone-aware."""
    return datetime.datetime.now(datetime.timezone.utc)


def log(message):
    """Print one timestamped line for the operator's journal."""
    print(f"{utc_now():%Y-%m-%dT%H:%M:%SZ} {message}", flush=True)


def head_of_dev():
    """The head of `dev` on the public repository, as a full commit id."""
    out = subprocess.run(["git", "ls-remote", REPOSITORY, "refs/heads/dev"],
                         capture_output=True, text=True, check=True).stdout
    sha = out.split()[0] if out.split() else ""
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RuntimeError("the public repository did not report a dev head")
    return sha


def probe_root():
    """Whether root on compute01 answers now, and why not when it does not.

    Returns `(True, "")` or `(False, reason)`. A netbird that is not installed is an error of the
    operator's host, not a missing root, so it raises instead of skipping.
    """
    try:
        result = subprocess.run(["netbird", "ssh", ROOT_HOST, "true"], capture_output=True, text=True,
                                timeout=PROBE_TIMEOUT)
    except FileNotFoundError:
        raise RuntimeError("`netbird` is not on PATH") from None
    except subprocess.TimeoutExpired:
        return False, f"no answer from {ROOT_HOST} within {PROBE_TIMEOUT} s"
    if result.returncode != 0:
        first = (result.stderr.strip().splitlines() or ["no reason given"])[0][:200]
        return False, f"`{ROOT_HOST}` refused the probe (exit {result.returncode}): {first}"
    return True, ""


def run_remote(sha):
    """Run `ROOT_SCRIPT` as root for `sha`; return `(exit status, combined output)`."""
    result = subprocess.run(["netbird", "ssh", ROOT_HOST, f"{REMOTE_ENV} bash -s -- {sha}"],
                            input=ROOT_SCRIPT, capture_output=True, text=True, timeout=RUN_TIMEOUT)
    return result.returncode, result.stdout + result.stderr


def verdict(status, output):
    """Pass only when root's side printed its exit marker as 0 and ssh itself returned 0.

    The marker must be present: a run that dies before the proof (a failed clone, a dropped
    session) prints none and is a failure, never a silent pass.
    """
    marks = re.findall(r"UP_APPROVAL_NIGHTLY_EXIT=(\d+) commit=[0-9a-f]{40}", output)
    if status == 0 and marks == ["0"]:
        return "pass", ""
    if not marks:
        return "fail", f"no exit marker (ssh exit {status}); the run did not reach the proof"
    return "fail", f"the proof exited {marks[-1]} (ssh exit {status})"


def record(out_root, sha, status, reason, output):
    """Write `log.txt` and `result.json` into a new run folder under `out_root`; return the folder."""
    folder = out_root / f"{utc_now():%Y%m%dT%H%M%SZ}-{sha[:12]}"
    folder.mkdir(parents=True, exist_ok=False, mode=0o700)
    (folder / "log.txt").write_text(output, encoding="utf-8")
    (folder / "result.json").write_text(json.dumps({"sha": sha, "status": status, "reason": reason},
                                                   indent=2) + "\n", encoding="utf-8")
    return folder


def main(argv):
    """Pick the commit, probe root, run the proof when root answers, record the result and return its exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run", help="run the nightly proof once")
    run_parser.add_argument("--sha", help="the full 40-character commit to prove (default: the head of dev)")
    run_parser.add_argument("--out", type=Path, default=Path.home() / "nightly-up-approval",
                            help="where run folders go (default: ~/nightly-up-approval)")
    args = parser.parse_args(argv[1:])
    sha = args.sha or head_of_dev()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        parser.error("--sha must be a full 40-character lowercase commit id")

    args.out.mkdir(parents=True, exist_ok=True, mode=0o700)
    reachable, reason = probe_root()
    if not reachable:
        log(f"SKIP: root is unavailable on compute01 ({reason}); the join proof was not run")
        folder = record(args.out, sha, "skip", reason, "")
        log(f"UP_APPROVAL_NIGHTLY status=skip sha={sha} record={folder}")
        return EXIT_SKIP

    log(f"running the join proof as root at {sha}")
    status, output = run_remote(sha)
    result, why = verdict(status, output)
    folder = record(args.out, sha, result, why, output)
    print(output, end="" if output.endswith("\n") else "\n")
    log(f"UP_APPROVAL_NIGHTLY status={result} sha={sha} record={folder}" + (f" reason={why}" if why else ""))
    return EXIT_PASS if result == "pass" else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main(sys.argv))
