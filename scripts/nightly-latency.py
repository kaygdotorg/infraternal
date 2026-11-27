#!/usr/bin/env python3
"""Nightly D375 latency run on the perf VM, with a comment on #447 only when it matters [D375, #447].

D375 sets ten p99 latency targets and `scripts/verify latency` measures all of them,
but nothing ran it. This script runs it every night, on the quiet perf VM, where gate
decisions belong (PROCESS section 6): shared build hosts make the flood row flap.

Where each part runs, and why (the perf VM only measures):

- `run` is the coordinator. It runs on hd01 from a systemd user timer, because only
  hd01 reaches both the build VM and the perf VM, hd01 holds the Forgejo login (`fj`),
  and the perf VM has no cargo, no sudo and no user lingering. It never builds or
  measures on hd01.
  1. Takes the head of `origin/dev` (or `--sha`).
  2. Builds the static x86_64 `infraternal` on compute01 through `build-slot`, with a
     fresh target per run, and streams the binary to the perf VM (checked with sha256).
  3. Streams its own copy to the perf VM and runs `measure` there under `perf-run`.
  4. Reads the result and posts a short comment on #447 when a row fails or regressed.
- `measure` runs on the perf VM, inside `perf-run`. It clones the exact commit, runs
  `scripts/verify latency` on the prebuilt binary (native probe plus the tracer browser
  specs), and publishes the table atomically: everything is written into a hidden
  directory under `published/`, synced, and renamed, then the `latest` link is swapped
  by rename. A reader sees the previous night or the whole new night, never part of one.

Regression rule: a gated row regressed when it is more than 10 % worse than the previous
published night AND worse by more than `NOISE_FLOOR` (0.5 in the row's own unit, so
a 0.6 ms row cannot trip the rule on 0.06 ms of jitter). Failing rows are always reported.

Usage:
    nightly-latency.py run [--sha SHA] [--no-comment] [--keep-work]
    nightly-latency.py measure --sha SHA --binary PATH --root DIR      (internal)
"""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

REPOSITORY = "https://git.kayg.org/kayg/infraternal.git"
ISSUE = "kayg/infraternal#447"
FORGEJO_HOST = "git.kayg.org"
BUILD_HOST = os.environ.get("NIGHTLY_LATENCY_BUILD_HOST", "claude@infraternal-dev-01-compute01.vpn.kayg.org")
PERF_HOST = os.environ.get("NIGHTLY_LATENCY_PERF_HOST", "claude@infraternal-perf-01-backup01.vpn.kayg.org")
#: Where the run keeps its files on the perf VM (relative to the perf account's home).
PERF_ROOT = "nightly-latency"
#: A row regressed when it is worse than the previous night by more than this share ...
REGRESSION_SHARE = 0.10
#: ... and by more than this much in the row's own unit (ms, MB or fps): below it the move is jitter.
NOISE_FLOOR = 0.5
#: Free space a run needs before it starts: in /tmp for the checkout and tracer dependencies, and in the
#: home for the published night (a Playwright upgrade also re-downloads about 270 MB there).
MIN_TMP_FREE_BYTES = 1_500_000_000
MIN_HOME_FREE_BYTES = 100_000_000
#: How long `scripts/verify latency` may run on the perf VM before it is killed (seconds).
VERIFY_TIMEOUT = 75 * 60
#: How long the coordinator waits for the build and for the perf VM's lock plus the run (seconds).
BUILD_TIMEOUT = 3 * 3600
PERF_TIMEOUT = 2 * 3600
#: Published nights kept on the perf VM.
KEEP_NIGHTS = 30

# The build VM's half of a run. It is fed to `bash -s` with the commit and the output folder as
# arguments. A fresh CARGO_TARGET_DIR per run: a target must never be shared between revisions (#542).
BUILD_SCRIPT = r"""
set -euo pipefail
sha=$1 out=$HOME/$2
repo=$HOME/infraternal wt=$HOME/worktrees/nightly-latency
git -C "$repo" fetch -q origin dev
git -C "$repo" cat-file -e "$sha^{commit}" 2>/dev/null || git -C "$repo" fetch -q origin "$sha"  # a branch head, when the profile itself is tried by hand
[ -d "$wt" ] || git -C "$repo" worktree add -f --detach "$wt" "$sha"
git -C "$wt" checkout -q --detach "$sha"
mkdir -m 700 -p "$HOME/.nl"
target=/mnt/build/targets/nightly-latency-${sha:0:12}
trap 'rm -rf "$target"' EXIT
rm -rf "$target"
cd "$wt"
# scripts/auth-toolchain fetches the checksum-pinned Zig the static C builds need; `scripts/verify` does the same.
nix develop "$wt" -c env TMPDIR="$HOME/.nl" CARGO_TARGET_DIR="$target" \
    "$HOME/infraternal-ops/build-slot" bash -c 'scripts/auth-toolchain &&
    PATH="$CARGO_TARGET_DIR/auth-tools/zig:$PATH" scripts/static-cargo build --locked --release \
    --package infraternal --target x86_64-unknown-linux-musl'
rm -rf "$out" && mkdir -p "$out"
install -m 0755 "$target/x86_64-unknown-linux-musl/release/infraternal" "$out/infraternal"
(cd "$out" && sha256sum infraternal > SHA256)
"""

# The perf VM's receiving half: a private folder for the run, the script and the binary from stdin.
RECEIVE_SCRIPT = """
set -euo pipefail
dir=$HOME/%(root)s/in/$1
mkdir -p -m 700 "$dir"
cat > "$dir/$2"
chmod 700 "$dir/$2"
"""


def utc_now():
    """The current UTC time, timezone-aware."""
    return datetime.datetime.now(datetime.timezone.utc)


def log(message):
    """Print one timestamped line; the systemd journal is the coordinator's log."""
    print(f"{utc_now():%Y-%m-%dT%H:%M:%SZ} {message}", flush=True)


# ---------------------------------------------------------------------------
# Pure helpers: the gated measurement of each row, the comparison and the comment.
# ---------------------------------------------------------------------------

def gated_rows(latency_targets, log_text):
    """The gated measurement of every D375 row in a profile log, as `{key: summary}`.

    A gating row uses its unthrottled (browser), native, or explicit display, and a
    reported-only row falls back to whichever display was measured (for example `60hz`
    for `first-paint-network.spec.ts`), matching `latency_targets.report`. Preserves
    `protocol` and `wire` tags when present so nights compare within one protocol (#573).
    """
    measured = latency_targets.parse("\n".join([log_text, *latency_targets.compose_own_overhead(log_text)]))
    rows = {}
    for row in (*latency_targets.ROWS, *latency_targets.EXTRA_ROWS):
        entries = measured.get(row.key, {})
        display = latency_targets.gated_display(row, entries)
        if display is None and not row.gating:
            display = next(iter(entries), None)
        if display is None:
            continue
        fields = entries[display]
        try:
            value, samples = float(fields["value"]), int(fields.get("n", "0"))
        except (KeyError, ValueError):
            continue
        result = fields.get("result", "FAIL")
        if samples < row.min_n:
            result = f"FAIL (n {samples} < {row.min_n})" if row.gating else f"REPORT (n {samples} < {row.min_n})"
        measure = latency_targets.row_measure(row, fields) if hasattr(latency_targets, "row_measure") else row.measure
        summary = {"measure": measure, "value": value, "unit": fields.get("unit", ""),
                   "gate": fields.get("gate", "?"), "n": samples, "result": result,
                   "display": display}
        if "protocol" in fields:
            summary["protocol"] = fields["protocol"]
        if "wire" in fields:
            summary["wire"] = fields["wire"]
        rows[row.key] = summary
    return rows


def regressions(previous, current):
    """The rows that got worse than the previous night by more than the share and the noise floor.

    `previous` and `current` are `gated_rows` results. Frame rates are better when higher.
    A row without a previous value, a previous night that failed to measure it, or a row
    whose transport `protocol` changed (for example HTTP/1.1 to HTTP/2, #573) is not compared.
    """
    found = []
    for key, now in current.items():
        before = previous.get(key)
        if before is None or before["unit"] != now["unit"] or before.get("protocol") != now.get("protocol"):
            continue
        worse_by = before["value"] - now["value"] if now["unit"] == "fps" else now["value"] - before["value"]
        if worse_by > NOISE_FLOOR and worse_by > REGRESSION_SHARE * abs(before["value"]):
            found.append({"key": key, "measure": now["measure"], "before": before["value"],
                          "now": now["value"], "unit": now["unit"], "percent": 100 * worse_by / abs(before["value"])})
    return found


def failing(latency_targets, current):
    """The rows that failed their gate, plus every D375 row that is missing from the run."""
    # A reported row (result REPORT) shows in the table and the regression check but never fails the night.
    bad = [(key, row["measure"], f"{row['value']:.2f} {row['unit']} against a gate of {row['gate']}")
           for key, row in current.items() if row["result"] not in ("PASS", "REPORT")]
    bad += [(row.key, row.measure, "not measured") for row in (*latency_targets.ROWS, *latency_targets.EXTRA_ROWS)
            if row.key not in current]
    return bad


def comment_text(meta, bad, slower, table, published):
    """The short #447 comment for a night with failing or regressed rows (empty when there is none)."""
    if not bad and not slower:
        return ""
    lines = [f"**Nightly D375 latency, perf VM, dev `{meta['sha'][:12]}`** ({meta['run']}): "
             + ("a gate failed" if bad else "no gate failed, but a row got slower") + "."]
    for _, measure, detail in bad:
        lines.append(f"- FAIL {measure}: {detail}")
    for item in slower:
        lines.append(f"- SLOWER {item['measure']}: {item['before']:.2f} to {item['now']:.2f} {item['unit']} "
                     f"(+{item['percent']:.0f} % against {meta.get('previous') or 'the previous night'})")
    lines += ["", table, "", f"Full log and table: `{published}` on the perf VM. `scripts/nightly-latency.py`, D375, #447."]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# measure: runs on the perf VM, inside perf-run.
# ---------------------------------------------------------------------------

def find_bun():
    """The directory holding `bun`: NIGHTLY_LATENCY_BUN_DIR, the PATH, or the newest bun in the nix store."""
    configured = os.environ.get("NIGHTLY_LATENCY_BUN_DIR")
    if configured:
        return configured
    found = shutil.which("bun")
    if found:
        return str(Path(found).parent)
    candidates = sorted(Path("/nix/store").glob("*-bun-*/bin/bun"))
    return str(candidates[-1].parent) if candidates else None


def sync_directory(path):
    """fsync a directory so a rename into it survives a crash."""
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish(root, name, files):
    """Publish `files` (`{filename: text-or-Path}`) as `published/<name>` atomically, then move `latest`.

    Everything is written into a hidden sibling, fsynced, and renamed into place; the `latest`
    symlink is replaced by renaming a fresh link over it. Older nights beyond KEEP_NIGHTS are removed.
    """
    published = root / "published"
    published.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=published))
    try:
        for filename, content in files.items():
            target = staging / filename
            if isinstance(content, Path):
                shutil.copyfile(content, target)
            else:
                target.write_text(content, encoding="utf-8")
            descriptor = os.open(target, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        sync_directory(staging)
        os.chmod(staging, 0o755)
        os.rename(staging, published / name)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    link = published / ".latest-tmp"
    link.unlink(missing_ok=True)
    link.symlink_to(name)
    os.replace(link, published / "latest")
    sync_directory(published)
    nights = sorted(entry for entry in published.iterdir() if entry.is_dir() and not entry.name.startswith("."))
    for old in nights[:-KEEP_NIGHTS]:
        shutil.rmtree(old, ignore_errors=True)


def previous_night(root):
    """The previous published night as `(name, rows)`, or `(None, {})` when there is none yet."""
    latest = root / "published" / "latest"
    try:
        return latest.resolve().name, json.loads((latest / "rows.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, {}


#: The Debian packages that hold the shared libraries Chromium's headless shell links against and the
#: perf VM does not have. They are fetched with `apt-get download` and unpacked privately: no root needed.
BROWSER_LIBRARY_PACKAGES = (
    "libnspr4", "libnss3", "libatk1.0-0t64", "libatk-bridge2.0-0t64", "libatspi2.0-0t64", "libxcomposite1",
    "libxdamage1", "libxfixes3", "libxrandr2", "libgbm1", "libxkbcommon0", "libasound2t64", "libxrender1", "libdrm2", "libxi6")


#: The one font package the private fontconfig file points at.
BROWSER_FONT_PACKAGES = ("fonts-dejavu-core",)


def missing_libraries(browsers, env):
    """The shared libraries the installed headless shell cannot find under `env` (empty when it can start)."""
    shell = next(browsers.glob("chromium_headless_shell-*/*/chrome-headless-shell"))
    out = subprocess.run(["ldd", str(shell)], env=env, capture_output=True, text=True).stdout
    return [line.split()[0] for line in out.splitlines() if "not found" in line]


def ensure_browser_libraries(root, browsers, env):
    """Make the headless shell startable: unpack the missing Debian libraries and one font under `<root>/libs` once.

    The perf VM has no fontconfig setup or fonts either, and Chromium aborts in Skia ("Not implemented") the first
    time a page needs a font, which killed the long terminal spec 40 s in. So a private fontconfig file points at
    the DejaVu font unpacked beside the libraries. Sets LD_LIBRARY_PATH and FONTCONFIG_FILE in `env`.
    Raises RuntimeError naming what is still missing if that is not enough.
    """
    libs = root / "libs"
    library_path = libs / "usr/lib/x86_64-linux-gnu"
    fonts = libs / "usr/share/fonts"
    env["LD_LIBRARY_PATH"] = f"{library_path}:{env['LD_LIBRARY_PATH']}" if env.get("LD_LIBRARY_PATH") else str(library_path)
    env["FONTCONFIG_FILE"] = str(libs / "fonts.conf")
    if not missing_libraries(browsers, env) and fonts.exists():
        return
    shutil.rmtree(libs, ignore_errors=True)
    libs.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="debs", dir="/tmp") as download:
        subprocess.run(["apt-get", "download", *BROWSER_LIBRARY_PACKAGES, *BROWSER_FONT_PACKAGES], cwd=download, check=True)
        for package in sorted(Path(download).glob("*.deb")):
            subprocess.run(["dpkg-deb", "-x", str(package), str(libs)], check=True)
    (libs / "fonts.conf").write_text(
        '<?xml version="1.0"?>\n<!DOCTYPE fontconfig SYSTEM "fonts.dtd">\n<fontconfig>\n'
        f"  <dir>{fonts}</dir>\n  <cachedir>{root / 'fontcache'}</cachedir>\n</fontconfig>\n", encoding="utf-8")
    still = missing_libraries(browsers, env)
    if still or not fonts.exists():
        raise RuntimeError(f"the browser still lacks {', '.join(still) or 'its font'}")


def prepare_tracer(source, root, env):
    """Install the tracer's dependencies and the one Playwright browser this commit's lockfile pins.

    The perf VM's shared browser cache lags the lockfile (it held 1228 when 1255 was pinned), and its
    disk is nearly full, so the run keeps its own cache in `<root>/browsers`: the headless shell only
    (about 270 MB), downloaded once per Playwright version and wiped when the version changes.
    Returns the browsers path. Raises CalledProcessError when an install fails.
    """
    tracer = source / "apps" / "tracer"
    subprocess.run(["bun", "install", "--frozen-lockfile"], cwd=tracer, env=env, check=True)
    version = json.loads((tracer / "node_modules/playwright/package.json").read_text(encoding="utf-8"))["version"]
    browsers = root / "browsers"
    marker = browsers / ".playwright-version"
    if not marker.exists() or marker.read_text(encoding="utf-8") != version:
        shutil.rmtree(browsers, ignore_errors=True)
    browsers.mkdir(parents=True, exist_ok=True)
    env["PLAYWRIGHT_BROWSERS_PATH"] = str(browsers)
    subprocess.run(["bun", "x", "playwright", "install", "--only-shell", "chromium"], cwd=tracer, env=env, check=True)
    marker.write_text(version, encoding="utf-8")
    ensure_browser_libraries(root, browsers, env)
    return browsers


def run_verify(source, binary, work, log_path, root):
    """Run `scripts/verify latency` on the prebuilt binary and return its exit status (124 on timeout)."""
    tmp = tempfile.mkdtemp(prefix="nl", dir="/tmp")  # short and private: socket paths must fit SUN_LEN (J952)
    env = dict(os.environ, INFRATERNAL_LATENCY_BINARY=str(binary), CARGO_TARGET_DIR=str(work / "target"),
               TMPDIR=tmp, INFRATERNAL_EVIDENCE_DIR=str(work / "evidence"))
    # Production (ssh.kayg.org) serves HTTP/2; keep FIRST_PAINT_PROTOCOL=http1 selectable when comparing (#573).
    env.setdefault("FIRST_PAINT_PROTOCOL", "http2")
    bun_dir = find_bun()
    if bun_dir:
        env["PATH"] = f"{bun_dir}:{env['PATH']}"
    try:
        prepare_tracer(source, root, env)
    except (subprocess.CalledProcessError, OSError, ValueError, RuntimeError, StopIteration) as error:
        Path(log_path).write_text(f"nightly-latency: could not prepare the tracer: {error}\n", encoding="utf-8")
        shutil.rmtree(tmp, ignore_errors=True)
        return 125
    with open(log_path, "wb") as sink:
        child = subprocess.Popen(["scripts/verify", "latency"], cwd=source, env=env, stdout=sink,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return child.wait(timeout=VERIFY_TIMEOUT)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)  # by process group only, never by name
            child.wait()
            return 124
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def measure(args):
    """Run the profile on the perf VM and publish the night. Exits 0 once a night is published, even a failing one."""
    root = Path(args.root)
    started = utc_now()
    # The checkout and node_modules (about 0.7 GB) live in /tmp, a RAM-backed folder on the perf VM, because
    # its disk is nearly full; only the published night and the private browser and library caches use the disk.
    tmp_free, home_free = shutil.disk_usage("/tmp").free, shutil.disk_usage(Path.home()).free
    if tmp_free < MIN_TMP_FREE_BYTES or home_free < MIN_HOME_FREE_BYTES:
        print(f"nightly-latency: {tmp_free // 10**6} MB free in /tmp (need {MIN_TMP_FREE_BYTES // 10**6}) and "
              f"{home_free // 10**6} MB in the home (need {MIN_HOME_FREE_BYTES // 10**6})", file=sys.stderr)
        return 3
    work = Path(tempfile.mkdtemp(prefix="nlw", dir="/tmp"))
    try:
        source = work / "src"
        # Fetch exactly the commit under test (shallow: the perf VM's disk is nearly full). It is a dev head in
        # the nightly, or a branch head when a change to the profile itself is tried by hand.
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        for step in (["remote", "add", "origin", REPOSITORY], ["fetch", "-q", "--depth", "1", "origin", args.sha],
                     ["checkout", "-q", "--detach", "FETCH_HEAD"]):
            subprocess.run(["git", "-C", str(source), *step], check=True)
        sys.path.insert(0, str(source / "scripts"))
        import latency_targets  # the table of the commit under test, not of this script's install

        log_path = work / "verify-latency.log"
        status = run_verify(source, Path(args.binary).resolve(), work, log_path, root)
        text = log_path.read_text(encoding="utf-8", errors="replace")
        table, passed = latency_targets.report(text)
        current = gated_rows(latency_targets, text)
        before_name, before = previous_night(root)
        bad, slower = failing(latency_targets, current), regressions(before, current)
        if status != 0 and not bad:
            bad.append(("profile", "scripts/verify latency", f"exited {status}"))
        meta = {"run": args.run, "sha": args.sha, "started": f"{started:%Y-%m-%dT%H:%M:%SZ}",
                "finished": f"{utc_now():%Y-%m-%dT%H:%M:%SZ}", "verify_exit": status,
                "gate": "PASS" if passed and status == 0 else "FAIL", "previous": before_name,
                "failing": [key for key, _, _ in bad], "regressed": [item["key"] for item in slower],
                "environment": [line for line in text.splitlines() if line.startswith("ENVIRONMENT ")]}
        published = f"~/{PERF_ROOT}/published/{args.run}"
        files = {"table.md": table + "\n", "rows.json": json.dumps(current, indent=1) + "\n",
                 "meta.json": json.dumps(meta, indent=1) + "\n", "verify-latency.log": log_path}
        comment = comment_text(meta, bad, slower, table, published)
        if comment:
            files["comment.md"] = comment
        publish(root, args.run, files)
        print(f"nightly-latency: published {published} gate={meta['gate']}")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)  # the perf VM's disk is nearly full: keep only the published night


# ---------------------------------------------------------------------------
# run: the coordinator on hd01.
# ---------------------------------------------------------------------------

def netbird(host, command, *, stdin=None, timeout=None):
    """Run `command` on `host` through netbird ssh (network auth, no keys) and return the CompletedProcess."""
    return subprocess.run(["netbird", "ssh", host, command], stdin=stdin, capture_output=False, timeout=timeout)


def netbird_capture(host, command, *, timeout=300):
    """Run a command on a host and return its standard output as text (raises when it fails)."""
    result = subprocess.run(["netbird", "ssh", host, command], capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"{host}: {command!r} failed ({result.returncode}): {result.stderr.strip()[:500]}")
    return result.stdout


def dev_head():
    """The commit at the head of origin/dev, from the public repository."""
    out = subprocess.run(["git", "ls-remote", REPOSITORY, "refs/heads/dev"], capture_output=True, text=True, check=True).stdout
    return out.split()[0]


def post_comment(text):
    """Post `text` on #447 through `fj` (the body goes through a private file, never argv)."""
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as handle:
        handle.write(text)
    try:
        subprocess.run(["fj", "-H", FORGEJO_HOST, "issue", "comment", ISSUE, "--body-file", handle.name], check=True)
    finally:
        os.unlink(handle.name)


def stream(source_command, host, destination_command):
    """Pipe the output of a command on the build VM into a command on `host`, through this machine."""
    producer = subprocess.Popen(["netbird", "ssh", BUILD_HOST, source_command], stdout=subprocess.PIPE)
    consumer = subprocess.run(["netbird", "ssh", host, destination_command], stdin=producer.stdout, timeout=PERF_TIMEOUT)
    producer.stdout.close()
    return producer.wait() == 0 and consumer.returncode == 0


def run(args):
    """The nightly: build on compute01, ship, measure on the perf VM, comment when needed. Returns the exit status."""
    state = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "infraternal-nightly-latency"
    state.mkdir(parents=True, exist_ok=True)
    lock = open(state / "lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log("another nightly latency run holds the lock; nothing to do")
        return 0
    sha = args.sha or dev_head()
    run_id = args.run_id or f"{utc_now():%Y%m%dT%H%M%SZ}-{sha[:12]}"
    log(f"run {run_id}: measuring dev {sha}")
    built = f"nightly-latency-out/{run_id}"
    perf_in = f"{PERF_ROOT}/in/{run_id}"
    failure = None
    try:
        if args.reuse_build:
            log(f"reusing the binary already in ~/{built} on the build VM")
        else:
            build = subprocess.run(["netbird", "ssh", BUILD_HOST, f"bash -s -- {sha} {built}"],
                                   input=BUILD_SCRIPT.encode(), timeout=BUILD_TIMEOUT)
            if build.returncode != 0:
                raise RuntimeError(f"the build on compute01 failed ({build.returncode})")
        digest = netbird_capture(BUILD_HOST, f"cut -d' ' -f1 {built}/SHA256").strip()
        receive = f"bash -c {shlex.quote(RECEIVE_SCRIPT % {'root': PERF_ROOT})} _ {run_id}"
        if not stream(f"cat {built}/infraternal", PERF_HOST, f"{receive} infraternal"):
            raise RuntimeError("could not copy the binary to the perf VM")
        with Path(__file__).resolve().open("rb") as own:
            if netbird(PERF_HOST, f"{receive} nightly-latency.py", stdin=own).returncode != 0:
                raise RuntimeError("could not copy the measurement script to the perf VM")
        got = netbird_capture(PERF_HOST, f"sha256sum {perf_in}/infraternal").split()[0]
        if got != digest:
            raise RuntimeError(f"the binary changed on the way to the perf VM ({digest[:12]} against {got[:12]})")
        log("binary is on the perf VM; measuring under perf-run")
        measured = netbird(PERF_HOST, f"perf-run --out $HOME/{PERF_ROOT}/perf-run -- python3 $HOME/{perf_in}/nightly-latency.py "
                           f"measure --sha {sha} --binary $HOME/{perf_in}/infraternal --root $HOME/{PERF_ROOT} --run {run_id}",
                           timeout=PERF_TIMEOUT)
        if measured.returncode != 0:
            raise RuntimeError(f"the measurement on the perf VM failed ({measured.returncode})")
        night = f"{PERF_ROOT}/published/{run_id}"
        meta = json.loads(netbird_capture(PERF_HOST, f"cat {night}/meta.json"))
        log(f"gate {meta['gate']}; failing={meta['failing']} regressed={meta['regressed']}")
        comment = ""
        if meta["failing"] or meta["regressed"]:
            comment = netbird_capture(PERF_HOST, f"cat {night}/comment.md")
    except Exception as error:  # a night with no numbers is itself a gate failure worth one comment
        failure = str(error)
        log(f"FAILED: {failure}")
        comment = (f"**Nightly D375 latency did not run** (dev `{sha[:12]}`, {run_id}): {failure}. "
                   "See `journalctl --user -u infraternal-nightly-latency` on hd01. #447, D375.\n")
    finally:
        if not args.keep_work:
            netbird(BUILD_HOST, f"rm -rf {built}")
            netbird(PERF_HOST, f"rm -rf {perf_in}")
    if comment and not args.no_comment:
        post_comment(comment)
        log("posted a comment on #447")
    elif comment:
        log("a comment is due but --no-comment was given:\n" + comment)
    return 1 if failure else 0


def main(argv):
    """Parse the subcommand and run it."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    runner = sub.add_parser("run", help="the nightly coordinator (hd01)")
    runner.add_argument("--sha", help="measure this dev commit instead of the head of origin/dev")
    runner.add_argument("--no-comment", action="store_true", help="do not post on #447; print the comment instead")
    runner.add_argument("--run-id", help="name the run (needed with --reuse-build, to find its binary)")
    runner.add_argument("--reuse-build", action="store_true", help="skip the build: use ~/nightly-latency-out/<run-id> on the build VM (recovery)")
    runner.add_argument("--keep-work", action="store_true", help="leave the built binary on the build and perf VMs")
    measurer = sub.add_parser("measure", help="the measurement on the perf VM (internal)")
    measurer.add_argument("--sha", required=True)
    measurer.add_argument("--binary", required=True)
    measurer.add_argument("--root", required=True)
    measurer.add_argument("--run", default=f"{utc_now():%Y%m%dT%H%M%SZ}-manual")
    args = parser.parse_args(argv[1:])
    return run(args) if args.command == "run" else measure(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
