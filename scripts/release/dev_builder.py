#!/usr/bin/env python3
"""Build gated dev heads serially with pinned tools and bounded host capacity [244,250]."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import urllib.request


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def private(path):
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    if not path.is_dir() or path.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("release state must be an owned private directory")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def gate_passed(sha, context):
    # Public read only: credentials and provider publication are outside this builder.
    url = f"https://git.kayg.org/api/v1/repos/kayg/infraternal/commits/{sha}/statuses?limit=100"
    request = urllib.request.Request(url, headers={"User-Agent": "infraternal-dev-builder"})
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read(131073)
    if len(raw) > 131072:
        raise ValueError("gate status response exceeds bound")
    statuses = json.loads(raw)
    # The API orders newest first. A later pending/failure overrides an earlier success.
    return next((s["status"] == "success" for s in statuses if s["context"] == context), False)


def prune(root, keep=10):
    releases = sorted((p for p in root.iterdir() if re.fullmatch(r"[0-9a-f]{40}", p.name)
                       and p.is_dir() and not p.is_symlink()), key=lambda p: p.stat().st_mtime_ns)
    for old in releases[:-keep]:
        shutil.rmtree(old)


def build(repo, sha, cache, scratch, gate_mode="local", context=""):
    source = scratch / "source"
    staging = cache / f".building-{sha}"
    if staging.exists():
        shutil.rmtree(staging)
    private(staging)
    if source.exists():
        # This exact path belongs to the serialized builder, including crash residue.
        run("git", "worktree", "remove", "--force", str(source), cwd=repo)
    run("git", "worktree", "add", "--detach", str(source), sha, cwd=repo,
        stdout=subprocess.DEVNULL)
    try:
        env = os.environ.copy()
        env.update(CARGO_TARGET_DIR=str(scratch / "target"), CARGO_BUILD_JOBS="2",
                   INFRATERNAL_RELEASE_BUILD="1",
                   INFRATERNAL_RELEASE_VERSION="edge-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
        run("scripts/auth-toolchain", cwd=source, env=env)
        env["PATH"] = str(scratch / "target/auth-tools/zig") + ":" + env["PATH"]
        gate = {"sha": sha, "result": "passed", "mode": gate_mode}
        if gate_mode == "local":
            private(scratch / "gates")
            log = scratch / "gates" / (sha + ".log")
            with log.open("wb") as output:
                run("scripts/verify", "fast", cwd=source, env=env,
                    stdout=output, stderr=subprocess.STDOUT)
            gate["log_sha256"] = digest(log)
            run("scripts/package-release", str(staging / "bundle"), "x86_64", "--built", cwd=source, env=env)
        else:
            gate["context"] = context
            run("scripts/package-release", str(staging / "bundle"), cwd=source, env=env)
        for item in (staging / "bundle").iterdir():
            item.rename(staging / item.name)
        (staging / "bundle").rmdir()
        run("bun", "install", "--frozen-lockfile", cwd=source / "apps/tracer", env=env)
        env["TRACER_DIST"] = str(staging / "web")
        run("bun", "run", "build", cwd=source / "apps/tracer", env=env)
        (staging / "VERSION").write_text(env["INFRATERNAL_RELEASE_VERSION"] + "\n")
        (staging / "SOURCE").write_text(sha + "\n")
        (staging / "GATE").write_text(json.dumps(gate) + "\n")
        files = sorted(p for p in staging.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
        (staging / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.relative_to(staging)}\n" for p in files))
        # Directory publication is atomic; unsigned build hashes are never release signatures.
        staging.rename(cache / sha)
        private(scratch / "completed")
        (scratch / "completed" / sha).write_text("built\n")
        # A deploy pins its local bundle with this lock; pruning must not remove
        # a selected release between verification and transfer.
        with (cache / ".deploy.lock").open("a") as deploy_lock:
            try:
                fcntl.flock(deploy_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            prune(cache)
    finally:
        run("git", "worktree", "remove", "--force", str(source), cwd=repo)
        if staging.exists():
            shutil.rmtree(staging)


def cycle(repo, cache, scratch, context, limit, start_sha, gate_mode="local"):
    if max(os.getloadavg()[:2]) >= limit:
        print("Build deferred: host capacity limit reached", flush=True)
        return
    run("git", "fetch", "origin", "dev", cwd=repo, stdout=subprocess.DEVNULL)
    run("git", "merge-base", "--is-ancestor", start_sha, "origin/dev", cwd=repo)
    heads = run("git", "rev-list", "--first-parent", "--reverse", "origin/dev", "^" + start_sha,
                cwd=repo, capture_output=True, text=True).stdout.splitlines()
    private(scratch / "failed")
    for sha in heads:
        failed = scratch / "failed" / sha
        if ((cache / sha).exists() or (scratch / "completed" / sha).exists()
                or (failed.exists() and time.time() - failed.stat().st_mtime < 900)
                or (gate_mode == "status" and not gate_passed(sha, context))):
            continue
        if max(os.getloadavg()[:2]) >= limit:
            return
        try:
            build(repo, sha, cache, scratch, gate_mode, context)
        except (OSError, ValueError, subprocess.CalledProcessError):
            # One failing historical head must not block later dev heads. Retry
            # transient failures slowly; retain the exact gate output per head.
            failed.touch()
            print("Release build failed for " + sha + "; gate log retained", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--gate-mode", choices=("local", "status"), default="local")
    parser.add_argument("--gate-context", default="", help="exact successful full-gate status context")
    parser.add_argument("--start-sha", required=True, help="fixed dev ancestor before the first eligible build")
    parser.add_argument("--load-limit", type=float, default=8.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.start_sha):
        parser.error("start SHA must be a fixed full commit identity")
    if args.gate_mode == "status" and not args.gate_context:
        parser.error("status mode requires the exact full-gate context")
    if not 0 < args.load_limit <= (os.cpu_count() or 1):
        parser.error("load limit must be positive and no larger than the CPU count")
    cache = Path.home() / ".cache/infraternal-releases"
    scratch = Path.home() / ".cache/codex-scratch/dev-release-builder"
    private(cache)
    private(scratch)
    with (cache / ".builder.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        while True:
            try:
                cycle(args.repo.resolve(), cache, scratch, args.gate_context, args.load_limit, args.start_sha, args.gate_mode)
            except (OSError, ValueError, subprocess.CalledProcessError, KeyError):
                # Provider diagnostics and inherited environments never enter logs.
                print("Build deferred: source, gate status or build unavailable", flush=True)
            if args.once:
                return
            time.sleep(60)


if __name__ == "__main__":
    os.umask(0o077)
    main()
