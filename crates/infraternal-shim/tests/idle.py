#!/usr/bin/env python3
"""Measure resident memory of the actual static shim, excluding its login shell [41]."""
import os
import pathlib
import shutil
import subprocess
import time

state = pathlib.Path("target/idle-canary")
env = dict(os.environ, ZDOTDIR=str(pathlib.Path("crates/infraternal/tests/profile").resolve()))
child = subprocess.Popen(["target/x86_64-unknown-linux-musl/release/infraternal", "__shim", "--session", "b" * 32, "--uid", str(os.getuid()), "--state", str(state)], env=env)
try:
    deadline = time.monotonic() + 5
    while not (state / "sessions" / ("b" * 32 + ".sock")).exists():
        assert time.monotonic() < deadline
        time.sleep(.01)
    time.sleep(1)
    status = pathlib.Path(f"/proc/{child.pid}/status").read_text()
    rss = next(int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS:"))
    print(f"static shim idle RSS: {rss} KiB ({rss / 1024:.3f} MiB); 80x24; default 8 MiB ring allocated lazily; 10,000-line scrollback limit")
    assert rss < 4096
finally:
    child.kill()
    child.wait()
    shutil.rmtree(state, ignore_errors=True)
