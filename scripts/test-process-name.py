#!/usr/bin/env python3
"""Check the host daemon name when launched from an installation slot (#87)."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

scratch = Path.home() / '.cache/codex-scratch/release-addhost'
scratch.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='p', dir=scratch) as temporary:
    root = Path(temporary)
    slot = root / 'live'
    slot.symlink_to(Path(sys.argv[1]).resolve())
    parent, child = socket.socketpair()
    process = subprocess.Popen([str(slot), 'agent', '--fd', str(child.fileno()), '--state', str(root / 's')], pass_fds=[child.fileno()], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    child.close()
    try:
        time.sleep(0.1)
        name = Path(f'/proc/{process.pid}/comm').read_text().strip()
        assert name == 'infraternal', f'host process name is {name!r}'
        print('PASS: slot launch reports infraternal in /proc/comm')
    finally:
        parent.close()
        process.terminate()
        process.wait(timeout=5)
