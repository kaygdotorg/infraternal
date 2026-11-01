#!/usr/bin/env python3
"""Verify an inherited-account terminal reaps completed adopted jobs while its shell remains open [D18,D240]."""
import json
import os
from pathlib import Path
import pwd
import select
import shlex
import shutil
import signal
import sys
import time
import uuid

sys.dont_write_bytecode = True
repo = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo / 'scripts'))
from agent_fixture import Binary, cleanup, control, detach, marker, select_terminal


def main():
    assert os.geteuid() != 0
    root = Path.home() / '.cache/codex-scratch/real-logins-review' / ('z' + uuid.uuid4().hex[:8])
    root.mkdir(mode=0o700, parents=True)
    os.environ['INFRATERNAL_TEST_RTT'] = '0'
    client = None
    pins = []
    person = uuid.uuid4()
    try:
        client = Binary(Path(sys.argv[1]).resolve(), root)
        values = dict(person=str(person), account=pwd.getpwuid(os.geteuid()).pw_name, uid=os.geteuid(), cols=80, rows=24)
        session = control(client, 1, 'terminal.open', values)['session_id']
        select_terminal(client, session)
        # Each short child outlives its immediate parent, so the terminal's
        # subreaper adopts it. Pin fixture processes before their controlled exit.
        for index in range(4):
            path = root / f'job{index}.pid'
            release = root / f'job{index}.release'
            command = f'printf "%s\\n" "$$" > {shlex.quote(str(path))}; read x < {shlex.quote(str(release))}'
            os.mkfifo(release, 0o600)
            client.input(f"sh -c {shlex.quote('sh -c ' + shlex.quote(command) + ' </dev/null >/dev/null 2>&1 &')}\n".encode())
            marker(client, f'review-job{index}-started')
            deadline = time.monotonic() + 5
            while not path.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            pid = int(path.read_text().strip())
            pins.append((pid, os.pidfd_open(pid)))
            deadline = time.monotonic() + 5
            while True:
                try:
                    writer = os.open(release, os.O_WRONLY | os.O_NONBLOCK)
                    break
                except OSError:
                    assert time.monotonic() < deadline, 'fixture job did not open release pipe'
                    time.sleep(.01)
            os.write(writer, b'done\n')
            os.close(writer)
        assert all(select.select([fd], [], [], 5)[0] for _, fd in pins), 'fixture jobs did not end'
        # Further input gives the shim another normal poll iteration after
        # every SIGCHLD. No idle timing or performance measurement is asserted.
        marker(client, 'review-jobs-ended')
        zombies = []
        for pid, _ in pins:
            try:
                fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
                if fields[0] == 'Z':
                    zombies.append(pid)
            except FileNotFoundError:
                pass
        print(json.dumps(dict(completed_jobs=len(pins), unreaped_jobs=len(zombies), shell_usable=True)), flush=True)
        assert not zombies, 'completed adopted jobs retained process entries while the terminal stayed open'
    finally:
        if client is not None:
            # A cleanup retry is part of fixture teardown, never an account-wide
            # scan. It reaps precisely the descendants of this terminal.
            try:
                control(client, 2, 'terminal.login.revoke', dict(person=str(person)))
            except (OSError, EOFError, RuntimeError):
                pass
            client.kill()
        cleanup(root)
        for _, fd in pins:
            if not select.select([fd], [], [], 0)[0]:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            os.close(fd)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    main()
