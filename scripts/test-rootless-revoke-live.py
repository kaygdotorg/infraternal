#!/usr/bin/env python3
"""Verify person revocation stops existing own-account PTYs without stopping another person [D18,D240]."""
import json
import os
from pathlib import Path
import pwd
import select
import shlex
import shutil
import sys
import time
import uuid

sys.dont_write_bytecode = True
repo = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo / 'scripts'))
from agent_fixture import Binary, cleanup, control, detach, select_terminal, terminal_marker



def main():
    assert os.geteuid() != 0, 'this fixture requires an own-account rootless daemon'
    root = Path.home() / '.cache/codex-scratch/real-logins-review' / f'v{os.getpid()}'
    root.mkdir(mode=0o700, parents=True)
    # Keep the frozen Unix rendezvous below Linux's 108-byte sun_path limit.
    state = root
    os.environ['INFRATERNAL_TEST_RTT'] = '0'
    people = [uuid.uuid4(), uuid.uuid4()]
    expanded = '--expanded' in sys.argv[2:]
    if expanded:
        people.append(people[0])
    values = dict(account=pwd.getpwuid(os.geteuid()).pw_name,
                  uid=os.geteuid(), cols=80, rows=24)
    client = None
    pin = None
    extra_pins = []
    try:
        client = Binary(Path(sys.argv[1]).resolve(), state)
        sessions = [control(client, i + 1, 'terminal.open',
                                      values | dict(person=str(person)))['session_id']
                    for i, person in enumerate(people)]
        select_terminal(client, sessions[0])
        pid_path = root / 'shell.pid'
        client.input(f'printf "%s\\n" "$$" > {shlex.quote(str(pid_path))}\n'.encode())
        terminal_marker(client, 'review-shell-started')
        # Pin the actual shell, so PID reuse cannot make a retained process
        # appear stopped. No unrelated process or host login is touched.
        pin = os.pidfd_open(int(pid_path.read_text().strip()))
        assert not select.select([pin], [], [], 0)[0], 'fixture shell already stopped'
        detach(client)
        if expanded:
            select_terminal(client, sessions[2])
            extra = root / 'extra.pid'
            descendant = root / 'descendant.pid'
            client.input(f'printf "%s\\n" "$$" > {shlex.quote(str(extra))}\n'.encode())
            # This sleeping detached job ignores hangup and leaves the shell's
            # foreground group. Subreaper cleanup must still retire it.
            command = f'trap "" HUP TERM; printf "%s\\n" "$$" > {shlex.quote(str(descendant))}; exec sleep 600'
            client.input(f"setsid sh -c {shlex.quote(command)} </dev/null >/dev/null 2>&1 &\n".encode())
            terminal_marker(client, 'review-descendant-started')
            deadline = time.monotonic() + 5
            while not descendant.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            foreground = root / 'foreground.pid'
            command = f'printf "%s\\n" "$$" > {shlex.quote(str(foreground))}; exec sleep 600'
            client.input(f"sh -c {shlex.quote(command)}\n".encode())
            deadline = time.monotonic() + 5
            while not foreground.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            extra_pins = [os.pidfd_open(int(path.read_text().strip())) for path in (extra, descendant, foreground)]
            detach(client)
            client.kill()
            client = Binary(Path(sys.argv[1]).resolve(), state)
        assert control(client, 3, 'terminal.login.revoke',
                                  dict(person=str(people[0])))['revoked']
        if expanded:
            assert all(select.select([fd], [], [], 0)[0] for fd in [pin, *extra_pins]), 'revocation acknowledged before every owned process ended'
        control(client, 4, 'terminal.open',
                           values | dict(person=str(people[0])), expected=False)
        stopped = bool(select.select([pin], [], [], 5)[0])
        select_terminal(client, sessions[1])
        terminal_marker(client, 'review-other-person-survives')
        detach(client)
        if expanded:
            assert all(select.select([fd], [], [], 5)[0] for fd in extra_pins), 'restart revocation retained another shell or detached descendant'
            assert control(client, 5, 'terminal.login.revoke', dict(person=str(people[0])))['revoked']
        assert stopped, 'acknowledged rootless person revocation retained its existing shell'
        print(json.dumps(dict(revocation_acknowledged=True, new_open_refused=True,
                              existing_shell_stopped=stopped, other_person_survives=True,
                              restart_and_multiple_terminals=expanded, detached_descendant_stopped=expanded, foreground_job_stopped=expanded,
                              acknowledgement_after_reaping=expanded)))
    finally:
        for fd in extra_pins:
            os.close(fd)
        if pin is not None:
            os.close(pin)
        if client is not None:
            client.kill()
        cleanup(state)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    main()
