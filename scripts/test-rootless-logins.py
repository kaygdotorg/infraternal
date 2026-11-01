#!/usr/bin/env python3
"""Exercise shipped rootless own-account terminals, readiness and explicit restoration [D18,D247]."""
import json
import os
from pathlib import Path
import pwd
import shutil
import sys
import uuid
sys.dont_write_bytecode = True
repo = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo / 'scripts'))
from agent_fixture import Binary, cleanup, control, detach, marker, select_terminal


def main():
    assert os.geteuid() != 0, 'this fixture must run without root'
    binary = Path(sys.argv[1]).resolve()
    root = Path.home() / '.cache' / ('rl7r' + str(os.getpid()))
    root.mkdir(mode=0o700)
    tools = root / 'bin'
    tools.mkdir(mode=0o700)
    marker = root / 'su-called'
    (tools / 'su').write_text('#!/bin/sh\n# Fixture refuses interactive authentication.\n'
                             f'touch {marker}\nexit 1\n')
    (tools / 'su').chmod(0o700)
    os.environ.update(XDG_RUNTIME_DIR=str(root), INFRATERNAL_TEST_RTT='0',
                      PATH=str(tools) + os.pathsep + os.environ['PATH'])
    state = root / 'state'
    state.mkdir(mode=0o700)
    client = None
    person = uuid.uuid4()
    values = dict(person=str(person), account=pwd.getpwuid(os.geteuid()).pw_name,
                  uid=os.geteuid(), cols=80, rows=24)
    try:
        client = Binary(binary, state)
        assert control(client, 1, 'terminal.login.prepare', values)['prepared']
        opened = control(client, 2, 'terminal.open', values)
        assert not opened['fallback']
        select_terminal(client, opened['session_id'])
        marker(client, 'rootless-ready')
        client.input(b'exit\n')
        client.wait_event('terminal.exited')
        detach(client)
        # The exited terminal can still queue a final stream Close. Use a fresh
        # leg-B fixture for the fixed readiness command, avoiding stream reuse.
        client.kill()
        cleanup(state)
        state = root / 'probe'
        state.mkdir(mode=0o700)
        client = Binary(binary, state)
        probe = control(client, 3, 'terminal.open',
                                   dict(uid=os.geteuid(), cols=80, rows=24, readiness=True))
        select_terminal(client, probe['session_id'])
        client.input(b'\n')
        client.until(b'infraternal-ready')
        client.wait_event('terminal.exited')
        detach(client)
        assert not marker.exists(), 'terminal or readiness attempted su authentication'
        assert control(client, 4, 'terminal.login.revoke', dict(person=str(person)))['revoked']
        control(client, 5, 'terminal.login.prepare', values, expected=False)
        assert control(client, 6, 'terminal.login.restore', dict(person=str(person)))['restored']
        assert control(client, 7, 'terminal.login.prepare', values)['prepared']
        refused = values | dict(account='root')
        control(client, 8, 'terminal.open', refused, expected=False)
        print(json.dumps(dict(own_account_terminal=True, readiness_same_account=True,
                              su_not_called=True, switching_refused=True,
                              revocation_fenced=True, explicit_restoration=True)))
    finally:
        if client is not None:
            client.kill()
        cleanup(state)
        shutil.rmtree(root)


if __name__ == '__main__':
    main()
