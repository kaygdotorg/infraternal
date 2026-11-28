#!/usr/bin/env python3
"""Exercise shipped rootless own-account terminals, readiness and explicit restoration [D18,D247]."""
import json
import os
from pathlib import Path
import pwd
import shutil
import sys
import time
import uuid
sys.dont_write_bytecode = True
repo = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo / 'scripts'))
from agent_fixture import Binary, cleanup, control, detach, select_terminal, terminal_marker


def main():
    """Open the enrolled account in the real daemon and verify the live shell identity."""
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
    sockets = None
    if sys.platform == 'darwin':
        # Exercise the installed LaunchAgent's shape inside the fixture home.
        state = root / 'Library/Application Support/infraternal/state'
        caches = root / 'Library/Caches'
        caches.mkdir(mode=0o700, parents=True)
        sockets = caches / 'infraternal/up'
        leaf = 'a' * 32 + '.sock'
        assert len(os.fsencode(state / 'sessions' / leaf)) >= 104
        assert len(os.fsencode(sockets / leaf)) < 104
    state.mkdir(mode=0o700, parents=True)
    client = None
    person = uuid.uuid4()
    account = pwd.getpwuid(os.geteuid()).pw_name
    values = dict(person=str(person), account=account, uid=os.geteuid(), cols=80, rows=24)
    enrolled = values | dict(account=None, grant=dict(accounts=[account]))
    try:
        client = Binary(binary, state)
        assert control(client, 1, 'terminal.login.prepare', values)['prepared']
        opened = control(client, 2, 'terminal.open', enrolled)
        assert opened['account'] == account
        assert opened['requested_account'] is None
        assert not opened['fallback']
        session_id = opened['session_id']
        terminal_id = uuid.UUID(session_id).hex
        path = (sockets if sockets is not None else state / 'sessions') / (terminal_id + '.sock')
        record = state / 'infraternal-login-locks' / f'{person.hex}-{terminal_id}.terminal'
        stop = path.with_suffix('.stop')
        assert path.is_socket() and stop.is_socket()
        assert record.is_file()
        select_terminal(client, opened['session_id'])
        terminal_marker(client, 'rootless-ready')
        # PTY output may use LF or CRLF. Shell echo cannot contain the complete
        # marker because its account field is computed only during execution.
        client.input(b"""printf 'whoami-%s-end\\n' "$(whoami)"\n""")
        client.until(b'whoami-' + os.fsencode(account) + b'-end')
        assert control(client, 3, 'terminal.login.revoke', dict(person=str(person)))['revoked']
        event = client.wait_event('terminal.exited')
        assert event['session_id'] == session_id and event['status'] == -9, event
        detach(client)
        deadline = time.monotonic() + 30
        while path.exists() or stop.exists() or record.exists():
            assert time.monotonic() < deadline, 'revoked shell retained its socket or ownership record'
            time.sleep(.005)  # Poll only until the sealed shim retirement is visible on disk.
        assert path.with_suffix('.ended').exists()
        control(client, 4, 'terminal.open', enrolled, expected=False)
        # The exited terminal can still queue a final stream Close. Use a fresh
        # leg-B fixture for the fixed readiness command, avoiding stream reuse.
        client.kill()
        cleanup(state, sockets)
        sockets = None
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
                              revocation_fenced=True, live_shell_reaped=True,
                              revoked_record_and_sockets_removed=True, explicit_restoration=True)))
    finally:
        if client is not None:
            client.kill()
        cleanup(state, sockets)
        shutil.rmtree(root)


if __name__ == '__main__':
    main()
