#!/usr/bin/env python3
"""Verify a private readiness probe does not refuse unrelated person cleanup [D18,D240,D247]."""
import importlib.util
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
from agent_fixture import Binary, cleanup
spec = importlib.util.spec_from_file_location('login_controller', repo / 'scripts/login-bench/round3/controller.py')
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)


def main():
    assert os.geteuid() != 0
    root = Path.home() / '.cache/codex-scratch/real-logins-review' / ('p' + uuid.uuid4().hex[:8])
    root.mkdir(mode=0o700, parents=True)
    os.environ['INFRATERNAL_TEST_RTT'] = '0'
    client = None
    person = uuid.uuid4()
    try:
        client = Binary(Path(sys.argv[1]).resolve(), root)
        values = dict(person=str(person), account=pwd.getpwuid(os.geteuid()).pw_name,
                      uid=os.geteuid(), cols=80, rows=24)
        assert controller.control(client, 1, 'terminal.login.prepare', values)['prepared']
        # Readiness awaits the canary input. Keep its actual socket present,
        # without starting any person terminal or modifying fixture processes.
        probe = controller.control(client, 2, 'terminal.open',
                                   dict(uid=os.geteuid(), cols=80, rows=24, readiness=True))['session_id']
        path = root / 'sessions' / (uuid.UUID(probe).hex + '.sock')
        assert path.exists() and not path.with_suffix('.ended').exists()
        try:
            result = controller.control(client, 3, 'terminal.login.revoke',
                                        dict(person=str(person)))
            confirmed = result.get('revoked') is True
        except RuntimeError as error:
            result = dict(refusal=str(error))
            confirmed = False
        print(json.dumps(dict(private_probe_present=path.exists(), person_terminals=0,
                              cleanup_confirmed=confirmed, result=result)), flush=True)
        # Finish the private probe as a positive control, then repeat cleanup.
        controller.select_terminal(client, probe)
        client.input(b'\n')
        client.until(b'infraternal-ready')
        client.wait_event('terminal.exited')
        controller.detach(client)
        assert controller.control(client, 4, 'terminal.login.revoke',
                                  dict(person=str(person)))['revoked']
        assert confirmed, 'private readiness was treated as an unattributed person terminal'
    finally:
        if client is not None:
            client.kill()
        cleanup(root)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    main()
