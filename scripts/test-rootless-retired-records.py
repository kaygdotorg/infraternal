#!/usr/bin/env python3
"""Verify retired own-account terminals release their durable cleanup attribution [D18,D240,D247]."""
import importlib.util
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
from agent_fixture import Binary, cleanup
spec = importlib.util.spec_from_file_location('login_controller', repo / 'scripts/login-bench/round3/controller.py')
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)


def main():
    assert os.geteuid() != 0
    root = Path.home() / '.cache/codex-scratch/real-logins-review' / ('r' + uuid.uuid4().hex[:8])
    root.mkdir(mode=0o700, parents=True)
    os.environ['INFRATERNAL_TEST_RTT'] = '0'
    client = None
    person = uuid.uuid4()
    counts = []
    try:
        client = Binary(Path(sys.argv[1]).resolve(), root)
        values = dict(person=str(person), account=pwd.getpwuid(os.geteuid()).pw_name,
                      uid=os.geteuid(), cols=80, rows=24)
        for index in range(8):
            session = controller.control(client, index + 1, 'terminal.open', values)['session_id']
            controller.select_terminal(client, session)
            client.events.clear()
            client.input(b'exit 0\n')
            event = client.wait_event('terminal.exited')
            assert event['session_id'] == session and event['status'] == 0
            controller.detach(client)
            path = root / 'sessions' / (uuid.UUID(session).hex + '.sock')
            deadline = time.monotonic() + 5
            while path.exists():
                assert time.monotonic() < deadline, 'fixture terminal did not retire'
                time.sleep(.005)
            assert path.with_suffix('.ended').exists(), 'retirement lacks sealed cleanup proof'
            client.fence()
            counts.append(len(list((root / 'infraternal-login-locks').glob('*.terminal'))))
        assert not list((root / 'sessions').glob('*.sock'))
        print(json.dumps(dict(completed_cycles=len(counts), live_shims=0,
                              retained_ownership_records=counts)), flush=True)
        # A sealed ended record already proves complete descendant retirement.
        # No viewer, restart or retry needs a per-session attribution afterward.
        assert counts[-1] == 0, 'retired terminals retained unbounded person ownership records'
    finally:
        if client is not None:
            try:
                controller.control(client, 20, 'terminal.login.revoke', dict(person=str(person)))
            except (OSError, EOFError, RuntimeError):
                pass
            client.kill()
        cleanup(root)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    main()
