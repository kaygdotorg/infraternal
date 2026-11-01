#!/usr/bin/env python3
"""Verify rootless explicit-state admission without the default runtime environment [D18,D247]."""
import json
import os
from pathlib import Path
import pwd
import struct
import sys
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from agent_fixture import Binary, cleanup, varint


def control(client, number, action, values):
    """Read one exact control result while retaining unrelated fixture events."""
    name = action.encode()
    client.send(0, 0x30, struct.pack('<I', number) + varint(len(name)) + name + json.dumps(values).encode())
    while True:
        frame = client.read()
        if frame[:2] == (0, 0x31):
            body = frame[2]
            assert struct.unpack('<I', body[:4])[0] == number
            return body[4] == 1, json.loads(body[5:])
        client.process(frame=frame)


def main():
    assert os.geteuid() != 0, 'this fixture requires a rootless process'
    os.environ.pop('XDG_RUNTIME_DIR', None)
    os.environ['INFRATERNAL_TEST_RTT'] = '0'
    # Keep every socket below sun_path while staying inside this review's scratch.
    state = Path.home() / '.cache/codex-scratch/real-logins-review' / f'r{os.getpid()}'
    state.mkdir(mode=0o700, parents=True)
    client = None
    try:
        client = Binary(Path(sys.argv[1]).resolve(), state)
        readiness, readiness_result = control(
            client, 1, 'terminal.open',
            dict(uid=os.geteuid(), cols=80, rows=24, readiness=True),
        )
        assert readiness, f'explicit-state fixed readiness was refused: {readiness_result}'
        prepared, result = control(client, 2, 'terminal.login.prepare',
                                   dict(uid=os.geteuid(), cols=80, rows=24,
                                        person=str(uuid.uuid4()), account=pwd.getpwuid(os.geteuid()).pw_name))
    finally:
        if client is not None:
            client.kill()
        cleanup(state)
    assert prepared, f'explicit-state own-account preparation was refused: {result}'


if __name__ == '__main__':
    main()
