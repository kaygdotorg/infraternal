#!/usr/bin/env python3
"""Prove real leg-B readiness bypasses isolated shell profiles that never return (#169)."""
import argparse
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
from unittest.mock import patch
import uuid

sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, fixture_state, varint


def run(binary):
    original = subprocess.Popen
    for index, startup in enumerate(('tmux', 'zellij', 'menu', 'bash')):
        state = fixture_state(f'r{index}')
        state.mkdir(mode=0o700)
        profile = state / 'profile'
        profile.mkdir(mode=0o700)
        witness = profile / 'started'
        # Real shell startup integrations are confined to a fixture profile;
        # no account, home profile or global environment is changed.
        if startup == 'tmux':
            command = f"export TMUX_TMPDIR='{profile}'; exec {shutil.which('tmux')} -L readiness new-session"
        elif startup == 'zellij' and shutil.which('zellij'):
            command = f"export XDG_RUNTIME_DIR='{profile}'; exec {shutil.which('zellij')}"
        elif startup == 'bash':
            rc = profile / 'bashrc'
            rc.write_text(f"printf started > '{witness}'\nexec /bin/sleep 3600\n")
            command = f"exec {shutil.which('bash')} --rcfile '{rc}' -i"
        else:
            command = 'exec /bin/sleep 3600'
        (profile / '.zshrc').write_text(f"printf started > '{witness}'\n{command}\n")

        def spawn(*args, **kwargs):
            kwargs['env'] = dict(kwargs.get('env', os.environ), ZDOTDIR=str(profile))
            return original(*args, **kwargs)

        engine = None
        started = time.monotonic()
        try:
            with patch('subprocess.Popen', spawn):
                engine = Binary(binary, state)
            action = b'terminal.open'
            request = json.dumps(dict(uid=os.getuid(), cols=80, rows=24, readiness=True)).encode()
            engine.send(0, 0x30, struct.pack('<I', 1) + varint(len(action)) + action + request)
            stream, kind, body = engine.read()
            assert (stream, kind) == (0, 0x31) and body[4] == 1, 'readiness open refused'
            engine.id = uuid.UUID(json.loads(body[5:])['session_id'])
            engine.send(1, 0x16, engine.id.bytes + struct.pack('<QQ', 0, 0))
            engine.send(1, 0x14, struct.pack('<I', 65536))
            engine.input(b'\n')
            output = bytearray()
            while b'infraternal-ready' not in output:
                stream, kind, body = engine.read()
                if kind in (0x11, 0x15):
                    output.extend(body[8:])
                assert len(output) <= 65536
            assert not witness.exists(), f'{startup} startup was executed'
            print(f'READINESS startup={startup} real_pty=true marker=true rc_executed=false elapsed_ms={(time.monotonic()-started)*1000:.1f}', flush=True)
        finally:
            if engine:
                engine.kill()
            cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    run(args.binary.resolve())
