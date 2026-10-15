#!/usr/bin/env python3
"""Keep admitted SSH sessions in managed scopes when the checked manager withdraws (D255, #189)."""

import argparse
import importlib.util
import os
from pathlib import Path
import shlex
import socket
import struct
import subprocess
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from agent_fixture import cleanup, exact, fixture_state

spec = importlib.util.spec_from_file_location('bridge', ROOT / 'scripts/verify-ssh-session.py')
bridge_fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge_fixture)


def run(binary, case, private_image):
    """Use a real managed shim; fake only the capability probe and withdrawal failure."""
    state = fixture_state('ml')
    state.mkdir(mode=0o700)
    bridge = None
    try:
        commands = state / 'commands'
        commands.mkdir(mode=0o700)
        witness = state / 'manager-consulted'
        probe = commands / 'systemctl'
        probe.write_text(
            '#!/bin/sh\n# Public fixture witness only.\nprintf consulted > '
            + shlex.quote(str(witness)) + '\nexit 1\n'
        )
        probe.chmod(0o700)
        env = {
            **os.environ,
            'PATH': str(commands) + os.pathsep + os.environ.get('PATH', ''),
            'ZDOTDIR': str(ROOT / 'crates/infraternal/tests/profile'),
        }
        if case == 'withdrawn':
            # Admission succeeded earlier; this failure must never select Detached.
            scope = commands / 'systemd-run'
            scope.write_text('#!/bin/sh\n# The checked manager withdrew.\nexit 1\n')
            scope.chmod(0o700)
            child = subprocess.run(
                [str(binary), '__ssh-session', '--state', str(state)],
                input=b'', capture_output=True, env=env, timeout=8,
            )
            assert child.returncode != 0, 'Withdrawn managed scope returned success'
            assert not child.stdout, 'Withdrawn managed scope published a session receipt'
            assert not list((state / 'sessions').glob('*.sock')), 'Scope refusal left a session'
            print('PASS: withdrawn manager refuses without a detached shim or session receipt')
        else:
            with patch.dict(os.environ, env):
                bridge = bridge_fixture.Bridge(binary, state)
            if private_image:
                assert bridge.hello_caps == 0, 'Expected the private image without node actions'
            bridge.attach()
            bridge.until(b'shim-test')
            bridge.input(b"printf 'MANAGED_%s\\n' SHELL\n")
            bridge.until(b'MANAGED_SHELL\r\n')
            bridge.wait_ack()
            # The full dispatcher separately warms detection for future node
            # actions. Its probe says nothing about this shell's launch scope.
            # Authenticate the actual shim and inspect its kernel membership.
            with socket.socket(socket.AF_UNIX) as peer:
                peer.settimeout(8)
                peer.connect(str(state / 'sessions' / f'{bridge.id.hex}.sock'))
                length = struct.unpack('<I', exact(peer, 4))[0]
                assert 31 <= length <= 64, 'Unexpected shim Hello length'
                hello = exact(peer, length)
            assert hello[0] == 1 and hello[11:27] == bridge.id.bytes
            pid = struct.unpack('<I', hello[27:31])[0]
            group = Path(f'/proc/{pid}/cgroup').read_text()
            assert f'infraternal-session-{bridge.id.hex}.scope' in group, 'Shim escaped its managed scope'
            if private_image:
                assert not witness.exists(), 'Private image repeated the admitted capability probe'
            print('PASS: admitted SSH helper keeps its authenticated shim in the managed scope')
    finally:
        if bridge is not None:
            bridge.kill()
        # The fixture kills only PIDs authenticated by its own rendezvous sockets.
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--case', choices=['probe', 'withdrawn'], required=True)
    parser.add_argument('--private-image', action='store_true')
    args = parser.parse_args()
    run(args.binary.resolve(), args.case, args.private_image)
