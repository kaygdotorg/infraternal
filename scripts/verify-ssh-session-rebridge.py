#!/usr/bin/env python3
"""Verify explicit D255 bridge retry retains exactly one owned live shell (#189).

Resume names the original session, so reconnect cannot select another person's
shell or accidentally create a replacement while the infraternal agent joins.
"""
import argparse
import importlib.util
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent_fixture import cleanup, fixture_state

spec = importlib.util.spec_from_file_location('verify_ssh_session', Path(__file__).resolve().parent / 'verify-ssh-session.py')
bridge_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge_module)


def live_sessions(state):
    return sorted(path.stem for path in (state / 'sessions').glob('*.sock'))


def run(binary):
    state = fixture_state('rb')
    state.mkdir(mode=0o700)
    first = second = None
    try:
        first = bridge_module.Bridge(binary, state)
        first.attach()
        first.until(b'shim-test')
        original = first.id
        # The SSH transport is lost before the installed agent has joined.
        first.kill()
        first = None
        second = bridge_module.Bridge(binary, state, original)
        sessions = live_sessions(state)
        assert sessions == [original.hex], (
            f'reopening the bridge launched another shell: {len(sessions)} live sessions '
            f'(original {original}, new receipt {second.id})')
        print('PASS: reopened bridge keeps the one existing session')
    finally:
        for bridge in (first, second):
            if bridge is not None:
                bridge.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    run(args.binary.resolve())
