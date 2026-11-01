#!/usr/bin/env python3
"""Assert an inherited daemon serves its idle channel without probing login backends [D247]."""
import argparse
import os
from pathlib import Path
import shlex
import shutil
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, fixture_state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    root = fixture_state('lm')
    root.mkdir(mode=0o700)
    client = None
    try:
        commands = root / 'commands'
        commands.mkdir(mode=0o700)
        observed = root / 'probe'
        systemctl = shutil.which('systemctl')
        assert systemctl is not None, 'real systemctl is required by this fixture'
        wrapper = commands / 'systemctl'
        # Record only this fixed public operation, never command arguments or
        # environment values. Other host operations still use the real tool.
        wrapper.write_text('#!/bin/sh\n# Observe fixture backend initialization only.\n'
                           'for argument do\n'
                           '  if [ "$argument" = show-environment ]; then\n'
                           f'    printf "probe\\n" >> {shlex.quote(str(observed))}\n'
                           '  fi\n'
                           'done\n'
                           f'exec {shlex.quote(systemctl)} "$@"\n')
        wrapper.chmod(0o700)
        with patch.dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH']):
            client = Binary(args.binary.resolve(), root)
        # Binary.start fences startup with Pong; this assertion needs no sleep
        # and proves the idle control channel works before any login request.
        assert not observed.exists(), 'idle daemon eagerly probed its login backend'
        client.open()
        assert observed.read_text() == 'probe\n', 'first terminal did not initialize its backend'
        client.open()
        assert observed.read_text() == 'probe\n', 'second terminal repeated backend initialization'
        print('idle greeting and Pong served without a login backend probe: PASS')
        print('two real terminal opens share one backend probe: PASS')
    finally:
        if client is not None:
            client.kill()
        cleanup(root)


if __name__ == '__main__':
    main()
