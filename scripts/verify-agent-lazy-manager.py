#!/usr/bin/env python3
"""Keep backend detection off the control path while the login manager warms [D255]."""
import argparse
import os
from pathlib import Path
import shutil
import socket
import sys
import time
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
    probe_listener = None
    try:
        commands = root / 'commands'
        commands.mkdir(mode=0o700)
        observed = root / 'probe'
        probe_socket = root / 'probe.sock'
        systemctl = shutil.which('systemctl')
        assert systemctl is not None, 'real systemctl is required by this fixture'
        wrapper = commands / 'systemctl'
        # Hold only the fixed manager probe. Once released, use the real host
        # tool with its original arguments and keep those arguments unlogged.
        wrapper.write_text(f'''#!/usr/bin/python3
import os
import socket
import sys
if 'show-environment' not in sys.argv[1:]:
    os.execv({systemctl!r}, [{systemctl!r}, *sys.argv[1:]])
with open({str(observed)!r}, 'a') as trace:
    trace.write('probe' + chr(10))
with socket.socket(socket.AF_UNIX) as peer:
    peer.connect({str(probe_socket)!r})
    peer.sendall(b'probe' + bytes((10,)))
    if peer.recv(1) != b'r':
        raise RuntimeError('manager probe fixture was not released')
os.execv({systemctl!r}, [{systemctl!r}, *sys.argv[1:]])
''')
        wrapper.chmod(0o700)
        probe_listener = socket.socket(socket.AF_UNIX)
        probe_listener.bind(str(probe_socket))
        probe_listener.listen(1)
        probe_listener.settimeout(20)
        with patch.dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH']):
            startup_started = time.perf_counter()
            client = Binary(args.binary.resolve(), root)
        startup_ms = (time.perf_counter() - startup_started) * 1000

        # Binary.start fences startup with Hello and Pong. Accepting the held
        # probe now proves that manager detection cannot park this control path.
        probe, _ = probe_listener.accept()
        with probe, probe.makefile('rb') as probe_reader:
            assert probe_reader.readline() == b'probe' + bytes((10,))
            assert observed.read_bytes() == b'probe' + bytes((10,))
            probe.sendall(b'r')

        first_started = time.perf_counter()
        client.open()
        first_open_ms = (time.perf_counter() - first_started) * 1000
        client.open()
        assert observed.read_bytes() == b'probe' + bytes((10,)), 'terminal opens repeated manager detection'
        print('greeting and Pong complete while the background manager probe is blocked: PASS')
        print('two real terminal opens share one manager probe: PASS')
        print(f'METRIC manager_probe_startup_pong_ms={startup_ms:.3f} first_terminal_open_ms={first_open_ms:.3f}')
    finally:
        if client is not None:
            client.kill()
        if probe_listener is not None:
            probe_listener.close()
        cleanup(root)


if __name__ == '__main__':
    main()
