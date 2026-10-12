#!/usr/bin/env python3
"""Exercise real PTY open/input/output from an infraternal agent whose running image is anonymous (#157)."""
import os
from pathlib import Path
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from agent_fixture import Binary, cleanup, fixture_state

os.environ["INFRATERNAL_ANONYMOUS_BINARY"] = str(Path(sys.argv[1]).resolve())
os.environ["INFRATERNAL_TEST_RTT"] = "0"
state = fixture_state("m")
state.mkdir(mode=0o700)
client = None
try:
    client = Binary(Path(__file__).with_name("anonymous_exec.py").resolve(), state)
    identity = client.open()
    client.attach()
    client.until(b"shim-test")
    client.input(b"printf 'ANONYMOUS_%s\\n' OK\n")
    client.until(b"ANONYMOUS_OK\r\n")
    client.wait_ack()
    print("ANONYMOUS_IMAGE real_pty=true input_output=true exact_running_image=true control_fd_isolated=true")
finally:
    if client is not None:
        client.kill()
    cleanup(state)
