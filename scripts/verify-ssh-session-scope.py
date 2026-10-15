#!/usr/bin/env python3
"""Verify the private first-prompt image refuses other sessions and node actions without retiring its shell (#189)."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent_fixture import cleanup, fixture_state, varint

spec = importlib.util.spec_from_file_location("ssh_session", Path(__file__).with_name("verify-ssh-session.py"))
bridge_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge_module)


def run(binary, installed):
    state = fixture_state("sc")
    state.mkdir(mode=0o700)
    bridge = other = None
    try:
        bridge = bridge_module.Bridge(binary, state)
        assert bridge.hello_caps == 0, "private image advertises node actions"
        bridge.attach()
        bridge.until(b"shim-test")
        original = bridge.id
        other = bridge_module.Writer(installed, state)
        other.open()
        assert other.id != original
        action = b"terminal.open"
        body = (struct.pack("<I", 77) + varint(len(action)) + action +
                json.dumps(dict(uid=os.getuid(), cols=80, rows=24)).encode())
        bridge.send(0, 0x30, body)
        while True:
            frame = bridge.read()
            if frame[:2] == (0, 0x31):
                assert frame[2][:4] == struct.pack("<I", 77)
                assert frame[2][4] == 0, "private image opened another session"
                break
            bridge.process(frame=frame)
        bridge.send(4, 0x16, other.id.bytes + struct.pack("<QQ", 0, 0))
        while True:
            frame = bridge.read()
            if frame[0] == 4:
                assert frame[1] == 0x0F and struct.unpack("<H", frame[2][:2])[0] == 4404, (
                    "private image attached another live session")
                break
            bridge.process(frame=frame)
        bridge.ping(78, 0)
        bridge.input(b"printf 'KEPT_%s\\n' ORIGINAL\n")
        bridge.until(b"KEPT_ORIGINAL\r\n")
        bridge.wait_ack()
        assert bridge.id == original
        assert sorted(path.stem for path in (state / "sessions").glob("*.sock")) == sorted([
            original.hex, other.id.hex])
        print("PASS: private image refuses node actions and foreign session attachment; original shell/control remain usable")
    finally:
        for fixture in (bridge, other):
            if fixture is not None:
                fixture.kill()
        cleanup(state)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--installed-binary", type=Path, required=True)
    arguments = parser.parse_args()
    run(arguments.binary.resolve(), arguments.installed_binary.resolve())
