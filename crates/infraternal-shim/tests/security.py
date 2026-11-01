#!/usr/bin/env python3
"""Root-only Linux canary: login credential drop and rejected SO_PEERCRED [40]."""
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import time

binary = pathlib.Path(sys.argv[1]).resolve()
target_uid = int(sys.argv[2])
state = pathlib.Path("target/root-canary")
path = state / "sessions" / ("a" * 32 + ".sock")
env = dict(os.environ, ZDOTDIR=str(pathlib.Path("crates/infraternal/tests/profile").resolve()))
child = subprocess.Popen([str(binary), "__shim", "--session", "a" * 32, "--uid", str(target_uid), "--state", str(state)], env=env)

def recv_exact(peer, size):
    data = bytearray()
    while len(data) < size:
        part = peer.recv(size - len(data))
        assert part
        data.extend(part)
    return bytes(data)

def read(peer):
    size, = struct.unpack("<I", recv_exact(peer, 4))
    assert 0 < size <= 1048576
    return recv_exact(peer, size)

def send(peer, kind, payload=b""):
    peer.sendall(struct.pack("<IB", 1 + len(payload), kind) + payload)

try:
    deadline = time.monotonic() + 5
    while not path.exists():
        assert time.monotonic() < deadline
        time.sleep(.01)
    assert state.stat().st_mode & 0o777 == 0o700
    assert (state / "sessions").stat().st_mode & 0o777 == 0o700
    print("shim session socket directory: 0700")
    peer = socket.socket(socket.AF_UNIX)
    peer.settimeout(5)
    peer.connect(str(path))
    hello = read(peer)
    assert hello[0] == 1
    shim_pid, = struct.unpack_from("<I", hello, 27)
    shell_pids = pathlib.Path(f"/proc/{shim_pid}/task/{shim_pid}/children").read_text().split()
    assert shell_pids
    terminal = os.stat(f"/proc/{shell_pids[0]}/fd/0")
    assert terminal.st_uid == target_uid
    assert terminal.st_mode & 0o777 == 0o600
    print(f"PTY slave: uid={terminal.st_uid}, mode=0600")
    status = pathlib.Path(f"/proc/{shell_pids[0]}/status").read_text()
    uids = next(line.split()[1:] for line in status.splitlines() if line.startswith("Uid:"))
    groups = next(line.split()[1:] for line in status.splitlines() if line.startswith("Groups:"))
    assert all(int(uid) == target_uid for uid in uids)
    assert "0" not in groups
    print(f"rootful shell: real/effective/saved/fs uid={uids}; supplementary groups={groups}; root group absent")
    # Temporarily permit traversal only in this canary's directories, so the
    # kernel's path permissions do not mask the shim's peer credential check.
    state.chmod(0o711)
    (state / "sessions").chmod(0o711)
    path.chmod(0o666)
    probe = os.fork()
    if probe == 0:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
        test = socket.socket(socket.AF_UNIX)
        test.settimeout(2)
        test.connect(str(path))
        try:
            refused = test.recv(64) == b""
        except ConnectionResetError:
            refused = True
        os._exit(0 if refused else 1)
    _, result = os.waitpid(probe, 0)
    assert os.waitstatus_to_exitcode(result) == 0
    print("SO_PEERCRED: uid 65534 connected but received no Hello; authenticated root connection retained")
    path.chmod(0o600)
    (state / "sessions").chmod(0o700)
    state.chmod(0o700)
    send(peer, 2, struct.pack("<Q", 0))
    send(peer, 0x13, struct.pack("<Q", 0))
    send(peer, 0x10, b"exit 0\n")
    while True:
        frame = read(peer)
        if frame[0] == 0x20:
            status, = struct.unpack_from("<i", frame, 1)
            assert status == 0
            send(peer, 0x21)
            break
    assert child.wait(timeout=5) == 0
    assert not path.exists()
    print("Exited(0) -> ExitAck: shim exited and socket removed")
finally:
    if child.poll() is None:
        child.kill()
        child.wait()
    shutil.rmtree(state, ignore_errors=True)
