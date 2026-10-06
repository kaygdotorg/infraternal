#!/usr/bin/env python3
"""Capture real full-screen program output at 200x60 for VT comparisons [13]."""
import fcntl
import os
import pathlib
import pty
import select
import signal
import struct
import termios
import time

root = pathlib.Path(__file__).parent
for name, argv, keys in [
    ("vim", ["vim", "-u", "NONE", "-i", "NONE", "-n", str(root / "capture.py")], b"Ggg\x1b:q!\r"),
    ("htop", ["htop", "-p", "1"], b"q"),
    ("less", ["less", "-R", str(root / "capture.py")], b"Ggq"),
]:
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 60, 200, 0, 0))
    pid = os.fork()
    if pid == 0:
        os.close(master)
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        for fd in range(3):
            os.dup2(slave, fd)
        os.close(slave)
        os.environ["TERM"] = "xterm-256color"
        os.execvp(argv[0], argv)
    os.close(slave)
    output = bytearray()
    until = time.monotonic() + 1
    while time.monotonic() < until:
        if select.select([master], [], [], .05)[0]:
            output.extend(os.read(master, 65536))
    # Keep the active full-screen state, then collect an independent continuation.
    (root / (name + ".vt")).write_bytes(output)
    os.write(master, keys)
    continuation = bytearray()
    until = time.monotonic() + .5
    while time.monotonic() < until:
        if select.select([master], [], [], .05)[0]:
            try:
                continuation.extend(os.read(master, 65536))
            except OSError:
                break
    (root / (name + ".continue.vt")).write_bytes(continuation)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    os.close(master)
