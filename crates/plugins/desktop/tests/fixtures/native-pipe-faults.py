#!/usr/bin/env python3
"""Private companion faults selected by per-run symlink names [D203, #146]."""
# SPDX-License-Identifier: AGPL-3.0-only
import os
from pathlib import Path
import signal
import struct
import sys

mode = Path(sys.argv[0]).name
if mode == "pixel-reader.py":
    # Startup is observed before the real stdio owner fills the unread pipe.
    with open(sys.argv[0] + ".pid", "w") as output:
        output.write(str(os.getpid()))
    signal.pause()
elif mode == "reply-ordering.py":
    source = sys.stdin.buffer
    sink = sys.stdout.buffer

    def request():
        prefix = source.read(4)
        if len(prefix) != 4:
            sys.exit(0)
        length, = struct.unpack(">I", prefix)
        body = source.read(length)
        if len(body) != length:
            sys.exit(0)

    request()
    request()
    sink.write(struct.pack(">IBB", 4, 1, 65) + b"{}")
    sink.write(struct.pack(">IBB", 4, 1, 68) + b"{}")
    sink.flush()
else:
    raise SystemExit("unknown native pipe fixture mode")
