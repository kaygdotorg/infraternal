#!/usr/bin/env python3
"""Start a known fixture binary from a sealed image while preserving its inherited control fd (#157)."""
import fcntl
import os
import sys

image = os.memfd_create("infraternal-fixture", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
with open(os.environ["INFRATERNAL_ANONYMOUS_BINARY"], "rb") as source:
    while chunk := source.read(65536):
        view = memoryview(chunk)
        while view:
            view = view[os.write(image, view):]
fcntl.fcntl(image, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
os.execve(image, [os.environ["INFRATERNAL_ANONYMOUS_BINARY"], *sys.argv[1:]], os.environ)
