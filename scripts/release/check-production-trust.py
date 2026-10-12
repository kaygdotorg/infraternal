#!/usr/bin/env python3
"""Reject per-run staging authority in every production static image (#188 D1)."""
import mmap
from pathlib import Path
import sys


def check(binary):
    with Path(binary).open("rb") as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as image:
            if image.find(b"infraternal-staging-trust-v1") >= 0:
                raise ValueError("production binary contains staging-trust authority")


if __name__ == "__main__":
    try:
        check(sys.argv[1])
    except (OSError, ValueError, IndexError):
        print("production trust: FAIL (missing image or staging authority)", file=sys.stderr)
        raise SystemExit(1) from None
    print("production trust: PASS (staging-trust authority absent)")
