#!/usr/bin/env python3
"""Subtract only coordinator-certified cgroup freezes from fixture time [D270]."""
import mmap
import os
import struct
import time


class ActiveClock:
    """One immutable mapping; the coordinator updates it only while we are frozen."""
    def __init__(self, path):
        with open(path, 'rb') as source:
            if os.fstat(source.fileno()).st_size != 8:
                raise ValueError('invalid pause clock length')
            self.mapping = mmap.mmap(source.fileno(), 8, access=mmap.ACCESS_READ)

    def now(self):
        return time.monotonic() - struct.unpack_from('<Q', self.mapping)[0] / 1e9


_clock = ActiveClock(os.environ['PPU_PAUSE_CLOCK']) if 'PPU_PAUSE_CLOCK' in os.environ else None
now = _clock.now if _clock else time.monotonic
