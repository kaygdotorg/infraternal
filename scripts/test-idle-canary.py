#!/usr/bin/env python3
"""Prove the scheduler canary observes a phased one-hertz process wakeup."""
import pathlib
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from idle_canary import measure_scheduled_slices


def cpu_ticks(pid):
    """Return process user and system ticks, as the old canary sampled them."""
    return pathlib.Path(f"/proc/{pid}/stat").read_text().split()[13:15]


def main():
    code = "\n".join(
        (
            "import signal",
            "signal.signal(signal.SIGALRM, lambda *_: None)",
            # Keep the old half-second sample before the first periodic wake.
            "signal.setitimer(signal.ITIMER_REAL, 1.5, 1.0)",
            "print('READY', flush=True)",
            "while True:",
            "    signal.pause()",
        )
    )
    sleeper = subprocess.Popen(
        [sys.executable, "-c", code], stdout=subprocess.PIPE, text=True
    )
    try:
        assert sleeper.stdout is not None
        assert sleeper.stdout.readline().strip() == "READY"
        before = cpu_ticks(sleeper.pid)
        time.sleep(0.5)
        after = cpu_ticks(sleeper.pid)
        assert before == after, ("legacy 500 ms CPU-tick sample did not miss", before, after)

        observed = measure_scheduled_slices(sleeper.pid, 2.5, sample_interval=0.05)
        assert observed.total_slices >= 2, observed
        print(
            "phased 1 Hz SIGALRM: legacy 500 ms ticks unchanged; "
            f"schedstat observed {observed.total_slices} slices over "
            f"{observed.elapsed_seconds:.3f} s"
        )
    finally:
        sleeper.kill()
        sleeper.wait()


if __name__ == "__main__":
    main()
