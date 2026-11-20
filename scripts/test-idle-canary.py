#!/usr/bin/env python3
"""Prove the scheduler canary scopes wakeups to one process and catches a periodic wakeup."""
from concurrent.futures import ThreadPoolExecutor
import pathlib
import select
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from idle_canary import assert_process_idle, measure_scheduled_slices


def wait_until_blocked(pid):
    """Wait for a target process to enter interruptible sleep without waking it."""
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        stat = pathlib.Path(f"/proc/{pid}/stat").read_text()
        state = stat[stat.rfind(")") + 2]
        if state == "S":
            return
        # sleep: poll the target's kernel state without sending it work.
        time.sleep(0.01)
    raise TimeoutError(f"process {pid} did not enter interruptible sleep")


def wait_for_ready(process):
    """Read a child's readiness line within a load-tolerant bound."""
    if process.stdout is None:
        raise RuntimeError("canary child has no readiness pipe")
    readable, _, _ = select.select([process.stdout], [], [], 30.0)
    if not readable:
        raise TimeoutError(f"process {process.pid} did not become ready")
    if process.stdout.readline().strip() != "READY":
        raise RuntimeError(f"process {process.pid} sent an invalid readiness line")


def main():
    """Check that a busy sibling is ignored and a periodic target is detected."""
    quiet_code = "\n".join(
        (
            "import signal",
            "print('READY', flush=True)",
            "while True:",
            "    signal.pause()",
        )
    )
    periodic_code = "\n".join(
        (
            "import signal",
            "signal.signal(signal.SIGALRM, lambda *_: None)",
            "signal.setitimer(signal.ITIMER_REAL, 0.25, 1.0)",
            "print('READY', flush=True)",
            "while True:",
            "    signal.pause()",
        )
    )
    processes = []
    try:
        quiet = subprocess.Popen(
            [sys.executable, "-c", quiet_code], stdout=subprocess.PIPE, text=True
        )
        processes.append(quiet)
        periodic = subprocess.Popen(
            [sys.executable, "-c", periodic_code], stdout=subprocess.PIPE, text=True
        )
        processes.append(periodic)
        wait_for_ready(quiet)
        wait_for_ready(periodic)
        wait_until_blocked(quiet.pid)
        wait_until_blocked(periodic.pid)

        # Observe both targets over the same full timer period. The quiet
        # process proves that its active sibling's work is not attributed to it.
        with ThreadPoolExecutor(max_workers=2) as monitors:
            quiet_sample = monitors.submit(
                measure_scheduled_slices, quiet.pid, 2.5, sample_interval=0.05
            )
            periodic_check = monitors.submit(
                assert_process_idle, periodic.pid, "periodic wakeup mutant", 2.5
            )
            quiet_observed = quiet_sample.result()
            try:
                periodic_check.result()
            except AssertionError as error:
                mutant_failure = str(error)
                assert "scheduled " in mutant_failure, mutant_failure
            else:
                raise AssertionError("periodic wakeup mutant passed the idle canary")

        assert quiet_observed.total_slices == 0, quiet_observed
        print(
            "process-scoped scheduler canary: quiet sibling=0 slices over "
            f"{quiet_observed.elapsed_seconds:.3f} s; periodic mutant rejected: "
            f"{mutant_failure}"
        )
    finally:
        for process in processes:
            process.kill()
            process.wait()


if __name__ == "__main__":
    main()
