"""Observe Linux task scheduling without sending requests to idle processes."""
from dataclasses import dataclass
from pathlib import Path
import time


@dataclass(frozen=True)
class ScheduledSlices:
    """Per-thread scheduler activations observed in one wall-clock window."""

    elapsed_seconds: float
    per_thread: dict[int, int]

    @property
    def total_slices(self):
        """Return the number of observed task scheduling activations."""
        return sum(self.per_thread.values())

    @property
    def scheduled_per_minute(self):
        """Normalize observed task activations to a per-minute rate."""
        return self.total_slices * 60.0 / self.elapsed_seconds


def _schedstat_slices(pid):
    """Read the third schedstat field for every live thread in a process."""
    tasks = Path(f"/proc/{pid}/task")
    try:
        entries = list(tasks.iterdir())
    except FileNotFoundError as error:
        raise ProcessLookupError(f"process {pid} has no live task directory") from error

    slices = {}
    for task in entries:
        try:
            fields = (task / "schedstat").read_text().split()
        except FileNotFoundError:
            # A thread can exit after readdir; the next sample observes the rest.
            continue
        if len(fields) < 3:
            raise RuntimeError(f"incomplete schedstat for thread {task.name}")
        slices[int(task.name)] = int(fields[2])
    if not slices:
        raise ProcessLookupError(f"process {pid} has no readable live tasks")
    return slices


def measure_scheduled_slices(pid, duration_seconds, sample_interval=0.1):
    """Count task schedule-ins through procfs without waking the target process.

    The monitor sleeps between read-only procfs snapshots. A timer in the
    monitor therefore does not count as activity in the observed process.
    New threads contribute their current counter because their creation is
    itself unexpected activity during an idle window.
    """
    if duration_seconds <= 0 or sample_interval <= 0:
        raise ValueError("measurement duration and sample interval must be positive")

    previous = _schedstat_slices(pid)
    per_thread = {tid: 0 for tid in previous}
    started = time.monotonic()
    deadline = started + duration_seconds
    while (remaining := deadline - time.monotonic()) > 0:
        time.sleep(min(sample_interval, remaining))
        current = _schedstat_slices(pid)
        for tid, slices in current.items():
            before = previous.get(tid)
            delta = slices if before is None else max(0, slices - before)
            per_thread[tid] = per_thread.get(tid, 0) + delta
        previous = current

    current = _schedstat_slices(pid)
    for tid, slices in current.items():
        before = previous.get(tid)
        delta = slices if before is None else max(0, slices - before)
        per_thread[tid] = per_thread.get(tid, 0) + delta
    elapsed = time.monotonic() - started
    return ScheduledSlices(elapsed, per_thread)


def assert_process_idle(pid, label, duration_seconds=2.2):
    """Require zero scheduled task activations over the requested window."""
    measurement = measure_scheduled_slices(pid, duration_seconds)
    if measurement.total_slices:
        threads = []
        for tid, slices in sorted(measurement.per_thread.items()):
            if slices == 0:
                continue
            try:
                name = Path(f"/proc/{pid}/task/{tid}/comm").read_text().strip()
            except FileNotFoundError:
                name = "exited"
            threads.append(f"{name} (tid {tid}): {slices}")
        detail = "; ".join(threads)
        raise AssertionError(
            f"{label} scheduled {measurement.total_slices} times in "
            f"{measurement.elapsed_seconds:.3f} s: {detail}"
        )
    return measurement


def session_shim_pid(session_id):
    """Find a real shim by its session argument without connecting to its socket."""
    expected = str(session_id).replace("-", "").encode("ascii")
    matches = []
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            arguments = (process / "cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if b"__shim" in arguments and expected in arguments:
            matches.append(int(process.name))
    if len(matches) != 1:
        raise RuntimeError(f"expected one live shim for session {session_id}, found {matches}")
    return matches[0]
