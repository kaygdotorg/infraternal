"""Observe Linux task scheduling without sending requests to idle processes.

The D81 check has two parts. First wait, on what the kernel reports, until the
target has finished the work it already started (`wait_until_idle`). Then count
every scheduler activation in a fixed window and allow none
(`assert_process_idle`). A fixed sleep cannot replace the first part: on a
loaded host, startup work outlives any sleep and its last wakeup lands in the
window.
"""
from dataclasses import dataclass
from pathlib import Path
import time

# Programs a process starts, waits for and is woken by exactly once: the init
# manager probe and the launcher that execs a session shim.
_ONE_SHOT_PROGRAMS = frozenset({b"systemctl", b"systemd-run"})


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


def measure_scheduled_slices(pid, duration_seconds, sample_interval=0.1, on_activation=None):
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
            if delta and on_activation is not None:
                on_activation(time.monotonic() - started, tid, delta)
        previous = current

    current = _schedstat_slices(pid)
    for tid, slices in current.items():
        before = previous.get(tid)
        delta = slices if before is None else max(0, slices - before)
        per_thread[tid] = per_thread.get(tid, 0) + delta
        if delta and on_activation is not None:
            on_activation(time.monotonic() - started, tid, delta)
    elapsed = time.monotonic() - started
    return ScheduledSlices(elapsed, per_thread)


def _thread_states(pid):
    """Return each live thread's kernel state letter without waking it."""
    states = {}
    for task in Path(f"/proc/{pid}/task").iterdir():
        try:
            stat = (task / "stat").read_text()
        except (FileNotFoundError, ProcessLookupError):
            continue
        # The thread name may contain spaces or parentheses; the state follows the last one.
        states[int(task.name)] = stat[stat.rfind(")") + 2]
    return states


def _pending_child(pid):
    """Describe a child whose exit will still wake the process, or return None.

    That is a child that has exited and is not reaped yet, or a one-shot program
    that is still running. Long-lived children, such as session shims and their
    shells, do not count: an idle process may keep them.
    """
    for task in Path(f"/proc/{pid}/task").iterdir():
        try:
            children = (task / "children").read_text().split()
        except (FileNotFoundError, ProcessLookupError):
            # The thread exited after readdir. Its children move to a sibling.
            continue
        for child in children:
            try:
                stat = Path(f"/proc/{child}/stat").read_text()
                arguments = Path(f"/proc/{child}/cmdline").read_bytes().split(b"\0")
            except (FileNotFoundError, ProcessLookupError):
                continue
            if stat[stat.rfind(")") + 2] == "Z":
                return f"child {child} has exited and is not reaped"
            # A script runs as `interpreter path`, so look at the first two arguments.
            for argument in arguments[:2]:
                name = argument.rsplit(b"/", 1)[-1]
                if name in _ONE_SHOT_PROGRAMS:
                    return f"one-shot child {child} ({name.decode()}) is still running"
    return None


def wait_until_idle(pid, label, quiet_seconds=0.5, timeout_seconds=60.0, sample_interval=0.05):
    """Block until the process has finished the work it already started.

    Idle means that for `quiet_seconds` without a break no thread was scheduled,
    every thread was in interruptible sleep (so none was waiting for a CPU or a
    disk), and no child was about to wake the process. A busy host only makes
    this take longer. A process that never gets there, for example because a
    timer fires more often than `quiet_seconds`, fails after `timeout_seconds`.
    """
    deadline = time.monotonic() + timeout_seconds
    previous = _schedstat_slices(pid)
    quiet_since = time.monotonic()
    reason = "not observed yet"
    while True:
        # sleep: sample the target's kernel state; nothing is sent to it.
        time.sleep(sample_interval)
        current = _schedstat_slices(pid)
        busy = sorted(tid for tid, state in _thread_states(pid).items() if state != "S")
        pending = _pending_child(pid)
        now = time.monotonic()
        if current != previous:
            ran = sorted(tid for tid in current.keys() | previous.keys()
                         if current.get(tid) != previous.get(tid))
            reason = f"threads {ran} were scheduled or came and went"
        elif busy:
            reason = f"threads {busy} were runnable or in uninterruptible sleep"
        elif pending:
            reason = pending
        elif now - quiet_since >= quiet_seconds:
            return
        if current != previous or busy or pending:
            quiet_since = now
        previous = current
        if now >= deadline:
            raise AssertionError(
                f"{label} never went idle for {quiet_seconds} s within "
                f"{timeout_seconds} s: {reason}"
            )


def assert_process_idle(pid, label, duration_seconds=2.2, on_activation=None,
                        settle_timeout=60.0):
    """Require zero scheduled task activations once the process has gone idle (D81).

    Waits for the process with `wait_until_idle`, then observes the window. The
    window allows no activation at all, so any timer with a period up to
    `duration_seconds` fails it, whatever the host's load.
    """
    wait_until_idle(pid, label, timeout_seconds=settle_timeout)
    measurement = measure_scheduled_slices(pid, duration_seconds, on_activation=on_activation)
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


def main():
    """Observe an explicitly supplied daemon/server PID without probing its API."""
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--label', default='infraternal process')
    parser.add_argument('--seconds', type=float, default=10.0)
    parser.add_argument('--events', action='store_true', help='timestamp positive activations on stderr')
    args = parser.parse_args()
    def report_activation(elapsed, tid, count):
        print(f'{args.label}: +{count} activation(s) at {elapsed:.3f}s; tid={tid}',
              file=sys.stderr, flush=True)

    measurement = assert_process_idle(args.pid, args.label, args.seconds,
                                      report_activation if args.events else None)
    status = Path(f'/proc/{args.pid}/status').read_text().splitlines()
    rss = next(line.split()[1] for line in status if line.startswith('VmRSS:'))
    print(f'{args.label}: {measurement.total_slices} scheduler activations / '
          f'{measurement.elapsed_seconds:.3f}s '
          f'({measurement.scheduled_per_minute:.3f}/min); RSS={rss} KiB; '
          f'threads={len(measurement.per_thread)}')


if __name__ == '__main__':
    main()
