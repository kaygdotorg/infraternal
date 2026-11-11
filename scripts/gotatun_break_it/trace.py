"""Correlate GotaTun loaded-latency stalls with throughput and runtime traces."""

from __future__ import annotations

import math
import re
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
import subprocess

from .report import Probe


@dataclass(frozen=True, slots=True)
class GoodputSample:
    """A goodput rate measured for one interval, timestamped by its end."""

    timestamp_ns: int
    goodput_bps: int


@dataclass(frozen=True, slots=True)
class CounterSample:
    """A snapshot of GotaTun counters taken on the monotonic clock."""

    timestamp_ns: int
    counters: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class SchedulerEvent:
    """A scheduler event with its observed runnable delay and task identity."""

    timestamp_ns: int
    task: str
    event: str
    delay_ns: int


def load_probe_samples(path: Path) -> list[Probe]:
    """Read monotonic probe rows from the JSONL file written by the soak probe."""
    return [
        Probe(
            sequence=int(row["sequence"]),
            sent_ns=int(row["sent_ns"]),
            rtt_ms=None if row["rtt_ms"] is None else float(row["rtt_ms"]),
            sender_stalled=bool(row.get("sender_stalled", False)),
        )
        for row in _read_jsonl(path)
    ]


def load_counter_samples(path: Path) -> list[CounterSample]:
    """Read flattened product and kernel counter snapshots from monotonic JSONL rows."""
    samples = []
    for row in _read_jsonl(path):
        counters = row.get("counters")
        if not isinstance(counters, dict):
            raise ValueError(f"{path}: each row needs a counters object")
        samples.append(
            CounterSample(
                timestamp_ns=int(row["timestamp_ns"]),
                counters={name: int(value) for name, value in counters.items()},
            )
        )
    return samples


def _read_jsonl(path: Path) -> Iterable[dict[str, object]]:
    """Yield object rows from JSONL while identifying malformed evidence lines."""
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{line_number}: invalid JSON row") from error
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: expected a JSON object")
            yield row


def goodput_from_counters(
    samples: Sequence[CounterSample], counter_name: str
) -> list[GoodputSample]:
    """Turn a monotonic byte counter into measured rates for each sample interval."""
    if not counter_name.strip():
        raise ValueError("counter name must not be empty")
    ordered = sorted(samples, key=lambda sample: sample.timestamp_ns)
    rates: list[GoodputSample] = []
    for previous, current in zip(ordered, ordered[1:]):
        previous_bytes = previous.counters.get(counter_name)
        current_bytes = current.counters.get(counter_name)
        elapsed_ns = current.timestamp_ns - previous.timestamp_ns
        if (
            previous_bytes is None
            or current_bytes is None
            or elapsed_ns <= 0
            or current_bytes < previous_bytes
        ):
            continue
        goodput_bps = (current_bytes - previous_bytes) * 8_000_000_000 // elapsed_ns
        rates.append(GoodputSample(current.timestamp_ns, goodput_bps))
    return rates


def parse_perf_sched(
    lines: str | Iterable[str], *, minimum_delay_ns: int = 0
) -> list[SchedulerEvent]:
    """Convert `perf script` scheduler events to monotonic runnable delays.

    Run `perf sched record` with `--clockid mono`; then these timestamps use
    the same clock as the probe and product-counter streams. The parser pairs
    each wakeup, or a preempted runnable task, with the next switch onto that
    task so long futex and worker wake delays remain visible.
    """
    if minimum_delay_ns < 0:
        raise ValueError("minimum scheduler delay must be non-negative")
    events: list[SchedulerEvent] = []
    ready_at_ns: dict[int, int] = {}
    event_pattern = re.compile(
        r"(?P<timestamp>\d+(?:\.\d+)?):\s+sched:(?P<kind>\w+):\s*(?P<payload>.*)"
    )
    input_lines = lines.splitlines() if isinstance(lines, str) else lines
    for line in input_lines:
        match = event_pattern.search(line)
        if match is None:
            continue
        try:
            timestamp_ns = int(Decimal(match.group("timestamp")) * 1_000_000_000)
        except InvalidOperation:
            continue
        kind = match.group("kind")
        payload = match.group("payload")
        if kind in {"sched_wakeup", "sched_wakeup_new"}:
            pid_match = re.search(r"\bpid=(\d+)\b", payload)
            if pid_match is not None:
                pid = int(pid_match.group(1))
                ready_at_ns.setdefault(pid, timestamp_ns)
            continue
        if kind != "sched_switch":
            continue

        previous = re.search(r"\bprev_pid=(\d+)\b.*?\bprev_state=(\S+)", payload)
        if previous is not None and previous.group(2) == "R":
            previous_pid = int(previous.group(1))
            if previous_pid != 0:
                ready_at_ns[previous_pid] = timestamp_ns

        next_task = re.search(r"\bnext_comm=(\S+)\s+next_pid=(\d+)\b", payload)
        if next_task is None:
            continue
        task = next_task.group(1)
        pid = int(next_task.group(2))
        ready_ns = ready_at_ns.pop(pid, None)
        delay_ns = timestamp_ns - ready_ns if ready_ns is not None else -1
        if delay_ns >= minimum_delay_ns:
            events.append(
                SchedulerEvent(
                    timestamp_ns,
                    task=f"{task}/{pid}",
                    event="runnable_delay",
                    delay_ns=delay_ns,
                )
            )
    return events


def parse_pipeline_queue_events(
    lines: Iterable[str], *, monotonic_offset_ns: int, side: str
) -> list[CounterSample]:
    """Map opt-in GotaTun queue events onto the probe host's monotonic clock.

    GotaTun reports `mono_ns` relative to its first diagnostic event. The
    caller measures that event's host-monotonic offset while tailing stderr,
    then supplies the offset here so queue depth lines can share the probe and
    scheduler timeline.
    """
    if monotonic_offset_ns < 0:
        raise ValueError("pipeline monotonic offset must be non-negative")
    if side not in {"a", "b"}:
        raise ValueError("pipeline side must be 'a' or 'b'")

    pattern = re.compile(
        r"pipeline mono_ns=(?P<elapsed>\d+) "
        r"stage=crypto_queue_(?:push|pop) queued_jobs=(?P<queued>\d+)"
    )
    samples = []
    for line in lines:
        match = pattern.search(line)
        if match is None:
            continue
        samples.append(
            CounterSample(
                timestamp_ns=monotonic_offset_ns + int(match.group("elapsed")),
                counters={f"{side}_crypto_queue_jobs": int(match.group("queued"))},
            )
        )
    return sorted(samples, key=lambda sample: sample.timestamp_ns)


def summarize_soak(
    *,
    probes: Sequence[Probe],
    goodput: Sequence[GoodputSample],
    counters: Sequence[CounterSample],
    scheduler_events: Sequence[SchedulerEvent],
    slow_threshold_ms: float = 100.0,
    scheduler_trace_window_ns: tuple[int, int] | None = None,
    window_seconds: int = 60,
) -> dict[str, object]:
    """Report slow probe bursts beside samples from the same monotonic interval.

    A lost probe is a slow probe and occupies an infinite latency rank. Each
    burst spans from its first probe send until the last slow reply would have
    arrived. The raw streams stay separate on disk; this summary keeps only
    aligned counter ranges and the ten longest scheduler waits per burst.
    """
    _validate_inputs(probes, goodput, counters, scheduler_events, slow_threshold_ms)
    if window_seconds < 1:
        raise ValueError("latency window must be at least one second")
    if scheduler_trace_window_ns is not None:
        trace_start_ns, trace_end_ns = scheduler_trace_window_ns
        if trace_start_ns < 0 or trace_end_ns < trace_start_ns:
            raise ValueError("scheduler trace window must be non-negative and ordered")
    ordered_probes = sorted(probes, key=lambda probe: (probe.sent_ns, probe.sequence))
    ordered_goodput = sorted(goodput, key=lambda sample: sample.timestamp_ns)
    ordered_counters = sorted(counters, key=lambda sample: sample.timestamp_ns)
    ordered_scheduler = sorted(
        scheduler_events, key=lambda event: (event.timestamp_ns, event.task, event.event)
    )
    bursts = _slow_bursts(ordered_probes, slow_threshold_ms)
    probe_start_ns = ordered_probes[0].sent_ns if ordered_probes else 0
    probe_end_ns = (
        max(probe.sent_ns for probe in ordered_probes) if ordered_probes else 0
    )
    trace_covers_probes = (
        scheduler_trace_window_ns is not None
        and scheduler_trace_window_ns[0] <= probe_start_ns
        and scheduler_trace_window_ns[1] >= probe_end_ns
    )
    scheduler_overlaps_probes = any(
        probe_start_ns <= event.timestamp_ns <= probe_end_ns
        for event in ordered_scheduler
    )

    return {
        "probe_count": len(ordered_probes),
        "probe_loss_count": sum(probe.rtt_ms is None for probe in ordered_probes),
        "probe_sender_stall_count": sum(probe.sender_stalled for probe in ordered_probes),
        "p99_ms": _nearest_rank_p99(ordered_probes),
        "p99_state": _p99_state(ordered_probes),
        "slow_threshold_ms": slow_threshold_ms,
        "slow_probe_count": sum(_is_slow(probe, slow_threshold_ms) for probe in ordered_probes),
        "goodput_sample_count": len(ordered_goodput),
        "goodput_min_bps": min((sample.goodput_bps for sample in ordered_goodput), default=None),
        "goodput_max_bps": max((sample.goodput_bps for sample in ordered_goodput), default=None),
        "gotatun_counter_sample_count": len(ordered_counters),
        "counter_drift": _counter_drift(ordered_counters),
        "latency_windows": _latency_windows(ordered_probes, window_seconds),
        "scheduler_event_count": len(ordered_scheduler),
        "scheduler_trace_window_ns": list(scheduler_trace_window_ns)
        if scheduler_trace_window_ns is not None
        else None,
        "correlation_status": (
            "complete"
            if ordered_goodput
            and ordered_counters
            and (trace_covers_probes or scheduler_overlaps_probes)
            else "incomplete"
        ),
        "stall_bursts": [
            _summarize_burst(
                burst,
                ordered_goodput,
                ordered_counters,
                ordered_scheduler,
                scheduler_trace_window_ns,
            )
            for burst in bursts
        ],
    }


def _validate_inputs(
    probes: Sequence[Probe],
    goodput: Sequence[GoodputSample],
    counters: Sequence[CounterSample],
    scheduler_events: Sequence[SchedulerEvent],
    slow_threshold_ms: float,
) -> None:
    """Reject malformed timestamps and counter values before reporting them."""
    if not math.isfinite(slow_threshold_ms) or slow_threshold_ms <= 0:
        raise ValueError("slow threshold must be finite and positive")
    seen_sequences: set[int] = set()
    for probe in probes:
        if probe.sequence < 1 or probe.sent_ns < 0:
            raise ValueError("probe sequences and timestamps must be positive")
        if probe.sequence in seen_sequences:
            raise ValueError(f"probe sequence {probe.sequence} is repeated")
        seen_sequences.add(probe.sequence)
        if probe.rtt_ms is not None and (
            not math.isfinite(probe.rtt_ms) or probe.rtt_ms < 0
        ):
            raise ValueError("probe RTT must be finite and non-negative")
    for sample in goodput:
        if sample.timestamp_ns < 0 or sample.goodput_bps < 0:
            raise ValueError("goodput timestamps and rates must be non-negative")
    for sample in counters:
        if sample.timestamp_ns < 0:
            raise ValueError("counter timestamps must be non-negative")
        for name, value in sample.counters.items():
            if not name.strip() or isinstance(value, bool) or value < 0:
                raise ValueError("counter names must be present and values non-negative")
    for event in scheduler_events:
        if event.timestamp_ns < 0 or event.delay_ns < 0:
            raise ValueError("scheduler timestamps and delays must be non-negative")
        if not event.task.strip() or not event.event.strip():
            raise ValueError("scheduler task and event names must be present")


def _slow_bursts(probes: Sequence[Probe], threshold_ms: float) -> list[list[Probe]]:
    """Group adjacent slow or lost probes without merging separate recoveries."""
    bursts: list[list[Probe]] = []
    current: list[Probe] = []
    for probe in probes:
        if _is_slow(probe, threshold_ms):
            current.append(probe)
        elif current:
            bursts.append(current)
            current = []
    if current:
        bursts.append(current)
    return bursts


def _summarize_burst(
    probes: Sequence[Probe],
    goodput: Sequence[GoodputSample],
    counters: Sequence[CounterSample],
    scheduler_events: Sequence[SchedulerEvent],
    scheduler_trace_window_ns: tuple[int, int] | None,
) -> dict[str, object]:
    """Join one slow burst to measurements whose monotonic time overlaps it."""
    started_ns = probes[0].sent_ns
    last_probe = probes[-1]
    ended_ns = last_probe.sent_ns + round((last_probe.rtt_ms or 0.0) * 1_000_000)
    matched_goodput = [
        sample
        for sample in goodput
        if started_ns <= sample.timestamp_ns <= ended_ns
    ]
    matched_counters = [
        sample
        for sample in counters
        if started_ns <= sample.timestamp_ns <= ended_ns
    ]
    matched_scheduler = [
        event
        for event in scheduler_events
        if started_ns <= event.timestamp_ns <= ended_ns
    ]
    scheduler_covers_burst = (
        scheduler_trace_window_ns is not None
        and scheduler_trace_window_ns[0] <= started_ns
        and scheduler_trace_window_ns[1] >= ended_ns
    )
    names = sorted({name for sample in matched_counters for name in sample.counters})
    counter_min = {
        name: min(sample.counters[name] for sample in matched_counters if name in sample.counters)
        for name in names
    }
    counter_max = {
        name: max(sample.counters[name] for sample in matched_counters if name in sample.counters)
        for name in names
    }
    top_waits = sorted(
        matched_scheduler,
        key=lambda event: (-event.delay_ns, event.timestamp_ns, event.task, event.event),
    )[:10]
    finite_rtts = [probe.rtt_ms for probe in probes if probe.rtt_ms is not None]

    return {
        "started_ns": started_ns,
        "ended_ns": ended_ns,
        "duration_ms": round((ended_ns - started_ns) / 1_000_000, 4),
        "first_probe_sequence": probes[0].sequence,
        "last_probe_sequence": last_probe.sequence,
        "probe_count": len(probes),
        "probe_loss_count": sum(probe.rtt_ms is None for probe in probes),
        "probe_sender_stall_count": sum(probe.sender_stalled for probe in probes),
        "p99_ms": _nearest_rank_p99(probes),
        "max_rtt_ms": max(finite_rtts) if finite_rtts else None,
        "goodput_sample_count": len(matched_goodput),
        "goodput_min_bps": min(sample.goodput_bps for sample in matched_goodput)
        if matched_goodput
        else None,
        "counter_sample_count": len(matched_counters),
        "counter_min": counter_min,
        "counter_max": counter_max,
        "scheduler_event_count": len(matched_scheduler),
        "scheduler_wait_total_ns": sum(event.delay_ns for event in matched_scheduler),
        "scheduler_wait_max_ns": max((event.delay_ns for event in matched_scheduler), default=0),
        "scheduler_top_waits": [
            {
                "timestamp_ns": event.timestamp_ns,
                "task": event.task,
                "event": event.event,
                "delay_ns": event.delay_ns,
            }
            for event in top_waits
        ],
        "correlation_status": (
            "complete"
            if matched_goodput
            and matched_counters
            and (matched_scheduler or scheduler_covers_burst)
            else "incomplete"
        ),
    }


def _is_slow(probe: Probe, threshold_ms: float) -> bool:
    """Treat a lost reply as a stalled probe and compare finite RTTs to the threshold."""
    return probe.rtt_ms is None or probe.rtt_ms >= threshold_ms


def _nearest_rank_p99(probes: Sequence[Probe]) -> float | None:
    """Return nearest-rank p99, counting an unanswered probe as infinite latency."""
    if not probes:
        return None
    ordered = sorted(math.inf if probe.rtt_ms is None else probe.rtt_ms for probe in probes)
    value = ordered[math.ceil(0.99 * len(ordered)) - 1]
    return value if math.isfinite(value) else None


def _p99_state(probes: Sequence[Probe]) -> str:
    """Name empty input and loss-dominated p99 values without inventing a latency."""
    if not probes:
        return "no_probes"
    return "infinite_due_to_loss" if _nearest_rank_p99(probes) is None else "finite"


def _counter_drift(counters: Sequence[CounterSample]) -> dict[str, dict[str, int]]:
    """Report first-to-last and peak ranges for process and GotaTun counters."""
    names = sorted({name for sample in counters for name in sample.counters})
    drift = {}
    for name in names:
        values = [sample.counters[name] for sample in counters if name in sample.counters]
        if values:
            drift[name] = {
                "first": values[0],
                "last": values[-1],
                "delta": values[-1] - values[0],
                "min": min(values),
                "max": max(values),
            }
    return drift


def _latency_windows(probes: Sequence[Probe], window_seconds: int) -> list[dict[str, object]]:
    """Keep per-window loss and tail latency so a long soak exposes latency drift."""
    if not probes:
        return []
    origin_ns = min(probe.sent_ns for probe in probes)
    window_ns = window_seconds * 1_000_000_000
    grouped: dict[int, list[Probe]] = {}
    for probe in probes:
        index = (probe.sent_ns - origin_ns) // window_ns
        grouped.setdefault(index, []).append(probe)
    return [
        {
            "window_index": index,
            "started_ns": min(probe.sent_ns for probe in group),
            "probe_count": len(group),
            "probe_loss_count": sum(probe.rtt_ms is None for probe in group),
            "p50_ms": _nearest_rank(group, 0.50),
            "p99_ms": _nearest_rank(group, 0.99),
        }
        for index, group in sorted(grouped.items())
    ]


def _nearest_rank(probes: Sequence[Probe], percentile: float) -> float | None:
    """Return a loss-aware nearest-rank percentile for a non-empty probe set."""
    if not probes:
        return None
    values = sorted(math.inf if probe.rtt_ms is None else probe.rtt_ms for probe in probes)
    value = values[math.ceil(percentile * len(values)) - 1]
    return value if math.isfinite(value) else None


def summarize_soak_files(
    probe_path: Path,
    counter_path: Path,
    perf_data_path: Path,
    *,
    goodput_counter: str = "b_gotatun_rx_bytes",
    slow_threshold_ms: float = 100.0,
    scheduler_trace_window_ns: tuple[int, int] | None = None,
) -> dict[str, object]:
    """Join raw monotonic probes and counters to a captured `perf sched` data file."""
    probes = load_probe_samples(probe_path)
    counters = load_counter_samples(counter_path)
    pipeline_counter_path = counter_path.with_name("pipeline-counters.jsonl")
    pipeline_counters = (
        load_counter_samples(pipeline_counter_path) if pipeline_counter_path.is_file() else []
    )
    counters.extend(pipeline_counters)
    events: list[SchedulerEvent] = []
    with subprocess.Popen(
        ["perf", "script", "-i", str(perf_data_path)],
        stdout=subprocess.PIPE,
        text=True,
    ) as process:
        if process.stdout is None:
            raise RuntimeError("perf script did not expose its output stream")
        events = parse_perf_sched(process.stdout, minimum_delay_ns=100_000)
        if process.wait() != 0:
            raise RuntimeError("perf script could not read the scheduler trace")
    report = summarize_soak(
        probes=probes,
        goodput=goodput_from_counters(counters, goodput_counter),
        counters=counters,
        scheduler_events=events,
        slow_threshold_ms=slow_threshold_ms,
        scheduler_trace_window_ns=scheduler_trace_window_ns,
    )
    queue_samples = sum(
        any(
            name in sample.counters
            for name in (
                "a_crypto_queue_jobs",
                "a_crypto_queue_jobs_max",
                "b_crypto_queue_jobs",
                "b_crypto_queue_jobs_max",
            )
        )
        for sample in pipeline_counters
    )
    lock_event_count = sum(
        int(sample.counters.get(f"{side}_ordered_delivery_lock_wait_events", 0))
        + int(sample.counters.get(f"{side}_ordered_delivery_lock_acquired_events", 0))
        + int(sample.counters.get(f"{side}_ordered_delivery_lock_unmatched_acquired_events", 0))
        for sample in pipeline_counters
        for side in ("a", "b")
    )
    report["pipeline_queue_sample_count"] = queue_samples
    report["pipeline_queue_trace_status"] = "captured" if queue_samples else "missing"
    report["pipeline_lock_event_count"] = lock_event_count
    report["pipeline_lock_trace_status"] = "captured" if lock_event_count else "missing"
    report["pipeline_lock_timestamp_basis"] = (
        "host monotonic log-tail observations (nominal 10 ms polling; backlog can widen)"
        if lock_event_count
        else "missing"
    )
    return report


def main() -> None:
    """Write the correlated report from the three retained soak evidence files."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probes", required=True, type=Path)
    parser.add_argument("--counters", required=True, type=Path)
    parser.add_argument("--perf-data", required=True, type=Path)
    parser.add_argument("--goodput-counter", default="b_gotatun_rx_bytes")
    parser.add_argument("--scheduler-start-ns", type=int)
    parser.add_argument("--scheduler-end-ns", type=int)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    if (arguments.scheduler_start_ns is None) != (arguments.scheduler_end_ns is None):
        parser.error("scheduler start and end timestamps must be supplied together")
    scheduler_window = (
        (arguments.scheduler_start_ns, arguments.scheduler_end_ns)
        if arguments.scheduler_start_ns is not None
        else None
    )
    report = summarize_soak_files(
        arguments.probes,
        arguments.counters,
        arguments.perf_data,
        goodput_counter=arguments.goodput_counter,
        scheduler_trace_window_ns=scheduler_window,
    )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
