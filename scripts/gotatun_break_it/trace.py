"""Correlate GotaTun loaded-latency stalls with throughput and runtime traces."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

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


def parse_perf_sched(lines: str) -> list[SchedulerEvent]:
    """Convert `perf script` scheduler events to monotonic runnable delays.

    Run `perf sched record` with `--clockid mono`; then these timestamps use
    the same clock as the probe and product-counter streams. The parser pairs
    each wakeup, or a preempted runnable task, with the next switch onto that
    task so long futex and worker wake delays remain visible.
    """
    events: list[SchedulerEvent] = []
    ready_at_ns: dict[int, int] = {}
    event_pattern = re.compile(
        r"(?P<timestamp>\d+(?:\.\d+)?):\s+sched:(?P<kind>\w+):\s*(?P<payload>.*)"
    )
    for line in lines.splitlines():
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
        if ready_ns is not None and timestamp_ns >= ready_ns:
            events.append(
                SchedulerEvent(
                    timestamp_ns,
                    task=f"{task}/{pid}",
                    event="runnable_delay",
                    delay_ns=timestamp_ns - ready_ns,
                )
            )
    return events


def summarize_soak(
    *,
    probes: Sequence[Probe],
    goodput: Sequence[GoodputSample],
    counters: Sequence[CounterSample],
    scheduler_events: Sequence[SchedulerEvent],
    slow_threshold_ms: float = 100.0,
) -> dict[str, object]:
    """Report slow probe bursts beside samples from the same monotonic interval.

    A lost probe is a slow probe and occupies an infinite latency rank. Each
    burst spans from its first probe send until the last slow reply would have
    arrived. The raw streams stay separate on disk; this summary keeps only
    aligned counter ranges and the ten longest scheduler waits per burst.
    """
    _validate_inputs(probes, goodput, counters, scheduler_events, slow_threshold_ms)
    ordered_probes = sorted(probes, key=lambda probe: (probe.sent_ns, probe.sequence))
    ordered_goodput = sorted(goodput, key=lambda sample: sample.timestamp_ns)
    ordered_counters = sorted(counters, key=lambda sample: sample.timestamp_ns)
    ordered_scheduler = sorted(
        scheduler_events, key=lambda event: (event.timestamp_ns, event.task, event.event)
    )
    bursts = _slow_bursts(ordered_probes, slow_threshold_ms)

    return {
        "probe_count": len(ordered_probes),
        "probe_loss_count": sum(probe.rtt_ms is None for probe in ordered_probes),
        "p99_ms": _nearest_rank_p99(ordered_probes),
        "p99_state": _p99_state(ordered_probes),
        "slow_threshold_ms": slow_threshold_ms,
        "slow_probe_count": sum(_is_slow(probe, slow_threshold_ms) for probe in ordered_probes),
        "goodput_sample_count": len(ordered_goodput),
        "gotatun_counter_sample_count": len(ordered_counters),
        "scheduler_event_count": len(ordered_scheduler),
        "correlation_status": (
            "complete"
            if ordered_goodput and ordered_counters and ordered_scheduler
            else "incomplete"
        ),
        "stall_bursts": [
            _summarize_burst(burst, ordered_goodput, ordered_counters, ordered_scheduler)
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
            if matched_goodput and matched_counters and matched_scheduler
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
