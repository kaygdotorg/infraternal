"""Parse and summarize the ICMP samples used by the GotaTun rotation proof."""

import math
import re
from collections.abc import Sequence


_PING_REPLY = re.compile(
    r"^\[(?P<timestamp>[0-9]+(?:\.[0-9]+)?)\].*?icmp_seq=(?P<sequence>[0-9]+)"
    r".*?time[=<](?P<rtt>[0-9]+(?:\.[0-9]+)?)\s*ms(?:\s|$)"
)


def cpu_mask_for_namespace(namespace: str, side_a: str, side_b: str, housekeeping: str) -> str:
    """Assign each fixture namespace to its D348 endpoint pair or housekeeping CPUs."""
    if namespace == "nodeA":
        return side_a
    if namespace == "nodeB":
        return side_b
    return housekeeping


def cpu_scope_unit_name(namespace: str, pid: int, nonce: int) -> str:
    """Expose only the two measured endpoint sides to the D348 audit."""
    prefix = "j88i-j279" if namespace in ("nodeA", "nodeB") else "j279"
    return f"{prefix}-{namespace}-{pid}-{nonce}.scope"


def parse_ping_reply(line: str) -> tuple[float, int, float] | None:
    """Read the timestamp, sequence and round-trip time from one iputils reply."""
    match = _PING_REPLY.search(line)
    if match is None:
        return None
    return (
        float(match.group("timestamp")),
        int(match.group("sequence")),
        float(match.group("rtt")),
    )


def summarize_latency(
    expected_sequences: Sequence[int], replies: Sequence[tuple[int, float]]
) -> dict[str, float | int | str | None]:
    """Summarize one probe window, making its p99 infinite whenever a probe was lost."""
    expected = tuple(expected_sequences)
    if len(set(expected)) != len(expected) or any(sequence < 1 for sequence in expected):
        raise ValueError("expected probe sequences must be unique and positive")

    expected_set = set(expected)
    latencies: dict[int, float] = {}
    for sequence, latency_ms in replies:
        if sequence not in expected_set:
            raise ValueError(f"reply sequence {sequence} was not sent in this window")
        if sequence in latencies:
            raise ValueError(f"probe sequence {sequence} replied more than once")
        if latency_ms < 0:
            raise ValueError("probe latency cannot be negative")
        latencies[sequence] = latency_ms

    ordered = sorted(latencies.values())
    sent = len(expected)
    received = len(ordered)
    lost = sent - received
    loss_aware = [*ordered, *([math.inf] * lost)]
    p99_rank = _nearest_rank(loss_aware, 0.99) if loss_aware else None
    p99_state = (
        "no_probes"
        if p99_rank is None
        else "finite"
        if math.isfinite(p99_rank)
        else "infinite_due_to_loss"
    )
    return {
        "sent": sent,
        "received": received,
        "lost": lost,
        "loss_pct": round(lost * 100 / sent, 4) if sent else 0.0,
        "p50_ms": _nearest_rank(ordered, 0.50) if ordered else None,
        "p99_loss_aware_ms": p99_rank if p99_state == "finite" else None,
        "p99_state": p99_state,
    }


def _nearest_rank(values: Sequence[float], percentile: float) -> float:
    """Return the D348 nearest-rank percentile from an already sorted sample."""
    return values[math.ceil(percentile * len(values)) - 1]
