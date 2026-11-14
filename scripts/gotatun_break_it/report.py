"""Summarize the recovery and integrity facts from one GotaTun fault case.

All timestamps use the monotonic clock. Lost probes count as infinite latency
for nearest-rank p99, and each report keeps both the injected fault duration
and the time after the fault clears until a valid reply returns.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Probe:
    """One numbered liveness probe, with `None` RTT when its reply was lost."""

    sequence: int
    sent_ns: int
    rtt_ms: float | None
    sender_stalled: bool = False


def report_case(
    *,
    case: str,
    platform: str,
    fault_started_ns: int,
    fault_cleared_ns: int | None,
    recovery_started_ns: int | None = None,
    recovery_budget_ms: float | None = None,
    observed_through_ns: int | None = None,
    probes: Sequence[Probe],
    bytes_sent: int,
    bytes_verified: int,
    integrity_ok: bool,
    bytes_stalled: int | None = None,
    manual_fixes: Sequence[str] = (),
) -> dict[str, str | int | float | bool | None | list[str]]:
    """Return one machine-readable result using shared J526 recovery definitions.

    Recovery is the first successful probe sent after `recovery_started_ns`,
    or after fault clear when no separate recovery start is supplied. This lets
    endpoint changes measure reconvergence while the changed path is active.
    `bytes_stalled` is the sender/receiver progress gap at fault-clear time;
    `bytes_unverified` records bytes whose delivery the workload did not verify.
    """
    if not case.strip():
        raise ValueError("case name must not be empty")
    if platform not in {"linux", "macos"}:
        raise ValueError("platform must be 'linux' or 'macos'")
    if fault_started_ns < 0 or (
        fault_cleared_ns is not None and fault_cleared_ns < fault_started_ns
    ):
        raise ValueError("fault timestamps must be monotonic and ordered")
    if recovery_started_ns is not None and recovery_started_ns < fault_started_ns:
        raise ValueError("recovery start must not precede the fault")
    if recovery_budget_ms is not None and (
        not isinstance(recovery_budget_ms, (int, float))
        or isinstance(recovery_budget_ms, bool)
        or not math.isfinite(recovery_budget_ms)
        or recovery_budget_ms <= 0
    ):
        raise ValueError("recovery budget must be finite and positive")
    observation_end_ns = (
        observed_through_ns if observed_through_ns is not None else fault_cleared_ns
    )
    if observation_end_ns is None:
        raise ValueError("an uncleared fault needs an observation end timestamp")
    if observation_end_ns < fault_started_ns or (
        fault_cleared_ns is not None and observation_end_ns < fault_cleared_ns
    ):
        raise ValueError("observation timestamp must follow the fault interval")
    if recovery_started_ns is not None and recovery_started_ns > observation_end_ns:
        raise ValueError("recovery start must not follow the observation end")
    if bytes_sent < 0 or bytes_verified < 0 or bytes_verified > bytes_sent:
        raise ValueError("verified bytes must be between zero and bytes sent")
    if bytes_stalled is not None and (
        type(bytes_stalled) is not int or not 0 <= bytes_stalled <= bytes_sent
    ):
        raise ValueError("stalled bytes must be between zero and bytes sent")

    ordered = sorted(probes, key=lambda probe: (probe.sent_ns, probe.sequence))
    sequences: set[int] = set()
    for probe in ordered:
        if probe.sequence < 1 or probe.sent_ns < 0:
            raise ValueError("probe sequences and monotonic timestamps must be positive")
        if probe.sequence in sequences:
            raise ValueError(f"probe sequence {probe.sequence} is repeated")
        sequences.add(probe.sequence)
        if probe.rtt_ms is not None and (not math.isfinite(probe.rtt_ms) or probe.rtt_ms < 0):
            raise ValueError("probe RTT must be finite and non-negative")

    recovery_reference_ns = (
        recovery_started_ns if recovery_started_ns is not None else fault_cleared_ns
    )
    recovery_probe = (
        next(
            (
                probe
                for probe in ordered
                if probe.sent_ns >= recovery_reference_ns and probe.rtt_ms is not None
            ),
            None,
        )
        if recovery_reference_ns is not None
        else None
    )
    recovered_at_ns = (
        recovery_probe.sent_ns + round(recovery_probe.rtt_ms * 1_000_000)
        if recovery_probe is not None
        else None
    )
    window_end_ns = recovered_at_ns if recovered_at_ns is not None else observation_end_ns
    window = [
        probe
        for probe in ordered
        if probe.sent_ns >= fault_started_ns
        and probe.sent_ns <= window_end_ns
    ]
    lost = sum(probe.rtt_ms is None for probe in window)
    p99_ms = _nearest_rank_latency(window)
    manual = list(manual_fixes)
    recovery_ms_from_reference = (
        _elapsed_ms(recovery_reference_ns, recovered_at_ns)
        if recovery_reference_ns is not None
        else None
    )
    recovery_budget_met = (
        recovery_ms_from_reference is not None
        and recovery_ms_from_reference <= recovery_budget_ms
        if recovery_budget_ms is not None
        else None
    )
    outcome = (
        "PASS"
        if recovered_at_ns is not None
        and integrity_ok
        and not manual
        and recovery_budget_met is not False
        else "FAIL"
    )

    return {
        "case": case,
        "platform": platform,
        "outcome": outcome,
        "fault_duration_ms": _elapsed_ms(fault_started_ns, fault_cleared_ns),
        "observation_duration_ms": _elapsed_ms(fault_started_ns, observation_end_ns),
        "recovery_ms_from_fault_start": _elapsed_ms(fault_started_ns, recovered_at_ns),
        "recovery_ms_from_reference": recovery_ms_from_reference,
        "recovery_ms_after_fault_cleared": (
            _elapsed_ms(fault_cleared_ns, recovered_at_ns)
            if fault_cleared_ns is not None
            and recovered_at_ns is not None
            and recovered_at_ns >= fault_cleared_ns
            else None
        ),
        "recovery_reference": (
            "explicit"
            if recovery_started_ns is not None
            else "fault_cleared" if fault_cleared_ns is not None else None
        ),
        "recovery_budget_ms": recovery_budget_ms,
        "recovery_budget_met": recovery_budget_met,
        "p99_recovery_ms": p99_ms,
        "p99_state": _p99_state(window, p99_ms),
        "recovery_probe_count": len(window),
        "recovery_probe_loss_count": lost,
        "recovery_probe_loss_pct": round(lost * 100 / len(window), 4) if window else 0.0,
        "bytes_sent": bytes_sent,
        "bytes_verified": bytes_verified,
        "bytes_stalled": bytes_stalled,
        "bytes_unverified": bytes_sent - bytes_verified,
        "integrity_ok": integrity_ok,
        "manual_fix": bool(manual),
        "manual_fix_actions": manual,
        "recovered_probe_sequence": recovery_probe.sequence if recovery_probe else None,
    }


def failed_case_report(
    *,
    case: str,
    platform: str,
    fault_started_ns: int,
    fault_cleared_ns: int | None,
    recovery_started_ns: int | None = None,
    recovery_budget_ms: float | None = None,
    observed_through_ns: int | None = None,
    probes: Sequence[Probe],
    bytes_sent: int,
    bytes_verified: int,
    bytes_stalled: int | None,
    error: str,
    manual_fixes: Sequence[str] = (),
) -> dict[str, str | int | float | bool | None | list[str]]:
    """Retain recovery and byte evidence when one side of a case cannot join.

    A live sender's atomic progress file can trail a receiver snapshot by one
    publication interval. Keep that sender value separately and use the
    receiver count as the conservative lower bound for total bytes sent.
    """
    if not error.strip():
        raise ValueError("failed case reports need a useful error")
    observed_sent = max(bytes_sent, bytes_verified)
    observed_stalled = (
        None if bytes_stalled is None else min(max(0, bytes_stalled), observed_sent)
    )
    report = report_case(
        case=case,
        platform=platform,
        fault_started_ns=fault_started_ns,
        fault_cleared_ns=fault_cleared_ns,
        recovery_started_ns=recovery_started_ns,
        recovery_budget_ms=recovery_budget_ms,
        observed_through_ns=observed_through_ns,
        probes=probes,
        bytes_sent=observed_sent,
        bytes_verified=bytes_verified,
        bytes_stalled=observed_stalled,
        integrity_ok=False,
        manual_fixes=manual_fixes,
    )
    report["error"] = error
    report["sender_progress_bytes"] = bytes_sent
    if bytes_sent < bytes_verified:
        report["progress_snapshot_skew_bytes"] = bytes_verified - bytes_sent
    return report


def _elapsed_ms(started_ns: int, ended_ns: int | None) -> float | None:
    """Convert one ordered monotonic interval to milliseconds."""
    if ended_ns is None:
        return None
    return round((ended_ns - started_ns) / 1_000_000, 4)


def _nearest_rank_latency(probes: Sequence[Probe]) -> float | None:
    """Return nearest-rank p99, with a lost reply occupying an infinite rank."""
    if not probes:
        return None
    values = sorted(
        math.inf if probe.rtt_ms is None else probe.rtt_ms for probe in probes
    )
    rank = math.ceil(0.99 * len(values))
    value = values[rank - 1]
    return value if math.isfinite(value) else None


def _p99_state(probes: Sequence[Probe], value: float | None) -> str:
    """Explain why the p99 is finite, infinite from loss, or unavailable."""
    if not probes:
        return "no_probes"
    return "finite" if value is not None else "infinite_due_to_loss"
