"""Define repeatable Linux namespace faults for the GotaTun break-it suite."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Mapping, Sequence
from typing import Any


@dataclass(frozen=True, slots=True)
class FaultCase:
    """Describe one isolated fault profile by stable name and parameters."""

    name: str
    kind: str
    value: int | float | None = None
    correlation_pct: int | None = None


def build_fault_matrix() -> tuple[FaultCase, ...]:
    """Return the Linux reliability cases required by J526 in run order."""

    return (
        FaultCase("endpoint-ip-rebind", "endpoint-ip"),
        FaultCase("nat-port-rebind", "nat-port"),
        FaultCase("loss-1pct", "loss", 1),
        FaultCase("loss-5pct", "loss", 5),
        FaultCase("loss-20pct", "loss", 20),
        FaultCase("reorder", "reorder", 25, 50),
        FaultCase("duplicate", "duplicate", 2),
        FaultCase("link-down-up", "link-down-up"),
        FaultCase("rekey-under-load", "rekey-load"),
        FaultCase("rekey-timer-expiry-under-load", "rekey-timer-load"),
        FaultCase("agent-restart", "agent-restart"),
        FaultCase("server-restart", "server-restart"),
        FaultCase("coordinator-peer-churn", "peer-churn"),
        FaultCase("mtu-change-mid-flow", "mtu-change"),
        FaultCase("peer-scale-50", "peer-scale", 50),
        FaultCase("peer-scale-200", "peer-scale", 200),
    )


def build_netem_command(
    tc: Path,
    interface: str,
    *,
    loss_pct: int | None = None,
    reorder_pct: int | None = None,
    reorder_correlation_pct: int | None = None,
    duplicate_pct: int | None = None,
) -> list[str]:
    """Build one seeded netem command limited to a suite-owned veth."""

    if interface not in {"underlay0", "underlay1"}:
        raise ValueError("netem may only alter the disposable underlay veths")
    profiles = [
        ("loss", loss_pct),
        ("reorder", reorder_pct),
        ("duplicate", duplicate_pct),
    ]
    selected = [(name, value) for name, value in profiles if value is not None]
    if len(selected) != 1:
        raise ValueError("choose exactly one loss, reorder, or duplicate profile")
    for name, value in selected:
        if type(value) is not int or not 0 <= value <= 100:
            raise ValueError(f"{name} percentage must be an integer between 0 and 100")

    name, value = selected[0]
    command = [str(tc), "qdisc", "replace", "dev", interface, "root", "netem", name, f"{value}%"]
    if name == "reorder":
        correlation = 0 if reorder_correlation_pct is None else reorder_correlation_pct
        if type(correlation) is not int or not 0 <= correlation <= 100:
            raise ValueError("reorder correlation must be an integer between 0 and 100")
        command.append(f"{correlation}%")
    elif reorder_correlation_pct is not None:
        raise ValueError("reorder correlation only applies to a reorder profile")
    command.extend(("seed", "526"))
    return command


def build_next_config_chunks(
    chunks: Sequence[Mapping[str, Any]], *, current_version: int
) -> list[dict[str, Any]]:
    """Advance a freshly compiled full coordinator snapshot past installed state."""

    if type(current_version) is not int or current_version < 1:
        raise ValueError("the installed coordinator version must be positive")
    if not chunks:
        raise ValueError("a coordinator snapshot must contain at least one chunk")
    advanced: list[dict[str, Any]] = []
    for index, chunk in enumerate(chunks):
        if chunk.get("index") != index or chunk.get("last") is not (index == len(chunks) - 1):
            raise ValueError("coordinator chunks must keep their ordered snapshot markers")
        row = deepcopy(dict(chunk))
        row["from_version"] = current_version
        row["version"] = current_version + 1
        advanced.append(row)
    return advanced


def bytes_stalled(bytes_sent: int, bytes_verified: int) -> int:
    """Count payload sent but not verified by the receiving workload at a snapshot."""

    if (
        type(bytes_sent) is not int
        or type(bytes_verified) is not int
        or bytes_sent < 0
        or bytes_verified < 0
    ):
        raise ValueError("byte counters must be non-negative integers")
    return max(0, bytes_sent - bytes_verified)
