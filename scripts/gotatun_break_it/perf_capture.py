"""Attach a scheduler trace to the two GotaTun processes in a loaded window."""

# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Sequence


def build_scheduler_record_command(
    perf: Path, output: Path, agent_tids: Sequence[int]
) -> list[str]:
    """Build a monotonic tracepoint capture filtered to every GotaTun thread."""
    tids = tuple(agent_tids)
    if len(tids) < 2 or any(type(tid) is not int or tid < 1 for tid in tids):
        raise ValueError("scheduler capture needs at least two positive GotaTun thread IDs")
    if len(set(tids)) != len(tids):
        raise ValueError("scheduler capture needs distinct GotaTun thread IDs")
    switch_filter = " || ".join(
        f"prev_pid == {tid} || next_pid == {tid}" for tid in tids
    )
    wake_filter = " || ".join(f"pid == {tid}" for tid in tids)
    return [
        str(perf),
        "record",
        "--all-cpus",
        "--event",
        "sched:sched_switch",
        "--filter",
        switch_filter,
        "--event",
        "sched:sched_wakeup",
        "--filter",
        wake_filter,
        "--event",
        "sched:sched_wakeup_new",
        "--filter",
        wake_filter,
        "--compression-level=1",
        "--clockid",
        "mono",
        "--output",
        str(output),
    ]


def read_agent_manifest(
    path: Path,
) -> tuple[tuple[int, int], tuple[int, ...], tuple[int, ...] | None]:
    """Read the process pair and its start and optional end thread snapshots."""
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read GotaTun process and thread manifest at {path}") from error
    if not isinstance(manifest, dict):
        raise ValueError("GotaTun process and thread manifest must be a JSON object")
    pids = manifest.get("pids")
    tids = manifest.get("tids")
    if (
        not isinstance(pids, list)
        or len(pids) != 2
        or any(type(pid) is not int or pid < 1 for pid in pids)
        or pids[0] == pids[1]
    ):
        raise ValueError("GotaTun process manifest must contain two distinct positive process IDs")
    if (
        not isinstance(tids, list)
        or len(tids) < 2
        or any(type(tid) is not int or tid < 1 for tid in tids)
        or len(set(tids)) != len(tids)
        or not set(pids).issubset(tids)
    ):
        raise ValueError("GotaTun thread manifest must contain distinct positive TIDs for both processes")
    tids_after = manifest.get("tids_after")
    if tids_after is not None and (
        not isinstance(tids_after, list)
        or len(tids_after) < 2
        or any(type(tid) is not int or tid < 1 for tid in tids_after)
        or len(set(tids_after)) != len(tids_after)
        or not set(pids).issubset(tids_after)
    ):
        raise ValueError("GotaTun final thread manifest must contain distinct positive TIDs for both processes")
    return (
        (pids[0], pids[1]),
        tuple(sorted(tids)),
        None if tids_after is None else tuple(sorted(tids_after)),
    )


def read_agent_pids(path: Path) -> tuple[int, int]:
    """Read the validated process pair published by the real mesh fixture."""
    pids, _, _ = read_agent_manifest(path)
    return pids


def read_agent_tids(path: Path) -> tuple[int, ...]:
    """Read every product thread ID used to scope the scheduler trace."""
    _, tids, _ = read_agent_manifest(path)
    return tids


def main() -> None:
    """Replace this wrapper with `perf` after validating the complete TID manifest."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--perf", required=True, type=Path)
    parser.add_argument("--agent-pids", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    if not arguments.perf.is_file() or not os.access(arguments.perf, os.X_OK):
        parser.error(f"perf is not executable: {arguments.perf}")
    command = build_scheduler_record_command(
        arguments.perf,
        arguments.output,
        read_agent_tids(arguments.agent_pids),
    )
    os.execv(command[0], command)


if __name__ == "__main__":
    main()
