#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Capture peer-count RSS and kernel memory evidence for the #260 matrix."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


WIREGUARD_PEER_CACHE = re.compile(r"^(?:wg|wireguard)_peer$")


def parse_slabinfo(text: str) -> dict[str, Any]:
    """Return object totals for WireGuard peer-object caches only."""
    caches = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4 or not WIREGUARD_PEER_CACHE.match(fields[0]):
            continue
        try:
            active, objects, size = map(int, fields[1:4])
        except ValueError:
            continue
        caches.append({
            "name": fields[0],
            "active_objects": active,
            "total_objects": objects,
            "object_size_bytes": size,
            "allocated_bytes": objects * size,
        })
    return {
        "caches": caches,
        "named_cache_bytes": sum(cache["allocated_bytes"] for cache in caches) if caches else None,
    }


def parse_meminfo(text: str) -> dict[str, int]:
    """Read relevant kernel memory counters in bytes."""
    output: dict[str, int] = {}
    wanted = {"Slab", "SReclaimable", "SUnreclaim", "MemAvailable"}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0].rstrip(":") not in wanted:
            continue
        try:
            value = int(fields[1])
        except ValueError:
            continue
        output[fields[0].rstrip(":")] = value * 1024 if len(fields) > 2 and fields[2] == "kB" else value
    return output


def parse_kib_field(text: str, name: str) -> int | None:
    """Read one Linux memory field whose value is expressed in KiB."""
    prefix = f"{name}:"
    for line in text.splitlines():
        if not line.startswith(prefix):
            continue
        fields = line.split()
        if len(fields) < 2:
            return None
        try:
            return int(fields[1])
        except ValueError:
            return None
    return None


def capture_process_memory(
    proc: dict[str, Any], raw_dir: Path | None, peers: int, state: str
) -> tuple[list[dict[str, Any]], int | None, int | None, str]:
    """Pair each selected process's VmRSS and smaps_rollup PSS with raw evidence."""
    entries = proc.get("procs")
    if not isinstance(entries, list) or not entries:
        return [], None, None, "unavailable: proc-mem returned no selected process rows"

    records: list[dict[str, Any]] = []
    for entry in entries:
        try:
            pid = int(entry["pid"])
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError("proc-mem returned a process row without a usable PID") from error
        status_path = Path(f"/proc/{pid}/status")
        smaps_path = Path(f"/proc/{pid}/smaps_rollup")
        try:
            status_raw = status_path.read_text(encoding="utf-8", errors="replace")
            smaps_raw = smaps_path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            raise RuntimeError(f"could not capture resident memory for PID {pid}: {error}") from error
        vmrss_kb = parse_kib_field(status_raw, "VmRSS")
        pss_kb = parse_kib_field(smaps_raw, "Pss")
        if vmrss_kb is None or pss_kb is None:
            raise RuntimeError(f"PID {pid} lacks VmRSS or smaps_rollup Pss evidence")

        status_artifact = None
        smaps_artifact = None
        if raw_dir is not None:
            raw_dir.mkdir(parents=True, exist_ok=True)
            stem = f"process-{peers}-{state}-{pid}"
            status_file = raw_dir / f"{stem}-status.txt"
            smaps_file = raw_dir / f"{stem}-smaps_rollup.txt"
            status_file.write_text(status_raw, encoding="utf-8")
            smaps_file.write_text(smaps_raw, encoding="utf-8")
            status_artifact = str(status_file)
            smaps_artifact = str(smaps_file)

        records.append({
            "pid": pid,
            "comm": entry.get("comm"),
            "rss_kb": vmrss_kb,
            "pss_kb": pss_kb,
            "proc_mem_reported_rss_kb": entry.get("rss_kb"),
            "proc_mem_reported_pss_kb": entry.get("pss_kb"),
            "status_raw_path": status_artifact,
            "smaps_rollup_raw_path": smaps_artifact,
        })

    return (
        records,
        sum(record["rss_kb"] for record in records),
        sum(record["pss_kb"] for record in records),
        "captured: VmRSS from /proc/PID/status and Pss from /proc/PID/smaps_rollup",
    )


def snapshot(args: argparse.Namespace) -> dict[str, Any]:
    """Capture current process RSS plus labeled slab and meminfo deltas."""
    slab_raw = Path("/proc/slabinfo").read_text(encoding="utf-8", errors="replace")
    meminfo_raw = Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace")
    slab = parse_slabinfo(slab_raw)
    meminfo = parse_meminfo(meminfo_raw)
    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8")) if args.baseline else None
    proc = json.loads(Path(args.process_memory).read_text(encoding="utf-8")) if args.process_memory else {}
    raw_dir = Path(args.raw_dir) if args.raw_dir else None

    if args.engine == "kernel-plain":
        process_records = proc.get("procs", []) if isinstance(proc.get("procs", []), list) else []
        process_rss_kb = None
        process_pss_kb = None
        process_memory_status = "not applicable: kernel WireGuard peer state is not a userspace process"
    elif proc:
        process_records, process_rss_kb, process_pss_kb, process_memory_status = capture_process_memory(
            proc, raw_dir, args.peers, getattr(args, "state", "idle")
        )
    else:
        process_records = []
        process_rss_kb = None
        process_pss_kb = None
        process_memory_status = "not applicable: baseline was captured before the engine started"

    if args.engine == "kernel-plain":
        baseline_slab = baseline.get("slabinfo", {}).get("named_cache_bytes") if baseline else None
        named_delta = slab["named_cache_bytes"] - baseline_slab if slab["named_cache_bytes"] is not None and baseline_slab is not None else None
        baseline_mem = baseline.get("meminfo", {}).get("Slab") if baseline else None
        meminfo_delta = meminfo.get("Slab", 0) - baseline_mem if baseline_mem is not None else None
        if named_delta is not None:
            kernel_bytes = named_delta
            basis = "delta of WireGuard-named /proc/slabinfo caches from pre-engine baseline"
        else:
            kernel_bytes = meminfo_delta
            basis = "system-wide /proc/meminfo Slab delta from pre-engine baseline; not per-peer attributed"
    else:
        kernel_bytes = None
        named_delta = None
        meminfo_delta = None
        basis = "peer state is in the userspace engine; kernel peer cache is not applicable"

    result = {
        "schema_version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "measurement_state": getattr(args, "state", "idle"),
        "engine": args.engine,
        "configured_peers_per_endpoint": args.peers,
        "userspace_rss_kb": process_rss_kb,
        "userspace_rss_mib": process_rss_kb / 1024 if process_rss_kb is not None else None,
        "userspace_pss_kb": process_pss_kb,
        "userspace_process_memory_status": process_memory_status,
        "userspace_process_memory_method": {
            "rss": "/proc/<pid>/status VmRSS, KiB",
            "pss": "/proc/<pid>/smaps_rollup Pss, KiB",
            "aggregation": "sum over the selected endpoint process trees",
        },
        "kernel_peer_memory_bytes": kernel_bytes,
        "kernel_peer_memory_basis": basis,
        "named_wireguard_slab_delta_bytes": named_delta,
        "system_wide_meminfo_slab_delta_bytes": meminfo_delta,
        "slabinfo": slab,
        "meminfo": meminfo,
        "processes": process_records,
    }
    if raw_dir is not None:
        raw_dir.mkdir(parents=True, exist_ok=True)
        state = getattr(args, "state", "idle")
        (raw_dir / f"slabinfo-{args.peers}-{state}.txt").write_text(slab_raw, encoding="utf-8")
        (raw_dir / f"meminfo-{args.peers}-{state}.txt").write_text(meminfo_raw, encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, choices=["kernel-plain", "wireguard-go", "gotatun"])
    parser.add_argument("--peers", required=True, type=int)
    parser.add_argument("--state", choices=["baseline", "idle", "loaded"], default="idle",
                        help="whether this is the pre-engine baseline, settled idle state, or active-load sample")
    parser.add_argument("--baseline")
    parser.add_argument("--process-memory")
    parser.add_argument("--raw-dir")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = snapshot(args)
    Path(args.output).write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
