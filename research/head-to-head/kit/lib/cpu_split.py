#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Report which CPUs a measured window actually used, by D348 group (#260, J638).

D348 gives each side two CPUs (A = 1-2, B = 3-4) and leaves 0 and 5 for
housekeeping. That contains every process, but not all kernel work. Kernel
WireGuard queues its encryption and decryption with `queue_work_on()` on a CPU
picked round-robin from `cpu_online_mask` (`wg_cpumask_next_online` in
drivers/net/wireguard/queueing.h). Those are per-CPU bound kworkers, so
cpusets, the unbound-workqueue cpumask, RPS/XPS and IRQ affinity cannot keep
them off the housekeeping CPUs. J629 measured kernel WireGuard and NetBird's
kernel mode at 46-95% busy on CPUs 0 and 5, while userspace engines stayed
at 0-5%.

The kit does not try to constrain that work: the only ways are offlining CPUs
or isolcpus, and both change the host. It measures instead. This module turns
the cpuset audit's `/proc/stat` snapshots into busy cores per group, and the
pooled report divides throughput by the total busy cores. That makes the
per-core figure fair whatever CPUs the kernel chose. Busy time is user, nice,
system, irq and softirq; steal (time the hypervisor gave to someone else) is
reported separately and never counted as the engine's work.

Usage: cpu_split.py AUDIT_DIR   (reads proc-stat.{before,after}.txt, writes cpu-split.json)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SIDE_A = (1, 2)
SIDE_B = (3, 4)
HOUSEKEEPING = (0, 5)
# /proc/stat per-CPU field order after the name.
USER, NICE, SYSTEM, IDLE, IOWAIT, IRQ, SOFTIRQ, STEAL = range(8)


def parse(text: str) -> dict[int, list[int]]:
    """Return the first eight per-CPU counters for each `cpuN` line."""
    counters: dict[int, list[int]] = {}
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0].startswith("cpu") and fields[0] != "cpu":
            counters[int(fields[0][3:])] = [int(value) for value in fields[1:9]]
    if not counters:
        raise ValueError("no per-CPU lines in /proc/stat snapshot")
    return counters


def split(before_text: str, after_text: str) -> dict[str, object]:
    """Busy percentage per CPU and busy cores per D348 group over one window."""
    before, after = parse(before_text), parse(after_text)
    busy_pct: dict[str, float] = {}
    steal_pct: dict[str, float] = {}
    softirq_pct: dict[int, float] = {}
    for cpu in sorted(after):
        delta = [new - old for new, old in zip(after[cpu], before[cpu])]
        total = sum(delta)
        if total <= 0:
            raise ValueError(f"cpu{cpu} has no elapsed ticks")
        busy = delta[USER] + delta[NICE] + delta[SYSTEM] + delta[IRQ] + delta[SOFTIRQ]
        busy_pct[str(cpu)] = round(100.0 * busy / total, 3)
        steal_pct[str(cpu)] = round(100.0 * delta[STEAL] / total, 3)
        softirq_pct[cpu] = 100.0 * delta[SOFTIRQ] / total

    def cores(group: tuple[int, ...]) -> float:
        return round(sum(busy_pct[str(cpu)] for cpu in group if str(cpu) in busy_pct) / 100.0, 4)

    groups = {"side_a": cores(SIDE_A), "side_b": cores(SIDE_B), "housekeeping": cores(HOUSEKEEPING)}
    groups["total"] = round(sum(busy_pct.values()) / 100.0, 4)
    return {
        "basis": "/proc/stat deltas over the cpuset audit window; busy = user+nice+system+irq+softirq, steal excluded",
        "groups": {"side_a": list(SIDE_A), "side_b": list(SIDE_B), "housekeeping": list(HOUSEKEEPING)},
        "per_cpu_busy_pct": busy_pct,
        "per_cpu_steal_pct": steal_pct,
        "cores_busy": groups,
        "housekeeping_softirq_pct": round(sum(softirq_pct.get(cpu, 0.0) for cpu in HOUSEKEEPING) / len(HOUSEKEEPING), 3),
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    audit = Path(sys.argv[1])
    result = split((audit / "proc-stat.before.txt").read_text(), (audit / "proc-stat.after.txt").read_text())
    (audit / "cpu-split.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
