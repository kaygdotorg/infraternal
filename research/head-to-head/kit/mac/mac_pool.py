#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Counterbalanced orders and pooled tables for the Mac head-to-head windows (#260, J674).

Two subcommands:

  mac_pool.py orders ENGINE...         one comma-separated Williams order per line
  mac_pool.py report BASELINE WINDOW_DIR...   pooled tables, baseline-relative

A window is one `mac-window.sh` run: every engine once, in one order, and a `rows.tsv`
(`tag<TAB>engine` per line, in run order). Across the windows of a Williams design every
engine takes every position equally often and follows every other engine equally often,
so position effects and slow drift cancel in the within-window ratios. The report is
therefore built from per-window ratios to the baseline engine, not from raw medians
alone. A difference counts only when every window agrees in sign.

The cells are `lan-<mac-tx|mac-rx>-<1|8>f`, the same names the Linux holds use for their
flow counts. Loaded p99 is the loss-aware p99: loss above 1% counts as infinity.
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

CELLS = ["lan-mac-tx-1f", "lan-mac-tx-8f", "lan-mac-rx-1f", "lan-mac-rx-8f"]
NAMES = {
    "lan-mac-tx-1f": "Mac-send 1 flow", "lan-mac-tx-8f": "Mac-send 8 flows",
    "lan-mac-rx-1f": "Mac-receive 1 flow", "lan-mac-rx-8f": "Mac-receive 8 flows",
}
# key, title, higher is better
METRICS = [
    ("gbit", "Gbit/s", True),
    ("cpu", "Mac CPU s/Gbit", False),
    ("p99", "loaded p99 ms (loss-aware)", False),
    ("rss", "Mac RSS MiB", False),
]


def williams(items: list[str]) -> list[list[str]]:
    """Return the Williams design over `items`, one order per window.

    With an even number of engines it takes n windows; with an odd number, 2n
    (the square and its mirror).
    """
    size = len(items)
    if size < 2:
        raise ValueError("a square needs at least two engines")
    first = [0]
    low, high = 1, size - 1
    while len(first) < size:
        first.append(low)
        low += 1
        if len(first) < size:
            first.append(high)
            high -= 1
    orders = [[items[(index + shift) % size] for index in first] for shift in range(size)]
    if size % 2:
        orders += [list(reversed(order)) for order in orders]
    return orders


def load(window: Path, engine: str, cell: str) -> dict[str, float] | None:
    """One case's numbers, or None when the case did not produce all three receipts."""
    base = window / engine / cell
    try:
        source = json.loads(base.with_name(base.name + ".source.json").read_text())
        probe = json.loads(base.with_name(base.name + ".probe.json").read_text())
        meta = json.loads(base.with_name(base.name + ".meta.json").read_text())
    except (OSError, ValueError):
        return None
    sent = probe.get("sent") or 1
    p99 = probe.get("loss_aware_p99_ms", probe.get("p99_ms"))
    if probe["lost"] / sent > 0.01 or p99 is None:
        p99 = float("inf")
    gbit = source["gbit_per_s"]
    cpu = meta["mac_cpu_s"] / (gbit * source["secs"]) if gbit else float("inf")
    return {"gbit": gbit, "cpu": cpu, "p99": p99, "rss": meta["footprint_mac"] / 2**20}


def balance(windows: list[Path]) -> list[str]:
    """Report how many times each engine ran in each position, from every `rows.tsv`."""
    counts: dict[str, dict[int, int]] = {}
    for window in windows:
        rows = [line.split("\t")[1] for line in (window / "rows.tsv").read_text().splitlines() if line.strip()]
        for position, engine in enumerate(rows, 1):
            counts.setdefault(engine, {}).setdefault(position, 0)
            counts[engine][position] += 1
    return [f"{engine}: " + ", ".join(f"#{p}×{n}" for p, n in sorted(by.items())) for engine, by in sorted(counts.items())]


def cell(values: list[float], fmt: str) -> str:
    """`median (min–max)` of the values, or a dash when there are none."""
    if not values:
        return "-"
    finite = [v for v in values if v != float("inf")]
    if len(finite) != len(values):
        return f"inf ({len(values) - len(finite)} of {len(values)} lossy)"
    return f"{fmt.format(statistics.median(values))} ({fmt.format(min(values))}–{fmt.format(max(values))})"


def verdict(ratios: list[float], higher_better: bool) -> str:
    """`better`, `worse` or `unclear` for a list of per-window engine/baseline ratios."""
    finite = [r for r in ratios if r == r and r != float("inf")]
    if len(finite) != len(ratios) or len(ratios) < 2:
        return "unclear"
    if all(r > 1 for r in ratios):
        return "better" if higher_better else "worse"
    if all(r < 1 for r in ratios):
        return "worse" if higher_better else "better"
    return "unclear"


def report(baseline: str, windows: list[Path]) -> str:
    """The pooled markdown tables for `windows`, relative to the `baseline` engine."""
    engines = sorted({p.name for w in windows for p in w.iterdir() if p.is_dir()})
    if baseline not in engines:
        raise SystemExit(f"baseline engine {baseline!r} not found in {[str(w) for w in windows]}")
    out = [f"Windows: {len(windows)}. Position counts: " + "; ".join(balance(windows)), ""]
    for name in CELLS:
        out += [f"### {NAMES[name]}", "", "| engine | n | " + " | ".join(t for _, t, _ in METRICS) + " | vs baseline (every window agrees) |",
                "|---|---:|" + "---:|" * len(METRICS) + "---|"]
        for engine in engines:
            rows = [(w, load(w, engine, name)) for w in windows]
            rows = [(w, r) for w, r in rows if r]
            if not rows:
                continue
            cells, notes = [], []
            for key, title, higher in METRICS:
                values = [r[key] for _, r in rows]
                cells.append(cell(values, "{:.3f}" if key in ("gbit", "cpu") else "{:.2f}"))
                if engine != baseline:
                    ratios = []
                    for w, r in rows:
                        b = load(w, baseline, name)
                        ratios.append(r[key] / b[key] if b and b[key] else float("nan"))
                    notes.append(f"{key} {verdict(ratios, higher)}")
            out.append(f"| {engine} | {len(rows)} | " + " | ".join(cells) + " | " + ("baseline" if engine == baseline else ", ".join(notes)) + " |")
        out.append("")
    return "\n".join(out)


def main() -> int:
    """Command-line entry point."""
    if len(sys.argv) >= 4 and sys.argv[1] == "report":
        print(report(sys.argv[2], [Path(a) for a in sys.argv[3:]]))
        return 0
    if len(sys.argv) >= 4 and sys.argv[1] == "orders":
        for order in williams(sys.argv[2:]):
            print(",".join(order))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
