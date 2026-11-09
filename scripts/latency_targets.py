#!/usr/bin/env python3
"""The D375 latency target table, its METRIC row format and the end-of-run report [D375, D296, D267].

D375 (owner, 2026-11-09) sets ten p99 targets at 120 Hz, where one frame is
8.3 ms, and asks for every row to be reported on every run. This module is the
single Python copy of that table:

- `ROWS` lists the rows in the owner's order, with each target and how it gates;
- `row_line()` formats one measured row as a `METRIC name=d375_<key> ...` line, so
  every producer (the native agent probe, the tracer browser suite) prints the
  same shape;
- `compose_own_overhead()` adds the agent's and the browser's measured shares
  into the own-overhead row, since no single probe sees both;
- browser rows carry a `display=` field: the profile runs them unthrottled
  (the gate) and paced to a 60 Hz display (reported beside it), and checks
  with `frame_pacing` that the unthrottled run really ran above 60 Hz;
- `report()` reads a whole `scripts/verify latency` log and prints the table with
  the measured value next to each target. A row that is missing or failed makes
  the report exit non-zero, so a row cannot silently drop out of the gate.

The browser suite keeps a TypeScript copy of the same numbers in
`apps/tracer/test/latency-targets.ts`; `scripts/test-latency-report.py` checks
that the two copies agree.

How a row gates: most rows gate on their target. The own-overhead row is the
exception D375 names: its 8.3 ms target becomes the gate only once a run reaches
it. Until then the gate is "no worse than today's baseline", about 25 ms (D296),
held in `OWN_OVERHEAD_BASELINE_MS`. When a perf-VM run first meets 8.3 ms, lower
that constant to the target in the same change that records the run.

Usage: `python3 scripts/latency_targets.py report <log>`.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import sys

sys.dont_write_bytecode = True

#: One display frame at 120 Hz, in milliseconds: the unit every D375 budget is written in.
FRAME_MS = 1000 / 120
#: Today's own-overhead baseline (D296: the shipping terminal's pooled echo p99 on
#: the perf VM, about 25 ms). It is the overhead row's gate until 8.3 ms is reached.
OWN_OVERHEAD_BASELINE_MS = 25.0
#: The fixed allowance D259/D267 add after the round trips of a reconnect.
RECONNECT_ALLOWANCE_MS = 50.0
#: D41/D375: an idle infraternal agent stays under 15 MB resident (decimal megabytes).
IDLE_AGENT_RSS_MB = 15.0
#: D41/D375: first paint on a mid-range phone stays under one second.
FIRST_PAINT_MS = 1000.0
#: D375: sustained frame rate while the terminal receives 10 MB/s of output.
RENDER_FPS = 120.0


@dataclass(frozen=True)
class Row:
    """One D375 row: its METRIC key, the owner's wording and how its target reads."""

    key: str
    measure: str
    target: str


#: The D375 table in the owner's order. Keys are the suffix after `d375_` in METRIC lines.
ROWS = (
    Row("predicted_glyph", "Key to letter on screen, with prediction", "8.3 ms"),
    Row("real_echo", "Real echo", "round trip + 16.7 ms"),
    Row("flood_effect", "Flood effect on typing", "at most +8.3 ms"),
    Row("own_overhead", "Own overhead, no network", "8.3 ms (stretch 5 ms); gate 25 ms until reached"),
    Row("reconnect_last_screen", "Reconnect, last screen", "8.3 ms"),
    Row("reconnect_resumed_link", "Reconnect, typable, resumed link", "1 round trip + 50 ms"),
    Row("reconnect_network_change", "Reconnect, typable, after a network change", "4 round trips + 50 ms"),
    Row("render_10mbps", "Rendering at 10 MB/s output", "120 fps"),
    Row("first_paint_phone", "First paint, mid-range phone", "under 1 s"),
    Row("idle_agent_rss", "Idle infraternal agent", "under 15 MB RSS"),
)


def round_trip_bound_ms(rtt_ms: float, jitter_ms: float) -> float:
    """The longest round trip the test profile can produce: configured RTT plus its full jitter.

    D375 writes several budgets as "N round trips + X". The latency relay varies
    each burst's round trip by up to the jitter bound, so a p99 measured through
    it is compared against the slowest round trip the profile allows, not the
    mean; otherwise the jitter alone would fail the row.
    """
    return rtt_ms + jitter_ms


def row_line(key: str, *, source: str, n: int, value: float, unit: str, target: float, gate: float | None = None,
             higher_is_better: bool = False, extra: str = "", display: str | None = None) -> str:
    """Format one measured D375 row as a METRIC line and decide its result.

    `target` is the D375 number for this run (already expanded for the round trip
    where the row depends on it). `gate` is what fails the run; it defaults to the
    target and differs only for the own-overhead row. `higher_is_better` flips the
    comparison for frame rates. `extra` is appended verbatim (space-separated
    `key=value` details such as p50 or sample breakdowns). `display` tags a
    browser row with the frame pacing it ran under (`unthrottled` or `60hz`).
    """
    if key not in {row.key for row in ROWS}:
        raise ValueError(f"unknown D375 row: {key}")
    gate = target if gate is None else gate

    def within(limit: float) -> bool:
        return value >= limit if higher_is_better else value <= limit

    # No samples or a non-finite value (a probe that never finished) can never pass.
    result = "PASS" if n > 0 and value == value and abs(value) != float("inf") and within(gate) else "FAIL"
    met = "yes" if within(target) else "no"
    tail = f" {extra}" if extra else ""
    shown = f" display={display}" if display else ""
    return (f"METRIC name=d375_{key} source={source}{shown} n={n} value={value:.2f} unit={unit} "
            f"target={target:.2f} gate={gate:.2f} target_met={met} result={result}{tail}")


_ROW_PATTERN = re.compile(r"METRIC name=d375_(\w+) (.*)$")
_PACING_PATTERN = re.compile(r"METRIC name=frame_pacing (.*)$")

#: The browser rows run twice (D375 round 2): with the display cap lifted, which is what gates, and paced to a 60 Hz
#: display, which is reported beside it. Native rows have no display and gate as they are.
GATED_DISPLAYS = ("unthrottled", "native")
#: The idle animation-frame rate the unthrottled run must exceed to count as unthrottled. Headless Chromium paces
#: frames at 60 Hz; a run whose flags had no effect sits there, and its frame-bound rows would then measure the
#: wait for a 60 Hz frame again while claiming not to.
UNTHROTTLED_MIN_FPS = 70.0


def _fields(text: str) -> dict[str, str]:
    """Split `a=1 b=2` into a dict; tokens without `=` are ignored."""
    return dict(part.split("=", 1) for part in text.split() if "=" in part)


def parse(log_text: str) -> dict[str, dict[str, dict[str, str]]]:
    """Collect the last METRIC line for each D375 row and display, as key=value fields.

    Returns `{row: {display: fields}}`, where display is `unthrottled`, `60hz` or
    `native` (lines without a display field). Playwright may prefix test output,
    so the pattern searches anywhere in a line. A later line for the same row
    and display replaces an earlier one, so a rerun inside one log reports its
    final value.
    """
    rows: dict[str, dict[str, dict[str, str]]] = {}
    for line in log_text.splitlines():
        match = _ROW_PATTERN.search(line)
        if not match:
            continue
        fields = _fields(match.group(2))
        rows.setdefault(match.group(1), {})[fields.get("display", "native")] = fields
    return rows


def frame_pacing(log_text: str) -> dict[str, float]:
    """The idle animation-frame rate each browser display measured (`METRIC name=frame_pacing display= idle_fps=`)."""
    rates: dict[str, float] = {}
    for line in log_text.splitlines():
        match = _PACING_PATTERN.search(line)
        if match:
            fields = _fields(match.group(1))
            rates[fields.get("display", "60hz")] = float(fields.get("idle_fps", "0"))
    return rates


_PART_PATTERN = re.compile(r"METRIC name=own_overhead_(agent|browser) (.*)$")


def compose_own_overhead(log_text: str) -> list[str]:
    """Build the own-overhead row from its measured shares, one line per browser display.

    No single probe sees all of our own work: the native probe measures the
    real agent and PTY with the relay delay at 0 (`own_overhead_agent`), and the
    browser suite measures the browser's spans around the network
    (`own_overhead_browser`: keydown to socket send, plus echo arrival to
    paint). Each row is the agent p99 plus that display's browser p99, which can
    only overstate the p99 of the combined path, so a pass is never optimistic.
    Returns no lines while either share is missing.
    """
    agent: dict[str, str] | None = None
    browsers: dict[str, dict[str, str]] = {}
    for line in log_text.splitlines():
        match = _PART_PATTERN.search(line)
        if not match:
            continue
        fields = _fields(match.group(2))
        if match.group(1) == "agent":
            agent = fields
        else:
            browsers[fields.get("display", "60hz")] = fields
    if agent is None:
        return []
    lines = []
    for display, browser in browsers.items():
        agent_ms, browser_ms = float(agent["p99_ms"]), float(browser["p99_ms"])
        lines.append(row_line(
            "own_overhead", source="real-agent-pty+tracer-production-build", display=display,
            n=min(int(agent["n"]), int(browser["n"])), value=agent_ms + browser_ms, unit="ms",
            target=FRAME_MS, gate=OWN_OVERHEAD_BASELINE_MS,
            extra=f"agent_p99_ms={agent_ms:.2f} browser_p99_ms={browser_ms:.2f} stretch_ms=5.00"))
    return lines


def report(log_text: str) -> tuple[str, bool]:
    """Render the D375 table for one run and say whether every row passed its gate.

    Each row gates on its unthrottled (browser) or native measurement; the 60 Hz
    display's value is shown beside it and never gates. Returns the markdown table
    and `True` only when all ten rows have a gated measurement, none failed, and
    the unthrottled run really ran above 60 Hz. Missing rows are listed as
    MISSING: a producer that stopped printing its row must fail the gate rather
    than vanish from the report.
    """
    measured = parse("\n".join([log_text, *compose_own_overhead(log_text)]))
    lines = [
        "| Measure | Target, p99 | Gate this run | Measured (gated) | 60 Hz display | Target met | Result |",
        "|---|---|---|---|---|---|---|",
    ]
    passed = True
    unthrottled_rows = False
    for row in ROWS:
        entries = measured.get(row.key, {})
        display = next((name for name in GATED_DISPLAYS if name in entries), None)
        at_60 = entries.get("60hz")
        shown_60 = f"{at_60.get('value', '?')} {at_60.get('unit', '')}" if at_60 else "-"
        if display is None:
            passed = False
            lines.append(f"| {row.measure} | {row.target} | - | - | {shown_60} | - | MISSING |")
            continue
        unthrottled_rows |= display == "unthrottled"
        fields = entries[display]
        unit = fields.get("unit", "")
        result = fields.get("result", "FAIL")
        passed &= result == "PASS"
        lines.append(
            f"| {row.measure} | {row.target} | {fields.get('gate', '?')} {unit} | "
            f"{fields.get('value', '?')} {unit} (n={fields.get('n', '?')}) | {shown_60} | "
            f"{fields.get('target_met', '?')} | {result} |"
        )
    rates = frame_pacing(log_text)
    lines.append("")
    lines.append("Frame pacing (idle animation frames per second): " +
                 (", ".join(f"{name} {fps:.1f}" for name, fps in sorted(rates.items())) or "not measured"))
    if unthrottled_rows and rates.get("unthrottled", 0.0) <= UNTHROTTLED_MIN_FPS:
        passed = False
        lines.append(f"FAIL: the unthrottled run did not run above {UNTHROTTLED_MIN_FPS:.0f} fps, so its frame-bound "
                     "rows still include the wait for a 60 Hz frame.")
    return "\n".join(lines), passed


def main(argv: list[str]) -> int:
    """CLI entry: `report <log>` prints the table and exits 1 when a row is missing or failed."""
    if len(argv) != 3 or argv[1] != "report":
        print("usage: latency_targets.py report <log>", file=sys.stderr)
        return 2
    with open(argv[2], encoding="utf-8", errors="replace") as handle:
        table, passed = report(handle.read())
    print("\nD375 latency targets (one frame = 8.3 ms at 120 Hz)\n")
    print(table)
    print(f"\nD375 REPORT result={'PASS' if passed else 'FAIL'}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
