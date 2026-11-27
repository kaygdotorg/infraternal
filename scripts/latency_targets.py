#!/usr/bin/env python3
"""The D375 latency target table, its METRIC row format and the end-of-run report [D375, D296, D267].

D375 (owner, 2026-11-09) sets ten p99 targets at 120 Hz (an eleventh, the second burst, was added on 2026-11-21), where one frame is
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
  the measured value next to each target, appending the HTTP transport protocol
  label (`HTTP/2` or `HTTP/1.1`) whenever a row carries `protocol=`/`wire=`
  (#573). A row that is missing or failed makes the report exit non-zero, so a
  row cannot silently drop out of the gate.

The browser suite keeps a TypeScript copy of the same numbers in
`apps/tracer/test/latency-targets.ts`; `scripts/test-latency-report.py` checks
that the two copies agree.

How a row gates: most rows gate on their target. The own-overhead row is the
exception D375 names: its 8.3 ms target becomes the gate only once it is
reached. Until then the gate is `OWN_OVERHEAD_GATE_MS`, 12 ms since #447 round 3
(was the D296 baseline of about 25 ms). After two consecutive perf-VM runs at or
under 8.3 ms, set that constant to `FRAME_MS` in the change that records them.

Usage: `python3 scripts/latency_targets.py report <log>`.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import sys

sys.dont_write_bytecode = True

#: One display frame at 120 Hz, in milliseconds: the unit every D375 budget is written in.
FRAME_MS = 1000 / 120
#: The own-overhead row's gate until its 8.3 ms target is reached (orchestrator, #447
#: round 3). Measured unthrottled on dev-02: 8.56 ms (agent 0.56 + browser 8.00, the
#: browser p99 then the slowest of 20 keys); 12 ms leaves room for shared-VM noise and
#: halves the old 25 ms D296 baseline. Becomes FRAME_MS after two consecutive perf-VM
#: runs at or under 8.3 ms (PROCESS.md §6).
OWN_OVERHEAD_GATE_MS = 12.0
#: D375 row 1 (owner, 2026-11-21): our own work for a predicted letter, p99; the letter must also be in the first frame.
PREDICTED_GLYPH_WORK_MS = 4.0
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
    """One D375 row: its METRIC key, the owner's wording, how its target reads, and the fewest samples it may gate on.

    `min_n` keeps a p99 meaningful: below it a p99 is just the slowest few samples (J468 review). The latency profile
    measures 100 keys and 20 reconnects or pages; idle memory is read twice (no session, one quiet session).
    """

    key: str
    measure: str
    target: str
    min_n: int
    #: The display the row gates on when it is not `unthrottled`/`native`. Row 1 gates at normal 60 Hz pacing (vsync
    #: on): its target is about frames, and an unthrottled run has no frame to be in (owner, 2026-11-21).
    display: str | None = None
    #: False for a row that is measured and shown but cannot fail the run yet (`result=REPORT`).
    gating: bool = True


#: The D375 table in the owner's order. Keys are the suffix after `d375_` in METRIC lines.
ROWS = (
    Row("predicted_glyph", "Own work with prediction, and the letter in the first frame", "own work at most 4 ms; letter in the first frame after the key", 100, display="60hz"),
    Row("real_echo", "Real echo", "round trip + 16.7 ms", 100),
    Row("flood_effect", "Flood effect on typing", "at most +8.3 ms", 100),
    Row("own_overhead", "Own overhead, no network", "8.3 ms (stretch 5 ms); gate 12 ms until reached", 100),
    Row("reconnect_last_screen", "Reconnect, last screen", "8.3 ms", 20),
    Row("reconnect_resumed_link", "Reconnect, typable, resumed link", "1 round trip + 50 ms", 20),
    Row("reconnect_network_change", "Reconnect, typable, after a network change", "4 round trips + 50 ms", 20),
    Row("render_10mbps", "Rendering at 10 MB/s output", "120 fps", 100),
    Row("first_paint_phone", "First paint, mid-range phone", "under 1 s", 20),
    Row("second_burst_extra_frames", "Second burst, extra frames", "0 extra frames", 20),
    Row("idle_agent_rss", "Idle infraternal agent", "under 15 MB RSS", 2),
)


#: The rows a person typing and a person on a phone network see (#569 finding 2, #573). They are measured beside the
#: ten owner rows and shown in a second table. The old rows keep gating until these are stable.
#: `real_paint_after_ws` and `real_echo_shell` gate; the rest are reported until their fixes land (the first-paint
#: rows wait for J1069/J1100, #573; `real_typed_letter` for the predictor work, #569; `real_flood_effect` for two perf-VM runs).
EXTRA_ROWS = (
    Row("real_paint_after_ws", "Socket message to paint, real shell, overlapping typing", "8.3 ms", 100),
    Row("real_echo_shell", "Real echo, real shell, overlapping typing", "round trip + 16.7 ms", 100),
    Row("real_typed_letter", "Key to letter in its own cell, prediction on, real shell", "8.3 ms (reported)", 100, gating=False),
    Row("real_flood_effect", "Flood effect on typing, no jitter", "at most +8.3 ms (reported)", 100, gating=False),
    Row("first_paint_4g_signin", "First paint, 4G 9 Mbps/170 ms: sign-in visible", "under 1 s (reported)", 5, gating=False),
    Row("first_paint_4g_connected", "First paint, 4G 9 Mbps/170 ms: terminal connected", "reported", 5, gating=False),
    Row("first_paint_3g_signin", "First paint, fast 3G: sign-in visible", "reported", 5, gating=False),
    Row("first_paint_3g_connected", "First paint, fast 3G: terminal connected", "reported", 5, gating=False),
)
#: Proposed D81 budgets from J1321's five dev-02 windows on the J1286 release.
#: Keep the reference fixed so later reports can show whether rates grew (#602).
REMOTE_IDLE_ROWS = (
    ("remote_server_idle_zero", "Remote enabled, zero connected hosts", "CA clock check", 154),
    ("remote_server_idle_one", "Remote enabled, one connected Linux host", "CA clock check, QUIC keepalives and ACKs", 187),
)

#: Every key `row_line` accepts.
ROW_KEYS = {row.key for row in (*ROWS, *EXTRA_ROWS)} | {key for key, _, _, _ in REMOTE_IDLE_ROWS}


def round_trip_bound_ms(rtt_ms: float, jitter_ms: float) -> float:
    """The longest round trip the test profile can produce: configured RTT plus its full jitter.

    D375 writes several budgets as "N round trips + X". The latency relay varies
    each burst's round trip by up to the jitter bound, so a p99 measured through
    it is compared against the slowest round trip the profile allows, not the
    mean; otherwise the jitter alone would fail the row.
    """
    return rtt_ms + jitter_ms


def row_line(key: str, *, source: str, n: int, value: float, unit: str, target: float, gate: float | None = None,
             higher_is_better: bool = False, extra: str = "", display: str | None = None,
             report_only: bool = False) -> str:
    """Format one measured D375 row as a METRIC line and decide its result.

    `target` is the D375 number for this run (already expanded for the round trip
    where the row depends on it). `gate` is what fails the run; it defaults to the
    target and differs only for the own-overhead row. `higher_is_better` flips the
    comparison for frame rates. `extra` is appended verbatim (space-separated
    `key=value` details such as p50 or sample breakdowns). `display` tags a
    browser row with the frame pacing it ran under (`unthrottled` or `60hz`). `report_only` prints `result=REPORT`
    (measured, shown, never failing) for a row that does not gate yet.
    """
    if key not in ROW_KEYS:
        raise ValueError(f"unknown D375 row: {key}")
    gate = target if gate is None else gate

    def within(limit: float) -> bool:
        return value >= limit if higher_is_better else value <= limit

    # No samples or a non-finite value (a probe that never finished) can never pass.
    result = "PASS" if n > 0 and value == value and abs(value) != float("inf") and within(gate) else "FAIL"
    if report_only:
        result = "REPORT"
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
#: The animation-frame rate the unthrottled run must reach *while the rows are measured* (the prediction-off probe
#: run) to count: at least what a 120 Hz display gives. Below it the browser could not keep up with a 120 Hz screen
#: under the rows' own load, or the flags had no effect (headless Chromium then sits at 60 Hz), and the frame-bound
#: rows would include frame waits again while claiming not to. An idle-page rate is printed too but never gates.
UNTHROTTLED_MIN_FPS = RENDER_FPS
#: The CPU slowdown the phone first-paint row applies (Chromium's mobile preset uses the same factor).
PHONE_CPU_SLOWDOWN = 4
#: Human-readable transport protocol labels for METRIC `protocol=` / `wire=` tags (#573).
PROTOCOL_LABELS = {
    "http2": "HTTP/2",
    "h2": "HTTP/2",
    "http1": "HTTP/1.1",
    "http/1.1": "HTTP/1.1",
}


def protocol_label(fields: dict[str, str]) -> str | None:
    """Return the human-readable HTTP protocol label for a parsed METRIC line, or None when untagged.

    `first-paint-network.spec.ts` tags its rows with `protocol=http2 wire=h2` or
    `protocol=http1 wire=http/1.1` (#573). Reports use this label so every first-paint number
    states which transport protocol produced it.
    """
    raw = fields.get("protocol") or fields.get("wire")
    if not raw:
        return None
    return PROTOCOL_LABELS.get(raw.lower(), raw)


def row_measure(row: Row, fields: dict[str, str]) -> str:
    """Format a row's display name, appending its measured transport protocol when present."""
    label = protocol_label(fields)
    return f"{row.measure} ({label})" if label else row.measure


def _fields(text: str) -> dict[str, str]:
    """Split `a=1 b=2` into a dict; tokens without `=` are ignored."""
    return dict(part.split("=", 1) for part in text.split() if "=" in part)


def _worse(old: dict[str, str], new: dict[str, str]) -> bool:
    """True when `new` is the worse of two measurements of one row: a FAIL beats a PASS, then the worse value."""
    if (old.get("result") == "PASS") != (new.get("result") == "PASS"):
        return new.get("result") != "PASS"
    try:
        old_value, new_value = float(old.get("value", "nan")), float(new.get("value", "nan"))
    except ValueError:
        return True
    if new_value != new_value:
        return True
    higher_is_better = new.get("unit") == "fps"
    return new_value < old_value if higher_is_better else new_value > old_value


def parse(log_text: str) -> dict[str, dict[str, dict[str, str]]]:
    """Collect the worst METRIC line for each D375 row and display, as key=value fields.

    Returns `{row: {display: fields}}`, where display is `unthrottled`, `60hz` or
    `native` (lines without a display field). Playwright may prefix test output,
    so the pattern searches anywhere in a line. When one log measures a row more
    than once (a rerun), the worst measurement is kept, so a rerun can never hide
    an earlier FAIL, and `runs` counts how many there were.
    """
    rows: dict[str, dict[str, dict[str, str]]] = {}
    for line in log_text.splitlines():
        match = _ROW_PATTERN.search(line)
        if not match:
            continue
        fields = _fields(match.group(2))
        displays = rows.setdefault(match.group(1), {})
        display = fields.get("display", "native")
        previous = displays.get(display)
        runs = int(previous["runs"]) + 1 if previous else 1
        if previous is None or _worse(previous, fields):
            displays[display] = fields
        displays[display]["runs"] = str(runs)
    return rows


def gated_display(row: Row, entries: dict[str, dict[str, str]]) -> str | None:
    """The display whose measurement of `row` gates: the row's own (row 1 gates at 60 Hz), else unthrottled or native."""
    if row.display is not None:
        return row.display if row.display in entries else None
    return next((name for name in GATED_DISPLAYS if name in entries), None)


def frame_pacing(log_text: str) -> tuple[dict[str, float], dict[str, float]]:
    """Animation-frame rates per display: `(during_rows, idle)`.

    `during_rows` comes from `METRIC name=frame_pacing display= phase=rows fps=` (the slowest such run is kept),
    `idle` from `METRIC name=frame_pacing display= idle_fps=`. Only `during_rows` gates.
    """
    rows: dict[str, float] = {}
    idle: dict[str, float] = {}
    for line in log_text.splitlines():
        match = _PACING_PATTERN.search(line)
        if not match:
            continue
        fields = _fields(match.group(1))
        display = fields.get("display", "60hz")
        if fields.get("phase") == "rows":
            fps = float(fields.get("fps", "0"))
            rows[display] = min(fps, rows.get(display, fps))
        elif "idle_fps" in fields:
            idle[display] = float(fields["idle_fps"])
    return rows, idle


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
    def slower(old: dict[str, str] | None, new: dict[str, str]) -> dict[str, str]:
        """The worse of two measurements of one share: the higher p99 (a rerun can never hide a slow run)."""
        return new if old is None or float(new.get("p99_ms", "inf")) > float(old.get("p99_ms", "inf")) else old

    agent: dict[str, str] | None = None
    browsers: dict[str, dict[str, str]] = {}
    for line in log_text.splitlines():
        match = _PART_PATTERN.search(line)
        if not match:
            continue
        fields = _fields(match.group(2))
        if match.group(1) == "agent":
            agent = slower(agent, fields)
        else:
            display = fields.get("display", "60hz")
            browsers[display] = slower(browsers.get(display), fields)
    if agent is None:
        return []
    lines = []
    for display, browser in browsers.items():
        agent_ms, browser_ms = float(agent["p99_ms"]), float(browser["p99_ms"])
        lines.append(row_line(
            "own_overhead", source="real-agent-pty+tracer-production-build", display=display,
            n=min(int(agent["n"]), int(browser["n"])), value=agent_ms + browser_ms, unit="ms",
            target=FRAME_MS, gate=OWN_OVERHEAD_GATE_MS,
            extra=f"agent_p99_ms={agent_ms:.2f} browser_p99_ms={browser_ms:.2f} stretch_ms=5.00"))
    return lines


def report(log_text: str) -> tuple[str, bool]:
    """Render the D375 table for one run and say whether every row passed its gate.

    Each row gates on its unthrottled (browser) or native measurement; the 60 Hz
    display's value is shown beside it and never gates. Returns the markdown table
    and `True` only when all eleven rows have a gated measurement, none failed, and
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
        display = gated_display(row, entries)
        at_60 = entries.get("60hz") if row.display is None else entries.get("unthrottled")
        shown_60 = f"{at_60.get('value', '?')} {at_60.get('unit', '')}" if at_60 else "-"
        if display is None:
            passed = False
            lines.append(f"| {row.measure} | {row.target} | - | - | {shown_60} | - | MISSING |")
            continue
        unthrottled_rows |= display == "unthrottled"
        fields = entries[display]
        unit = fields.get("unit", "")
        result = fields.get("result", "FAIL")
        try:
            samples = int(fields.get("n", "0"))
        except ValueError:
            samples = 0
        if samples < row.min_n:
            result = f"FAIL (n {samples} < {row.min_n})"
        passed &= result == "PASS"
        reruns = f", worst of {fields['runs']} runs" if int(fields.get("runs", "1")) > 1 else ""
        lines.append(
            f"| {row_measure(row, fields)} | {row.target} | {fields.get('gate', '?')} {unit} | "
            f"{fields.get('value', '?')} {unit} (n={fields.get('n', '?')}{reruns}) | {shown_60} | "
            f"{fields.get('target_met', '?')} | {result} |"
        )
    lines.append("")
    lines.append("Rows a person typing, and a person on a phone network, sees (#569, #573; the rows above keep gating)")
    lines.append("")
    lines.append("| Measure | Target, p99 | Gate this run | Measured (gated) | Other display | Target met | Result |")
    lines.append("|---|---|---|---|---|---|---|")
    for row in EXTRA_ROWS:
        entries = measured.get(row.key, {})
        display = gated_display(row, entries) or next(iter(entries), None)
        if display is None:
            passed = False
            lines.append(f"| {row.measure} | {row.target} | - | - | - | - | MISSING |")
            continue
        fields = entries[display]
        unit = fields.get("unit", "")
        others = [f"{name} {entry.get('value', '?')} {entry.get('unit', '')}" for name, entry in entries.items() if name != display]
        result = fields.get("result", "FAIL")
        try:
            samples = int(fields.get("n", "0"))
        except ValueError:
            samples = 0
        if samples < row.min_n:
            result = f"FAIL (n {samples} < {row.min_n})" if row.gating else f"REPORT (n {samples} < {row.min_n})"
        # A reported row never fails the run; a gating one fails on anything but PASS.
        passed &= result == "PASS" if row.gating else not result.startswith("FAIL")
        lines.append(
            f"| {row_measure(row, fields)} | {row.target} | {fields.get('gate', '?')} {unit} | "
            f"{fields.get('value', '?')} {unit} (n={fields.get('n', '?')}) | {', '.join(others) or '-'} | "
            f"{fields.get('target_met', '?')} | {result} |"
        )
    lines.extend(("", "Remote-enabled server idle (D81, #602)", "",
                  "| Configuration | p95 activations/min | Proposed budget (activations/min) | Wakeup sources | Result |",
                  "|---|---|---|---|---|"))
    for key, measure, sources, budget in REMOTE_IDLE_ROWS:
        fields = measured.get(key, {}).get("native", {})
        present = {"value", "n"} <= fields.keys()
        value = f"{fields['value']} (n={fields['n']})" if present else "-"
        result = "REPORT" if present else "MISSING (reported)"
        lines.append(f"| {measure} | {value} | {budget} | {sources} | {result} |")
    during_rows, idle = frame_pacing(log_text)
    lines.append("")
    lines.append("Frame pacing while the rows ran (frames per second): " +
                 (", ".join(f"{name} {fps:.1f}" for name, fps in sorted(during_rows.items())) or "not measured") +
                 "; idle: " + (", ".join(f"{name} {fps:.1f}" for name, fps in sorted(idle.items())) or "not measured"))
    if unthrottled_rows and during_rows.get("unthrottled", 0.0) < UNTHROTTLED_MIN_FPS:
        passed = False
        lines.append(f"FAIL: while its rows ran, the unthrottled browser stayed under {UNTHROTTLED_MIN_FPS:.0f} fps, "
                     "so its frame-bound rows still include waits for a frame.")
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
