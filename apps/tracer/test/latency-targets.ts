/**
 * The D375 latency targets for the browser suites, and the METRIC row format they print [D375, D267].
 *
 * D375 (owner, 2026-11-09) sets every latency budget at 120 Hz, where one frame is 8.3 ms, and asks for every row to be
 * reported on every run. `scripts/latency_targets.py` holds the table and the end-of-run report; this file is its
 * TypeScript copy for the specs that measure the browser rows. `scripts/test-latency-report.py` checks that the numbers
 * here match the Python ones, so change both together.
 *
 * Use `d375Row()` to print a measured row: it decides PASS/FAIL against the gate and prints the same line shape the
 * Python report parses, tagged with the run's frame pacing (`latencyDisplay()`). The functional suite only prints rows (it never asserts speed, #314); the report at the end of
 * `scripts/verify latency` and the perf-VM suite are what gate.
 */

/** One display frame at 120 Hz, in milliseconds. */
export const FRAME_MS = 1000 / 120;
/** D375 row 1 (owner, 2026-11-21): our own work for a predicted letter, p99, in milliseconds. */
export const PREDICTED_GLYPH_WORK_MS = 4;
/** The fixed allowance D259/D267 add after a reconnect's round trips. */
export const RECONNECT_ALLOWANCE_MS = 50;
/** D41/D375: first paint on a mid-range phone stays under one second. */
export const FIRST_PAINT_MS = 1000;
/** D375: frames per second the terminal sustains under 10 MB/s of output. */
export const RENDER_FPS = 120;
/** The CPU slowdown that stands in for a mid-range phone (Chromium's own mobile preset uses the same factor). */
export const PHONE_CPU_SLOWDOWN = 4;

/**
 * The frame pacing this browser run uses, from `INFRATERNAL_LATENCY_DISPLAY`: `unthrottled` (vsync and the frame-rate
 * limit off, so a frame-bound row measures our own work; this is what gates) or `60hz` (headless Chromium's normal
 * pacing, reported beside it). `scripts/verify latency` runs the row specs once in each.
 */
export function latencyDisplay(): "unthrottled" | "60hz" {
  return process.env.INFRATERNAL_LATENCY_DISPLAY === "unthrottled" ? "unthrottled" : "60hz";
}

/**
 * The slowest round trip the test profile produces: the configured RTT plus its full jitter (0 when the delay is off).
 * Budgets written as "N round trips + X" use this, so the relay's own jitter cannot fail a row.
 */
export function roundTripBoundMs(rttMs: number): number {
  return rttMs + (rttMs === 0 ? 0 : 30);
}

/** What `d375Row()` needs to print one row. `gate` defaults to `target`; `higherIsBetter` is for frame rates. */
export interface D375Measurement {
  key:
    | "predicted_glyph"
    | "real_echo"
    | "reconnect_last_screen"
    | "reconnect_network_change"
    | "render_10mbps"
    | "first_paint_phone"
    | "real_paint_after_ws"
    | "real_echo_shell"
    | "real_typed_letter"
    | "real_flood_effect"
    | "first_paint_4g_signin"
    | "first_paint_4g_connected"
    | "first_paint_3g_signin"
    | "first_paint_3g_connected"
    | "second_burst_extra_frames";
  source: string;
  n: number;
  value: number;
  unit: "ms" | "fps" | "frames";
  target: number;
  gate?: number;
  higherIsBetter?: boolean;
  /** Print `result=REPORT` instead of PASS/FAIL: a row that is measured and shown but does not gate yet. */
  reportOnly?: boolean;
  /** A second condition the row must also meet (row 1's "letter in the first frame"); the row fails when `ok` is false. */
  condition?: { ok: boolean; note: string };
  extra?: string;
}

/** Formats one D375 row as the `METRIC name=d375_<key> ...` line the end-of-run report reads, and says if it passed. */
export function d375Row(row: D375Measurement): { line: string; passed: boolean } {
  const gate = row.gate ?? row.target;
  const within = (limit: number): boolean => (row.higherIsBetter ? row.value >= limit : row.value <= limit);
  const passed = Number.isFinite(row.value) && row.n > 0 && within(gate) && (row.condition?.ok ?? true);
  const line =
    `METRIC name=d375_${row.key} source=${row.source} display=${latencyDisplay()} n=${row.n} ` +
    `value=${row.value.toFixed(2)} unit=${row.unit} ` +
    `target=${row.target.toFixed(2)} gate=${gate.toFixed(2)} target_met=${within(row.target) ? "yes" : "no"} ` +
    `result=${row.reportOnly ? "REPORT" : passed ? "PASS" : "FAIL"}${row.extra ? ` ${row.extra}` : ""}`;
  return { line, passed };
}
