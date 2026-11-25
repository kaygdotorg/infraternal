/**
 * Browser-side cost of a reattach after a gap: raw replay versus Snapshot (#583, D13, D381).
 *
 * `scripts/bench-reattach-backlog.py --save DIR` keeps what one reattach received for each backlog size: either the
 * raw replay (`raw-<size>.bin`), or a Snapshot (`snapshot-<size>.bin`) plus the raw tail after it (`tail-<size>.bin`).
 * This script feeds those bytes to the pinned WASM terminal the tracer ships, the same way `terminal.ts` does, and
 * times the parse:
 *
 * - raw: every byte is written to the device's terminal, one 64 KiB frame at a time;
 * - snapshot: the device's history is kept with `keepHistoryVt` (#569), the terminal is replaced, and the kept rows,
 *   the repaint without its leading reset, and the tail are written.
 *
 * Both start from the same device state: an 80 × 24 terminal with the tracer's default scrollback that already shows
 * 2,000 earlier rows. When a size has both kinds (one directory from a binary that replays, another from one that
 * sends a Snapshot), the final screens are compared row by row, cursor included, and any difference fails the run.
 * The output is one JSON line per size and kind. It measures parsing only, not drawing: the renderer draws one frame
 * per animation frame either way.
 *
 * Usage (on the perf VM, through perf-run): `bun apps/tracer/perf/reattach-parse.bench.ts DIR [DIR...]`.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { Ghostty, type GhosttyTerminal } from "../vendor/ghostty-web";
import { concatBytes, hasKeepableContent, keepHistoryVt, withoutLeadingReset } from "../src/history-keep";

/** The pinned WASM terminal the tracer ships. */
const ghostty = await Ghostty.load(resolve(import.meta.dir, "../vendor/ghostty-web/dist/ghostty-vt.wasm"));
/** The tracer's default scrollback setting (`terminal.ts`), passed the same way. */
const DEVICE = { scrollbackLimit: 10_000 };
/** The tracer writes each received Output frame on its own; the agent sends at most 64 KiB per frame. */
const FRAME = 64 * 1024;
/** Timed repeats per file; the median is reported. */
const REPEATS = 5;
/** Earlier output the device already shows before the gap. */
const EARLIER = new TextEncoder().encode(Array.from({ length: 2000 }, (_, n) => `earlier ${n}\r\n`).join(""));

/** A device terminal in the state it had before the gap. */
function device(): GhosttyTerminal {
  const terminal = ghostty.createTerminal(80, 24, DEVICE);
  terminal.write(EARLIER);
  return terminal;
}

/** Writes `bytes` in tracer-sized frames. */
function writeFrames(terminal: GhosttyTerminal, bytes: Uint8Array): void {
  for (let offset = 0; offset < bytes.byteLength; offset += FRAME) terminal.write(bytes.subarray(offset, offset + FRAME));
}

/** The visible rows as text, trailing blanks cut, plus the cursor position. */
function screen(terminal: GhosttyTerminal): string[] {
  terminal.update();
  const cells = terminal.getViewport();
  const rows: string[] = [];
  for (let row = 0; row < terminal.rows; row += 1) {
    const line = cells.slice(row * terminal.cols, (row + 1) * terminal.cols);
    rows.push(line.filter((cell) => cell.width !== 0).map((cell) => (cell.codepoint > 32 ? String.fromCodePoint(cell.codepoint) : " ")).join("").trimEnd());
  }
  const cursor = terminal.getCursor();
  rows.push(`cursor ${cursor.x},${cursor.y}`);
  return rows;
}

/** Applies a raw replay; returns the elapsed parse time and the final screen. */
function raw(bytes: Uint8Array): { ms: number; screen: string[] } {
  const terminal = device();
  const started = performance.now();
  writeFrames(terminal, bytes);
  terminal.update();
  const ms = performance.now() - started;
  const result = screen(terminal);
  terminal.free();
  return { ms, screen: result };
}

/** Applies a Snapshot and its tail the way `terminal.ts` does; returns the elapsed time and the final screen. */
function snapshot(repaint: Uint8Array, tail: Uint8Array): { ms: number; screen: string[] } {
  const old = device();
  const started = performance.now();
  const kept = hasKeepableContent(old) ? keepHistoryVt(old, { skipped: true, previousScreen: undefined }) : undefined;
  old.free();
  const terminal = ghostty.createTerminal(80, 24, DEVICE);
  terminal.write(kept ? concatBytes(kept.bytes, withoutLeadingReset(repaint)) : repaint);
  writeFrames(terminal, tail);
  terminal.update();
  const ms = performance.now() - started;
  const result = screen(terminal);
  terminal.free();
  return { ms, screen: result };
}

/** Median of a non-empty list. */
function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)] ?? Number.NaN;
}

/** Times one kind for one size and prints its JSON line; returns the final screen. */
function measure(kind: string, size: number, run: () => { ms: number; screen: string[] }, bytes: number): string[] {
  const times: number[] = [];
  let last: string[] = [];
  for (let repeat = 0; repeat < REPEATS; repeat += 1) {
    const { ms, screen: rows } = run();
    times.push(ms);
    last = rows;
  }
  console.log(JSON.stringify({ kind, size, bytes, parse_p50_ms: Number(median(times).toFixed(2)), parse_max_ms: Number(Math.max(...times).toFixed(2)) }));
  return last;
}

/** The first final screen seen for each backlog size, to compare the other kind against. */
const screens = new Map<string, string[]>();
/** Sizes whose raw and Snapshot screens differed; any makes the run fail. */
let mismatches = 0;
for (const directory of process.argv.slice(2)) {
  for (const name of readdirSync(directory).sort()) {
    const match = /^(raw|snapshot)-(\d+)\.bin$/.exec(name);
    if (!match) continue;
    const size = Number(match[2]);
    const bytes = new Uint8Array(readFileSync(join(directory, name)));
    const rows = match[1] === "raw"
      ? measure("raw", size, () => raw(bytes), bytes.byteLength)
      : (() => {
          const tail = new Uint8Array(readFileSync(join(directory, `tail-${size}.bin`)));
          return measure("snapshot", size, () => snapshot(bytes, tail), bytes.byteLength + tail.byteLength);
        })();
    const key = String(size);
    const other = screens.get(key);
    if (other === undefined) {
      screens.set(key, rows);
    } else if (other.join("\n") !== rows.join("\n")) {
      mismatches += 1;
      console.log(JSON.stringify({ size, screen_match: false, first: other, second: rows }));
    } else {
      console.log(JSON.stringify({ size, screen_match: true }));
    }
  }
}
if (mismatches > 0) process.exit(1);
