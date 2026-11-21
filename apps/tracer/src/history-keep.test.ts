/**
 * A host repaint keeps the device's scrollback (#569, D381, D130).
 *
 * Drives the pinned WASM terminal, the same artifact the tracer ships, through the exact sequence `terminal.ts` runs
 * for a Snapshot: read the old terminal, reset it, write the kept history, then the repaint without its leading reset.
 */
import { describe, expect, test } from "bun:test";
import { resolve } from "node:path";
import { Ghostty, type GhosttyTerminal } from "../vendor/ghostty-web";
import {
  concatBytes,
  hasKeepableContent,
  keepHistoryVt,
  SKIPPED_OUTPUT_MARKER,
  withoutLeadingReset,
} from "./history-keep";

/** The pinned WASM terminal the tracer ships. */
const WASM = resolve(import.meta.dir, "../vendor/ghostty-web/dist/ghostty-vt.wasm");
/** The loaded terminal engine all tests share. */
const ghostty = await Ghostty.load(WASM);
/** The pinned build keeps this many bytes of history by default; tests that count thousands of rows lift it. */
const LARGE = { scrollbackLimit: 10_000_000 };
/** Encodes the fake host repaints the tests write. */
const encoder = new TextEncoder();

/** The text of every row, history first, then the screen, with trailing blanks cut. */
function allRows(terminal: GhosttyTerminal): string[] {
  const rows: string[] = [];
  const text = (cells: { codepoint: number; width: number }[]): string =>
    cells.filter((cell) => cell.width !== 0).map((cell) => (cell.codepoint > 32 ? String.fromCodePoint(cell.codepoint) : " ")).join("").trimEnd();
  for (let offset = 0; offset < terminal.getScrollbackLength(); offset += 1) rows.push(text(terminal.getScrollbackLine(offset) ?? []));
  terminal.update();
  const cells = terminal.getViewport();
  for (let row = 0; row < terminal.rows; row += 1) rows.push(text(cells.slice(row * terminal.cols, (row + 1) * terminal.cols)));
  return rows;
}

/** Runs the Snapshot sequence of `terminal.ts` on `terminal` and returns the terminal that replaces it. */
function repaint(terminal: GhosttyTerminal, snapshot: string, skipped: boolean, previous?: { screen?: string | undefined }): GhosttyTerminal {
  const kept = hasKeepableContent(terminal) ? keepHistoryVt(terminal, { skipped, previousScreen: previous?.screen }) : undefined;
  if (kept && previous) previous.screen = kept.screen;
  const cols = terminal.cols;
  const rows = terminal.rows;
  terminal.free();
  const fresh = ghostty.createTerminal(cols, rows, LARGE);
  const bytes = encoder.encode(snapshot);
  fresh.write(kept ? concatBytes(kept.bytes, withoutLeadingReset(bytes)) : bytes);
  return fresh;
}

/** Lines `line 00001` … from `first` to `last`, each ended with CRLF. */
function numbered(first: number, last: number): string {
  let out = "";
  for (let n = first; n <= last; n += 1) out += `line ${String(n).padStart(5, "0")}\r\n`;
  return out;
}

describe("a repaint keeps the device's history", () => {
  test("all earlier rows stay, the old screen and a marker follow, the repaint replaces only the screen", () => {
    const device = ghostty.createTerminal(80, 24, LARGE);
    device.write(numbered(1, 3000));
    const before = allRows(device).filter((row) => row !== "");
    expect(before[0]).toBe("line 00001");

    // The host skipped lines 3001..9000 and repaints from its own screen: a reset, 3 tail rows, a screen.
    const hostScreen = `\x1bc${numbered(9001, 9003)}\x1b[H\x1b[2Jhost screen row\r\nsecond row`;
    const after = repaint(device, hostScreen, true);
    const rows = allRows(after);
    const kept = rows.filter((row) => row !== "");

    // Every old row, in order, is still there.
    const marker = kept.indexOf(SKIPPED_OUTPUT_MARKER);
    expect(marker).toBeGreaterThan(0);
    expect(kept.slice(0, before.length)).toEqual(before);
    // The marker follows the old screen, once.
    expect(kept.filter((row) => row === SKIPPED_OUTPUT_MARKER)).toHaveLength(1);
    expect(marker).toBe(before.length);
    // The visible screen is the host's, and nothing of the old screen is on it.
    const screen = rows.slice(rows.length - 24);
    expect(screen[0]).toBe("host screen row");
    expect(screen[1]).toBe("second row");
    expect(screen.filter((row) => row.startsWith("line 0"))).toEqual([]);
    expect(after.getScrollbackLength()).toBeGreaterThan(3000 - 24);
    after.free();
  });

  test("no skipped output leaves no marker and no copy of the screen", () => {
    const device = ghostty.createTerminal(80, 24, LARGE);
    device.write(numbered(1, 100));
    const historyBefore = device.getScrollbackLength();
    const after = repaint(device, "\x1bcnew screen", false);
    const rows = allRows(after);
    expect(rows).not.toContain(SKIPPED_OUTPUT_MARKER);
    expect(after.getScrollbackLength()).toBe(historyBefore);
    expect(rows.filter((row) => row !== "").slice(-1)).toEqual(["new screen"]);
    after.free();
  });

  test("a terminal with nothing on it is repainted as before", () => {
    const device = ghostty.createTerminal(80, 24, LARGE);
    expect(hasKeepableContent(device)).toBe(false);
    const after = repaint(device, "\x1bcfirst paint", true);
    const rows = allRows(after);
    expect(rows.filter((row) => row !== "")).toEqual(["first paint"]);
    expect(after.getScrollbackLength()).toBe(0);
    after.free();
  });

  test("colours, text styles, wide characters and default colours survive", () => {
    const device = ghostty.createTerminal(40, 6, LARGE);
    device.write("plain\r\n\x1b[1;31mbold red\x1b[0m \x1b[48;2;1;2;3mbg\x1b[0m\r\n\x1b[38;2;10;20;30;3;4m界éx\x1b[0m\r\n");
    device.write(numbered(1, 10));
    device.update();
    const defaults = device.getColors();
    const after = repaint(device, "\x1bcrepaint", true);
    // Row 0 is "plain"; find the rows by text in the history.
    const find = (needle: string): { fg: number[]; bg: number[]; flags: number; width: number; codepoint: number }[] => {
      for (let offset = 0; offset < after.getScrollbackLength(); offset += 1) {
        const cells = after.getScrollbackLine(offset) ?? [];
        if (cells.map((cell) => String.fromCodePoint(cell.codepoint || 32)).join("").startsWith(needle)) {
          return cells.map((cell) => ({ fg: [cell.fg_r, cell.fg_g, cell.fg_b], bg: [cell.bg_r, cell.bg_g, cell.bg_b], flags: cell.flags, width: cell.width, codepoint: cell.codepoint }));
        }
      }
      throw new Error(`row ${needle} is missing`);
    };
    const at = <T,>(row: T[], index: number): T => {
      const cell = row[index];
      if (cell === undefined) throw new Error(`no cell ${index}`);
      return cell;
    };
    const plain = find("plain");
    expect(at(plain, 0).fg).toEqual([defaults.foreground.r, defaults.foreground.g, defaults.foreground.b]);
    expect(at(plain, 0).bg).toEqual([defaults.background.r, defaults.background.g, defaults.background.b]);
    const red = find("bold red");
    expect(at(red, 0).flags & 1).toBe(1);
    expect(at(red, 0).fg).not.toEqual(at(plain, 0).fg);
    const bg = at(find("bold red"), 9);
    expect(bg.bg).toEqual([1, 2, 3]);
    const wide = find("界");
    expect(at(wide, 0).width).toBe(2);
    expect(at(wide, 0).fg).toEqual([10, 20, 30]);
    expect(at(wide, 0).flags & 2).toBe(2);
    expect(at(wide, 0).flags & 4).toBe(4);
    after.free();
  });

  test("repeated repaints keep the history and add one marker each", () => {
    let device = ghostty.createTerminal(80, 24, LARGE);
    device.write(numbered(1, 500));
    for (let round = 0; round < 3; round += 1) device = repaint(device, `\x1bcscreen ${round}`, true);
    const rows = allRows(device);
    expect(rows.filter((row) => row === SKIPPED_OUTPUT_MARKER)).toHaveLength(3);
    expect(rows.filter((row) => row === "line 00001")).toHaveLength(1);
    expect(rows.filter((row) => row === "line 00500").length).toBeGreaterThan(0);
    device.free();
  });

  test("a flood that repaints the same screen again and again leaves one copy and one marker", () => {
    let device = ghostty.createTerminal(80, 24, LARGE);
    device.write(numbered(1, 200));
    const previous: { screen?: string | undefined } = {};
    for (let round = 0; round < 5; round += 1) device = repaint(device, `\x1bc${"y\r\n".repeat(23)}y`, true, previous);
    const rows = allRows(device);
    expect(rows.filter((row) => row === SKIPPED_OUTPUT_MARKER)).toHaveLength(2);
    // The first repaint copied the 24 numbered rows; the second copied the flood's screen once; the rest were repeats.
    expect(rows.filter((row) => row === "y")).toHaveLength(24 + 24);
    device.free();
  });

  test("history behind a full-screen program is kept", () => {
    let device = ghostty.createTerminal(80, 24, LARGE);
    device.write(numbered(1, 300));
    // A full-screen program is showing; the API reports no history from here.
    device.write("\x1b[?1049h\x1b[2J\x1b[Hprogram screen");
    expect(device.isAlternateScreen()).toBe(true);
    expect(device.getScrollbackLength()).toBe(0);
    device = repaint(device, "\x1bc\x1b[?1049hhost program screen", true);
    expect(device.isAlternateScreen()).toBe(true);
    // Leave the program: the primary screen and its history are what the host and the device kept.
    device.write("\x1b[?1049l");
    const rows = allRows(device).filter((row) => row !== "");
    expect(rows[0]).toBe("line 00001");
    expect(rows).toContain("line 00276");
    expect(rows).toContain(SKIPPED_OUTPUT_MARKER);
    device.free();
  });

  test("the repaint's own reset is removed only when it leads", () => {
    expect(Array.from(withoutLeadingReset(Uint8Array.of(0x1b, 0x63, 0x41)))).toEqual([0x41]);
    expect(Array.from(withoutLeadingReset(Uint8Array.of(0x41, 0x1b, 0x63)))).toEqual([0x41, 0x1b, 0x63]);
    expect(Array.from(withoutLeadingReset(Uint8Array.of(0x1b)))).toEqual([0x1b]);
  });
});
