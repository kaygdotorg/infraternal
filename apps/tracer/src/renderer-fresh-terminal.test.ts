/**
 * A new terminal must start blank, whatever terminals this page showed before (#241).
 *
 * Every terminal in a tab runs in one shared WASM instance. When a terminal is freed (a window closes, or
 * `Terminal.reset()` frees and recreates it for a session switch), its memory goes back to the WASM allocator; the
 * next terminal's first page comes from that memory. Unless the page is zeroed, the new terminal starts with the
 * freed terminal's cells, which are another session's screen. This drives the pinned WASM build directly, the same
 * artifact the tracer ships.
 */
import { describe, expect, test } from "bun:test";
import { resolve } from "node:path";
import { Ghostty, type GhosttyTerminal } from "../vendor/ghostty-web";

const WASM = resolve(import.meta.dir, "../vendor/ghostty-web/dist/ghostty-vt.wasm");

function screenRows(terminal: GhosttyTerminal): string[] {
  terminal.update();
  const cells = terminal.getViewport();
  const rows: string[] = [];
  for (let row = 0; row < terminal.rows; row += 1) {
    rows.push(cells.slice(row * terminal.cols, (row + 1) * terminal.cols)
      .map((cell) => (cell.codepoint > 32 ? String.fromCodePoint(cell.codepoint) : " ")).join("").trimEnd());
  }
  return rows;
}

describe("a new terminal after a freed one", () => {
  test("starts with an empty screen", async () => {
    const ghostty = await Ghostty.load(WASM);
    const earlier = ghostty.createTerminal(80, 24);
    earlier.write("shim-test% whoami\r\nfrom-the-closed-session\r\n");
    expect(screenRows(earlier).slice(0, 2)).toEqual(["shim-test% whoami", "from-the-closed-session"]);
    earlier.free();

    const fresh = ghostty.createTerminal(80, 24);
    expect(screenRows(fresh).filter(Boolean)).toEqual([]);
    // Output that does not erase the line keeps whatever was left in the row (the "root-test" seen in #241).
    fresh.write("root\r\n");
    expect(screenRows(fresh).filter(Boolean)).toEqual(["root"]);
    fresh.free();
  });
});
