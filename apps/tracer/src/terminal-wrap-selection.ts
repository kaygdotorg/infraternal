// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Terminal selection that understands soft wraps (#426), shared by the mouse and the touch paths.
 *
 * A program that prints a line longer than the terminal is wide does not send a newline: the terminal wraps it. The renderer's
 * own selection ignored that. It joined every row with "\n", so a pairing code or URL that wrapped copied with a line break in
 * the middle, and its word search stopped at the row's edge, so a double-click selected only half of a wrapped word. This module
 * replaces the two pieces that were wrong and nothing else:
 *
 * - `selectedText` is the text of the selection, with no newline where the next row is a soft-wrapped continuation of the
 *   previous one, and a newline everywhere else (a line the program ended itself still copies as a line). Mouse selection,
 *   which copies through the same method, gets it from `installWrapAwareSelection`.
 * - `wordRange` finds the word around a cell across wrapped rows, so a double-click and a long press select a wrapped word
 *   whole.
 *
 * How a wrap is known. The engine reports, for rows of the live screen, whether a row continues the one above it. Rows that
 * have scrolled into the history have lost that flag, so for them a row counts as continued when the row above it is full to
 * its last column. That is right for output that ran past the edge; it can only be wrong for a line the program ended at
 * exactly the terminal's width, which then copies joined to the next line.
 *
 * The renderer's selection manager keeps its members private in the type declarations, but they exist at runtime, and the
 * vendored build is pinned (vendor/ghostty-web/SHA256SUMS), so `SelectionManagerRuntime` names the few this module touches and
 * an upgrade of the renderer is checked against it by the selection specs.
 */

/** One cell of the grid: a column and a row. Rows are viewport rows and may lie outside the screen for a word that scrolls out. */
export interface Cell { col: number; row: number }

/** One cell as the engine reports it: only the fields this module reads. */
interface EngineCell { codepoint: number; grapheme_len: number }

/** The engine's terminal, as far as this module reads it. */
interface EngineTerminal {
  getScrollbackLength(): number;
  getScrollbackLine(index: number): EngineCell[] | null;
  getLine(row: number): EngineCell[] | null;
  getGraphemeString(row: number, col: number): string;
  getScrollbackGraphemeString(index: number, col: number): string;
  isRowWrapped(row: number): boolean;
}

/** The renderer's selection manager, as far as this module touches it (see the module doc). */
export interface SelectionManagerRuntime {
  selectionStart: { col: number; absoluteRow: number } | null;
  selectionEnd: { col: number; absoluteRow: number } | null;
  selectionChangedEmitter: { fire(): void };
  getSelection(): string;
  getWordAtCell(column: number, row: number): { startCol: number; endCol: number } | null;
  viewportRowToAbsolute(row: number): number;
  markCurrentSelectionDirty(): void;
  requestRender(): void;
  copyToClipboard(text: string): void;
}

/** The part of the renderer's terminal this module drives; the real `Terminal` satisfies it. */
export interface SelectableTerminal {
  readonly cols: number;
  readonly rows: number;
  readonly wasmTerm?: EngineTerminal;
  clearSelection(): void;
  getSelection(): string;
  readonly selectionManager?: SelectionManagerRuntime;
}

/** The characters a word is made of: the renderer's own set, kept so a wrapped word and an unwrapped one end in the same places. */
const WORD = /[\w\-./~@+]/;

/** Whether a cell holds a word character (see {@link WORD}). */
const isWordCell = (cell: EngineCell | undefined): boolean => !!cell && cell.codepoint !== 0 && WORD.test(String.fromCodePoint(cell.codepoint));

/** Reads rows by absolute index: the history first, then the live screen. */
class Rows {
  private readonly history: number;
  /** Reads rows of `engine`, a terminal `cols` columns wide. */
  constructor(private readonly engine: EngineTerminal, readonly cols: number) { this.history = engine.getScrollbackLength(); }

  /** The cells of row `abs`, or null when there is no such row. */
  line(abs: number): EngineCell[] | null {
    return abs < 0 ? null : abs < this.history ? this.engine.getScrollbackLine(abs) : this.engine.getLine(abs - this.history);
  }

  /** Whether row `abs` continues the row above it (see the module doc for how history rows are judged). */
  continues(abs: number): boolean {
    if (abs <= 0) return false;
    if (abs >= this.history) return this.engine.isRowWrapped(abs - this.history);
    const above = this.line(abs - 1)?.[this.cols - 1];
    return !!above && above.codepoint !== 0 && above.codepoint !== 32;
  }

  /** The text of one cell, with its combining marks. */
  text(abs: number, col: number, cell: EngineCell): string {
    if (cell.grapheme_len <= 0) return String.fromCodePoint(cell.codepoint);
    return abs < this.history ? this.engine.getScrollbackGraphemeString(abs, col) : this.engine.getGraphemeString(abs - this.history, col);
  }
}

/** The renderer's selection manager and the engine behind it, when both exist. */
function parts(terminal: SelectableTerminal): { manager: SelectionManagerRuntime; engine: EngineTerminal } | undefined {
  const manager = terminal.selectionManager, engine = terminal.wasmTerm;
  return manager && engine ? { manager, engine } : undefined;
}

/**
 * The text of the current selection. Rows are joined with a newline unless the lower one is a soft-wrapped continuation of the
 * upper one, in which case they are joined as they were printed. Trailing blanks are trimmed at the end of a line the program
 * ended and kept across a wrap (a space at the very edge is part of the text).
 */
export function selectedText(terminal: SelectableTerminal): string {
  const p = parts(terminal);
  if (!p || !p.manager.selectionStart || !p.manager.selectionEnd) return "";
  let { col: fromCol, absoluteRow: fromRow } = p.manager.selectionStart;
  let { col: toCol, absoluteRow: toRow } = p.manager.selectionEnd;
  if (fromRow > toRow || (fromRow === toRow && fromCol > toCol)) [fromCol, toCol, fromRow, toRow] = [toCol, fromCol, toRow, fromRow];
  const rows = new Rows(p.engine, terminal.cols);
  let out = "";
  for (let abs = fromRow; abs <= toRow; abs++) {
    const line = rows.line(abs);
    if (!line) continue;
    const first = abs === fromRow ? fromCol : 0, last = abs === toRow ? toCol : line.length - 1;
    let text = "", lastInk = -1;
    for (let col = first; col <= last; col++) {
      const cell = line[col];
      if (cell && cell.codepoint !== 0) {
        const piece = rows.text(abs, col, cell);
        text += piece;
        if (piece.trim()) lastInk = text.length;
      } else text += " ";
    }
    const joined = abs < toRow && rows.continues(abs + 1);
    out += joined ? text : lastInk >= 0 ? text.slice(0, lastInk) : "";
    if (abs < toRow && !joined) out += "\n";
  }
  return out;
}

/**
 * The word around a cell, as the first and last cell of it, following the word over soft wraps in both directions. Undefined
 * when the cell is not part of a word (blank space, punctuation that is not a word character).
 */
export function wordRange(terminal: SelectableTerminal, col: number, row: number): { from: Cell; to: Cell } | undefined {
  const p = parts(terminal);
  if (!p) return undefined;
  const rows = new Rows(p.engine, terminal.cols);
  const origin = p.manager.viewportRowToAbsolute(row);
  if (!isWordCell(rows.line(origin)?.[col])) return undefined;
  const shift = row - origin; // abs → viewport row
  let [startAbs, startCol, endAbs, endCol] = [origin, col, origin, col];
  for (;;) {
    if (startCol > 0 && isWordCell(rows.line(startAbs)?.[startCol - 1])) startCol--;
    else if (startCol === 0 && rows.continues(startAbs) && isWordCell(rows.line(startAbs - 1)?.[terminal.cols - 1])) { startAbs--; startCol = terminal.cols - 1; }
    else break;
  }
  for (;;) {
    if (endCol < terminal.cols - 1 && isWordCell(rows.line(endAbs)?.[endCol + 1])) endCol++;
    else if (endCol === terminal.cols - 1 && rows.continues(endAbs + 1) && isWordCell(rows.line(endAbs + 1)?.[0])) { endAbs++; endCol = 0; }
    else break;
  }
  return { from: { col: startCol, row: startAbs + shift }, to: { col: endCol, row: endAbs + shift } };
}

/**
 * Selects the cells from `a` to `b` inclusive, in either order, as the renderer's own mouse selection would store them (in
 * absolute rows, so the selection stays on the same text if the screen scrolls afterwards), and repaints.
 */
export function applySelection(terminal: SelectableTerminal, a: Cell, b: Cell): void {
  const manager = terminal.selectionManager;
  if (!manager) return;
  const [from, to] = a.row < b.row || (a.row === b.row && a.col <= b.col) ? [a, b] : [b, a];
  // The rows the old selection covered must repaint too, or its highlight stays behind when the selection shrinks.
  manager.markCurrentSelectionDirty();
  manager.selectionStart = { col: from.col, absoluteRow: manager.viewportRowToAbsolute(from.row) };
  manager.selectionEnd = { col: to.col, absoluteRow: manager.viewportRowToAbsolute(to.row) };
  manager.requestRender();
  manager.selectionChangedEmitter.fire();
}

/** What the cell lookup needs from the terminal screen. */
export interface CellGeometry {
  /** The canvas the cells are drawn on; its box is where cell (0, 0) starts. */
  canvas(): HTMLCanvasElement | undefined;
  /** One cell's size in CSS pixels. */
  metrics(): { width: number; height: number };
}

/**
 * The cell under a client point. With `clamp` the nearest edge cell is returned for a point outside the canvas (a drag that
 * runs past the edge); without it a point outside the canvas, such as the host's padding, is no cell at all.
 */
export function cellAtPoint(geometry: CellGeometry, terminal: SelectableTerminal, x: number, y: number, clamp: boolean): Cell | undefined {
  const canvas = geometry.canvas();
  const { width, height } = geometry.metrics();
  if (!canvas || width <= 0 || height <= 0) return undefined;
  const box = canvas.getBoundingClientRect();
  if (!clamp && (x < box.left || x >= box.right || y < box.top || y >= box.bottom)) return undefined;
  return {
    col: Math.max(0, Math.min(terminal.cols - 1, Math.floor((x - box.left) / width))),
    row: Math.max(0, Math.min(terminal.rows - 1, Math.floor((y - box.top) / height))),
  };
}

/**
 * Makes the renderer's mouse selection wrap-aware: its text is `selectedText` (so a drag across a soft wrap copies no newline,
 * and the copy it makes on release is right), and a double-click selects the whole word over wrapped rows and copies it. A
 * double-click on something that is not a word is left to the renderer, which does nothing with it.
 */
export function installWrapAwareSelection(terminal: SelectableTerminal, host: HTMLElement, geometry: CellGeometry): void {
  const manager = terminal.selectionManager;
  if (!manager) return;
  manager.getSelection = () => selectedText(terminal);
  host.addEventListener("click", (event) => {
    if (event.detail !== 2 || event.button !== 0) return;
    const cell = cellAtPoint(geometry, terminal, event.clientX, event.clientY, false);
    const word = cell && wordRange(terminal, cell.col, cell.row);
    if (!word) return;
    // The renderer's own handler would select only the part on this row; ours replaces it.
    event.stopImmediatePropagation();
    applySelection(terminal, word.from, word.to);
    const text = manager.getSelection();
    if (text) manager.copyToClipboard(text);
  }, { capture: true });
}
