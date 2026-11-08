// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Selecting and copying terminal text with a finger (#426).
 *
 * The terminal is a canvas, so the browser's own text selection can never reach it, and its built-in selection listens to
 * the mouse only. A finger never produces those events (one finger scrolls, D159), so on a phone nothing could be selected.
 * `terminal-touch.ts` recognises the gestures (a long press, a double tap, a drag after either) and calls the hooks built
 * here, which do the part that needs the terminal's cells:
 *
 * - `start(x, y)` selects the word under the finger, or the single cell when the finger is on blank space;
 * - `extend(x, y)` grows the selection to the cell under the finger, by whole cells. The word that was first selected
 *   stays inside it, so dragging backwards past the word's start keeps the word, as the system's own text does;
 * - `end()` offers a Copy callout, centred above the selection (the shared window menu, one row), when there is text;
 * - `clear()` drops the selection and the callout, and is what any other touch of the terminal does first.
 *
 * Coordinates are always the viewport's: a gesture is short enough that the viewport does not move under it, and the
 * selection is stored in the renderer's absolute rows, so it stays on the same text if the screen scrolls afterwards. Copying goes through the shared `writeClipboard`,
 * called inside the tap on Copy so iOS still counts it as the person's gesture.
 *
 * Loaded when the first finger touches the terminal (D188): a desktop session never carries it.
 */
import { CLIPBOARD, writeClipboard } from "../../../packages/ui/src/copy-feedback";

/**
 * The renderer's selection manager, as far as this module touches it. Its members are private in the renderer's types but
 * present at runtime, and the vendored build is pinned (vendor/ghostty-web/SHA256SUMS), so this is checked on every upgrade.
 * Why not the public `Terminal.select(column, row, length)`: it anchors rows at the viewport's scroll offset instead of the
 * scrollback length, so it selects the wrong lines as soon as there is scrollback. `viewportRowToAbsolute` is the renderer's
 * own conversion, the one its mouse selection uses.
 */
export interface SelectionManagerRuntime {
  selectionStart: { col: number; absoluteRow: number } | null;
  selectionEnd: { col: number; absoluteRow: number } | null;
  selectionChangedEmitter: { fire(): void };
  getWordAtCell(column: number, row: number): { startCol: number; endCol: number } | null;
  viewportRowToAbsolute(row: number): number;
  markCurrentSelectionDirty(): void;
  requestRender(): void;
}

/** The part of the terminal this module drives; the real `Terminal` from the renderer satisfies it. */
export interface SelectableTerminal {
  readonly cols: number;
  readonly rows: number;
  clearSelection(): void;
  getSelection(): string;
  readonly selectionManager?: SelectionManagerRuntime;
}

/** What `terminal-touch.ts` calls. */
export interface TouchSelectHooks {
  start(x: number, y: number): void;
  extend(x: number, y: number): void;
  end(): void;
  clear(): void;
  /** Whether a selection (or its callout) is showing. */
  active(): boolean;
}

export interface TouchSelectionOptions {
  terminal: SelectableTerminal;
  /** The terminal's host element: the callout's anchor, and what the finger is on. */
  host: HTMLElement;
  /** The canvas the cells are drawn on; its box is where cell (0, 0) starts. */
  canvas(): HTMLCanvasElement | undefined;
  /** One cell's size in CSS pixels. */
  metrics(): { width: number; height: number };
  /** Wakes the renderer so the new selection is painted while it is otherwise idle. */
  wake(): void;
}

interface Cell { col: number; row: number }

/** Builds the hooks for one terminal. */
export function createTouchSelection(options: TouchSelectionOptions): TouchSelectHooks {
  const { terminal, host } = options;
  /** The cells first selected (a word, or one cell): every extension keeps them inside. */
  let first: { from: Cell; to: Cell } | undefined;
  /** The cells selected now, in reading order. */
  let range: { from: Cell; to: Cell } | undefined;
  let menu: { close(how: "keyboard" | "pointer"): void } | undefined;
  let showing = false;

  const index = (cell: Cell): number => cell.row * terminal.cols + cell.col;

  /** The cell under a client point, clamped to the grid; undefined while the canvas is not laid out. */
  const cellAt = (x: number, y: number): Cell | undefined => {
    const canvas = options.canvas();
    const { width, height } = options.metrics();
    if (!canvas || width <= 0 || height <= 0) return undefined;
    const box = canvas.getBoundingClientRect();
    return {
      col: Math.max(0, Math.min(terminal.cols - 1, Math.floor((x - box.left) / width))),
      row: Math.max(0, Math.min(terminal.rows - 1, Math.floor((y - box.top) / height))),
    };
  };

  /** Selects the cells from `a` to `b` inclusive, in either order. */
  const paint = (a: Cell, b: Cell): void => {
    const [from, to] = index(a) <= index(b) ? [a, b] : [b, a];
    const manager = terminal.selectionManager;
    if (!manager) return;
    range = { from, to };
    options.wake();
    // The rows the old selection covered must repaint too, or its highlight stays behind when the selection shrinks.
    manager.markCurrentSelectionDirty();
    manager.selectionStart = { col: from.col, absoluteRow: manager.viewportRowToAbsolute(from.row) };
    manager.selectionEnd = { col: to.col, absoluteRow: manager.viewportRowToAbsolute(to.row) };
    manager.requestRender();
    manager.selectionChangedEmitter.fire();
  };

  const closeMenu = (): void => { menu?.close("pointer"); menu = undefined; };

  const hooks: TouchSelectHooks = {
    start(x, y) {
      closeMenu();
      const cell = cellAt(x, y);
      if (!cell) return;
      const word = terminal.selectionManager?.getWordAtCell(cell.col, cell.row);
      first = word ? { from: { col: word.startCol, row: cell.row }, to: { col: word.endCol, row: cell.row } } : { from: cell, to: cell };
      showing = true;
      paint(first.from, first.to);
    },

    extend(x, y) {
      const cell = cellAt(x, y);
      if (!cell || !first) return;
      closeMenu();
      // Before the first cells the selection runs from the finger to the end of them; after, from their start to the finger.
      if (index(cell) < index(first.from)) paint(cell, first.to);
      else if (index(cell) > index(first.to)) paint(first.from, cell);
      else paint(first.from, first.to);
    },

    end() {
      const text = terminal.getSelection();
      if (!text) { hooks.clear(); return; }
      const canvas = options.canvas();
      const { width, height } = options.metrics();
      if (!canvas || !range) return;
      const box = canvas.getBoundingClientRect();
      // Centred over the first selected row's selected span (to the last column when the selection goes on to the next row).
      const last = range.to.row > range.from.row ? terminal.cols - 1 : range.to.col;
      const point = { x: box.left + (range.from.col + last + 1) / 2 * width, y: box.top + range.from.row * height - 8 };
      const stage = host.closest<HTMLElement>(".cl-mockup, .terminal-screen") ?? document.body;
      void import("../../../packages/ui/src/window-menu.on-demand").then(({ openWindowMenu }) => {
        if (!showing) return;
        closeMenu();
        const mine = openWindowMenu(stage, host, [{
          id: "copy", label: "Copy", icon: CLIPBOARD,
          run: () => { void writeClipboard(terminal.getSelection()); hooks.clear(); },
        }], "pointer", () => { if (menu === mine) menu = undefined; }, {
          label: "Selected text", side: "above", at: point, atAlign: "centre", hug: true, maxWidth: 160,
        });
        menu = mine;
      });
    },

    clear() {
      closeMenu();
      first = range = undefined;
      if (showing) { showing = false; terminal.clearSelection(); options.wake(); }
    },

    active: () => showing,
  };
  return hooks;
}
