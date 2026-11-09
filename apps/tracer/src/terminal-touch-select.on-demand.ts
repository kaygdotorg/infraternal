// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Selecting and copying terminal text with a finger (#426).
 *
 * The terminal is a canvas, so the browser's own text selection can never reach it, and its built-in selection listens to
 * the mouse only. A finger never produces those events (one finger scrolls, D159), so on a phone nothing could be selected.
 * `terminal-touch.ts` recognises the gestures (a long press, a double tap, a drag after either) and calls the hooks built
 * here, which do the part that needs the terminal's cells:
 *
 * - `start(x, y)` selects the word under the finger (a word that wraps over rows is selected whole), or the single cell when
 *   the finger is on blank space, and nothing when the finger is outside the canvas, in the host's padding;
 * - `extend(x, y)` grows the selection to the cell under the finger, by whole cells. The word that was first selected
 *   stays inside it, so dragging backwards past the word's start keeps the word, as the system's own text does;
 * - `end()` offers a Copy callout (the shared window menu, one row) above the selection, or below it when above would leave
 *   the window or cover its title pill, always inside the window's content area;
 * - `clear()` drops the selection and the callout, and is what any other touch of the terminal does first.
 *
 * Copy answers on its own row, the way every copy does (TASTE "Every tap answers"): the clipboard icon turns into a tick and
 * the label says "Copied" for a moment, then the callout and the selection go. The write starts inside the tap on Copy, so iOS
 * still counts it as the person's gesture.
 *
 * Coordinates are the viewport's: a gesture is short enough that the viewport does not move under it, and the selection is
 * stored in the renderer's absolute rows (terminal-wrap-selection.ts), so it stays on the same text if the screen scrolls
 * afterwards. Loaded when the first finger touches the terminal (D188): a desktop session never carries it.
 */
import { CLIPBOARD, confirmAction, swapIcon, writeClipboard } from "../../../packages/ui/src/copy-feedback";
import { applySelection, cellAtPoint, selectedText, wordRange, type Cell, type CellGeometry, type SelectableTerminal } from "./terminal-wrap-selection";

/** How long the row says "Copied" before the callout and the selection go (the shared copy feedback's hold). */
const ANSWER_MS = 900;
/** The gap between the callout and the selected text. */
const GAP = 8;

/** What `terminal-touch.ts` calls. */
export interface TouchSelectHooks {
  start(x: number, y: number): void;
  extend(x: number, y: number): void;
  end(): void;
  clear(): void;
  /** Whether a selection (or its callout) is showing. */
  active(): boolean;
}

/** What the selection hooks need from the terminal screen they serve. */
export interface TouchSelectionOptions extends CellGeometry {
  terminal: SelectableTerminal;
  /** The terminal's host element: the callout's anchor, and what the finger is on. */
  host: HTMLElement;
  /** Wakes the renderer so the new selection is painted while it is otherwise idle. */
  wake(): void;
}

/** Builds the hooks for one terminal. */
export function createTouchSelection(options: TouchSelectionOptions): TouchSelectHooks {
  const { terminal, host } = options;
  /** The cells first selected (a word, or one cell): every extension keeps them inside. */
  let first: { from: Cell; to: Cell } | undefined;
  /** The cells selected now, in reading order. */
  let range: { from: Cell; to: Cell } | undefined;
  let menu: { close(how: "keyboard" | "pointer"): void } | undefined;
  let showing = false;
  let answer = 0;

  const index = (cell: Cell): number => cell.row * terminal.cols + cell.col;

  /** Selects the cells from `a` to `b` inclusive, in either order. */
  const paint = (a: Cell, b: Cell): void => {
    const [from, to] = index(a) <= index(b) ? [a, b] : [b, a];
    range = { from, to };
    options.wake();
    applySelection(terminal, from, to);
  };

  const closeMenu = (): void => { window.clearTimeout(answer); menu?.close("pointer"); menu = undefined; };

  /** The window's content area: where the callout must stay, and the header controls it must not cover. */
  const windowBoxes = (): { bounds: DOMRect; avoid: DOMRect[] } | undefined => {
    const frame = host.closest<HTMLElement>(".ui-window");
    const body = frame?.querySelector<HTMLElement>(".ui-window-body");
    if (!frame || !body) return undefined;
    const controls = [...frame.querySelectorAll<HTMLElement>(".ui-window-pill, .ui-window-actions")].map((el) => el.getBoundingClientRect());
    return { bounds: body.getBoundingClientRect(), avoid: controls };
  };

  const hooks: TouchSelectHooks = {
    start(x, y) {
      closeMenu();
      const cell = cellAtPoint(options, terminal, x, y, false);
      if (!cell) return;
      const word = wordRange(terminal, cell.col, cell.row);
      first = word ?? { from: cell, to: cell };
      showing = true;
      paint(first.from, first.to);
    },

    extend(x, y) {
      const cell = cellAtPoint(options, terminal, x, y, true);
      if (!cell || !first) return;
      closeMenu();
      // Before the first cells the selection runs from the finger to the end of them; after, from their start to the finger.
      if (index(cell) < index(first.from)) paint(cell, first.to);
      else if (index(cell) > index(first.to)) paint(first.from, cell);
      else paint(first.from, first.to);
    },

    end() {
      const text = selectedText(terminal);
      if (!text) { hooks.clear(); return; }
      const canvas = options.canvas();
      const { width, height } = options.metrics();
      if (!canvas || !range) return;
      const box = canvas.getBoundingClientRect();
      // Centred over the first visible selected row's span (to the last column when the selection goes on to the next row).
      const top = Math.max(0, range.from.row), bottom = Math.min(terminal.rows - 1, range.to.row);
      const [firstCol, lastCol] = range.to.row > range.from.row ? [range.from.row < 0 ? 0 : range.from.col, terminal.cols - 1] : [range.from.col, range.to.col];
      const point = { x: box.left + (firstCol + lastCol + 1) / 2 * width, y: box.top + top * height - GAP };
      const below = box.top + (bottom + 1) * height + GAP;
      const stage = host.closest<HTMLElement>(".cl-mockup, .terminal-screen") ?? document.body;
      const frame = windowBoxes();
      void import("../../../packages/ui/src/window-menu.on-demand").then(({ openWindowMenu }) => {
        if (!showing) return;
        closeMenu();
        const mine = openWindowMenu(stage, host, [{
          id: "copy", label: "Copy", icon: CLIPBOARD, keepOpen: true,
          run: (event) => {
            const row = event.currentTarget as HTMLElement;
            const label = row.lastElementChild!; // the icon is first, the label last
            void writeClipboard(selectedText(terminal)).then((ok) => {
              if (!showing) return; // something else ended the selection while the write was pending
              label.textContent = ok ? "Copied" : "Couldn't copy";
              if (ok) confirmAction(row, "Copied", event.detail === 0);
              mine.place();
              answer = window.setTimeout(() => hooks.clear(), ANSWER_MS);
            });
          },
        }], "pointer", () => { if (menu === mine) menu = undefined; }, {
          label: "Selected text", className: "ui-select-callout", side: "above", at: point, atAlign: "centre", atBelow: below, hug: true, maxWidth: 160, glassBed: true,
          ...(frame ? { bounds: () => windowBoxes()?.bounds, avoid: () => windowBoxes()?.avoid ?? [] } : {}),
        });
        menu = mine;
        // Pressing Copy must not take focus from the terminal's input: the cursor would go hollow and, with the keyboard up, the
        // keyboard and the key row would leave. A press on a button focuses it unless its mousedown is cancelled; the tap itself still clicks.
        for (const type of ["pointerdown", "mousedown"]) mine.root.addEventListener(type, (event) => event.preventDefault());
        // The Copy icon is the shared swap (icon to tick), so the row can answer in place.
        mine.root.querySelector("button svg")?.replaceWith(Object.assign(document.createElement("template"), { innerHTML: swapIcon(CLIPBOARD) }).content);
        mine.place();
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
