/**
 * Grid geometry of the canvas, pure (no DOM) so the placement rules can be tested on their own (D119, D177).
 *
 * - A view's *box* is its content plus a fixed margin, rounded up to whole grid cells.
 * - Boxes sit on a coarse grid (`CELL`) and never overlap. Dropping one on another pushes the
 *   other aside along the axis of least overlap, and that one pushes its neighbours in turn.
 * - Sizes follow the viewport so a snapped view fills it (`metricsFor`).
 */
import type { ViewModel } from "../model/types";
import { COLUMN_GAP, DEFAULT_SIZES, columnWidth, peekWidth, type WindowSizes } from "../window-sizes";

export { COLUMN_GAP };

export interface Pt { x: number; y: number }
export interface Rect { x: number; y: number; w: number; h: number }

export const CELL = 120;
/** Space inside a box around the content: left, top (room for the view label), right, bottom. */
export const MARGIN = { l: 48, t: 96, r: 48, b: 48 };

export interface Metrics {
  colW: number;
  /** A column's width in a strip of several on a phone (neighbours peek in); equal to `colW` elsewhere. */
  peekW: number;
  /** The narrowest a column is ever drawn (px); 0 where there is no floor. Display only: see `drawnWidth`. */
  minW: number;
  clh: number; narrow: boolean; nodeW: number; nodeH: number;
}

/**
 * The widest floor on a touch screen (D309, #243): room for a usable terminal of 40 monospace cells. Measured on a
 * 390 px phone at the touch terminal size: a 344 px terminal holds 39 cells, so a cell is about 8.8 px, and 40 cells with
 * the window's 2 px of border need 355 px. The canvas's own sideways pan reaches the columns that do not fit. Without a
 * floor a column the desktop set to the weight floor (a tenth of a column) is about 39 px wide on a phone, too narrow to
 * type in.
 */
export const MIN_TOUCH_COLUMN = 355;

/**
 * Sizes follow the viewport so a snapped view fills it: on a phone a lone column is the safe-area width and a column in a
 * strip of several is that width minus a sliver for each neighbour to peek in (`peekW`); on a desktop three columns fill the width; a column is always as tall
 * as the viewport (D119: windows tile the pane).
 */
export const metricsFor = (width: number, height: number, coarse: boolean, sizes: WindowSizes = DEFAULT_SIZES): Metrics => {
  const narrow = coarse || width < 720;
  const colW = columnWidth(width, narrow, sizes);
  // A view is as tall as the canvas area. It may get short (the on-screen keyboard is up): only the height changes,
  // never the width or a column count, so nothing rewraps and the camera does not scale the window down (D191).
  const clh = Math.max(120, Math.round(height));
  const peekW = peekWidth(width, narrow, colW, COLUMN_GAP, sizes);
  // The floor is never wider than a column of a default strip (`peekW`): a small phone's screen cannot show 40 cells with
  // a neighbour's slice beside them, and the floor must not change how a default layout looks there.
  return { colW, peekW, minW: coarse ? Math.min(MIN_TOUCH_COLUMN, peekW) : 0, clh, narrow, nodeW: narrow ? 200 : 208, nodeH: 104 };
};

/**
 * The width a column of saved width `w` is drawn at. The saved width (the weight times `colW`) is the layout; the drawn
 * width is only how this device shows it. Only drawing, the camera's stops and the content size read this; everything
 * that is saved reads the saved width (`ColumnModel.w`, `data-w`), so a phone never rewrites the layout it displays.
 */
export const drawnWidth = (w: number, m: Pick<Metrics, "minW">): number => Math.max(w, m.minW);

/** Size of the content (the tiled columns, or the graph canvas). */
export function contentSize(view: ViewModel, m: Metrics): { w: number; h: number } {
  if (view.layout === "graph") return view.graph ?? { w: 880, h: 400 };
  const n = Math.max(1, view.cols.length);
  const w = view.cols.length ? view.cols.reduce((sum, c) => sum + drawnWidth(c.w, m), 0) + COLUMN_GAP * (n - 1) : m.colW;
  return { w, h: view.cols.length ? m.clh : Math.round(m.clh * 0.7) };
}

export interface Box { id: string; x: number; y: number; w: number; h: number }

export function boxOf(view: ViewModel, m: Metrics): Box {
  const c = contentSize(view, m);
  const w = Math.ceil((c.w + MARGIN.l + MARGIN.r) / CELL) * CELL;
  const h = Math.ceil((c.h + MARGIN.t + MARGIN.b) / CELL) * CELL;
  return { id: view.id, x: view.x, y: view.y, w, h };
}

export const snapToGrid = (v: number): number => Math.round(v / CELL) * CELL;

const overlaps = (a: Box, b: Box): boolean => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

/**
 * Returns every box's position after `fixedId` is held where it is and the others that it
 * overlaps are pushed aside. A pushed box pushes the boxes it now overlaps (never the fixed
 * one). Each push is a whole number of cells because every box edge sits on the grid.
 */
export function resolve(boxes: Box[], fixedId: string): Map<string, { x: number; y: number }> {
  const at = new Map(boxes.map((b) => [b.id, { ...b }]));
  const fixed = new Set([fixedId]);
  const queue = [fixedId];
  for (let guard = 0; queue.length && guard < 64; guard++) {
    const pusher = at.get(queue.shift()!)!;
    for (const other of at.values()) {
      if (other.id === pusher.id || fixed.has(other.id) || !overlaps(pusher, other)) continue;
      const options = [
        { dx: pusher.x + pusher.w - other.x, dy: 0 },
        { dx: -(other.x + other.w - pusher.x), dy: 0 },
        { dx: 0, dy: pusher.y + pusher.h - other.y },
        { dx: 0, dy: -(other.y + other.h - pusher.y) },
      ];
      // Least travel wins; on a tie prefer moving away to the right or down.
      const best = options.reduce((a, b) => (Math.abs(b.dx) + Math.abs(b.dy) < Math.abs(a.dx) + Math.abs(a.dy) ? b : a));
      other.x += best.dx;
      other.y += best.dy;
      queue.push(other.id);
    }
  }
  return new Map([...at.values()].map((b) => [b.id, { x: b.x, y: b.y }]));
}

// ---- mock people, grants and content -------------------------------------------------------------

/** The default width of a column in a view of `count` columns: wider when alone, narrower when neighbours peek in. */
export const defaultWidth = (m: Metrics, count: number): number => (count > 1 ? m.peekW : m.colW);
/** Whether `w` is one of the default widths of `m` (a column the person never resized). */
export const isDefaultWidth = (w: number, m: Metrics): boolean => w === m.colW || w === m.peekW;
