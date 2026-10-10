/**
 * The tracks of a tiled view: how its columns and windows are laid out in the DOM (D212).
 *
 * A plain column is a flex stack (`.cl-col`), exactly as before. Columns linked by a window that spans them form a
 * **group**: one grid (`.cl-group`) whose column tracks are the columns' widths, whose row tracks are the shared bands,
 * and whose columns are `display: contents`, so each window is a grid item placed by its span and band. The grid rules
 * themselves are pure and tested in layout/grid.ts; this module only writes them into the DOM and reads them back.
 *
 * Invariants:
 * - The DOM is written from the model (`arrange`) and the model is read back from the DOM (`readColumns`), so a drag, a
 *   resize or a split all agree on one picture. A window's height is the style it has while it stands alone and the
 *   band's height inside a group; a group window never carries its own height style (the band stretches it).
 * - Every window's span, band and height are written to its element (data attributes) and to its model, so a saved
 *   document and a reloaded one place it the same way.
 * - Re-parenting a column is done only when the structure changes: a drag or a resize frame never moves terminals.
 */
import type { Ctx, ViewRec } from "../context";
import { COLUMN_GAP } from "../layout/geometry";
import { columnEls } from "../layout/columns";
import { bandHeights, runsOf, settle, type Col, type Run } from "../layout/grid";
import type { ColumnModel, WindowModel } from "../model/types";
import { el } from "../dom";

/** A group's padding and margin: the same 14 px a column has around its windows, so its tracks line up with plain columns. */
const PAD = 14;
const SIDE = PAD * 2;

/**
 * A row band's track. A band with its own height is a fixed track (`max` pins it: `minmax` would let the browser shrink it
 * to whatever is free, which is not what the person set); a band without one shares what is left equally (`1fr`).
 * Overflow scrolls the group, as an overfull plain column does.
 */
function bandTrack(h: number | undefined): string {
  if (h === undefined) return "minmax(160px, 1fr)";
  return `max(160px, ${h <= 1 ? `calc(var(--clh) * ${h})` : `${h}px`})`;
}

/** The height style of a window standing alone: a ratio of the column height, or pixels; none when it shares its column. */
function heightStyle(h: number | undefined): string {
  return h === undefined ? "" : h <= 1 ? `calc(var(--clh) * ${h})` : `${h}px`;
}

/**
 * Writes a style or attribute only when it differs. `arrange` runs on every drag and resize frame, and a write of the same
 * value still costs the browser a style pass for the element; at 57 windows that is most of the frame.
 */
function put(el: HTMLElement, key: "gridColumn" | "gridRow" | "height" | "flex" | "width" | "gridTemplateColumns" | "gridTemplateRows", value: string): void {
  if (el.style[key] !== value) el.style[key] = value;
}
function data(el: HTMLElement, key: "span" | "rows" | "row", value: string | undefined): void {
  if (value === undefined) { if (key in el.dataset) delete el.dataset[key]; } else if (el.dataset[key] !== value) el.dataset[key] = value;
}

/** Writes a window's span, band and rows to its element. Only what says something is written (a plain window has none). */
function markWin(root: HTMLElement, m: WindowModel, grouped: boolean): void {
  data(root, "span", m.span && m.span > 1 ? String(m.span) : undefined);
  data(root, "rows", m.rows && m.rows > 1 ? String(m.rows) : undefined);
  data(root, "row", grouped && m.row !== undefined ? String(m.row) : undefined);
}

/** An id no column of the view has: a new column never takes the id of one that is already there. */
export function freshColumnId(cx: Ctx, c: ViewRec): string {
  const taken = new Set(columnEls(c.colsEl).map((e) => e.dataset.id ?? ""));
  let id = "";
  do id = `c${++cx.state.serial}`; while (taken.has(id));
  return id;
}

/**
 * The view's columns as the DOM has them now (plain columns and group columns, in order). An empty column with no
 * drop slot in it is taken out of the DOM: nothing else would ever remove it.
 */
export function readColumns(cx: Ctx, c: ViewRec): ColumnModel[] {
  const cols: ColumnModel[] = [];
  for (const colEl of columnEls(c.colsEl)) {
    const wins: WindowModel[] = [];
    for (const n of colEl.querySelectorAll<HTMLElement>(":scope > .ui-window")) {
      const rec = c.wins.get(n.dataset.windowId ?? "");
      if (!rec) continue;
      const m = rec.model;
      // A height the person set is in the style, and the model takes it. A plain window with no height style shares its
      // column: its old height is gone (a close clears it so the neighbour grows). A group window has no style of its own:
      // its band's height stays in the model.
      if (n.style.height.endsWith("px")) m.h = Math.round(parseFloat(n.style.height));
      else if (!n.style.height.includes("calc") && !colEl.parentElement?.classList.contains("cl-group")) delete m.h;
      if (n.dataset.span) m.span = Number(n.dataset.span); else delete m.span;
      if (n.dataset.rows) m.rows = Number(n.dataset.rows); else delete m.rows;
      if (n.dataset.row !== undefined) m.row = Number(n.dataset.row); else delete m.row;
      wins.push(m);
    }
    if (!wins.length && !colEl.querySelector(".cl-slot")) { colEl.remove(); continue; }
    const half = colEl.dataset.half;
    cols.push({ id: colEl.dataset.id ?? `c${++cx.state.serial}`, w: Number(colEl.dataset.w) || cx.state.metrics.colW, ...(half ? { half } : {}), wins });
  }
  return cols;
}

/**
 * Makes the DOM agree with the model: groups are wrapped (and unwrapped) as the runs say, each group gets its grid, and
 * every window gets its placement or its own height. Writes the settled spans and bands back into the model.
 */
export function arrange(cx: Ctx, c: ViewRec, cols: ColumnModel[]): void {
  const els = columnEls(c.colsEl);
  const settled = settle(cols);
  const runs = runsOf(settled);
  const items: HTMLElement[] = [];
  const wrappers = new Map<Run, HTMLElement>();
  for (const run of runs) {
    const want = els.slice(run.from, run.to + 1);
    if (run.to === run.from) { items.push(want[0]!); continue; }
    // A group that already holds exactly these columns (possibly with a column just added beside them) is kept as it is:
    // re-parenting a column moves its terminals, so it happens only when a group is made.
    let g = want[0]!.parentElement;
    const reuse = !!g?.classList.contains("cl-group") && want.every((e) => e.parentElement === g);
    if (!reuse) {
      g = el("div", "cl-group");
      for (const e of want) g.append(e);
    }
    for (const extra of [...g!.children]) if (!want.includes(extra as HTMLElement)) c.colsEl.insertBefore(extra, g!);
    wrappers.set(run, g!);
    items.push(g!);
  }
  // The top-level order: plain columns and groups, as the model lists them. Only the items out of place are moved.
  let cursor: Element | null = c.colsEl.firstElementChild;
  for (const it of items) {
    if (it === cursor) { cursor = cursor.nextElementSibling; continue; }
    c.colsEl.insertBefore(it, cursor);
  }
  for (const g of [...c.colsEl.querySelectorAll<HTMLElement>(":scope > .cl-group")]) if (!items.includes(g) || !g.childElementCount) g.remove();

  // Plain columns: the flex stack, each window with its own height and no placement.
  for (const run of runs) {
    if (run.to !== run.from) continue;
    for (const w of settled[run.from]!.wins) {
      const m = c.wins.get(w.id)?.model;
      const root = c.wins.get(w.id)?.card.root;
      if (!m || !root) continue;
      delete m.span; delete m.rows; delete m.row;
      put(root, "gridColumn", ""); put(root, "gridRow", "");
      put(root, "height", heightStyle(m.h)); put(root, "flex", m.h === undefined ? "" : "none");
      markWin(root, m, false);
    }
  }
  // Groups: one grid per run, tracks from the widths and bands, every window placed by its span and band.
  for (const run of runs) {
    if (run.to === run.from) continue;
    const g = wrappers.get(run)!;
    const cols = settled.slice(run.from, run.to + 1);
    const total = cols.reduce((sum, col) => sum + col.w, 0) + COLUMN_GAP * (cols.length - 1);
    put(g, "width", `${total + SIDE}px`);
    put(g, "gridTemplateColumns", cols.map((col) => `${col.w}px`).join(" "));
    const bands = bandHeights(settled, run);
    put(g, "gridTemplateRows", Array.from({ length: run.rows }, (_, r) => bandTrack(bands[r])).join(" "));
    cols.forEach((col, j) => {
      for (const w of col.wins) {
        const rec = c.wins.get(w.id);
        if (!rec) continue;
        const m = rec.model;
        m.row = w.row;
        if (w.span > 1) m.span = w.span; else delete m.span;
        if (w.rows > 1) m.rows = w.rows; else delete m.rows;
        const root = rec.card.root;
        put(root, "gridColumn", `${j + 1} / span ${w.span}`);
        put(root, "gridRow", `${w.row + 1} / span ${w.rows}`);
        put(root, "height", ""); put(root, "flex", "");
        markWin(root, m, true);
      }
    });
  }
}

/**
 * Writes a model change into the DOM (a split, a close, a move that the grid decided): the columns take the model's
 * order, widths and halves, every window moves into its column and takes its span, band and height. The caller plays
 * the motion and then calls `geometry` to read it back.
 */
export function applyCols(cx: Ctx, c: ViewRec, cols: ColumnModel[]): void {
  // The window models take the given heights, spans and bands first: `arrange` reads them, and a stale model would undo the change.
  for (const col of cols) for (const m of col.wins) {
    const rec = c.wins.get(m.id);
    if (!rec || rec.model === m) continue;
    if (m.h !== undefined) rec.model.h = m.h; else delete rec.model.h;
    if (m.span !== undefined && m.span > 1) rec.model.span = m.span; else delete rec.model.span;
    if (m.rows !== undefined && m.rows > 1) rec.model.rows = m.rows; else delete rec.model.rows;
    if (m.row !== undefined) rec.model.row = m.row; else delete rec.model.row;
  }
  const kept = new Set(cols.map((col) => col.id));
  // Each column, in the model's order. A column that is new is inserted right after the one before it, so the columns
  // that are already in place are never re-parented (a column move re-parents its terminals: expensive, see `arrange`).
  let anchor: HTMLElement | undefined;
  for (const col of cols) {
    let colEl = columnEls(c.colsEl).find((e) => e.dataset.id === col.id);
    if (!colEl) {
      colEl = cx.view.newCol({ id: col.id, w: col.w, wins: [] });
      if (anchor) anchor.after(colEl);
      else { const first = columnEls(c.colsEl)[0]; if (first) first.before(colEl); else c.colsEl.append(colEl); }
    }
    anchor = colEl;
    colEl.dataset.w = String(col.w);
    colEl.style.setProperty("--w", `${col.w}px`);
    if (col.half) colEl.dataset.half = col.half; else delete colEl.dataset.half;
    // Windows in the column's order: a window already in place is not moved.
    let prev: Element | null = null;
    for (const m of col.wins) {
      const rec = c.wins.get(m.id);
      if (!rec) continue;
      const root = rec.card.root;
      const want: ChildNode | null = prev ? prev.nextSibling : colEl.firstChild;
      if (root.parentElement !== colEl || root !== want) colEl.insertBefore(root, want);
      prev = root;
    }
  }
  // Columns the model no longer has leave the DOM once their windows have moved out of them.
  for (const colEl of columnEls(c.colsEl)) if (!kept.has(colEl.dataset.id ?? "")) colEl.remove();
  arrange(cx, c, cols);
}

/**
 * The model a grid operation produced, written back into the window models (heights, spans, bands), ready for
 * `applyCols`. A window the operation did not know about keeps its model untouched.
 */
export function fromGrid(c: ViewRec, cols: readonly Col[]): ColumnModel[] {
  return cols.map((col) => ({
    id: col.id, w: col.w, ...(col.half !== undefined ? { half: col.half } : {}),
    wins: col.wins.flatMap((w): WindowModel[] => {
      const rec = c.wins.get(w.id);
      if (!rec) return [];
      const m = rec.model;
      if (w.h !== undefined) m.h = w.h; else delete m.h;
      if (w.span > 1) m.span = w.span; else delete m.span;
      if (w.rows > 1) m.rows = w.rows; else delete m.rows;
      m.row = w.row;
      return [m];
    }),
  }));
}
