/**
 * The grouped layout, on demand (D212, D188): everything a group of columns needs and a plain view never does.
 *
 * - The DOM of a group (`readColumns`, `arrange`, `applyCols`, `fromGrid`): one grid per group, read back from the DOM
 *   and written from the model (views/world.ts, windows/lifecycle.ts, windows/move.on-demand.ts).
 * - The rules that change a group (`splitRight`, `splitDown`, `newRight`, `removeWin`, the landing of a grouped move, and
 *   `problems`, the check every rule holds). The pure rules are in layout/grid.ts.
 *
 * A plain view never loads this module. A view that holds a group does: a document with a group loads it before its
 * views are built (product.ts), a stacked split right loads it before the split (lifecycle.ts), and the module registers
 * itself with layout/groups-handle.ts when it evaluates, so every path that loads it sees the same instance. A group's DOM
 * exists only after this module has run, so a caller that finds a group can use `groupsLoaded()` without waiting.
 */
import { COLUMN_GAP, drawnWidth } from "./geometry";
import { columnEls, setColumnWidth } from "./column-els";
import { bandHeights, copy, insertBand, insertSorted, locate, newRight, runOf, runsOf, settle, splitDown, splitRight, type Col, type ColIn, type Run, type Win } from "./grid";
import { registerGroups } from "./groups-handle";
import type { Ctx, ViewRec } from "../context";
import type { ColumnModel, WindowModel } from "../model/types";

/** A group's padding and margin: the same 14 px a column has around its windows, so its tracks line up with plain columns. */
const PAD = 14;
const SIDE = PAD * 2;

/**
 * A row band's track. A band with its own height is a fixed track (`max` pins it: `minmax` would let the browser shrink it
 * to whatever is free, which is not what the person set); a band without one shares what is left equally (`1fr`).
 * Overflow scrolls the group, as an overfull plain column does.
 */
function bandTrack(h: number | undefined): string {
  // The floor is the window's own `min-height` (clusters.css, `.cl-group > .cl-col > .ui-window`: 10rem), so a row is never
  // shorter than the window it holds. It was 160px, which equals 10rem only at a 16 px root; at the desktop base (#283: 110 %)
  // the window drew 176 px in a 160 px row, and two bands split down in a group overlapped each other and the window below.
  if (h === undefined) return "minmax(10rem, 1fr)";
  return `max(10rem, ${h <= 1 ? `calc(var(--clh) * ${h})` : `${h}px`})`;
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
      g = Object.assign(document.createElement("div"), { className: "cl-group" });
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
    // The tracks are drawn widths: a touch screen's floor widens them, the saved widths (`col.w`) stay as they are.
    const drawn = cols.map((col) => drawnWidth(col.w, cx.state.metrics));
    const total = drawn.reduce((sum, w) => sum + w, 0) + COLUMN_GAP * (cols.length - 1);
    put(g, "width", `${total + SIDE}px`);
    put(g, "gridTemplateColumns", drawn.map((w) => `${w}px`).join(" "));
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
    setColumnWidth(colEl, col.w, cx.state.metrics);
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

/** Every rule the grid must hold, as messages (empty when it holds). Used by the tests and by the DOM sync in development. */
export function problems(cols: readonly Col[]): string[] {
  const out: string[] = [];
  for (const run of runsOf(cols)) {
    const cover = new Map<string, number>();
    for (let j = run.from; j <= run.to; j++) {
      for (const v of cols[j]!.wins) {
        if (v.span < 1 || v.rows < 1) out.push(`${v.id} has an empty span or band`);
        if (j + v.span - 1 > run.to) out.push(`${v.id} leaves its group`);
        for (let x = j; x < j + v.span; x++) for (let y = v.row; y < v.row + v.rows; y++) cover.set(`${x}:${y}`, (cover.get(`${x}:${y}`) ?? 0) + 1);
      }
      const rows = cols[j]!.wins.map((v) => v.row);
      if (rows.some((r, i) => i > 0 && r < rows[i - 1]!)) out.push(`column ${cols[j]!.id} is not in row order`);
    }
    // Every cell of every run is covered once: a plain column has no gaps either.
    for (let j = run.from; j <= run.to; j++) for (let y = 0; y < run.rows; y++) {
      const n = cover.get(`${j}:${y}`) ?? 0;
      if (n !== 1) out.push(`cell ${j}:${y} is covered ${n} times`);
    }
  }
  return out;
}

/**
 * Where a window dropped on a grid lands (D212): the layout it was taken from, without it (its space given to its
 * neighbours, as a close does), with it inserted as a new band of the column the slot is in, above the window that is
 * below the slot. A slot in a new column makes a plain column at that place. Returns nothing when no valid place
 * exists, and the window goes back where it was.
 */
/**
 * `cols0` is the view as it stood at the grab, `gap` the column gap, `newId` a fresh column id. The DOM is read only for the
 * slot: the column it sits in, the window below it and the column order, so this module stays free of the DOM setup.
 */
export function landing(input: { cols0: readonly ColumnModel[]; gap: number; id: string; root: HTMLElement; h: number; w: number; view: HTMLElement; newId: () => string; slot: HTMLElement }): Col[] | undefined {
  const { cols0, gap, id, root, h, w, view, newId, slot } = input;
  const grid0 = { cols: [...cols0] as ColIn[], w, h };
  const base = removeWin(grid0.cols, id, gap);
  const colEl = slot.parentElement as HTMLElement | null;
  if (!colEl) return undefined;
  const slotTop = slot.getBoundingClientRect().top;
  const below = [...colEl.querySelectorAll<HTMLElement>(":scope > .ui-window")]
    .filter((n) => n !== root && n.getBoundingClientRect().top > slotTop)
    .map((n) => n.dataset.windowId);
  const next: Col[] = [...base];
  const N = { id, span: 1, rows: 1, row: 0, h: grid0.h > 0 ? grid0.h : undefined };
  const at = next.findIndex((col) => col.id === colEl.dataset.id);
  let out: Col[];
  if (at >= 0) {
    const col = next[at]!;
    const belowWin = below.map((b) => col.wins.find((w) => w.id === b)).find((w) => w !== undefined);
    const bottom = Math.max(0, ...col.wins.map((w) => w.row + w.rows));
    const runRows = Math.max(0, ...next.flatMap((x) => x.wins.map((w) => w.row + w.rows)));
    const rowAt = belowWin ? belowWin.row : bottom || runRows;
    out = insertBand(next, at, rowAt, { id, span: 1, h: N.h });
  } else {
    // A new column: it takes its place among the columns, by where its element stands in the view.
    const els = [...view.querySelectorAll<HTMLElement>(":scope > .cl-col, :scope > .cl-group > .cl-col")];
    const pos = els.indexOf(colEl);
    const before = els.slice(0, pos).map((e) => e.dataset.id);
    const index = next.filter((col) => before.includes(col.id)).length;
    const colId = colEl.dataset.id ?? newId();
    const fresh: Col = { id: colId, w: grid0.w, wins: [{ id, span: 1, rows: 1, row: 0, ...(N.h !== undefined ? { h: N.h } : {}) }] };
    next.splice(index, 0, fresh);
    out = settle(next);
  }
  return problems(out).length ? undefined : out;
}

// ---- removing a window (a grouped close, D212) ----
/** A window's rectangle in grid cells, inclusive: columns `c0..c1`, bands `r0..r1`. */
interface Rect { c0: number; c1: number; r0: number; r1: number }

/**
 * Removes a window (D212). Its cells are given to the windows around them: each freed cell goes to a neighbour whose
 * bounding box grows over it, but only over cells that are free, so every window stays a rectangle. A window that
 * grows over a band it did not own takes that band's share of the height (its `h` grows by the removed window's `h`).
 * Then columns and bands that nothing starts in or crosses are removed, so a closed split leaves the layout it came
 * from: closing the right half returns the width to the left half, and a window that spanned into it drops back.
 */
export function removeWin(cols: readonly ColIn[], id: string, gap: number): Col[] {
  const c = copy(settle(cols));
  const at = locate(c, id);
  if (!at) return c;
  const W = c[at.col]!.wins[at.at]!;
  // The run as it was: a spanning window's freed columns belong to the group it linked, even once it is gone.
  const was = runOf(c, at.col);
  c[at.col]!.wins.splice(at.at, 1);
  fillFreed(c, at.col, W, was);
  return normalize(c, gap);
}

/** The rectangle of every window, by id. */
function rectsOf(c: readonly Col[]): Map<string, Rect> {
  const out = new Map<string, Rect>();
  c.forEach((col, j) => col.wins.forEach((v) => out.set(v.id, { c0: j, c1: j + v.span - 1, r0: v.row, r1: v.row + v.rows - 1 })));
  return out;
}

/**
 * Gives every freed cell of the removed window (it stood in column `wc`) to a neighbour whose bounding box can grow over
 * it without covering a window. Cells are taken in reading order, so the result does not depend on list order.
 */
function fillFreed(c: Col[], wc: number, W: Win, run: Run): void {
  const rects = rectsOf(c);
  const owner = new Map<string, string>();
  for (const [vid, r] of rects) for (let x = r.c0; x <= r.c1; x++) for (let y = r.r0; y <= r.r1; y++) owner.set(`${x}:${y}`, vid);
  const rows = Math.max(run.rows, W.row + W.rows);
  const freed = new Set<string>();
  for (let y = W.row; y < W.row + W.rows; y++) for (let x = wc; x < wc + W.span; x++) freed.add(`${x}:${y}`);
  // Each pass takes the neighbour that absorbs the most freed cells, so one window cannot take the cells another needs.
  // Passes repeat until nothing moves: a window grows along the freed band one neighbour at a time.
  for (let progress = true; progress;) {
    progress = false;
    let best: { vid: string; nb: Rect; gain: number; r: Rect } | undefined;
    for (const [vid, r] of rects) {
      // Candidate boxes: the window's box grown to take one free cell beside it, for every free cell beside it.
      for (let y = 0; y < rows; y++) for (let x = run.from; x <= run.to; x++) {
        if (owner.has(`${x}:${y}`) || !freed.has(`${x}:${y}`)) continue;
        const adjacent = (x === r.c0 - 1 || x === r.c1 + 1) && y >= r.r0 && y <= r.r1 || (y === r.r0 - 1 || y === r.r1 + 1) && x >= r.c0 && x <= r.c1;
        if (!adjacent) continue;
        const nb: Rect = { c0: Math.min(r.c0, x), c1: Math.max(r.c1, x), r0: Math.min(r.r0, y), r1: Math.max(r.r1, y) };
        if (nb.c0 < run.from || nb.c1 > run.to || nb.r0 < 0 || nb.r1 >= rows) continue;
        let clear = true, gain = 0;
        for (let u = nb.c0; u <= nb.c1 && clear; u++) for (let v = nb.r0; v <= nb.r1 && clear; v++) {
          const o = owner.get(`${u}:${v}`);
          if (o !== undefined && o !== vid) clear = false;
          else if (o === undefined && freed.has(`${u}:${v}`)) gain++;
        }
        if (!clear || gain === 0) continue;
        if (!best || gain > best.gain) best = { vid, nb, gain, r };
      }
    }
    if (!best) break;
    const { vid, nb, r } = best;
    for (let u = nb.c0; u <= nb.c1; u++) for (let v = nb.r0; v <= nb.r1; v++) owner.set(`${u}:${v}`, vid);
    // A window that grows down or up by the freed band takes that band's height as well.
    const grew = nb.r1 - nb.r0 - (r.r1 - r.r0);
    if (nb.c0 === r.c0 && nb.c1 === r.c1 && grew === W.rows && W.h !== undefined) {
      const w = c.flatMap((col) => col.wins).find((x2) => x2.id === vid)!;
      if (w.h !== undefined) w.h += W.h;
    }
    rects.set(vid, nb);
    applyRect(c, vid, nb);
    progress = true;
  }
}

/** Writes a window's rectangle back into the columns: it moves to the column it now starts in. */
function applyRect(c: Col[], id: string, r: Rect): void {
  const at = locate(c, id);
  if (!at) return;
  const [w] = c[at.col]!.wins.splice(at.at, 1);
  w!.span = r.c1 - r.c0 + 1;
  w!.row = r.r0;
  w!.rows = r.r1 - r.r0 + 1;
  insertSorted(c[r.c0]!.wins, w!);
}

/** Removes empty columns and unused band boundaries until nothing is left to remove. */
function normalize(input: Col[], gap: number): Col[] {
  let c = input;
  for (let guard = 0; guard < 256; guard++) {
    c = settle(c);
    let changed = false;
    for (let j = c.length - 1; j >= 0 && !changed; j--) {
      if (c[j]!.wins.length) continue;
      // Windows that start left of the empty column and reach past it are the ones that cross it.
      let crossed = false;
      for (let k = 0; k < j; k++) for (const v of c[k]!.wins) if (k + v.span > j) { crossed = true; v.span -= 1; }
      const gone = c[j]!;
      const partner = gone.half !== undefined ? c.findIndex((x, k) => k !== j && x.half === gone.half) : -1;
      // The width of a closed half goes back to its partner; a column that was crossed hands its width to a neighbour.
      if (partner >= 0) c[partner]!.w += gone.w + gap;
      else if (crossed && j > 0) c[j - 1]!.w += gone.w + gap;
      else if (crossed && j + 1 < c.length) c[j + 1]!.w += gone.w + gap;
      c.splice(j, 1);
      changed = true;
    }
    if (changed) continue;
    for (const run of runsOf(c)) {
      for (let L = 1; L < run.rows && !changed; L++) {
        let used = false;
        for (let j = run.from; j <= run.to && !used; j++) for (const v of c[j]!.wins) if (v.row === L || v.row + v.rows === L) { used = true; break; }
        if (used) continue;
        for (let j = run.from; j <= run.to; j++) for (const v of c[j]!.wins) {
          if (v.row >= L) v.row -= 1;
          else if (v.row + v.rows > L) v.rows -= 1;
        }
        changed = true;
      }
      if (changed) break;
    }
    if (!changed) break;
  }
  return settle(c);
}


/** The grouped layout's functions, as the caller sees them through `groupsLoaded()` / `loadGroups()`. */
export const groups = { readColumns, arrange, applyCols, fromGrid, settle, runsOf, splitRight, splitDown, newRight, removeWin, landing, problems };
registerGroups(groups);
