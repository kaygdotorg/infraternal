/**
 * Dropping a window of a group on a grid (D212), loaded only when that happens (D188): the grid's rules are in layout/grid.ts
 * and stay in the canvas bundle; the place a dropped window lands and the check that the result holds every rule are
 * needed only by a grouped move, so they load with the first one. The check is also the test oracle for the grid.
 */
import type { ColumnModel } from "../model/types";
import { copy, insertBand, insertSorted, locate, runOf, runsOf, settle, type Col, type ColIn, type Run, type Win } from "./grid";

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

