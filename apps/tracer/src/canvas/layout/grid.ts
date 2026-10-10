/**
 * The grid of a tiled view's windows (D212): columns stay as they are, and a window may cover several of them.
 *
 * Model (pure, no DOM, so the rules can be tested alone):
 * - A column is an ordered list of windows that start in it. A window covers `span` consecutive columns from its
 *   own, and `rows` row bands from its own `row`. A window with span 1 and rows 1 is a plain stacked window.
 * - A **group** is a maximal run of adjacent columns linked by at least one window with span > 1. Columns outside
 *   any group are plain flex stacks in the DOM and never reach this module's grid rendering (see views/world.ts).
 * - Inside a group the rows are shared: every column of the group is cut by the same row bands, so a spanning window
 *   is level with its neighbours. Band heights come from the explicit `h` of the single-band windows in that band;
 *   a band without one takes an equal share of what is left (`1fr`), as a flat column does.
 *
 * Invariants (checked by `problems`, and by the tests):
 * - Every cell of a group (row band x column) is covered by exactly one window. No gaps, no overlaps.
 * - A column's windows are listed in row order.
 * - A column that no window starts in and no window crosses is removed, and its width goes to its half partner (or
 *   the column on its left), so a closed split gives back exactly what it took.
 *
 * Operations take columns, return new columns (the input is never mutated) and always end in `settle`, so a
 * result is never half-placed. `row` is explicit after `settle`; a window that has none gets the first free band at
 * or below its predecessor in the list (the order a document or an older layout implies).
 */

/** A window as the grid sees it. `span` and `rows` are at least 1; `row` is the band it starts in (explicit after settle). */
export interface Win { id: string; span: number; rows: number; row: number; h?: number }
/** A column: its width, its split pair (`half`, the id both halves of one split share) and the windows that start in it. */
export interface Col { id: string; w: number; half?: string; wins: Win[] }
/** A run of adjacent columns: `from..to` inclusive, `rows` bands tall. A run of one column is not a group. */
export interface Run { from: number; to: number; rows: number }

/** Input before settling: `row`, `span`, `rows` may be missing or out of range. */
export interface WinIn { id: string; span?: number; rows?: number; row?: number; h?: number }
export interface ColIn { id: string; w: number; half?: string; wins: WinIn[] }

const whole = (v: number | undefined, lo: number): number => (typeof v === "number" && Number.isFinite(v) ? Math.max(lo, Math.floor(v)) : lo);

/**
 * Settles columns: clamps spans to the columns that exist, keeps every explicit `row` that still fits, and places the
 * rest greedily in list order. Returns new columns. Runs are recomputed from the spans, so the result is always the
 * one grid those windows describe.
 */
export function settle(input: readonly ColIn[]): Col[] {
  const n = input.length;
  const cols: Col[] = input.map((c, i) => ({
    id: c.id, w: c.w, ...(c.half !== undefined ? { half: c.half } : {}),
    wins: c.wins.map((w): Win => ({
      id: w.id,
      span: Math.min(whole(w.span, 1), Math.max(1, n - i)),
      rows: whole(w.rows, 1),
      // -1 means "not placed yet": pass 2 finds its band.
      row: typeof w.row === "number" && Number.isFinite(w.row) && w.row >= 0 ? Math.floor(w.row) : -1,
      ...(w.h !== undefined ? { h: w.h } : {}),
    })),
  }));
  const runs = runsOf(cols);
  for (const run of runs) {
    const taken = new Set<string>();
    const key = (c: number, r: number): string => `${c}:${r}`;
    const free = (c: number, r: number, span: number, rows: number): boolean => {
      for (let x = c; x < c + span; x++) for (let y = r; y < r + rows; y++) if (taken.has(key(x, y))) return false;
      return true;
    };
    const mark = (c: number, r: number, span: number, rows: number): void => {
      for (let x = c; x < c + span; x++) for (let y = r; y < r + rows; y++) taken.add(key(x, y));
    };
    // Pass 1: every explicit row that is still free keeps its band.
    for (let i = run.from; i <= run.to; i++) {
      for (const w of cols[i]!.wins) if (w.row >= 0 && free(i, w.row, w.span, w.rows)) mark(i, w.row, w.span, w.rows); else w.row = -1;
    }
    // Pass 2: the rest, column by column in list order; a placed window moves the cursor past itself.
    for (let i = run.from; i <= run.to; i++) {
      let cursor = 0;
      for (const w of cols[i]!.wins) {
        if (w.row < 0) {
          let r = cursor;
          while (!free(i, r, w.span, w.rows)) r++;
          w.row = r;
          mark(i, r, w.span, w.rows);
        }
        cursor = Math.max(cursor, w.row + w.rows);
      }
    }
  }
  return cols;
}

/** The runs of columns: a group is a run of more than one column; the rest are single columns (a flat stack). */
export function runsOf(cols: readonly { wins: readonly { span: number }[] }[] | readonly ColIn[]): Run[] {
  const n = cols.length;
  const reach = cols.map((_, i) => i);
  cols.forEach((c, i) => {
    for (const w of c.wins as readonly { span?: number }[]) reach[i] = Math.max(reach[i]!, Math.min(n - 1, i + whole(w.span, 1) - 1));
  });
  const runs: Run[] = [];
  for (let i = 0; i < n;) {
    let end = reach[i]!;
    for (let k = i; k <= end; k++) end = Math.max(end, reach[k]!);
    runs.push({ from: i, to: end, rows: 0 });
    i = end + 1;
  }
  for (const run of runs) {
    let rows = 0;
    for (let i = run.from; i <= run.to; i++) for (const w of cols[i]!.wins as readonly { row?: number; rows?: number }[]) rows = Math.max(rows, (w.row ?? 0) + whole(w.rows, 1));
    run.rows = rows;
  }
  return runs;
}

/** The group a column belongs to (a run of more than one column), if any. */
export function groupOf(runs: readonly Run[], col: number): Run | undefined {
  return runs.find((r) => col >= r.from && col <= r.to && r.to > r.from);
}

/** Locates a window: its column index and its position in that column's list. */
export function locate(cols: readonly Col[], id: string): { col: number; at: number } | undefined {
  for (let i = 0; i < cols.length; i++) {
    const at = cols[i]!.wins.findIndex((w) => w.id === id);
    if (at >= 0) return { col: i, at };
  }
  return undefined;
}

/** Inserts a window into a column's list at its row position, so the list stays in row order. */
function insertSorted(list: Win[], w: Win): void {
  const at = list.findIndex((x) => x.row > w.row);
  if (at < 0) list.push(w); else list.splice(at, 0, w);
}

const copy = (cols: readonly Col[]): Col[] => cols.map((c) => ({ ...c, wins: c.wins.map((w) => ({ ...w })) }));

/**
 * Split right (D212). A window that spans columns halves its span: the right half becomes a new window in the column
 * it reaches, on its own band; nothing else moves. A plain window divides its column in two (`gap` between the halves,
 * the total width unchanged); every other window that covers the column is widened to cover the new half, so the
 * windows above and below keep their bands. The new window sits on the band of the window it came from.
 */
export function splitRight(cols: readonly ColIn[], id: string, next: { id: string; colId: string; pair: string }, gap: number): Col[] {
  const c = copy(settle(cols));
  const at = locate(c, id);
  if (!at) return c;
  const W = c[at.col]!.wins[at.at]!;
  if (W.span >= 2) {
    const a = Math.ceil(W.span / 2);
    const N: Win = { id: next.id, span: W.span - a, rows: W.rows, row: W.row, ...(W.h !== undefined ? { h: W.h } : {}) };
    W.span = a;
    insertSorted(c[at.col + a]!.wins, N);
    return settle(c);
  }
  const X = at.col;
  for (let j = 0; j < c.length; j++) for (const v of c[j]!.wins) if (v.id !== id && j <= X && X < j + v.span) v.span += 1;
  const total = c[X]!.w;
  const w1 = Math.round((total - gap) / 2);
  c[X]!.w = w1;
  c[X]!.half = next.pair;
  const N: Win = { id: next.id, span: 1, rows: W.rows, row: W.row, ...(W.h !== undefined ? { h: W.h } : {}) };
  c.splice(X + 1, 0, { id: next.colId, w: total - gap - w1, half: next.pair, wins: [N] });
  return settle(c);
}

/**
 * Inserts a window as a new band at `rowAt`, over the columns `col .. col + span - 1` (D212). Windows that start at or below
 * `rowAt` move down one band. A window that covers the boundary above `rowAt` outside those columns grows by one band, so
 * the windows beside the new one keep their height. The caller picks a `rowAt` where the other columns of the group reach
 * the boundary: inside a group that is any band boundary, and a new band at the group's top or bottom must span every column.
 * Used by split down (at the window's bottom), by new window below, and by a window moved into a column.
 */
export function insertBand(cols: readonly ColIn[], col: number, rowAt: number, next: { id: string; span: number; h?: number | undefined }): Col[] {
  const c = copy(settle(cols));
  const run = runOf(c, col);
  const span = Math.max(1, next.span);
  for (let j = run.from; j <= run.to; j++) {
    for (const v of c[j]!.wins) {
      if (v.row >= rowAt) { v.row += 1; continue; }
      // A window that covers the boundary grows, unless it stands in the new band's columns: those are its neighbours.
      const overlaps = j < col + span && col < j + v.span;
      if (v.row + v.rows >= rowAt && !overlaps) v.rows += 1;
    }
  }
  const N: Win = { id: next.id, span: Math.max(1, next.span), rows: 1, row: rowAt, ...(next.h !== undefined ? { h: next.h } : {}) };
  insertSorted(c[col]!.wins, N);
  return settle(c);
}

/**
 * Split down (D212): the window keeps its columns and the upper part of its band; a new window of the same span takes
 * the lower part, right under it. Windows below move down one band, and the windows around grow as `insertBand` says.
 * `h1`/`h2`: the two heights (px) when the caller knows them; undefined leaves each window to share its band.
 */
export function splitDown(cols: readonly ColIn[], id: string, next: { id: string }, h1: number | undefined, h2: number | undefined): Col[] {
  const at = locate(settle(cols), id);
  if (!at) return settle(cols);
  const W = settle(cols)[at.col]!.wins[at.at]!;
  const withHeight = cols.map((col) => ({ ...col, wins: col.wins.map((w) => (w.id === id && h1 !== undefined ? { ...w, h: h1 } : w)) }));
  return insertBand(withHeight, at.col, W.row + W.rows, { id: next.id, span: W.span, h: h2 });
}

/**
 * New window right (D212): a full-size column after the window's group, or after the window when it stands alone. It
 * never divides anything, and nothing spans the new boundary.
 */
export function newRight(cols: readonly ColIn[], id: string, next: { id: string; colId: string }, w: number): Col[] {
  const c = copy(settle(cols));
  const at = locate(c, id);
  if (!at) return c;
  const after = runOf(c, at.col).to;
  c.splice(after + 1, 0, { id: next.colId, w, wins: [{ id: next.id, span: 1, rows: 1, row: 0 }] });
  return settle(c);
}

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

/** The heights of a group's bands: a band with a single-band window that has an `h` is that height; otherwise `undefined` (a `1fr` share). */
export function bandHeights(cols: readonly Col[], run: Run): (number | undefined)[] {
  const out: (number | undefined)[] = new Array(run.rows).fill(undefined);
  for (let j = run.from; j <= run.to; j++) for (const v of cols[j]!.wins) if (v.rows === 1 && v.h !== undefined && out[v.row] === undefined) out[v.row] = v.h;
  return out;
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

/** The run that holds a column index (a single column when it is plain). */
export function runOf(cols: readonly { wins: readonly { span: number }[] }[] | readonly Col[], col: number): Run {
  return runsOf(cols as readonly ColIn[]).find((r) => col >= r.from && col <= r.to) ?? { from: col, to: col, rows: 1 };
}
