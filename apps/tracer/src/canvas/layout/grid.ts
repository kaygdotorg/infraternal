/**
 * The grid of a tiled view's windows (D212): columns stay as they are, and a window may cover several of them.
 *
 * Model (pure, no DOM, so the rules can be tested alone):
 * - A column is an ordered list of windows that start in it. A window covers `span` consecutive columns from its
 *   own, and `rows` row bands from its own `row`. A window with span 1 and rows 1 is a plain stacked window.
 * - A **group** is a maximal run of adjacent columns that are linked: by at least one window with span > 1, or by naming the
 *   same `group` (a row group, D212 amendment 2026-11-03: Settings is one row of windows for each component, and the rows scroll
 *   together). Columns outside any group are plain flex stacks in the DOM and never reach this module's grid rendering
 *   (see views/world.ts).
 * - Inside a group the rows are shared: every column of the group is cut by the same row bands, so a spanning window
 *   is level with its neighbours. Band heights come from the explicit `h` of the single-band windows in that band;
 *   a band without one takes an equal share of what is left (`1fr`), as a flat column does.
 *
 * Invariants (checked by `problems` in groups.on-demand.ts, and by the tests):
 * - A cell of a group (row band x column) is covered by at most one window: no overlaps. In a group made by spans every cell is
 *   covered, no gaps. A row group may have empty cells (a row with fewer windows than the longest one ends early); nothing
 *   spans to fill them.
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
export interface Col { id: string; w: number; half?: string; group?: string; wins: Win[] }
/** A run of adjacent columns: `from..to` inclusive, `rows` bands tall. A run of one column is not a group. */
export interface Run { from: number; to: number; rows: number }

/** Input before settling: `row`, `span`, `rows` may be missing or out of range. */
export interface WinIn { id: string; span?: number; rows?: number; row?: number; h?: number }
export interface ColIn { id: string; w: number; half?: string; group?: string; wins: WinIn[] }

const whole = (v: number | undefined, lo: number): number => (typeof v === "number" && Number.isFinite(v) ? Math.max(lo, Math.floor(v)) : lo);

/**
 * Settles columns: clamps spans to the columns that exist, keeps every explicit `row` that still fits, and places the
 * rest greedily in list order. Returns new columns. Runs are recomputed from the spans, so the result is always the
 * one grid those windows describe.
 */
export function settle(input: readonly ColIn[]): Col[] {
  const n = input.length;
  const cols: Col[] = input.map((c, i) => ({
    id: c.id, w: c.w, ...(c.half !== undefined ? { half: c.half } : {}), ...(c.group !== undefined ? { group: c.group } : {}),
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

/**
 * The runs of columns: a group is a run of more than one column; the rest are single columns (a flat stack). Two adjacent columns
 * are one run when a window of the first spans into the second, or when both name the same `group`.
 */
export function runsOf(cols: readonly { wins: readonly { span: number }[]; group?: string }[] | readonly ColIn[]): Run[] {
  const n = cols.length;
  const reach = cols.map((_, i) => i);
  cols.forEach((c, i) => {
    for (const w of c.wins as readonly { span?: number }[]) reach[i] = Math.max(reach[i]!, Math.min(n - 1, i + whole(w.span, 1) - 1));
    if (c.group !== undefined && cols[i + 1]?.group === c.group) reach[i] = Math.max(reach[i]!, i + 1);
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
export function insertSorted(list: Win[], w: Win): void {
  const at = list.findIndex((x) => x.row > w.row);
  if (at < 0) list.push(w); else list.splice(at, 0, w);
}

export const copy = (cols: readonly Col[]): Col[] => cols.map((c) => ({ ...c, wins: c.wins.map((w) => ({ ...w })) }));

/**
 * Split right (D212). A window that spans columns halves its span: the right half becomes a new window in the column
 * it reaches, on its own band; nothing else moves. A plain window divides its column in two (`gap` between the halves,
 * the total width unchanged); every other window that covers the column is widened to cover the new half, so the
 * windows above and below keep their bands. The new window sits on the band of the window it came from.
 */
export function splitRight(cols: readonly ColIn[], id: string, next: { id: string; colId: string; pair: string }, gap: number, minimumWidth = 0): Col[] {
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
  // At the canonical weight floor a split grows the footprint enough to keep both windows.
  const w1 = Math.max(minimumWidth, Math.round((total - gap) / 2));
  c[X]!.w = w1;
  c[X]!.half = next.pair;
  const N: Win = { id: next.id, span: 1, rows: W.rows, row: W.row, ...(W.h !== undefined ? { h: W.h } : {}) };
  c.splice(X + 1, 0, { id: next.colId, w: Math.max(minimumWidth, total - gap - w1), half: next.pair, ...(c[X]!.group !== undefined ? { group: c[X]!.group } : {}), wins: [N] });
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

/** The heights of a group's bands: a band with a single-band window that has an `h` is that height; otherwise `undefined` (a `1fr` share). */
export function bandHeights(cols: readonly Col[], run: Run): (number | undefined)[] {
  const out: (number | undefined)[] = new Array(run.rows).fill(undefined);
  for (let j = run.from; j <= run.to; j++) for (const v of cols[j]!.wins) if (v.rows === 1 && v.h !== undefined && out[v.row] === undefined) out[v.row] = v.h;
  return out;
}

/** The run that holds a column index (a single column when it is plain). */
export function runOf(cols: readonly { wins: readonly { span: number }[] }[] | readonly Col[], col: number): Run {
  return runsOf(cols as readonly ColIn[]).find((r) => col >= r.from && col <= r.to) ?? { from: col, to: col, rows: 1 };
}
