/**
 * Dropping a window of a group on a grid (D212), loaded only when that happens (D188): the grid's rules are in layout/grid.ts
 * and stay in the canvas bundle; the place a dropped window lands and the check that the result holds every rule are
 * needed only by a grouped move, so they load with the first one. The check is also the test oracle for the grid.
 */
import type { ColumnModel } from "../model/types";
import { insertBand, removeWin, runsOf, settle, type Col, type ColIn } from "./grid";

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
