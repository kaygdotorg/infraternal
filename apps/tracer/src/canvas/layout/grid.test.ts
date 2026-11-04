/** The grid of a tiled view (D212): groups, split right and down, closing back to the original layout, and the invariants. */
import { expect, test } from "bun:test";
import { insertBand, runsOf, settle, splitDown, splitRight, newRight, type ColIn, type Col } from "./grid";
import { problems, removeWin } from "./groups.on-demand";

const GAP = 12;
const W = 900;

/** A stacked column [A, B, C] in a view of one column, the case the owner reported. */
const stacked = (): ColIn[] => [{ id: "c1", w: W, wins: [{ id: "A" }, { id: "B" }, { id: "C" }] }];

/** Only the parts a document keeps: ids, widths, spans, bands. Two layouts with the same snapshot are the same layout. */
const snapshot = (cols: Col[]) => cols.map((c) => ({ id: c.id, w: c.w, wins: c.wins.map((w) => ({ id: w.id, span: w.span, rows: w.rows, row: w.row })) }));

const spanOf = (cols: Col[], id: string): number => cols.flatMap((c) => c.wins).find((w) => w.id === id)!.span;
const bandOf = (cols: Col[], id: string): number => cols.flatMap((c) => c.wins).find((w) => w.id === id)!.row;

test("split right in a stacked column makes a group: the window's column halves, its neighbours span both halves", () => {
  const cols = splitRight(stacked(), "B", { id: "B2", colId: "c2", pair: "p1" }, GAP);
  expect(problems(cols)).toEqual([]);
  expect(cols.map((c) => c.wins.map((w) => w.id))).toEqual([["A", "B", "C"], ["B2"]]);
  expect(cols[0]!.w + GAP + cols[1]!.w).toBe(W);
  expect([spanOf(cols, "A"), spanOf(cols, "B"), spanOf(cols, "C"), spanOf(cols, "B2")]).toEqual([2, 1, 2, 1]);
  expect([bandOf(cols, "A"), bandOf(cols, "B"), bandOf(cols, "C"), bandOf(cols, "B2")]).toEqual([0, 1, 2, 1]);
  expect(runsOf(cols)).toEqual([{ from: 0, to: 1, rows: 3 }]);
});

test("closing the new half gives the layout back exactly, in the model", () => {
  const original = settle(stacked());
  const split = splitRight(stacked(), "B", { id: "B2", colId: "c2", pair: "p1" }, GAP);
  const back = removeWin(split, "B2", GAP);
  expect(problems(back)).toEqual([]);
  expect(snapshot(back)).toEqual(snapshot(original));
  expect(back.length).toBe(1);
  expect(back[0]!.w).toBe(W);
});

test("closing the window it came from makes the new half take its band, and the layout is one column again", () => {
  const split = splitRight(stacked(), "B", { id: "B2", colId: "c2", pair: "p1" }, GAP);
  const back = removeWin(split, "B", GAP);
  expect(problems(back)).toEqual([]);
  expect(back.length).toBe(1);
  expect(back[0]!.wins.map((w) => [w.id, w.span, w.row])).toEqual([["A", 1, 0], ["B2", 1, 1], ["C", 1, 2]]);
  expect(back[0]!.w).toBe(W);
});

test("split right of a spanning window halves its span inside the existing columns, with the footprint unchanged", () => {
  const grouped = splitRight(stacked(), "B", { id: "B2", colId: "c2", pair: "p1" }, GAP);
  const cols = splitRight(grouped, "A", { id: "A2", colId: "unused", pair: "p9" }, GAP);
  expect(problems(cols)).toEqual([]);
  expect(cols.length).toBe(2);
  expect(cols.map((c) => c.w)).toEqual(grouped.map((c) => c.w));
  expect(cols[0]!.wins.map((w) => [w.id, w.span, w.row])).toEqual([["A", 1, 0], ["B", 1, 1], ["C", 2, 2]]);
  expect(cols[1]!.wins.map((w) => [w.id, w.span, w.row])).toEqual([["A2", 1, 0], ["B2", 1, 1]]);
});

test("split down in a group divides only the window's band: the partner window grows to keep its height", () => {
  const grouped = splitRight(stacked(), "B", { id: "B2", colId: "c2", pair: "p1" }, GAP);
  const cols = splitDown(grouped, "B", { id: "N" }, 200, 200);
  expect(problems(cols)).toEqual([]);
  expect(cols[0]!.wins.map((w) => [w.id, w.row, w.rows])).toEqual([["A", 0, 1], ["B", 1, 1], ["N", 2, 1], ["C", 3, 1]]);
  expect(cols[1]!.wins.map((w) => [w.id, w.row, w.rows])).toEqual([["B2", 1, 2]]);
});

test("closing the window split down gives its band back to the window above and to the partner", () => {
  const grouped = splitRight(stacked(), "B", { id: "B2", colId: "c2", pair: "p1" }, GAP);
  const down = splitDown(grouped, "B", { id: "N" }, 200, 200);
  const back = removeWin(down, "N", GAP);
  expect(problems(back)).toEqual([]);
  expect(back[0]!.wins.map((w) => [w.id, w.row, w.rows])).toEqual([["A", 0, 1], ["B", 1, 1], ["C", 2, 1]]);
  expect(back[1]!.wins.map((w) => [w.id, w.row, w.rows])).toEqual([["B2", 1, 1]]);
  expect(back[0]!.wins.find((w) => w.id === "B")!.h).toBe(400);
});

test("a window split down in a plain column stacks under it and moves the windows below down", () => {
  const cols = splitDown(stacked(), "B", { id: "N" }, undefined, undefined);
  expect(problems(cols)).toEqual([]);
  expect(cols[0]!.wins.map((w) => [w.id, w.row])).toEqual([["A", 0], ["B", 1], ["N", 2], ["C", 3]]);
});

test("new window right opens a full-size column after the whole group, never inside it", () => {
  const grouped = splitRight(stacked(), "B", { id: "B2", colId: "c2", pair: "p1" }, GAP);
  const cols = newRight(grouped, "A", { id: "X", colId: "c3" }, 300);
  expect(problems(cols)).toEqual([]);
  expect(cols.map((c) => c.id)).toEqual(["c1", "c2", "c3"]);
  expect(spanOf(cols, "A")).toBe(2);
  expect(cols[2]!.w).toBe(300);
});

test("runs: adjacent columns linked by a spanning window form one group, the rest stay plain", () => {
  const cols: ColIn[] = [
    { id: "a", w: 100, wins: [{ id: "a1" }] },
    { id: "b", w: 100, wins: [{ id: "b1", span: 2 }, { id: "b2" }] },
    { id: "c", w: 100, wins: [{ id: "c1" }] },
    { id: "d", w: 100, wins: [{ id: "d1" }] },
  ];
  expect(runsOf(cols).map((r) => [r.from, r.to])).toEqual([[0, 0], [1, 2], [3, 3]]);
});

test("spans are clamped to the columns that exist and a stale row is re-placed, never overlapped", () => {
  const cols = settle([{ id: "a", w: 100, wins: [{ id: "a1", span: 9, row: 0 }, { id: "a2", row: 0 }] }, { id: "b", w: 100, wins: [{ id: "b1" }] }]);
  expect(problems(cols)).toEqual([]);
  expect(cols[0]!.wins[0]!.span).toBe(2);
  expect(cols[0]!.wins[1]!.row).toBe(1);
});

/** A tiny seeded generator, so a failing sequence can be replayed. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; };
}

test("random sequences of split right, split down, new window right and close never break the grid", () => {
  for (let seed = 1; seed <= 40; seed++) {
    const rand = rng(seed);
    let cols: Col[] = settle(stacked());
    let serial = 0;
    for (let step = 0; step < 30; step++) {
      const ids = cols.flatMap((c) => c.wins.map((w) => w.id));
      if (!ids.length) break;
      const pick = ids[Math.floor(rand() * ids.length)]!;
      const action = rand();
      const before = JSON.stringify(cols);
      // The window sizes never let a column go below its minimum (300 px), so the fuzz does not halve narrower than that.
      const narrow = cols.some((c) => c.wins.some((w) => w.id === pick) && c.w < 2 * 300 + GAP);
      if (action < 0.35) { if (!narrow) cols = splitRight(cols, pick, { id: `s${seed}-${serial}`, colId: `k${seed}-${serial++}`, pair: `p${seed}-${serial}` }, GAP); }
      else if (action < 0.6) cols = splitDown(cols, pick, { id: `s${seed}-${serial++}` }, 150, 150);
      else if (action < 0.7) cols = newRight(cols, pick, { id: `s${seed}-${serial}`, colId: `k${seed}-${serial++}` }, 200);
      else cols = removeWin(cols, pick, GAP);
      const found = problems(cols);
      if (found.length) throw new Error(`seed ${seed} step ${step} (${before.length} bytes before): ${found.join("; ")}`);
      // The footprint of the whole view only ever changes by a column boundary's gap, never by a window's span.
      expect(cols.every((c) => c.w >= 0)).toBe(true);
    }
  }
});

test("closing every window of a group returns the view to nothing, with no problem on the way", () => {
  let cols: Col[] = splitRight(stacked(), "B", { id: "B2", colId: "c2", pair: "p1" }, GAP);
  cols = splitDown(cols, "A", { id: "A2" }, 100, 100);
  for (const id of ["A2", "A", "B2", "B", "C"]) {
    cols = removeWin(cols, id, GAP);
    expect(problems(cols)).toEqual([]);
  }
  expect(cols.flatMap((c) => c.wins)).toEqual([]);
});

test("a full-width band under a group moves nothing and extends the group by one band", () => {
  const grouped = splitRight(stacked(), "B", { id: "B2", colId: "c2", pair: "p1" }, GAP);
  const cols = insertBand(grouped, 0, 3, { id: "T", span: 2 });
  expect(problems(cols)).toEqual([]);
  expect(cols[0]!.wins.map((w) => [w.id, w.row, w.rows])).toEqual([["A", 0, 1], ["B", 1, 1], ["C", 2, 1], ["T", 3, 1]]);
});

test("a band inserted between two bands of one column grows the windows beside it and moves the rest", () => {
  // Between B and C, over column 0 only: the window beside B (B2, column 1) grows across the new band, C moves down.
  const grouped = splitRight(stacked(), "B", { id: "B2", colId: "c2", pair: "p1" }, GAP);
  const cols = insertBand(grouped, 0, 2, { id: "T", span: 1 });
  expect(problems(cols)).toEqual([]);
  expect(cols[0]!.wins.map((w) => [w.id, w.row, w.rows])).toEqual([["A", 0, 1], ["B", 1, 1], ["T", 2, 1], ["C", 3, 1]]);
  expect(cols[1]!.wins.map((w) => [w.id, w.row, w.rows])).toEqual([["B2", 1, 2]]);
});

test("a narrow right split grows both drawn tracks to the canonical minimum", () => {
  const cols = splitRight([{ id: "c", w: 125, wins: [{ id: "a" }] }], "a", { id: "b", colId: "right", pair: "p" }, GAP, 100);
  expect(cols.map((c) => c.w)).toEqual([100, 100]);
  expect(cols.flatMap((c) => c.wins.map((w) => w.id))).toEqual(["a", "b"]);
});

// ---- row groups (D212 amended 2026-11-03: Settings is one row of windows for each component, no window spans) ----

/** Three rows of 3, 2 and 1 windows: a window is at its track (column) and its band (row); the short rows end early. */
const rowsOf = (): ColIn[] => [
  { id: "t0", w: 400, group: "rows", wins: [{ id: "a0", row: 0 }, { id: "b0", row: 1 }, { id: "c0", row: 2 }] },
  { id: "t1", w: 400, group: "rows", wins: [{ id: "a1", row: 0 }, { id: "b1", row: 1 }] },
  { id: "t2", w: 400, group: "rows", wins: [{ id: "a2", row: 0 }] },
];

test("columns that name the same group are one run, with no window spanning, and rows may end early", () => {
  const cols = settle(rowsOf());
  expect(runsOf(cols)).toEqual([{ from: 0, to: 2, rows: 3 }]);
  expect(cols.flatMap((c) => c.wins).every((w) => w.span === 1)).toBe(true);
  expect(cols.map((c) => c.wins.map((w) => w.row))).toEqual([[0, 1, 2], [0, 1], [0]]);
  // The empty cells are not a problem of a row group; a plain group made by spans has none.
  expect(problems(cols)).toEqual([]);
});

test("without the name the same columns are three plain columns, and a different name does not link", () => {
  const plain = rowsOf().map(({ group: _g, ...c }) => c);
  expect(runsOf(plain)).toEqual([{ from: 0, to: 0, rows: 3 }, { from: 1, to: 1, rows: 2 }, { from: 2, to: 2, rows: 1 }]);
  const two = rowsOf();
  two[2]!.group = "other";
  expect(runsOf(two).map((r) => [r.from, r.to])).toEqual([[0, 1], [2, 2]]);
});

test("a window is never covered twice, in a row group either", () => {
  const cols = settle(rowsOf());
  cols[1]!.wins[0]!.span = 2; // a1 over a2's cell
  expect(problems(cols).some((m) => m.includes("covered 2 times"))).toBe(true);
});

test("a row group keeps its name when a window in it is split to the right, and the rows stay level", () => {
  const split = splitRight(rowsOf(), "b0", { id: "b0x", colId: "t0x", pair: "p" }, GAP);
  expect(problems(split)).toEqual([]);
  expect(split.map((c) => c.group)).toEqual(["rows", "rows", "rows", "rows"]);
  expect(runsOf(split)).toEqual([{ from: 0, to: 3, rows: 3 }]);
  // The windows around the split span both halves, so the rows keep their bands.
  expect([bandOf(split, "a0"), bandOf(split, "b0"), bandOf(split, "b0x"), bandOf(split, "c0")]).toEqual([0, 1, 1, 2]);
});

test("closing a window of a row group leaves its row as it was, the others do not move", () => {
  const after = removeWin(rowsOf(), "b1", GAP);
  expect(problems(after)).toEqual([]);
  expect(runsOf(after).length).toBe(1);
  expect(bandOf(after, "a1")).toBe(0);
  expect(bandOf(after, "b0")).toBe(1);
});
