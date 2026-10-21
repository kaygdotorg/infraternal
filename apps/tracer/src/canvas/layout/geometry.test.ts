/** Placement rules of the clusters mockup: grid snapping, pushing and grant reach (src/canvas/layout/geometry.ts). */
import { expect, test } from "bun:test";
import { CELL, COLUMN_GAP, MIN_TOUCH_COLUMN, contentSize, defaultWidth, drawnWidth, isDefaultWidth, metricsFor, resolve, snapToGrid, type Box } from "./geometry";
import { DEFAULT_SIZES, PEEK } from "../window-sizes";
import { reach } from "../mesh/grants";
import { INITIAL_GRANTS, TAGS } from "../mock/data";

const overlaps = (a: Box, b: Box, at: Map<string, { x: number; y: number }>): boolean => {
  const p = at.get(a.id)!, q = at.get(b.id)!;
  return p.x < q.x + b.w && q.x < p.x + a.w && p.y < q.y + b.h && q.y < p.y + a.h;
};

test("a dropped view pushes the one it lands on along the axis of least overlap, never itself", () => {
  const boxes: Box[] = [
    { id: "a", x: 0, y: 0, w: 4 * CELL, h: 3 * CELL },
    { id: "b", x: 4 * CELL, y: 0, w: 3 * CELL, h: 3 * CELL },
    { id: "c", x: 0, y: 4 * CELL, w: 4 * CELL, h: 2 * CELL },
  ];
  // Drop "c" so it overlaps the right edge of "a" and the left of "b".
  const moved = boxes.map((b) => (b.id === "c" ? { ...b, x: 2 * CELL, y: 1 * CELL } : b));
  const at = resolve(moved, "c");
  expect(at.get("c")).toEqual({ x: 2 * CELL, y: 1 * CELL });
  for (let i = 0; i < moved.length; i++) for (let j = i + 1; j < moved.length; j++) expect(overlaps(moved[i]!, moved[j]!, at)).toBe(false);
  // Every push is a whole number of cells, so the grid is kept.
  for (const p of at.values()) { expect(Math.abs(p.x % CELL)).toBe(0); expect(Math.abs(p.y % CELL)).toBe(0); }
});

test("a chain of neighbours is pushed in turn", () => {
  const boxes: Box[] = [
    { id: "a", x: 0, y: 0, w: 2 * CELL, h: 2 * CELL },
    { id: "b", x: 2 * CELL, y: 0, w: 2 * CELL, h: 2 * CELL },
    { id: "c", x: 4 * CELL, y: 0, w: 2 * CELL, h: 2 * CELL },
  ];
  const at = resolve(boxes.map((b) => (b.id === "a" ? { ...b, x: CELL } : b)), "a");
  expect(at.get("b")!.x).toBe(3 * CELL);
  expect(at.get("c")!.x).toBe(5 * CELL);
});

test("display settlement clears disconnected overlaps while keeping its one anchor fixed", () => {
  const boxes: Box[] = [
    { id: "settings", x: 0, y: 0, w: 29 * CELL, h: 9 * CELL },
    { id: "console", x: -3 * CELL, y: -2 * CELL, w: 5 * CELL, h: 9 * CELL },
    { id: "mesh", x: 21 * CELL, y: 8 * CELL, w: 9 * CELL, h: 5 * CELL },
    { id: "a", x: -8 * CELL, y: -8 * CELL, w: 5 * CELL, h: 7 * CELL },
    { id: "b", x: -7 * CELL, y: -11 * CELL, w: 5 * CELL, h: 7 * CELL },
    { id: "c", x: 2 * CELL, y: -11 * CELL, w: 5 * CELL, h: 7 * CELL },
    { id: "d", x: -2 * CELL, y: 0, w: 5 * CELL, h: 7 * CELL },
    { id: "e", x: 0, y: 16 * CELL, w: 5 * CELL, h: 7 * CELL },
    { id: "f", x: 23 * CELL, y: 20 * CELL, w: 5 * CELL, h: 7 * CELL },
  ];
  const at = resolve(boxes, "settings", true);
  expect(at.get("settings")).toEqual({ x: 0, y: 0 });
  for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) expect(overlaps(boxes[i]!, boxes[j]!, at)).toBe(false);
});

test("snapping rounds to whole cells", () => {
  expect(snapToGrid(59)).toBe(0);
  expect(snapToGrid(61)).toBe(CELL);
  expect(snapToGrid(-CELL * 1.6)).toBe(-2 * CELL);
});

test("reach follows grants through tags and keeps the relay", () => {
  expect(reach("build-01", INITIAL_GRANTS, TAGS)).toEqual([{ host: "nix-cache" }, { host: "edge-arm", via: "fra-relay" }]);
  // studio-mac is a member of tag:ops, which may reach build-01 and nix-cache.
  expect(reach("studio-mac", INITIAL_GRANTS, TAGS).map((r) => r.host).sort()).toEqual(["build-01", "nix-cache"]);
  expect(reach("db-never", INITIAL_GRANTS, TAGS)).toEqual([]);
});

test("phone edge to edge: a lone window is the whole area, in a strip it leaves the gap and PEEK px of each neighbour; full width is the whole area always", () => {
  const edge = metricsFor(393, 700, true);
  expect(defaultWidth(edge, 1)).toBe(393);
  expect(defaultWidth(edge, 3)).toBe(393 - 2 * (COLUMN_GAP + PEEK));
  const full = metricsFor(393, 700, true, { ...DEFAULT_SIZES, phone: "full" });
  expect(full.colW).toBe(393);
  expect(defaultWidth(full, 3)).toBe(393);
  expect(defaultWidth(edge, 3)).toBeLessThan(defaultWidth(full, 3));
  expect(isDefaultWidth(edge.colW, edge) && isDefaultWidth(edge.peekW, edge) && isDefaultWidth(full.colW, full) && !isDefaultWidth(300, edge)).toBe(true);
});

test("comfortable phones: a column in a strip leaves PEEK px of each neighbour; a lone one keeps the screen less the margins", () => {
  const m = metricsFor(361, 700, true, { ...DEFAULT_SIZES, phone: "comfortable" });
  expect(m.colW).toBe(333);
  expect(defaultWidth(m, 3)).toBe(m.peekW);
  expect((361 - m.peekW) / 2).toBe(COLUMN_GAP + PEEK);
});

test("a desktop column is the same alone and in a strip", () => {
  const m = metricsFor(1400, 900, false);
  expect(m.peekW).toBe(m.colW);
});

test("D309: a touch screen draws every column at least MIN_TOUCH_COLUMN wide, never wider than a lone column; a fine pointer has no floor", () => {
  const wide = metricsFor(430, 932, true);
  expect(wide.minW).toBe(MIN_TOUCH_COLUMN);
  expect(drawnWidth(39, wide)).toBe(MIN_TOUCH_COLUMN);
  expect(drawnWidth(500, wide)).toBe(500);
  // A narrower screen cannot show a floor wider than a column of its default strip: the floor is that column, so the
  // default layout looks as it did and a column never overflows the screen.
  for (const width of [320, 375, 393]) { const m = metricsFor(width, 700, true); expect(m.minW).toBe(m.peekW); expect(m.minW).toBeLessThan(MIN_TOUCH_COLUMN); }
  const desktop = metricsFor(1440, 900, false);
  expect(desktop.minW).toBe(0);
  expect(drawnWidth(39, desktop)).toBe(39);
  // A narrow desktop window is still a fine pointer: no floor.
  expect(metricsFor(600, 800, false).minW).toBe(0);
});

test("D309: the content is as wide as the drawn columns, so the camera reaches every column", () => {
  const phone = metricsFor(430, 932, true);
  const view = { id: "console", name: "Console", layout: "tiled" as const, nodes: [], x: 0, y: 0, cols: [39, 39, 430].map((w, i) => ({ id: `c${i}`, w, wins: [] })) };
  expect(contentSize(view, phone).w).toBe(2 * MIN_TOUCH_COLUMN + 430 + 2 * COLUMN_GAP);
  expect(contentSize(view, metricsFor(1440, 900, false)).w).toBe(39 + 39 + 430 + 2 * COLUMN_GAP);
});
