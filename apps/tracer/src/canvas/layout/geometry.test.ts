/** Placement rules of the clusters mockup: grid snapping, pushing and grant reach (src/canvas/layout/geometry.ts). */
import { expect, test } from "bun:test";
import { CELL, resolve, snapToGrid, type Box } from "./geometry";
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
