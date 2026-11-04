/** Stops: where the camera rests while the canvas lock is on (layout/stops.ts). */
import { expect, test } from "bun:test";
import type { ViewModel } from "../model/types";
import { FREE_GRAPH_NODES, isFreeView, nearestStop, stopsFor } from "./stops";

const view = (widths: number[]): ViewModel => ({ id: "console", name: "Console", layout: "tiled", nodes: [], x: 0, y: 0, cols: widths.map((w, i) => ({ id: `c${i}`, w, wins: [] })) });

test("a view that fits the viewport has one stop, centred", () => {
  const st = stopsFor(view([400]), { x: 48, y: 96, w: 400, h: 700 }, 1000, 700);
  expect(st.lefts).toHaveLength(1);
  expect(st.z).toBe(1);
  expect(st.lefts[0]! + st.view / 2).toBe(48 + 200);
});

test("a wide view has one stop per column and the last stop ends at the right edge", () => {
  const r = { x: 0, y: 0, w: 3 * 400 + 24, h: 700 };
  const st = stopsFor(view([400, 400, 400]), r, 500, 700);
  expect(st.lefts.length).toBe(3);
  expect(st.lefts[st.lefts.length - 1]).toBe(Math.round(r.w - st.view));
  expect(st.lefts).toEqual([...st.lefts].sort((a, b) => a - b));
});

test("a view taller than the viewport is scaled down so it fits", () => {
  const st = stopsFor(view([400]), { x: 0, y: 0, w: 400, h: 1400 }, 1000, 700);
  expect(st.z).toBe(0.5);
});

test("each stop names the column it is for: the first of columns that share it, the last at the right edge", () => {
  const r = { x: 0, y: 0, w: 3 * 400 + 24, h: 700 };
  const st = stopsFor(view([400, 400, 400]), r, 500, 700);
  expect(st.owners).toEqual([0, 1, 2]);
  // Two columns narrower than the viewport rest at the same left edge (the first stop is clamped to the content): the first owns it.
  const crowded = stopsFor(view([200, 200, 200, 200, 200, 200]), { x: 0, y: 0, w: 6 * 200 + 5 * 24, h: 700 }, 700, 700);
  expect(crowded.owners.length).toBe(crowded.lefts.length);
  expect(crowded.owners[0]).toBe(0);
  expect(crowded.owners[crowded.owners.length - 1]).toBe(5);
});

test("nearestStop picks the stop whose centre is closest", () => {
  const st = stopsFor(view([400, 400, 400]), { x: 0, y: 0, w: 1224, h: 700 }, 500, 700);
  const centre = (i: number): number => st.lefts[i]! + st.view / 2;
  expect(nearestStop(st, centre(0) + 10)).toBe(0);
  expect(nearestStop(st, centre(2) - 10)).toBe(2);
});

const graph = (count: number): ViewModel => ({
  id: "mesh", name: "Mesh", layout: "graph", cols: [], x: 0, y: 0,
  nodes: Array.from({ length: count }, (_, i) => ({ id: `n${i}`, kind: "host" as const, label: `n${i}`, x: i * 230, y: 0, detail: "", sub: "" })),
});

test("a big graph opens fitted whole, in one stop, and its canvas is free", () => {
  const big = graph(FREE_GRAPH_NODES + 1), r = { x: 0, y: 0, w: 6000, h: 3000 };
  expect(isFreeView(big)).toBe(true);
  const st = stopsFor(big, r, 1440, 900);
  expect(st.lefts).toHaveLength(1);
  expect(st.z).toBeCloseTo(0.216, 3); // 0.9 * 1440 / 6000: the whole width fits, with a margin (the height has more room)
  expect(r.w * st.z).toBeLessThanOrEqual(0.9 * 1440 + 1);
  expect(r.h * st.z).toBeLessThanOrEqual(0.86 * 900 + 1);
});

test("a small graph keeps one stop per node column", () => {
  const small = graph(6), r = { x: 0, y: 0, w: 1500, h: 400 };
  expect(isFreeView(small)).toBe(false);
  expect(stopsFor(small, r, 600, 700).lefts.length).toBeGreaterThan(1);
});

test("on a narrow screen a big graph does not shrink past where its names can be read: it starts at the top left", () => {
  const big = graph(FREE_GRAPH_NODES + 1), r = { x: 100, y: 200, w: 7800, h: 6800 };
  const st = stopsFor(big, r, 393, 852);
  expect(st.z).toBe(0.1);
  expect(st.lefts).toHaveLength(1);
  expect(st.lefts[0]!).toBeLessThanOrEqual(r.x);
  expect(st.cy - 852 / (2 * st.z)).toBeLessThanOrEqual(r.y);
});

test("centred stops (a phone's strip) rest every column mid-screen, the first and last included", () => {
  const w = 317, r = { x: 48, y: 0, w: 3 * w + 24, h: 700 };
  const st = stopsFor(view([w, w, w]), r, 361, 700, true);
  expect(st.lefts).toHaveLength(3);
  st.lefts.forEach((left, i) => expect(Math.abs(left + st.view / 2 - (r.x + i * (w + 12) + w / 2))).toBeLessThanOrEqual(0.5));
});

test("D309: with a floor, a narrow column gets a stop of its drawn width and each column is reachable", () => {
  const floor = 340, r = { x: 48, y: 0, w: 2 * floor + 393 + 24, h: 700 };
  const st = stopsFor(view([39, 39, 393]), r, 393, 700, true, floor);
  expect(st.lefts).toHaveLength(3);
  // The columns' drawn centres: the first two are floor wide, the third is as saved.
  const centres = [48 + 170, 48 + 352 + 170, 48 + 704 + 196.5];
  st.lefts.forEach((left, i) => expect(Math.abs(left + st.view / 2 - centres[i]!)).toBeLessThanOrEqual(0.5));
});
