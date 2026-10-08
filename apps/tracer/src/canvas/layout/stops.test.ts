/** Stops: where the camera rests while the canvas lock is on (layout/stops.ts). */
import { expect, test } from "bun:test";
import type { ViewModel } from "../model/types";
import { nearestStop, stopsFor } from "./stops";

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

test("nearestStop picks the stop whose centre is closest", () => {
  const st = stopsFor(view([400, 400, 400]), { x: 0, y: 0, w: 1224, h: 700 }, 500, 700);
  const centre = (i: number): number => st.lefts[i]! + st.view / 2;
  expect(nearestStop(st, centre(0) + 10)).toBe(0);
  expect(nearestStop(st, centre(2) - 10)).toBe(2);
});
