/** The size a stream asks the machine for always passes the wire's checks (contracts/wire.md section 9, the helper's Size.validate). */
import { expect, test } from "bun:test";
import { chooseSize, densityMilli, sizeChanged } from "./size";
import { shapeFor } from "./shape-math";

/** The machine's own check, written out. */
function acceptable(s: ReturnType<typeof chooseSize>): boolean {
  return s.width >= 2 && s.height >= 2 && s.width <= 4096 && s.height <= 4096 && s.width * s.height <= 4 * 1024 * 1024 && s.width % 2 === 0 && s.height % 2 === 0
    && s.backingScale >= 1 && s.backingScale <= 4 && Math.abs(s.canvasWidth * s.backingScale - s.width) <= 1 && Math.abs(s.canvasHeight * s.backingScale - s.height) <= 1;
}

test("a window at 2x density asks for twice its points, even", () => {
  const s = chooseSize(461, 771, 2);
  expect(s).toMatchObject({ width: 922, height: 1542, backingScale: 2 });
  expect(acceptable(s)).toBe(true);
  expect(densityMilli(s)).toBe(2000);
});

test("every size in a sweep is acceptable, including huge boxes and odd densities", () => {
  for (const w of [1, 2, 37, 389, 700, 1440, 2500, 5000, 9000]) for (const h of [1, 2, 55, 852, 900, 3000, 8000]) for (const d of [0.5, 1, 1.25, 2, 3, 4, 7]) {
    const s = chooseSize(w, h, d);
    expect(acceptable(s)).toBe(true);
  }
});

test("too many pixels lower the density before the box", () => {
  const s = chooseSize(2400, 1500, 2);
  expect(s.backingScale).toBeLessThan(2);
  expect(Math.abs(s.canvasWidth - 2400)).toBeLessThan(3);
});

test("rounding noise is not a resize", () => {
  const a = chooseSize(461, 771, 2);
  expect(sizeChanged(a, chooseSize(461.4, 771.2, 2))).toBe(false);
  expect(sizeChanged(a, chooseSize(470, 771, 2))).toBe(true);
  expect(sizeChanged(undefined, a)).toBe(true);
});

const box = { width: 900, height: 700, chromeWidth: 2, chromeHeight: 40, minWidth: 300, maxWidth: 1800, minHeight: 160, maxHeight: 900 };

test("a remote shape keeps the window's height and gives the picture area that aspect", () => {
  const shaped = shapeFor(box, 2502 / 1378);
  expect(shaped.height).toBe(700);
  expect((shaped.width - box.chromeWidth) / (shaped.height - box.chromeHeight)).toBeCloseTo(2502 / 1378, 2);
});

test("a shape wider than the width limit keeps the limit and lowers the height instead", () => {
  const shaped = shapeFor(box, 4);
  expect(shaped.width).toBe(1800);
  expect((shaped.width - box.chromeWidth) / (shaped.height - box.chromeHeight)).toBeCloseTo(4, 2);
});

test("a window that already has the remote shape is left alone", () => {
  const aspect = (900 - 2) / (700 - 40);
  expect(shapeFor(box, aspect)).toEqual({ width: 900, height: 700 });
});
