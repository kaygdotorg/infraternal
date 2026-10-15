/** The size a stream asks the machine for always passes the wire's checks (contracts/wire.md section 9, the helper's Size.validate). */
import { expect, test } from "bun:test";
import { chooseSize, densityMilli, sizeChanged } from "./size";

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
