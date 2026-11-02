/** The wire input a browser event becomes (contracts/wire.md section 9). */
import { expect, test } from "bun:test";
import { containedRect, framePoint, movedEnough, scrollDelta, wireButton } from "./input";

test("a picture letterboxed in its box maps pointer positions onto the picture, clamped", () => {
  const box = { width: 400, height: 800 };
  const picture = containedRect(box, { width: 1280, height: 800 });
  expect(picture).toEqual({ x: 0, y: 800 / 2 - 125, width: 400, height: 250 });
  expect(framePoint(200, 400, picture)).toMatchObject({ x: 500_000, y: 500_000 });
  expect(framePoint(-10, 0, picture)).toMatchObject({ x: 0, y: 0 });
  expect(framePoint(999, 999, picture)).toMatchObject({ x: 1_000_000, y: 1_000_000 });
  expect(containedRect(box, { width: 0, height: 0 })).toEqual({ x: 0, y: 0, width: 400, height: 800 });
});

test("buttons map to the wire's left, right, middle; others have no code", () => {
  expect([0, 1, 2, 3, 4].map(wireButton)).toEqual([0, 2, 1, undefined, undefined]);
});

test("scroll is pixels, flipped to the content's direction, with lines and pages converted", () => {
  expect(scrollDelta({ deltaX: 0, deltaY: 100, deltaMode: 0 })).toEqual({ dx: 0, dy: -100 });
  expect(scrollDelta({ deltaX: -4, deltaY: 0, deltaMode: 0 })).toEqual({ dx: 4, dy: 0 });
  expect(scrollDelta({ deltaX: 0, deltaY: 3, deltaMode: 1 })).toEqual({ dx: 0, dy: -48 });
  expect(scrollDelta({ deltaX: 0, deltaY: 1e12, deltaMode: 0 }).dy).toBe(-2_000_000);
});

test("a move to the same millionth is not sent again", () => {
  expect(movedEnough(undefined, { x: 1, y: 1 })).toBe(true);
  expect(movedEnough({ x: 1, y: 1 }, { x: 1, y: 1 })).toBe(false);
  expect(movedEnough({ x: 1, y: 1 }, { x: 2, y: 1 })).toBe(true);
});


test("CSS letterbox positions are distinguished from valid picture input before clamping", () => {
  const picture = containedRect({ width: 800, height: 600 }, { width: 1600, height: 900 });
  expect(framePoint(400, 10, picture)).toMatchObject({ x: 500000, y: 0, inside: false });
  expect(framePoint(400, 300, picture)).toMatchObject({ x: 500000, y: 500000, inside: true });
  expect(framePoint(400, 590, picture)).toMatchObject({ inside: false });
  expect(framePoint(800, 300, picture)).toMatchObject({ inside: false });
});
