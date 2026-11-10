/** Pins where a confirmation card may sit: inside its window and the viewport, with the viewport as the fallback (D385, #486). */
import { expect, test } from "bun:test";
import { confirmBox } from "./confirm-bounds";

const view = { width: 393, height: 852 };

test("a card about something in a window stays inside that window with a 9 px inset", () => {
  expect(confirmBox({ left: 41, top: 20, right: 352, bottom: 832 }, view, 200)).toEqual({ left: 50, top: 29, right: 343, bottom: 823 });
});

test("a window partly panned off screen is cut to the viewport first", () => {
  const box = confirmBox({ left: -150, top: 20, right: 250, bottom: 900 }, view, 200);
  expect(box).toEqual({ left: 9, top: 29, right: 241, bottom: 843 });
  const right = confirmBox({ left: 200, top: 20, right: 700, bottom: 400 }, view, 200);
  expect(right.right).toBe(384);
});

test("a window too short for the card plus its inset falls back to the viewport, never overflowing", () => {
  const box = confirmBox({ left: 41, top: 300, right: 352, bottom: 420 }, view, 200);
  expect(box).toEqual({ left: 9, top: 9, right: 384, bottom: 843 });
});

test("a window almost entirely off screen falls back to the viewport", () => {
  const box = confirmBox({ left: -300, top: 20, right: 40, bottom: 832 }, view, 200);
  expect(box).toEqual({ left: 9, top: 9, right: 384, bottom: 843 });
});

test("with no window the viewport is used, inset 12 px", () => {
  expect(confirmBox(undefined, view, 200)).toEqual({ left: 12, top: 12, right: 381, bottom: 840 });
});

test("a viewport smaller than the insets never yields a negative box", () => {
  const box = confirmBox({ left: 0, top: 0, right: 10, bottom: 10 }, { width: 10, height: 10 }, 50);
  expect(box.right).toBeGreaterThanOrEqual(box.left);
  expect(box.bottom).toBeGreaterThanOrEqual(box.top);
});
