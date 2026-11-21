/** The canvas wheel modifier (D377): Option/Alt, the words people see for it, and what it does to a wheel's amounts. */
import { expect, test } from "bun:test";
import { CANVAS_WHEEL_MODIFIER, canvasDeltas, canvasModifierHeld, canvasModifierKeys } from "./canvas-wheel-modifier";

/** A wheel event with just the fields the helpers read. */
const wheel = (f: Partial<Record<"altKey" | "shiftKey" | "ctrlKey" | "metaKey" | "deltaX" | "deltaY", number | boolean>>): WheelEvent =>
  ({ altKey: false, shiftKey: false, ctrlKey: false, metaKey: false, deltaX: 0, deltaY: 0, ...f }) as unknown as WheelEvent;

test("the modifier is Option/Alt, and Shift is not a canvas key", () => {
  expect(CANVAS_WHEEL_MODIFIER).toBe("Alt");
  expect(canvasModifierHeld(wheel({ altKey: true }))).toBe(true);
  expect(canvasModifierHeld(wheel({ shiftKey: true }))).toBe(false);
});

test("the gesture is named “⌥ + scroll” on a Mac and “Alt + scroll” elsewhere", () => {
  expect(canvasModifierKeys()).toEqual({ mac: "⌥ + scroll", other: "Alt + scroll" });
});

test("with the modifier held a vertical turn becomes a sideways move and drift is dropped", () => {
  expect(canvasDeltas(wheel({ altKey: true, deltaY: 120 }))).toEqual({ dx: 120, dy: 0 });
  expect(canvasDeltas(wheel({ altKey: true, deltaX: 40, deltaY: 9 }))).toEqual({ dx: 40, dy: 0 });
  expect(canvasDeltas(wheel({ deltaX: 5, deltaY: 7 }))).toEqual({ dx: 5, dy: 7 });
});
