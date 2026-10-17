/** Regression tests for keeping a host's setup surface attached to its terminal window. */
import { expect, test } from "bun:test";
const previous = globalThis.matchMedia;
globalThis.matchMedia = (() => ({ matches: false })) as unknown as typeof matchMedia;
const { shouldCloseWindowAfterExit } = await import("./body");
if (previous) globalThis.matchMedia = previous;
else Reflect.deleteProperty(globalThis, "matchMedia");

test("a clean terminal exit keeps the window while host setup can still fail", () => {
  expect(shouldCloseWindowAfterExit(0, true)).toBe(false);
});

test("clean exits still close ordinary windows, and failed exits stay visible", () => {
  expect(shouldCloseWindowAfterExit(0, false)).toBe(true);
  expect(shouldCloseWindowAfterExit(1, true)).toBe(false);
});
