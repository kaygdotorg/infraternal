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

test("every normal exit closes an ordinary window (D357)", () => {
  for (const status of [0, 1, 3, 127, 129, 130, 255]) expect(shouldCloseWindowAfterExit(status, false)).toBe(true);
  expect(shouldCloseWindowAfterExit(3, true)).toBe(false);
});

test("a signal preserves the ended window (D357)", () => {
  for (const status of [-1, -9, -11, -15]) expect(shouldCloseWindowAfterExit(status, false)).toBe(false);
});
