/** Deferred focus belongs to the latest input activity, with listeners only while waiting. */
import { expect, test } from "bun:test";
import { captureFocusIntent } from "./focus-intent";

for (const type of ["focusin", "pointerdown", "keydown", "input"]) test(`${type} supersedes every older focus intent`, () => {
  const target = new EventTarget();
  const first = captureFocusIntent(target), second = captureFocusIntent(target);
  expect(first.isCurrent()).toBe(true);
  target.dispatchEvent(new Event(type));
  expect(first.isCurrent()).toBe(false);
  expect(second.isCurrent()).toBe(false);
  const later = captureFocusIntent(target);
  first.dispose(); first.dispose(); second.dispose();
  expect(later.isCurrent()).toBe(true);
  target.dispatchEvent(new Event(type));
  expect(later.isCurrent()).toBe(false);
  later.dispose();
  const fresh = captureFocusIntent(target);
  expect(fresh.isCurrent()).toBe(true);
  fresh.dispose();
  expect(fresh.isCurrent()).toBe(false);
});
