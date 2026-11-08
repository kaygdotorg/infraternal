/** The last key or pointer press decides the input source, and the root attribute follows it in the same task. */
import { expect, test } from "bun:test";
import { inputSource, installInputSource, triggeredByKeyboard } from "./input-source";

/** A stand-in animation-frame queue the test steps by hand, so it can check the two-frame window. */
const queue = new Map<number, () => void>();
/** The id the next queued frame callback gets. */
let nextFrame = 1;
(globalThis as { requestAnimationFrame?: unknown }).requestAnimationFrame = (callback: () => void): number => { queue.set(nextFrame, callback); return nextFrame++; };
(globalThis as { cancelAnimationFrame?: unknown }).cancelAnimationFrame = (id: number): void => { queue.delete(id); };
/** Runs the callbacks queued so far (one frame); ones they queue wait for the next call. */
const stepFrame = (): void => { const due = [...queue.values()]; queue.clear(); for (const callback of due) callback(); };

test("a key press is keyboard, a pointer press is pointer, the newest wins, and dispose restores the default", () => {
  const target = new EventTarget();
  const root = { dataset: {} as Record<string, string | undefined> } as unknown as HTMLElement;
  (globalThis as { window?: unknown }).window = target;
  const dispose = installInputSource(root);
  expect(installInputSource(root)).toBe(dispose);
  expect(root.dataset.input).toBe("pointer");
  expect(triggeredByKeyboard()).toBe(false);

  target.dispatchEvent(new Event("keydown"));
  expect(root.dataset.input).toBe("keyboard");
  expect(inputSource()).toBe("keyboard");
  expect(triggeredByKeyboard()).toBe(true);

  // A pointer close of a keyboard-opened surface is a pointer event; the next key is a keyboard one again.
  target.dispatchEvent(new Event("pointerdown"));
  expect(root.dataset.input).toBe("pointer");
  expect(triggeredByKeyboard()).toBe(false);
  target.dispatchEvent(new Event("keydown"));
  expect(triggeredByKeyboard()).toBe(true);

  // A modifier on its own is not a shortcut: it leaves a pointer source alone, and the chord's last key sets the source.
  target.dispatchEvent(new Event("pointerdown"));
  for (const key of ["Shift", "Control", "Alt", "Meta"]) target.dispatchEvent(Object.assign(new Event("keydown"), { key }));
  expect(inputSource()).toBe("pointer");
  target.dispatchEvent(Object.assign(new Event("keydown"), { key: "k" }));
  expect(inputSource()).toBe("keyboard");

  // The key's "fresh" mark (the CSS that drops open and close motion) lasts two frames, then goes; the source stays.
  expect(root.dataset.inputFresh).toBe("");
  stepFrame();
  expect(root.dataset.inputFresh).toBe("");
  stepFrame();
  expect(root.dataset.inputFresh).toBeUndefined();
  expect(inputSource()).toBe("keyboard");
  target.dispatchEvent(Object.assign(new Event("keydown"), { key: "j" }));
  expect(root.dataset.inputFresh).toBe("");
  target.dispatchEvent(new Event("pointerdown"));
  expect(root.dataset.inputFresh).toBeUndefined();

  // A wheel or trackpad swipe is a pointer input even though it presses nothing.
  target.dispatchEvent(new Event("wheel"));
  expect(inputSource()).toBe("pointer");

  dispose();
  expect(root.dataset.input).toBeUndefined();
  expect(inputSource()).toBe("pointer");
  target.dispatchEvent(new Event("keydown"));
  expect(inputSource()).toBe("pointer");
});
