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

/**
 * A stand-in for `window` that calls the listeners with plain objects. The browser marks an event the person made `isTrusted`
 * and no script can forge that (it is an unconfigurable property of every Event), so the test cannot dispatch real events
 * for both kinds; it hands the tracker the same fields instead.
 */
class FakeWindow {
  private readonly listeners = new Map<string, Array<(event: unknown) => void>>();
  /** Registers a listener for `type`, as `window.addEventListener` does. */
  addEventListener(type: string, listener: (event: unknown) => void): void { this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]); }
  /** Removes a listener registered with {@link FakeWindow.addEventListener}. */
  removeEventListener(type: string, listener: (event: unknown) => void): void { this.listeners.set(type, (this.listeners.get(type) ?? []).filter((l) => l !== listener)); }
  /** Delivers an event of `type` to the listeners; `isTrusted` defaults to true, as for the person's own events. */
  dispatchEvent(event: { type: string; isTrusted?: boolean; key?: string }): void {
    for (const listener of this.listeners.get(event.type) ?? []) listener({ isTrusted: true, ...event });
  }
}
/** An event the person made (trusted), with optional fields such as `key`. */
const person = (type: string, props: { key?: string } = {}): { type: string; isTrusted: boolean; key?: string } => ({ type, isTrusted: true, ...props });
/** An event a script made: the same shape, marked untrusted. */
const script = (type: string, props: { key?: string } = {}): { type: string; isTrusted: boolean; key?: string } => ({ type, isTrusted: false, ...props });

test("a key press is keyboard, a pointer press is pointer, the newest wins, and dispose restores the default", () => {
  const target = new FakeWindow();
  const root = { dataset: {} as Record<string, string | undefined> } as unknown as HTMLElement;
  (globalThis as { window?: unknown }).window = target;
  const dispose = installInputSource(root);
  expect(installInputSource(root)).toBe(dispose);
  expect(root.dataset.input).toBe("pointer");
  expect(triggeredByKeyboard()).toBe(false);

  target.dispatchEvent(person("keydown"));
  expect(root.dataset.input).toBe("keyboard");
  expect(inputSource()).toBe("keyboard");
  expect(triggeredByKeyboard()).toBe(true);

  // A pointer close of a keyboard-opened surface is a pointer event; the next key is a keyboard one again.
  target.dispatchEvent(person("pointerdown"));
  expect(root.dataset.input).toBe("pointer");
  expect(triggeredByKeyboard()).toBe(false);
  target.dispatchEvent(person("keydown"));
  expect(triggeredByKeyboard()).toBe(true);

  // A modifier on its own is not a shortcut: it leaves a pointer source alone, and the chord's last key sets the source.
  target.dispatchEvent(person("pointerdown"));
  for (const key of ["Shift", "Control", "Alt", "Meta"]) target.dispatchEvent(person("keydown", { key }));
  expect(inputSource()).toBe("pointer");
  target.dispatchEvent(person("keydown", { key: "k" }));
  expect(inputSource()).toBe("keyboard");

  // The key's "fresh" mark (the CSS that drops open and close motion) lasts two frames, then goes; the source stays.
  expect(root.dataset.inputFresh).toBe("");
  stepFrame();
  expect(root.dataset.inputFresh).toBe("");
  stepFrame();
  expect(root.dataset.inputFresh).toBeUndefined();
  expect(inputSource()).toBe("keyboard");
  target.dispatchEvent(person("keydown", { key: "j" }));
  expect(root.dataset.inputFresh).toBe("");
  target.dispatchEvent(person("pointerdown"));
  expect(root.dataset.inputFresh).toBeUndefined();

  // A script's key or pointer event says nothing about the person: it is ignored whichever way it points.
  target.dispatchEvent(person("pointerdown"));
  target.dispatchEvent(script("keydown", { key: "k" }));
  expect(inputSource()).toBe("pointer");
  target.dispatchEvent(person("keydown", { key: "k" }));
  target.dispatchEvent(script("pointerdown"));
  expect(inputSource()).toBe("keyboard");

  // A wheel or trackpad swipe is a pointer input even though it presses nothing.
  target.dispatchEvent(person("wheel"));
  expect(inputSource()).toBe("pointer");

  dispose();
  expect(root.dataset.input).toBeUndefined();
  expect(inputSource()).toBe("pointer");
  target.dispatchEvent(person("keydown"));
  expect(inputSource()).toBe("pointer");
});
