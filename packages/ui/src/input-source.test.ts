/** The last key or pointer press decides the input source, and the root attribute follows it in the same task. */
import { expect, test } from "bun:test";
import { inputSource, installInputSource, markMotion, triggeredByKeyboard } from "./input-source";

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
/** An element stand-in: only the attribute calls `markMotion` makes. */
class FakeElement {
  readonly attrs: Record<string, string> = {};
  /** Reads an attribute. */
  getAttribute(name: string): string | null { return this.attrs[name] ?? null; }
  /** Writes an attribute. */
  setAttribute(name: string, value: string): void { this.attrs[name] = value; }
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

  // Space and Enter count: a button clicks on keyup, long after the keydown, and still finds the source "keyboard".
  target.dispatchEvent(person("pointerdown"));
  target.dispatchEvent(person("keydown", { key: " " }));
  expect(triggeredByKeyboard()).toBe(true);
  target.dispatchEvent(person("pointerdown"));
  target.dispatchEvent(person("keydown", { key: "Enter" }));
  expect(triggeredByKeyboard()).toBe(true);

  // markMotion writes the answer onto the elements at the moment of the call, and returns it.
  const palette = new FakeElement(), scrim = new FakeElement();
  expect(markMotion(palette as unknown as Element, scrim as unknown as Element, null, undefined)).toBe(true);
  expect(palette.attrs["data-motion"]).toBe("instant");
  expect(scrim.attrs["data-motion"]).toBe("instant");
  target.dispatchEvent(person("pointerdown"));
  expect(markMotion(palette as unknown as Element)).toBe(false);
  expect(palette.attrs["data-motion"]).toBe("animate");
  expect(scrim.attrs["data-motion"], "an element not named in the call is left as it was").toBe("instant");

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
