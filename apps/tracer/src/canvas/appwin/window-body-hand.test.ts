/**
 * Promises of the app-window body that need no browser (#146, D208 A3, D342):
 * 1. a window opened from the picker is told it is already the active one when its binding attaches, so its first press
 *    acts (the picker activates the window before the on-demand body has made a binding to tell);
 */
import { afterAll, beforeAll, expect, test } from "bun:test";

const originals = new Map<string, PropertyDescriptor | undefined>();
let mountAppWindowBody: typeof import("./body.on-demand").mountAppWindowBody;
beforeAll(async () => {
  class Canvas { className = ""; width = 2; height = 2; transferControlToOffscreen() { return {}; } }
  const globals = { window: globalThis, document: { createElement: () => new Canvas() }, HTMLCanvasElement: Canvas,
    OffscreenCanvas: class {}, VideoDecoder: class {}, EncodedVideoChunk: class {}, Worker: class {},
    matchMedia: () => ({ matches: false }) };
  for (const [key, value] of Object.entries(globals)) {
    originals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
  }
  mountAppWindowBody = (await import("./body.on-demand")).mountAppWindowBody;
});
afterAll(() => {
  for (const [key, descriptor] of originals) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else Reflect.deleteProperty(globalThis, key);
  }
});

/** A stand-in for the pieces of the canvas that `mountAppWindowBody` reads; `active` says whether the rec is the active window. */
function mountFixture(active: boolean) {
  const calls: string[] = [];
  const rec = { closing: false, model: { id: "w1" }, card: { body: {} }, owner: { wins: new Map<string, unknown>() }, binding: undefined as unknown } as Record<string, any>;
  rec.owner.wins.set("w1", rec);
  const binding = { setActive: (value: boolean) => calls.push(`setActive:${value}`), mount: () => calls.push("mount") };
  const cx = {
    signal: new AbortController().signal,
    state: { activeWin: active ? rec : undefined },
    adapters: { appWindows: { available: () => true } },
    appWindows: { load: () => Promise.resolve({ bindingFor: () => binding }) },
    visibility: { watch: () => calls.push("watch") },
  };
  return { cx, rec, calls, binding };
}

test("a window that is already active when its binding attaches is told so, before it mounts", async () => {
  const f = mountFixture(true);
  mountAppWindowBody(f.cx as never, f.rec as never);
  await new Promise<void>((resolve) => setImmediate(resolve));
  expect(f.rec.binding).toBe(f.binding);
  expect(f.calls).toEqual(["setActive:true", "mount", "watch"]);
});

test("a window that is not the active one is not told it is", async () => {
  const f = mountFixture(false);
  mountAppWindowBody(f.cx as never, f.rec as never);
  await new Promise<void>((resolve) => setImmediate(resolve));
  expect(f.calls).toEqual(["mount", "watch"]);
});
