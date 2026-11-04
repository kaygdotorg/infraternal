/**
 * Two promises of the app-window body that need no browser (#146, D208 A3, D342):
 * 1. a window opened from the picker is told it is already the active one when its binding attaches, so its first press
 *    acts (the picker activates the window before the on-demand body has made a binding to tell);
 * 2. "a person just resized" (`handPending`) never outlives the moment it was meant for: if the window cannot follow yet
 *    (not open, or too small to measure), the flag is dropped, so the machine's first shape report cannot be mistaken for
 *    a person's resize and take the lease.
 */
import { afterAll, beforeAll, expect, test } from "bun:test";

const originals = new Map<string, PropertyDescriptor | undefined>();
let bindingPrototype: { refit(): void };
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
  bindingPrototype = (await import("./window-body")).AppBinding.prototype as unknown as { refit(): void };
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

/** An `AppBinding` with only what `refit` and `measure` read: a stage of the given size and a stream that records opening. */
function refitFixture(stage: { clientWidth: number; clientHeight: number }) {
  const opened: unknown[] = [];
  const binding = Object.assign(Object.create(bindingPrototype), {
    disposed: false, opened: false, listedShapeTried: false, shaping: false, handPending: false, visible: true,
    remoteShape: undefined, resizeTimer: 0, stage, o: { aspect: undefined },
    stream: { setVisible() {}, open: (size: unknown) => { opened.push(size); return Promise.resolve(); } },
  }) as { refit(): void; handPending: boolean; opened: boolean };
  return { binding, opened };
}

test("a refit before the window is open does not leave a pending hand resize behind", () => {
  const { binding, opened } = refitFixture({ clientWidth: 600, clientHeight: 400 });
  binding.refit();
  expect(opened).toHaveLength(1);
  expect(binding.opened).toBe(true);
  // Nothing was following yet, so the machine's first shape report must find no "by hand" waiting for it.
  expect(binding.handPending).toBe(false);
});

test("a refit while the window is too small to measure does not leave a pending hand resize behind", () => {
  const { binding, opened } = refitFixture({ clientWidth: 1, clientHeight: 1 });
  binding.refit();
  expect(opened).toHaveLength(0);
  expect(binding.handPending).toBe(false);
});
