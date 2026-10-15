/** Exercises viewer/control ownership through public stream operations without a decoder or DOM renderer [D208,D232]. */
import { afterAll, beforeAll, expect, test } from "bun:test";
import type { StreamHandler } from "../../connection";
import type { WireFrame } from "../../../../../packages/protocol/src/codec";
import { AppStream, type StreamOptions } from "./stream";

const originals = new Map<string, PropertyDescriptor | undefined>();
beforeAll(() => {
  class Canvas { className = ""; width = 2; height = 2; transferControlToOffscreen() { return {}; } }
  const globals = { window: globalThis, document: { createElement: () => new Canvas() }, HTMLCanvasElement: Canvas,
    OffscreenCanvas: class {}, VideoDecoder: class {}, EncodedVideoChunk: class {}, Worker: class {} };
  for (const [key, value] of Object.entries(globals)) {
    originals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
  }
});
afterAll(() => {
  for (const [key, descriptor] of originals) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else Reflect.deleteProperty(globalThis, key);
  }
});

async function fixture() {
  let next = 1;
  let controller: number | undefined;
  let clockReply: ((value: Record<string, unknown>) => void) | undefined;
  const handlers = new Map<number, StreamHandler>();
  const frames: Array<{ id: number; frame: WireFrame }> = [];
  const actions: string[] = [];
  const closed: number[] = [];
  const connection: StreamOptions["connection"] = {
    isWelcomed: true, onWelcome: () => () => undefined,
    async call(action, input) {
      actions.push(action);
      if (action === "desktop.session.start") return { session_id: "00000000-0000-0000-0000-000000000146" };
      if (action === "desktop.session.control") { controller = Number(input.stream_id); return {}; }
      if (action === "desktop.session.clock" || action === "desktop.session.status") return new Promise(resolve => { clockReply = resolve; });
      return {};
    },
    openStream(handler) { const id = next; next += 2; handlers.set(id, handler); queueMicrotask(() => handler.onWelcome(false)); return id; },
    closeStream(id) { closed.push(id); handlers.delete(id); if (controller === id) controller = undefined; },
    send(id, frame) { frames.push({ id, frame }); return true; },
  };
  const stream = new AppStream({ connection, hostId: "host", target: { type: "screen", displayId: 1 }, coarse: false,
    events: { state() {}, control() {}, picture() {}, surface() {} },
    makeWorker: () => ({ postMessage() {}, terminate() {} }) as unknown as Worker });
  await stream.open({ width: 800, height: 600, density: 1 });
  stream.setVisible(true);
  await Promise.resolve();
  return { stream, frames, actions, closed, handlers, controller: () => controller, reply: (value: Record<string, unknown>) => clockReply?.(value) };
}

test("viewing never sends controller-only resize before acquisition", async () => {
  const f = await fixture();
  try {
    expect(f.frames.filter(({ frame }) => frame.type === "Desktop" && frame.message.kind === "size")).toHaveLength(0);
    expect(f.controller()).toBeUndefined();
    f.stream.resize({ width: 1000, height: 600, density: 1 });
    await Promise.resolve(); await Promise.resolve();
    expect(f.controller()).toBe(1);
    expect(f.frames.some(({ frame }) => frame.type === "Desktop" && frame.message.kind === "size" && frame.message.width === 1000)).toBe(true);
  } finally { f.stream.dispose(); }
});

test("letting go retires the native lease and reattaches the same source for viewing", async () => {
  const f = await fixture();
  try {
    expect(await f.stream.takeControl()).toBe(true);
    f.stream.releaseControl(); await Promise.resolve();
    expect(f.controller()).toBeUndefined();
    expect(f.closed).toEqual([1]);
    expect([...f.handlers.keys()]).toEqual([3]);
    expect(f.actions.filter(a => a === "desktop.session.start")).toHaveLength(1);
    expect(f.actions).not.toContain("desktop.session.stop");
  } finally { f.stream.dispose(); }
});

test("local priority reads native clock and a stale reply cannot reacquire released control", async () => {
  const f = await fixture();
  try {
    await f.stream.takeControl();
    f.stream.sendInput({ kind: "text", scalar: 97 });
    expect(f.actions).toContain("desktop.session.clock");
    f.stream.releaseControl();
    f.reply({ input: { pause_remaining_ms: 2000 } });
    await new Promise<void>(resolve => setImmediate(resolve));
    expect(f.stream.controlState.kind).toBe("none");
  } finally { f.stream.dispose(); }
});

test("native local-input priority pauses control and release clears that state", async () => {
  const f = await fixture();
  try {
    await f.stream.takeControl();
    f.stream.sendInput({ kind: "text", scalar: 97 });
    f.reply({ input: { pause_remaining_ms: 2000, control_visible: true } });
    await new Promise<void>(resolve => setImmediate(resolve));
    expect(f.stream.controlState.kind).toBe("paused");
    expect(f.stream.sendInput({ kind: "text", scalar: 98 })).toBe(false);
    f.stream.releaseControl();
    expect(f.stream.controlState.kind).toBe("none");
    expect(f.controller()).toBeUndefined();
  } finally { f.stream.dispose(); }
});
