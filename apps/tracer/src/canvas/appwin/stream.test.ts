/** Exercises viewer/control ownership through public stream operations without a decoder or DOM renderer [D208,D232]. */
import { afterAll, beforeAll, expect, test } from "bun:test";
import type { StreamHandler } from "../../connection";
import type { VideoInput } from "../../../../../packages/protocol/src/desktop";
import type { WireFrame } from "../../../../../packages/protocol/src/codec";
import { AppStream, parseStatus, type StreamOptions } from "./stream";
import type { ControlState } from "./status";

const originals = new Map<string, PropertyDescriptor | undefined>();
let bindingPrototype: object;
beforeAll(async () => {
  class Canvas { className = ""; width = 2; height = 2; transferControlToOffscreen() { return {}; } }
  const globals = { window: globalThis, document: { createElement: () => new Canvas() }, HTMLCanvasElement: Canvas,
    OffscreenCanvas: class {}, VideoDecoder: class {}, EncodedVideoChunk: class {}, Worker: class {},
    matchMedia: () => ({ matches: false }) };
  for (const [key, value] of Object.entries(globals)) {
    originals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
  }
  bindingPrototype = (await import("./window-body")).AppBinding.prototype;
});
afterAll(() => {
  for (const [key, descriptor] of originals) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else Reflect.deleteProperty(globalThis, key);
  }
});

async function fixture(deferControl = false, onControl: (control: ControlState) => void = () => undefined) {
  const shapes: number[] = [];
  let controlReply: ((allowed: boolean) => void) | undefined;
  let next = 1;
  let controller: number | undefined;
  let clockReply: ((value: Record<string, unknown>) => void) | undefined;
  const handlers = new Map<number, StreamHandler>();
  const frames: Array<{ id: number; frame: WireFrame }> = [];
  const actions: string[] = [];
  const closed: number[] = [];
  const worker = { postMessage() {}, terminate() {}, onerror: null as ((event: Event) => void) | null };
  const connection: StreamOptions["connection"] = {
    isWelcomed: true, onWelcome: () => () => undefined,
    async call(action, input) {
      actions.push(action);
      if (action === "desktop.session.start") return { session_id: "00000000-0000-0000-0000-000000000146" };
      if (action === "desktop.session.control") {
        if (deferControl) await new Promise<void>((resolve, reject) => { controlReply = allowed => allowed ? resolve() : reject(new Error("refused")); });
        controller = Number(input.stream_id); return {};
      }
      if (action === "desktop.session.clock" || action === "desktop.session.status") return new Promise(resolve => { clockReply = resolve; });
      return {};
    },
    openStream(handler) { const id = next; next += 2; handlers.set(id, handler); queueMicrotask(() => handler.onWelcome(false)); return id; },
    closeStream(id) { closed.push(id); handlers.delete(id); if (controller === id) controller = undefined; },
    send(id, frame) { frames.push({ id, frame }); return true; },
  };
  const stream = new AppStream({ connection, hostId: "host", target: { type: "screen", displayId: 1 }, coarse: false,
    events: { state() {}, control: onControl, picture() {}, surface() {}, shape(aspect) { shapes.push(aspect); } },
    makeWorker: () => worker as unknown as Worker });
  await stream.open({ width: 800, height: 600, density: 1 });
  stream.setVisible(true);
  await Promise.resolve();
  return { stream, shapes, frames, actions, closed, handlers, worker, controller: () => controller, answerControl: (allowed: boolean) => controlReply?.(allowed), reply: (value: Record<string, unknown>) => clockReply?.(value) };
}

interface BindingProbe {
  queued: VideoInput[];
  send(input: VideoInput): void;
  paintControl(control: ControlState): void;
}

function bindingProbe(stream: AppStream): BindingProbe {
  return Object.assign(Object.create(bindingPrototype), {
    stream, queued: [], disposed: false, activeNow: true, justActivated: false,
    lastState: { kind: "live" }, o: { machine: "fixture" },
    // The pill's mark is DOM work these input tests do not exercise.
    paintPillMark() {},
  }) as BindingProbe;
}

test("retry after a decoder failure stops the previous native session", async () => {
  const f = await fixture();
  try {
    f.worker.onerror?.(new Event("error"));
    expect(f.stream.current.kind).toBe("failed");
    f.stream.retry({ width: 800, height: 600, density: 1 });
    await new Promise<void>(resolve => setImmediate(resolve));
    expect(f.actions.filter(action => action === "desktop.session.start")).toHaveLength(2);
    // Viewer Close only detaches: the server retains capture independently.
    // A retry must retire the old source before replacing its only session ID.
    expect(f.actions.filter(action => action === "desktop.session.stop")).toHaveLength(1);
  } finally { f.stream.dispose(); }
});

test("server Close unregisters its app-window handler before disposal", async () => {
  const f = await fixture();
  try {
    expect([...f.handlers.keys()]).toEqual([1]);
    f.handlers.get(1)!.onFrame({ type: "Close", code: 4404, reason: "viewer ended" }, new Uint8Array(), 0);
    await new Promise<void>(resolve => setImmediate(resolve));
    f.stream.dispose();
    // MuxConnection dispatches Close to the registered handler; only
    // closeStream removes that handler from the page's shared stream table.
    expect([...f.handlers.keys()]).toEqual([]);
  } finally { f.stream.dispose(); }
});

test("retry after server Close stops the retained native capture before replacement", async () => {
  const f = await fixture();
  try {
    f.handlers.get(1)!.onFrame({ type: "Close", code: 4403, reason: "stream unavailable" }, new Uint8Array(), 0);
    await new Promise<void>(resolve => setImmediate(resolve));
    expect(f.actions.filter(action => action === "desktop.session.stop")).toHaveLength(0);
    f.stream.retry({ width: 800, height: 600, density: 1 });
    await new Promise<void>(resolve => setImmediate(resolve));
    expect(f.actions.filter(action => action === "desktop.session.stop")).toHaveLength(1);
    expect(f.actions.filter(action => action === "desktop.session.start")).toHaveLength(2);
    expect(f.actions.indexOf("desktop.session.stop")).toBeLessThan(f.actions.lastIndexOf("desktop.session.start"));
  } finally { f.stream.dispose(); }
});

test("disposal after server Close releases the retired viewer's native capture", async () => {
  const f = await fixture();
  try {
    f.handlers.get(1)!.onFrame({ type: "Close", code: 4403, reason: "stream unavailable" }, new Uint8Array(), 0);
    await new Promise<void>(resolve => setImmediate(resolve));
    f.stream.dispose();
    await new Promise<void>(resolve => setImmediate(resolve));
    expect(f.actions.filter(action => action === "desktop.session.stop")).toHaveLength(1);
    expect(f.actions.filter(action => action === "desktop.session.start")).toHaveLength(1);
  } finally { f.stream.dispose(); }
});

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

test("resizing the card follows on the machine but never shows control (D208 A2, A3)", async () => {
  const seen: ControlState["kind"][] = [];
  const f = await fixture(false, (control) => seen.push(control.kind));
  try {
    f.stream.resize({ width: 1000, height: 600, density: 1 });
    await new Promise<void>(resolve => setImmediate(resolve));
    // The real window follows: the size reached the machine under the size-only lease ...
    expect(f.frames.some(({ frame }) => frame.type === "Desktop" && frame.message.kind === "size" && frame.message.width === 1000)).toBe(true);
    // ... and nothing on the page was told about control: no badge, no "controlled", no "requesting".
    expect(seen).toEqual([]);
    expect(f.stream.controlState.kind).toBe("none");
    // A second resize reuses the lease: it is one more size, not another handover.
    f.stream.resize({ width: 1200, height: 600, density: 1 });
    await Promise.resolve();
    expect(f.actions.filter(action => action === "desktop.session.control")).toHaveLength(1);
    expect(f.frames.filter(({ frame }) => frame.type === "Desktop" && frame.message.kind === "size" && frame.message.width === 1200)).toHaveLength(1);
    // Letting go ends the lease with the rest of control.
    f.stream.releaseControl();
    expect(f.closed.length).toBeGreaterThan(0);
  } finally { f.stream.dispose(); }
});

test("a refused size-only lease is silent: the person never asked to control", async () => {
  const seen: ControlState["kind"][] = [];
  const f = await fixture(true, (control) => seen.push(control.kind));
  try {
    f.stream.resize({ width: 1000, height: 600, density: 1 });
    f.answerControl(false);
    await new Promise<void>(resolve => setImmediate(resolve));
    expect(seen).toEqual([]);
    expect(f.frames.some(({ frame }) => frame.type === "Desktop" && frame.message.kind === "size")).toBe(false);
  } finally { f.stream.dispose(); }
});

test("a refused size-only lease never delays the person's own control", async () => {
  const f = await fixture(true);
  try {
    // The size-only lease is refused (the machine may not have registered the viewer yet) ...
    f.stream.resize({ width: 1000, height: 600, density: 1 });
    f.answerControl(false);
    await new Promise<void>(resolve => setImmediate(resolve));
    // ... and a real click right after still takes control at once, instead of waiting out a retry window.
    const taking = f.stream.takeControl();
    f.answerControl(true);
    expect(await taking).toBe(true);
    expect(f.stream.controlState.kind).toBe("controlled");
  } finally { f.stream.dispose(); }
});

test("following the machine's own shape sends no size at all (looking never moves it)", async () => {
  const f = await fixture();
  try {
    f.stream.resize({ width: 1000, height: 600, density: 1 }, false);
    await new Promise<void>(resolve => setImmediate(resolve));
    expect(f.actions).not.toContain("desktop.session.control");
    expect(f.frames.some(({ frame }) => frame.type === "Desktop" && frame.message.kind === "size")).toBe(false);
  } finally { f.stream.dispose(); }
});

test("a resize queued during control confirmation reaches the machine before pending input", async () => {
  let binding: BindingProbe | undefined;
  let resize: (() => void) | undefined;
  const f = await fixture(true, (control) => {
    // The size change is queued just before the binding's drain microtask to
    // model a resize already observed while control approval is settling.
    if (control.kind === "controlled") queueMicrotask(() => resize?.());
    binding?.paintControl(control);
  });
  try {
    binding = bindingProbe(f.stream);
    const worker = f.worker as unknown as { onmessage: (event: { data: unknown }) => void };
    worker.onmessage({ data: { t: "first", width: 800, height: 600 } });
    await new Promise<void>(resolve => setImmediate(resolve));
    resize = () => f.stream.resize({ width: 1000, height: 600, density: 1 }, false);

    binding.send({ kind: "text", scalar: 97 });
    expect(binding.queued).toEqual([{ kind: "text", scalar: 97 }]);
    f.answerControl(true);
    await new Promise<void>(resolve => setImmediate(resolve));

    const messages = f.frames
      .map(({ frame }) => frame.type === "Desktop" ? frame.message : undefined)
      .filter((message) => message?.kind === "size" || message?.kind === "input");
    expect(messages.map((message) => message?.kind)).toEqual(["size", "size", "input"]);
    expect(messages[0]).toMatchObject({ kind: "size", width: 800, height: 600 });
    expect(messages[1]).toMatchObject({ kind: "size", width: 1000, height: 600 });
    expect(binding.queued).toHaveLength(0);
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


test("a retired viewer's late control refusal does not throttle its replacement", async () => {
  const f = await fixture(true);
  try {
    const old = f.stream.takeControl();
    f.stream.releaseControl();
    await Promise.resolve();
    f.answerControl(false);
    expect(await old).toBe(false);
    const replacement = f.stream.takeControl();
    expect(f.actions.filter(action => action === "desktop.session.control")).toHaveLength(2);
    f.answerControl(true);
    expect(await replacement).toBe(true);
    expect(f.controller()).toBe(3);
  } finally { f.stream.dispose(); }
});

test("control held before a dropped connection comes back by itself on reconnect", async () => {
  const f = await fixture();
  try {
    expect(await f.stream.takeControl()).toBe(true);
    const id = [...f.handlers.keys()][0]!;
    f.handlers.get(id)!.onDisconnected(false);
    expect(f.stream.controlState.kind).toBe("none");
    // The socket reconnects: the same viewer is welcomed again, with no click from the person.
    f.handlers.get(id)!.onWelcome(false);
    await new Promise<void>(resolve => setImmediate(resolve));
    expect(f.actions.filter(action => action === "desktop.session.control")).toHaveLength(2);
    expect(f.stream.controlState.kind).toBe("controlled");
  } finally { f.stream.dispose(); }
});

test("control given back by the person is not taken again on reconnect", async () => {
  const f = await fixture();
  try {
    expect(await f.stream.takeControl()).toBe(true);
    f.stream.releaseControl();
    await new Promise<void>(resolve => setImmediate(resolve));
    const id = [...f.handlers.keys()].at(-1)!;
    f.handlers.get(id)!.onDisconnected(false);
    f.handlers.get(id)!.onWelcome(false);
    await new Promise<void>(resolve => setImmediate(resolve));
    expect(f.actions.filter(action => action === "desktop.session.control")).toHaveLength(1);
    expect(f.stream.controlState.kind).toBe("none");
  } finally { f.stream.dispose(); }
});

test("the machine's window shape is read from its capture rectangle", () => {
  expect(parseStatus({ capture_rect: { x: 41, y: 46, width: 2502, height: 1378 } }).shape).toBeCloseTo(2502 / 1378, 6);
  expect(parseStatus({ capture_rect: { width: 0, height: 10 } }).shape).toBeUndefined();
  expect(parseStatus({ capture_rect: { width: "wide", height: 10 } }).shape).toBeUndefined();
  expect(parseStatus({}).shape).toBeUndefined();
  // A window that follows the canvas window's size has no shape of its own to impose.
  expect(parseStatus({ reason: "following", capture_rect: { width: 1600, height: 900 } }).shape).toBeUndefined();
});

test("a live picture learns the remote window's shape without control, and again when it changes", async () => {
  const f = await fixture();
  try {
    const worker = f.worker as unknown as { onmessage: (event: { data: unknown }) => void };
    worker.onmessage({ data: { t: "first", width: 800, height: 600 } });
    await new Promise<void>(resolve => setImmediate(resolve));
    expect(f.actions).toContain("desktop.session.clock");
    f.reply({ state: "on", capture_rect: { x: 0, y: 0, width: 1600, height: 900 } });
    await new Promise<void>(resolve => setImmediate(resolve));
    expect(f.shapes).toEqual([1600 / 900]);
  } finally { f.stream.dispose(); }
});
