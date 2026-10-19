/** Pending app input follows confirmed control, including automatic reacquisition, and never survives refusal (#146, D208). */
import { afterAll, beforeAll, expect, test } from "bun:test";
import type { VideoInput } from "../../../../../packages/protocol/src/desktop";
import type { ControlState } from "./status";

let prototype: object;
const originals = new Map<string, PropertyDescriptor | undefined>();
beforeAll(async () => {
  for (const [name, value] of Object.entries({ window: globalThis, matchMedia: () => ({ matches: false }) })) {
    originals.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
  }
  prototype = (await import("./window-body")).AppBinding.prototype;
});
afterAll(() => {
  for (const [name, descriptor] of originals) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else Reflect.deleteProperty(globalThis, name);
  }
});

interface PendingBinding {
  queued: VideoInput[];
  send(input: VideoInput): void;
  paintControl(control: ControlState): void;
}
function pending(admit = false, afterSend?: (input: VideoInput, count: number) => void) {
  const sent: VideoInput[] = [];
  const order: string[] = [];
  let control: ControlState = { kind: "requesting" };
  let requests = 0;
  let finishRequest: ((ok: boolean) => void) | undefined;
  const label = { textContent: "" };
  const badge = { dataset: {}, hasAttribute: () => false, setAttribute() {}, removeAttribute() {}, querySelector: () => label };
  const stream = {
    get controlState() { return control; },
    sendInput(input: VideoInput) {
      if (control.kind !== "controlled") return false;
      sent.push(input);
      order.push("input");
      afterSend?.(input, sent.length);
      return true;
    },
    takeControl(): Promise<boolean> {
      requests++;
      if (!admit) return Promise.resolve(false);
      control = { kind: "requesting" };
      binding.paintControl(control);
      return new Promise((resolve) => { finishRequest = resolve; });
    },
  };
  // Exercise the existing binding's actual input/control methods. Its renderer
  // needs only an already mounted badge; no stream or desktop is created here.
  const binding = Object.assign(Object.create(prototype), {
    stream, queued: [], disposed: false, activeNow: true, justActivated: false,
    lastState: { kind: "live" }, o: { machine: "fixture" },
    root: { querySelector: (selector: string) => selector === ".aw-control" ? badge : undefined },
  }) as PendingBinding;
  return { binding, sent, order, resize() { order.push("size"); }, requests: () => requests, state(next: ControlState) {
    control = next;
    binding.paintControl(next);
    if (next.kind !== "requesting") finishRequest?.(next.kind === "controlled");
  } };
}

test("the first key that admits a control request also waits for approval", async () => {
  const f = pending(true);
  f.state({ kind: "none" });
  f.binding.send({ kind: "text", scalar: 97 });
  expect(f.requests()).toBe(1);
  expect(f.binding.queued).toHaveLength(1);
  expect(f.sent).toHaveLength(0);
  f.state({ kind: "controlled" });
  await Promise.resolve();
  expect(f.sent).toEqual([{ kind: "text", scalar: 97 }]);
});

test("a burst during automatic control reacquisition drains once after approval", async () => {
  const f = pending();
  const input: VideoInput[] = [..."typing"].map((letter) => ({ kind: "text", scalar: letter.charCodeAt(0) }));
  for (const event of input) f.binding.send(event);
  expect(f.sent).toHaveLength(0);
  expect(f.requests()).toBe(0);
  f.state({ kind: "controlled" });
  // AppStream pushes Size synchronously after announcing control. Pending
  // input must wait for that work without delaying ordinary controlled input.
  expect(f.sent).toHaveLength(0);
  await Promise.resolve();
  expect(f.sent).toEqual(input);
  expect(f.binding.queued).toHaveLength(0);
  f.state({ kind: "controlled" });
  await Promise.resolve();
  expect(f.sent).toEqual(input);
});

test("a lease lost before the pending drain cannot replay its input", async () => {
  const f = pending();
  f.binding.send({ kind: "text", scalar: 97 });
  f.state({ kind: "controlled" });
  f.state({ kind: "none" });
  await Promise.resolve();
  expect(f.sent).toHaveLength(0);
  f.state({ kind: "controlled" });
  f.binding.send({ kind: "text", scalar: 98 });
  expect(f.sent).toEqual([{ kind: "text", scalar: 98 }]);
  await Promise.resolve();
  expect(f.sent).toHaveLength(1);
});

test("lease flaps discard each old batch and drain only the new request once", async () => {
  const f = pending(true);
  f.binding.send({ kind: "text", scalar: 97 });
  f.binding.send({ kind: "text", scalar: 98 });
  f.state({ kind: "controlled" });
  f.state({ kind: "none" });
  await Promise.resolve();
  expect(f.sent).toHaveLength(0);

  f.state({ kind: "requesting" });
  f.binding.send({ kind: "text", scalar: 99 });
  f.state({ kind: "controlled" });
  await Promise.resolve();
  await Promise.resolve();
  expect(f.sent).toEqual([{ kind: "text", scalar: 99 }]);
  expect(f.binding.queued).toHaveLength(0);
});

test("a lease lost during a pending-input drain drops the rest of that batch", async () => {
  let f!: ReturnType<typeof pending>;
  let lost = false;
  f = pending(true, (_input, count) => {
    if (count === 1 && !lost) {
      lost = true;
      f.state({ kind: "none" });
    }
  });
  const oldBatch: [VideoInput, VideoInput, VideoInput] = [
    { kind: "text", scalar: 97 }, { kind: "text", scalar: 98 }, { kind: "text", scalar: 99 },
  ];
  for (const input of oldBatch) f.binding.send(input);
  f.state({ kind: "controlled" });
  await Promise.resolve();
  expect(f.sent).toEqual([oldBatch[0]]);
  expect(f.binding.queued).toHaveLength(0);

  f.state({ kind: "requesting" });
  f.binding.send({ kind: "text", scalar: 100 });
  f.state({ kind: "controlled" });
  await Promise.resolve();
  expect(f.sent).toEqual([oldBatch[0], { kind: "text", scalar: 100 }]);
});

test("a resize arriving before the queued drain sends Size before Input", async () => {
  const f = pending();
  f.binding.send({ kind: "text", scalar: 97 });
  f.state({ kind: "controlled" });
  f.resize();
  await Promise.resolve();
  expect(f.order).toEqual(["size", "input"]);
});

test("two windows for one app keep their pending input in separate streams", async () => {
  const first = pending();
  const second = pending();
  const firstInput = { kind: "text", scalar: 97 } as const;
  const secondInput = { kind: "text", scalar: 98 } as const;
  first.binding.send(firstInput);
  second.binding.send(secondInput);

  first.state({ kind: "controlled" });
  await Promise.resolve();
  expect(first.sent).toEqual([firstInput]);
  expect(second.sent).toHaveLength(0);
  expect(second.binding.queued).toEqual([secondInput]);

  second.state({ kind: "controlled" });
  await Promise.resolve();
  expect(first.sent).toEqual([firstInput]);
  expect(second.sent).toEqual([secondInput]);
});

test("automatic reacquisition after a reconnect never replays the lost lease's queue", async () => {
  const f = pending(true);
  f.binding.send({ kind: "text", scalar: 97 });
  f.state({ kind: "controlled" });
  f.state({ kind: "none" });
  await Promise.resolve();
  expect(f.sent).toHaveLength(0);

  f.state({ kind: "requesting" });
  f.binding.send({ kind: "text", scalar: 98 });
  f.state({ kind: "controlled" });
  await Promise.resolve();
  await Promise.resolve();
  expect(f.sent).toEqual([{ kind: "text", scalar: 98 }]);
});

test("automatic control keeps the existing 32-event queue bound", async () => {
  const f = pending();
  for (let i = 0; i < 100; i++) f.binding.send({ kind: "text", scalar: 32 + i });
  expect(f.binding.queued).toHaveLength(32);
  f.state({ kind: "controlled" });
  await Promise.resolve();
  expect(f.sent).toHaveLength(32);
});

test("a control request declined before admission cannot retain input for a later lease", async () => {
  const f = pending();
  f.state({ kind: "none" });
  f.binding.send({ kind: "text", scalar: 97 });
  await Promise.resolve();
  expect(f.requests()).toBe(1);
  expect(f.binding.queued).toHaveLength(0);
  f.state({ kind: "controlled" });
  await Promise.resolve();
  expect(f.sent).toHaveLength(0);
});

for (const state of [{ kind: "none" }, { kind: "view-only", why: "rights" }, { kind: "paused", untilMs: 2000 }] as const) {
  test(`${state.kind} discards pending input before another approval`, async () => {
    const f = pending();
    f.binding.send({ kind: "text", scalar: 97 });
    f.state(state);
    expect(f.binding.queued).toHaveLength(0);
    f.state({ kind: "controlled" });
    await Promise.resolve();
    expect(f.sent).toHaveLength(0);
  });
}
