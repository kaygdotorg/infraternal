/** Independent recovery ordering and notice regressions for #250; virtual time is functional evidence only. */
import { afterEach, beforeEach, expect, test } from "bun:test";
import { ServerCanvasStore, type LayoutTransport } from "./server-store";
import type { CanvasDocument } from "./schema";
import type { Intent } from "./operations";

const baseline = (revision = 1): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }] });
const tick = async (): Promise<void> => { for (let n = 0; n < 16; n++) await Promise.resolve(); };
class Transport implements LayoutTransport {
  isWelcomed = true;
  roundTripMs: number | undefined = 200;
  recoveryRoundTrips: 1 | 4 = 1;
  resyncs = 0;
  subscriptions = 0;
  listeners = new Set<(ms: number | undefined) => void>();
  event: (event: Record<string, unknown>) => void = () => {};
  open: () => void = () => {};
  calls: Array<{ input: Record<string, unknown>; resolve: (result: Record<string, unknown>) => void; reject: (error: Error) => void }> = [];
  call(_action: string, input: Record<string, unknown>): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => this.calls.push({ input: structuredClone(input), resolve, reject }));
  }
  onRoundTrip(listener: (ms: number | undefined) => void): () => void { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; }
  sample(ms: number): void { this.roundTripMs = ms; for (const listener of this.listeners) listener(ms); }
  subscribe(_filter: { topic: string }, event: (event: Record<string, unknown>) => void, open?: () => void) {
    this.subscriptions++; this.event = event; this.open = open ?? (() => {}); this.open();
    return Object.assign(() => { this.subscriptions--; this.event = () => {}; }, { resync: () => { this.resyncs++; this.open(); } });
  }
  snapshot(doc = baseline()): void { this.event({ type: "canvas.layout.snapshot", revision: doc.revision, document: doc, initialized: true }); }
  operation(revision: number, name: string, op_id = `peer-${revision}`): void {
    this.event({ type: "canvas.layout.operation", revision, op_id, intent: { type: "view.update", view_id: "console", name } });
  }
}
const native = { setTimeout: globalThis.setTimeout, clearTimeout: globalThis.clearTimeout, now: performance.now, random: Math.random };
let now = 0, timerId = 0;
const timers = new Map<number, { at: number; run: () => void }>();
const stores: ServerCanvasStore[] = [];
beforeEach(() => {
  now = 0; timerId = 0; timers.clear();
  const values = new Map<string, string>();
  const storage = { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key), key: (index: number) => [...values.keys()][index] ?? null, get length() { return values.size; } };
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: storage });
  Object.defineProperty(globalThis, "sessionStorage", { configurable: true, value: storage });
  globalThis.setTimeout = ((run: () => void, delay = 0) => { timers.set(++timerId, { at: now + delay, run }); return timerId; }) as unknown as typeof setTimeout;
  globalThis.clearTimeout = ((id: number) => { timers.delete(id); }) as unknown as typeof clearTimeout;
  Object.defineProperty(performance, "now", { configurable: true, value: () => now });
  Math.random = () => 0;
});
afterEach(() => {
  for (const store of stores.splice(0)) store.dispose();
  globalThis.setTimeout = native.setTimeout; globalThis.clearTimeout = native.clearTimeout;
  Object.defineProperty(performance, "now", { configurable: true, value: native.now }); Math.random = native.random;
});
async function advance(until: number): Promise<void> {
  for (let n = 0; n < 1000; n++) {
    const next = [...timers].sort((a, b) => a[1].at - b[1].at)[0];
    if (!next || next[1].at > until) { now = until; return; }
    now = next[1].at; timers.delete(next[0]); next[1].run(); await tick();
  }
  throw Error("timer did not settle");
}
function setup(transport = new Transport()) {
  const notices: Array<{ definitive: boolean | undefined; delayed: boolean | undefined }> = [];
  const store = new ServerCanvasStore(transport, "p3-review", (definitive, delayed) => notices.push({ definitive, delayed }));
  stores.push(store); transport.snapshot(); store.flush(); return { transport, store, notices };
}
async function rename(store: ServerCanvasStore, name: string): Promise<void> {
  const before = store.current(), next = structuredClone(before); next.views[0]!.name = name; await store.save(next, undefined, before);
}
async function failedEdit(transport: Transport, store: ServerCanvasStore): Promise<void> {
  await rename(store, "Local"); transport.isWelcomed = false; transport.calls[0]!.reject(Error("disconnected")); await tick();
}

test("review: two successive gaps coalesce while each snapshot is outstanding", async () => {
  const { transport, store } = setup();
  transport.operation(3, "Gap"); expect(transport.resyncs).toBe(1); transport.operation(9, "Later gap");
  await advance(10_000); expect(transport.resyncs).toBe(1); expect(store.current().revision).toBe(1);
  transport.snapshot(baseline(9)); transport.operation(11, "Second gap"); transport.operation(12, "Still waiting");
  await advance(20_000); expect(transport.resyncs).toBe(2); expect(store.current().revision).toBe(9);
  transport.snapshot(baseline(12)); transport.operation(13, "Live"); expect(store.current().views[0]!.name).toBe("Live");
});

test("review: a snapshot arriving after newer deltas never rolls back canonical state", () => {
  const { transport, store } = setup();
  transport.operation(2, "Newer"); expect(store.current().revision).toBe(2);
  transport.snapshot(baseline(1)); expect(store.current().revision).toBe(2); expect(store.current().views[0]!.name).toBe("Newer");
});

test("review: outage edits wait for snapshot then send each identity once in order", async () => {
  const { transport, store } = setup(); transport.isWelcomed = false;
  await rename(store, "First"); const next = store.current(); next.views[0]!.cell.x = 2; await store.save(next); expect(transport.calls).toHaveLength(0);
  transport.isWelcomed = true; transport.open(); expect(transport.calls).toHaveLength(0);
  transport.snapshot(baseline(2)); expect(transport.calls).toHaveLength(2);
  expect(transport.calls.map((call) => (call.input.intent as Extract<Intent, { type: "view.update" }>).name)).toEqual(["First", undefined]);
  expect(new Set(transport.calls.map((call) => call.input.op_id)).size).toBe(2);
  for (const [index, call] of transport.calls.entries()) {
    transport.event({ type: "canvas.layout.operation", revision: index + 3, op_id: call.input.op_id, intent: call.input.intent });
    call.resolve({ revision: index + 3 });
  }
  await tick(); transport.open(); transport.snapshot(store.current());
  expect(transport.calls).toHaveLength(2); expect(store.current().views[0]!.name).toBe("First"); expect(store.current().views[0]!.cell.x).toBe(2);
});

test("review: a 3 s RTT fresh route stays quiet until its complete recovery budget", async () => {
  const transport = new Transport(); transport.roundTripMs = 3000; transport.recoveryRoundTrips = 4;
  const { store, notices } = setup(transport); await failedEdit(transport, store);
  await advance(12049); expect(notices).toHaveLength(0); await advance(12050); expect(notices).toEqual([{ definitive: false, delayed: true }]);
});

test("review: changed RTT reschedules the notice and successful recovery cancels future notices", async () => {
  const { transport, store, notices } = setup(); await failedEdit(transport, store);
  await advance(100); transport.sample(3000); await advance(250); expect(notices).toHaveLength(0);
  transport.sample(100); await advance(250); expect(notices).toHaveLength(1);
  transport.isWelcomed = true; transport.open(); transport.snapshot(baseline());
  const call = transport.calls[1]!; transport.operation(2, "Local", String(call.input.op_id)); call.resolve({ revision: 2 }); await tick();
  await advance(60_000); expect(notices).toHaveLength(1);
});

test("review: recovery before the budget remains quiet across repeated drops and disposal frees timers", async () => {
  const { transport, store, notices } = setup();
  for (let cycle = 0; cycle < 20; cycle++) {
    await rename(store, `Cycle ${cycle}`); transport.isWelcomed = false; transport.calls.at(-1)!.reject(Error("disconnected")); await tick();
    await advance(now + 100); transport.isWelcomed = true; transport.open(); transport.snapshot(baseline(cycle + 1));
    const call = transport.calls.at(-1)!; transport.operation(cycle + 2, `Cycle ${cycle}`, String(call.input.op_id)); call.resolve({ revision: cycle + 2 }); await tick(); store.flush();
    expect(transport.subscriptions).toBe(1); expect(transport.listeners.size).toBe(1); expect(timers.size).toBe(0);
  }
  expect(notices).toHaveLength(0); store.dispose(); expect(timers.size).toBe(0); expect(transport.subscriptions).toBe(0); expect(transport.listeners.size).toBe(0);
  stores.splice(stores.indexOf(store), 1);
});

test("review: an edit first made while offline eventually emits the calm notice", async () => {
  const { transport, store, notices } = setup(); transport.isWelcomed = false;
  await rename(store, "Offline"); await advance(249); expect(notices).toHaveLength(0);
  await advance(10_000); expect(notices).toEqual([{ definitive: false, delayed: true }]);
});

test("review: a first-connect outage with no RTT sample cannot hide pending edits forever", async () => {
  const transport = new Transport(); transport.roundTripMs = undefined;
  const { store, notices } = setup(transport); await failedEdit(transport, store);
  await advance(60_000); expect(notices).toEqual([{ definitive: false, delayed: true }]);
});
test("hunt 4: slow snapshots own one watchdog; bounded retries pause offline and disposal cancels them", async () => {
  const { transport, store } = setup(); transport.sample(3000);
  transport.operation(3, "Gap"); expect(transport.resyncs).toBe(1);
  await advance(29_999); expect(transport.resyncs).toBe(1); expect(transport.subscriptions).toBe(1);
  await advance(30_249); expect(transport.resyncs).toBe(1);
  await advance(30_250); expect(transport.resyncs).toBe(2); expect(transport.subscriptions).toBe(1);
  transport.isWelcomed = false; await advance(90_000); expect(transport.resyncs).toBe(2);
  expect(timers.size).toBe(0);
  transport.isWelcomed = true; transport.open(); expect(timers.size).toBe(1);
  store.dispose(); await advance(200_000); expect(timers.size).toBe(0); expect(transport.subscriptions).toBe(0);
});
