/** Subscription, migration and per-tab retry ordering regressions for the product canvas (#243). */
import { beforeEach, expect, test } from "bun:test";
import { ServerCanvasStore, type LayoutTransport } from "./server-store";
import { ActionRefused } from "../../connection";
import { reduce, type Intent } from "./operations";
import type { CanvasDocument } from "./document";
import { canvasKey, clearAccountStorage } from "../../account-storage";
const document = (): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision: 0, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }] });
class Transport implements LayoutTransport {
  resyncs = 0;
  event: (e: Record<string, unknown>) => void = () => {};
  open: () => void = () => {};
  calls: Array<{ action: string; input: Record<string, unknown>; resolve: (r: Record<string, unknown>) => void; reject: (error?: Error) => void }> = [];
  call(action: string, input: Record<string, unknown>): Promise<Record<string, unknown>> { return new Promise((resolve, reject) => this.calls.push({ action, input: structuredClone(input), resolve, reject: (error?: Error) => reject(error ?? Error("disconnected")) })); }
  subscribe(_filter: { topic: string }, event: (e: Record<string, unknown>) => void, open?: () => void) { this.event = event; this.open = open ?? (() => {}); this.open(); return Object.assign(() => { this.event = () => {}; }, { resync: () => { this.resyncs++; this.open(); } }); }
  snapshot(doc = document(), initialized = true): void { this.event({ type: "canvas.layout.snapshot", document: doc, revision: doc.revision, initialized }); }
}
const tick = async (): Promise<void> => { for (let i = 0; i < 16; i++) await Promise.resolve(); };
/** Models the production pin bound and stale-base acceptance while broadcasting accepted operations to every device. */
class PinLimitTransport implements LayoutTransport {
  readonly isWelcomed = true;
  readonly listeners = new Set<(event: Record<string, unknown>) => void>();
  readonly document: CanvasDocument = {
    format: "infraternal.canvas", version: 1, revision: 1,
    views: [{ id: "mesh", kind: "mesh", name: "Mesh", cell: { x: 0, y: 0 }, layout: { type: "graph", pinned: {} } }],
  };
  accepted = 0;
  refused = 0;
  processed = 0;
  #tail: Promise<void> = Promise.resolve();

  subscribe(_filter: { topic: string }, event: (e: Record<string, unknown>) => void, open?: () => void) {
    this.listeners.add(event); open?.();
    event({ type: "canvas.layout.snapshot", document: structuredClone(this.document), revision: this.document.revision, initialized: true });
    return Object.assign(() => { this.listeners.delete(event); }, { resync: () => event({ type: "canvas.layout.snapshot", document: structuredClone(this.document), revision: this.document.revision, initialized: true }) });
  }

  call(action: string, input: Record<string, unknown>): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      this.#tail = this.#tail.then(() => {
        this.processed++;
        const intent = input.intent as Intent | undefined;
        if (action !== "canvas.layout.apply" || !intent || typeof input.base_revision !== "number" || input.base_revision > this.document.revision) {
          this.refused++; reject(new ActionRefused(undefined, "invalid input")); return;
        }
        const next = structuredClone(this.document);
        reduce(next, intent);
        const view = next.views.find((candidate) => candidate.id === "mesh")!;
        const invalidPins = view.layout.type !== "graph"
          || Object.keys(view.layout.pinned).length > 256
          || Object.values(view.layout.pinned).some(({ x, y }) =>
            !Number.isFinite(x) || !Number.isFinite(y) || Math.abs(x) > 100_000 || Math.abs(y) > 100_000);
        if (invalidPins) {
          this.refused++; reject(new ActionRefused(undefined, "invalid input")); return;
        }
        next.revision++;
        Object.assign(this.document, next);
        this.accepted++;
        const event = { type: "canvas.layout.operation", revision: this.document.revision, op_id: input.op_id, intent, noop: false };
        for (const listener of this.listeners) listener(event);
        resolve({ revision: this.document.revision });
      });
    });
  }

  async drain(expected: number): Promise<void> {
    for (let turn = 0; turn < 2000 && this.processed < expected; turn++) { await this.#tail; await tick(); }
    if (this.processed !== expected) throw new Error(`processed ${this.processed} of ${expected} layout intents`);
  }
}
beforeEach(() => {
  const values = new Map<string, string>();
  const area = { getItem: (k: string) => values.get(k) ?? null, setItem: (k: string, v: string) => values.set(k, v), removeItem: (k: string) => values.delete(k), key: (i: number) => [...values.keys()][i] ?? null, get length() { return values.size; } };
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: area });
  Object.defineProperty(globalThis, "sessionStorage", { configurable: true, value: area });
});
const opened: Intent = { type: "open", view_id: "console", column_id: "c", window: { id: "w", target: { type: "settings", section: "appearance" } } };
test("a negative drop on a 1,025-node mesh writes one pin, and the peer ends with every pin (#24)", async () => {
  const transport = new PinLimitTransport();
  const first = new ServerCanvasStore(transport, "mesh-owner"), second = new ServerCanvasStore(transport, "mesh-peer");
  try {
    const initial = await first.load(); await second.load();
    const graphOf = (doc: CanvasDocument) => {
      const view = doc.views.find((candidate) => candidate.id === "mesh")!;
      if (view.layout.type !== "graph") throw new Error("graph view missing");
      return view.layout;
    };
    // 200 cards moved earlier; a 1,000-host mesh with 25 tags has 1,025 nodes, almost all unmoved.
    const before = structuredClone(initial!);
    for (let n = 0; n < 200; n++) graphOf(before).pinned[`node-${n}`] = { x: n * 16, y: n * 16 };
    await first.save(before); first.flush();
    await transport.drain(200); // one intent per earlier pin
    const baseline = transport.processed;
    // The drop: the card is now left of and above the auto layout. Pins may be negative; no other pin is rewritten.
    const dropped = structuredClone(before);
    graphOf(dropped).pinned["node-1000"] = { x: -1280, y: -480 };
    const saved = first.save(dropped);
    first.flush();
    expect(first.pending).toBe(true);
    await saved;
    await transport.drain(baseline + 1);
    expect(transport.refused).toBe(0);
    const peer = await second.load();
    // The count and moved point alone miss a peer that changed or lost any earlier coordinates.
    expect(graphOf(peer!).pinned).toEqual(graphOf(dropped).pinned);
  } finally { first.dispose(); second.dispose(); }
});
test("repeated pin moves reach both coordinate limits; the next move is refused and rolled back", async () => {
  const transport = new PinLimitTransport(), notices: boolean[] = [];
  const first = new ServerCanvasStore(transport, "mesh-bound-owner", (definitive) => notices.push(definitive === true));
  const second = new ServerCanvasStore(transport, "mesh-bound-peer");
  const graphOf = (doc: CanvasDocument) => {
    const view = doc.views.find((candidate) => candidate.id === "mesh")!;
    if (view.layout.type !== "graph") throw new Error("graph view missing");
    return view.layout;
  };
  try {
    await first.load(); await second.load();
    let expected = 0;
    for (let step = 1; step <= 10; step++) {
      const next = structuredClone(first.current());
      graphOf(next).pinned["node-0"] = { x: -step * 10_000, y: step * 10_000 };
      const saved = first.save(next); first.flush(); await saved;
      await transport.drain(++expected);
      expect(graphOf(second.current()).pinned["node-0"]).toEqual({ x: -step * 10_000, y: step * 10_000 });
    }

    const outside = structuredClone(first.current());
    graphOf(outside).pinned["node-0"] = { x: -100_001, y: 100_001 };
    const saved = first.save(outside); first.flush(); await saved;
    await transport.drain(++expected);

    expect(transport.accepted).toBe(10);
    expect(transport.refused).toBe(1);
    expect(notices).toEqual([true]);
    expect(graphOf(first.current()).pinned["node-0"]).toEqual({ x: -100_000, y: 100_000 });
    expect(graphOf(second.current()).pinned["node-0"]).toEqual({ x: -100_000, y: 100_000 });
  } finally { first.dispose(); second.dispose(); }
});
test("event before Result and duplicate events do not apply an optimistic edit twice", async () => {
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); transport.snapshot();
  const next = document(); reduce(next, opened); await store.save(next);
  expect(transport.calls).toHaveLength(1); const call = transport.calls[0]!;
  transport.event({ type: "canvas.layout.operation", revision: 1, op_id: call.input.op_id, intent: opened, noop: false });
  transport.event({ type: "canvas.layout.operation", revision: 1, op_id: call.input.op_id, intent: opened, noop: false });
  call.resolve({ revision: 1 }); await tick();
  const value = await store.load(); expect(value?.revision).toBe(1); expect(JSON.stringify(value).match(/"id":"w"/g)).toHaveLength(1); store.dispose();
});
test("reconnect retries the exact request and an old receipt removes its optimistic overlay", async () => {
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); transport.snapshot();
  const next = document(); reduce(next, opened); await store.save(next); const first = transport.calls[0]!;
  first.reject(); await tick(); transport.open();
  const head = document(); reduce(head, opened); head.revision = 2; transport.snapshot(head); await tick();
  const retry = transport.calls[1]!; expect(retry.input).toEqual(first.input);
  retry.resolve({ revision: 1 }); await tick(); store.flush();
  expect(store.pending).toBe(false); store.dispose();
});
test("legacy import remains intact until canonical confirmation even if another device initialized", async () => {
  const legacy = document(); reduce(legacy, opened); localStorage.setItem(canvasKey("a"), JSON.stringify(legacy));
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a");
  transport.snapshot(); expect(await store.load()).toEqual(document()); await tick(); store.flush();
  expect(transport.calls[0]!.action).toBe("canvas.layout.initialize");
  expect(JSON.parse(localStorage.getItem(canvasKey("a"))!)).toEqual(legacy);
  transport.calls[0]!.resolve({ revision: 1 }); await tick(); store.flush();
  expect(JSON.parse(localStorage.getItem(canvasKey("a"))!)).toEqual(legacy);
  const confirmed = structuredClone(legacy); confirmed.revision = 1; transport.snapshot(confirmed); store.flush();
  expect(localStorage.getItem(canvasKey("a"))).toBeNull(); store.dispose();
});
test("dispose cancels late callbacks after sign-out", async () => {
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); transport.snapshot();
  const next = document(); reduce(next, opened); await store.save(next); store.dispose(); clearAccountStorage("a");
  transport.calls[0]!.resolve({ revision: 1 }); await tick(); store.flush(); expect(localStorage.getItem(canvasKey("a"))).toBeNull();
});
test("a pending reference preserves unrelated edits across remote paints and is never sent", async () => {
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); transport.snapshot();
  const initial = document(); reduce(initial, opened);
  await store.save(initial); const first = transport.calls[0]!;
  transport.event({ type: "canvas.layout.operation", revision: 1, op_id: first.input.op_id, intent: opened }); first.resolve({ revision: 1 }); await tick();
  const pending: Intent = { type: "split", view_id: "console", column_id: "c", anchor_id: "w", axis: "down", window: { id: "new", target: { type: "session", id: "new", host: "local" } } };
  const split = store.current(); reduce(split, pending);
  await store.save(split, new Map([["new", { windowId: "new", anchorId: "w", axis: "down" }]]), initial, new Set(["new"]));
  const moved = structuredClone(split); moved.views[0]!.cell.x = 3;
  await store.save(moved, undefined, split, new Set(["new"]));
  expect(transport.calls).toHaveLength(1);
  transport.event({ type: "canvas.layout.operation", revision: 2, op_id: "peer", intent: { type: "view.update", view_id: "console", name: "Peer" } });
  expect(store.current().views[0]!.cell.x).toBe(3);
  const resolved = structuredClone(store.current()), layout = resolved.views[0]!.layout;
  if (layout.type === "tiled") layout.columns[0]!.windows.find((w) => w.id === "new")!.target = { type: "session", id: "real", host: "local" };
  await store.save(resolved, undefined, store.current(), new Set());
  expect(transport.calls).toHaveLength(3);
  expect((transport.calls[1]!.input.intent as Extract<Intent, { type: "split" }>).window.target).toEqual({ type: "session", id: "real", host: "local" });
  store.dispose();
});
test("closing an unsent shell removes its unresolved birth without blocking surviving children", async () => {
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); transport.snapshot();
  const next = document(); reduce(next, { type: "open", view_id: "console", column_id: "c", window: { id: "pending", target: { type: "session", id: "pending", host: "local" } } });
  await store.save(next, undefined, document(), new Set(["pending"]));
  const surviving = structuredClone(next); reduce(surviving, { type: "split", view_id: "console", column_id: "c", window: { id: "child", target: { type: "session", id: "session", host: "local" } }, anchor_id: "pending", axis: "down" });
  await store.save(surviving, new Map([["child", { windowId: "child", anchorId: "pending", axis: "down" }]]), next, new Set(["pending"]));
  const closed = structuredClone(surviving); reduce(closed, { type: "close", window_id: "pending" });
  await store.save(closed, undefined, surviving);
  expect(transport.calls).toHaveLength(1);
  const intent = transport.calls[0]!.input.intent as Extract<Intent, { type: "open" }>;
  expect(intent.type).toBe("open"); expect(intent.window.id).toBe("child");
  store.flush(); expect(JSON.stringify(store.current())).not.toContain('"id":"pending"'); store.dispose();
});

test("an acknowledgement after its ordered event does not repaint the same layout", async () => {
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); transport.snapshot();
  let paints = 0; store.subscribe(() => { paints++; });
  const next = document(); reduce(next, opened); await store.save(next);
  const call = transport.calls[0]!;
  transport.event({ type: "canvas.layout.operation", revision: 1, op_id: call.input.op_id, intent: opened });
  expect(paints).toBe(2); call.resolve({ revision: 1 }); await tick(); expect(paints).toBe(2); store.dispose();
});


test("a bootstrap receipt before its canonical snapshot keeps the legacy layout drawable without rewriting its source", async () => {
  const legacy = document(); reduce(legacy, opened); localStorage.setItem(canvasKey("a"), JSON.stringify(legacy));
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); transport.snapshot(document(), false);
  const call = transport.calls[0]!; call.resolve({ revision: 1 }); await tick();
  expect(store.current().views[0]!.layout).toEqual(legacy.views[0]!.layout);
  store.dispose();
  const restored = new ServerCanvasStore(new Transport(), "a");
  restored.dispose(); expect(await restored.load()).toBeUndefined(); expect(localStorage.getItem(canvasKey("a"))).not.toBeNull();
});

test("ready edits share one network round trip with a bounded in-flight window", async () => {
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); transport.snapshot();
  let previous = document();
  for (let i = 0; i < 8; i++) {
    const next = structuredClone(previous); next.views[0]!.name = `Console ${i}`;
    await store.save(next, undefined, previous); previous = next;
  }
  expect(transport.calls).toHaveLength(4);
  const first = transport.calls[0]!; first.resolve({ revision: 1 }); await tick();
  expect(transport.calls).toHaveLength(5);
  expect(transport.calls[1]!.input.base_revision).toBe(0);
  store.dispose();
});

test("the optimistic semantic projection paints before any server receipt", async () => {
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); transport.snapshot();
  const paints: CanvasDocument[] = []; store.subscribe(() => paints.push(store.current()));
  const next = document(); reduce(next, opened); await store.save(next);
  expect(paints).toHaveLength(1); expect(paints[0]!.views[0]!.layout).toEqual(next.views[0]!.layout);
  const call = transport.calls[0]!;
  transport.event({ type: "canvas.layout.operation", revision: 1, op_id: call.input.op_id, intent: opened });
  expect(paints).toHaveLength(2); store.dispose();
});

test("a no-op drawing capture does not trigger another paint", async () => {
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); transport.snapshot();
  let paints = 0; store.subscribe(() => { paints++; }); await store.save(document());
  expect(paints).toBe(0); expect(transport.calls).toHaveLength(0); store.dispose();
});


// A permanently refused intent must not suppress every subsequent independent edit.
test("review: a refused structural edit cannot strand later valid edits", async () => {
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); transport.snapshot();
  try {
    const next = document(); reduce(next, opened); await store.save(next);
    const refused = transport.calls[0]!; refused.reject(new ActionRefused(undefined, "invalid")); await tick();
    const later = store.current(); later.views[0]!.name = "Later edit";
    await store.save(later, undefined, next); await tick();
    expect(transport.calls.some((call) => (call.input.intent as Intent).type === "view.update")).toBe(true);
  } finally { store.dispose(); }
});

test("a definitive refusal paints rollback in memory and never retries after reconnect", async () => {
  const transport = new Transport(), notices: boolean[] = [];
  const store = new ServerCanvasStore(transport, "a", (definitive) => notices.push(definitive === true)); transport.snapshot();
  try {
    const baseline = store.current(), next = structuredClone(baseline); reduce(next, opened);
    let painted = store.current(); store.subscribe(() => { painted = store.current(); });
    await store.save(next);
    expect(painted).toEqual(next);
    transport.calls[0]!.reject(new ActionRefused(undefined, "invalid")); await tick(); store.flush();
    expect(painted).toEqual(baseline); expect(notices).toEqual([true]);
    expect(store.pending).toBe(false); expect(store.current()).toEqual(baseline);
    transport.open(); transport.snapshot(); await tick();
    expect(transport.calls).toHaveLength(1);
  } finally { store.dispose(); }
});

test("a stale refusal cannot discard a new-connection retry", async () => {
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); transport.snapshot();
  try {
    const next = document(); reduce(next, opened); await store.save(next);
    transport.open(); transport.snapshot(); await tick();
    expect(transport.calls).toHaveLength(2);
    transport.calls[0]!.reject(new ActionRefused(undefined, "invalid")); await tick();
    store.flush(); expect(store.pending).toBe(true);
    expect(transport.calls[1]!.input).toEqual(transport.calls[0]!.input);
  } finally { store.dispose(); }
});

// A refusal must free a full pipeline slot, including work that has not reached the socket yet.
test("review r2: refusal drains independent edits waiting behind four in-flight requests", async () => {
  const transport = new Transport(), notices: boolean[] = [];
  const store = new ServerCanvasStore(transport, "a", (definitive) => notices.push(definitive === true));
  transport.snapshot();
  try {
    let previous = store.current();
    const birth = structuredClone(previous); reduce(birth, opened); await store.save(birth, undefined, previous); previous = birth;
    for (let n = 0; n < 6; n++) {
      const next = structuredClone(previous); next.views[0]!.name = `Queued ${n}`; if (n % 2) next.views[0]!.cell = { x: n, y: 0 };
      await store.save(next, undefined, previous); previous = next;
    }
    expect(transport.calls).toHaveLength(4);
    const first = transport.calls[0]!;
    first.reject(new ActionRefused(undefined, "invalid")); await tick();
    expect(transport.calls).toHaveLength(5); expect(notices).toEqual([true]);
    let revision = 0;
    // Each accepted event precedes its receipt; receipts release the remaining
    // queued suffix without another snapshot.
    for (let index = 1; index < transport.calls.length; index++) {
      const call = transport.calls[index]!;
      transport.event({ type: "canvas.layout.operation", revision: ++revision, op_id: call.input.op_id, intent: call.input.intent });
      call.resolve({ revision }); await tick();
    }
    expect(transport.calls).toHaveLength(7); expect(revision).toBe(6);
    store.flush();
    expect(store.pending).toBe(false);
    expect(store.current().views[0]!.name).toBe("Queued 5");
    const final = store.current(); transport.open(); transport.snapshot(final); await tick();
    expect(transport.calls).toHaveLength(7);
  } finally { store.dispose(); }
});

// Virtual scheduling covers the combined gap, withdrawal and reconnect state machine without host timing claims.

// The normal 300 ms fixture RTT must not race the first snapshot watchdog into another Subscribe.
test("a normal reconnect snapshot arrives before any replacement is requested", () => {
  const original = { setTimeout: globalThis.setTimeout, clearTimeout: globalThis.clearTimeout };
  const originalRandom = Math.random;
  const timers = new Map<number, { run: () => void; at: number }>(); let id = 0, now = 0;
  globalThis.setTimeout = ((run: () => void, delay: number) => { timers.set(++id, { run, at: now + delay }); return id; }) as unknown as typeof setTimeout;
  globalThis.clearTimeout = ((timer: number) => { timers.delete(timer); }) as unknown as typeof clearTimeout;
  Math.random = () => 0;
  const transport = new Transport(), store = new ServerCanvasStore(transport, "normal-reconnect");
  try {
    transport.snapshot(); store.flush(); transport.open();
    const head = document(); head.revision = 1;
    setTimeout(() => transport.snapshot(head), 300);
    while (true) {
      const next = [...timers].sort((a, b) => a[1].at - b[1].at)[0];
      if (!next || next[1].at > 300) break;
      now = next[1].at; timers.delete(next[0]); next[1].run();
    }
    expect(transport.resyncs).toBe(0); expect(store.current().revision).toBe(1);
    store.flush(); expect(timers.size).toBe(0);
  } finally { store.dispose(); Object.assign(globalThis, original); Math.random = originalRandom; }
});
for (const receiptFirst of [false, true]) test(`legacy import retires only after receipt and canonical coverage, receipt first=${receiptFirst}`, async () => {
  const key = canvasKey("legacy-order"), legacy = document(); localStorage.setItem(key, JSON.stringify(legacy));
  const transport = new Transport(), store = new ServerCanvasStore(transport, "legacy-order");
  try {
    transport.snapshot({ ...document(), views: [] }, false);
    const call = transport.calls[0]!; expect(call.action).toBe("canvas.layout.initialize");
    const canonical = { ...legacy, revision: 2 };
    if (receiptFirst) { call.resolve({ revision: 2 }); await tick(); expect(localStorage.getItem(key)).not.toBeNull(); transport.snapshot(canonical); }
    else { transport.snapshot(canonical); expect(localStorage.getItem(key)).not.toBeNull(); call.resolve({ revision: 2 }); await tick(); }
    expect(localStorage.getItem(key)).toBeNull(); expect(store.pending).toBe(false);
  } finally { store.dispose(); }
});
test("refused import and refused cleanup preserve their legacy source until confirmed removal succeeds", async () => {
  const key = canvasKey("legacy-refusal"), source = JSON.stringify(document()); localStorage.setItem(key, source);
  const transport = new Transport(), store = new ServerCanvasStore(transport, "legacy-refusal");
  try {
    transport.snapshot({ ...document(), views: [] }, false); transport.snapshot({ ...document(), revision: 2 });
    transport.calls[0]!.reject(new ActionRefused()); await tick();
    expect(localStorage.getItem(key)).toBe(source);
  } finally { store.dispose(); }
  const next = new Transport(); let cleanupNotices = 0;
  const imported = new ServerCanvasStore(next, "legacy-refusal", (_definitive, delayed) => { if (delayed) cleanupNotices++; });
  const remove = localStorage.removeItem.bind(localStorage);
  try {
    next.snapshot({ ...document(), views: [] }, false);
    localStorage.removeItem = () => { throw Error("cleanup refused"); };
    next.calls[0]!.resolve({ revision: 2 }); await tick(); next.snapshot({ ...document(), revision: 2 });
    expect(localStorage.getItem(key)).toBe(source); expect(cleanupNotices).toBe(1);
    localStorage.removeItem = remove; next.snapshot({ ...document(), revision: 2 }); expect(localStorage.getItem(key)).toBeNull();
  } finally { localStorage.removeItem = remove; imported.dispose(); }
});
test("reference completion during failed logout is retained without sending until edits resume", async () => {
  const { pauseAccountWork } = await import("../../account-lifetime");
  const transport = new Transport(), store = new ServerCanvasStore(transport, "logout-completion");
  try {
    transport.snapshot();
    const shell = store.current(); reduce(shell, opened); await store.save(shell, undefined, undefined, new Set(["w"]));
    expect(transport.calls).toHaveLength(0); pauseAccountWork("logout-completion", true);
    const resolved = store.current(), layout = resolved.views[0]!.layout;
    if (layout.type !== "tiled") throw Error("expected tiled view");
    layout.columns[0]!.windows[0]!.target = { type: "settings", section: "account" };
    await store.save(resolved); expect(transport.calls).toHaveLength(0);
    pauseAccountWork("logout-completion", false);
    expect(transport.calls).toHaveLength(1);
    expect((transport.calls[0]!.input.intent as Extract<Intent, { type: "open" }>).window.target).toEqual({ type: "settings", section: "account" });
  } finally { store.dispose(); }
});
