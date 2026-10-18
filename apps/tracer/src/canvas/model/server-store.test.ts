/** Subscription, migration and durable retry ordering regressions for the product canvas (#243). */
import { beforeEach, expect, test } from "bun:test";
import { ServerCanvasStore, type LayoutTransport } from "./server-store";
import { reduce, type Intent } from "./operations";
import type { CanvasDocument } from "./document";
import { canvasKey, clearAccountStorage } from "../../account-storage";
const document = (): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision: 0, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }] });
class Transport implements LayoutTransport {
  event: (e: Record<string, unknown>) => void = () => {};
  open: () => void = () => {};
  calls: Array<{ action: string; input: Record<string, unknown>; resolve: (r: Record<string, unknown>) => void; reject: () => void }> = [];
  call(action: string, input: Record<string, unknown>): Promise<Record<string, unknown>> { return new Promise((resolve, reject) => this.calls.push({ action, input: structuredClone(input), resolve, reject: () => reject(Error("disconnected")) })); }
  subscribe(_filter: { topic: string }, event: (e: Record<string, unknown>) => void, open?: () => void): () => void { this.event = event; this.open = open ?? (() => {}); this.open(); return () => { this.event = () => {}; }; }
  snapshot(doc = document(), initialized = true): void { this.event({ type: "canvas.layout.snapshot", document: doc, revision: doc.revision, initialized }); }
}
const tick = async (): Promise<void> => { for (let i = 0; i < 16; i++) await Promise.resolve(); };
beforeEach(() => {
  const values = new Map<string, string>();
  const area = { getItem: (k: string) => values.get(k) ?? null, setItem: (k: string, v: string) => values.set(k, v), removeItem: (k: string) => values.delete(k), key: (i: number) => [...values.keys()][i] ?? null, get length() { return values.size; } };
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: area });
  Object.defineProperty(globalThis, "sessionStorage", { configurable: true, value: area });
});
const opened: Intent = { type: "open", view_id: "console", column_id: "c", window: { id: "w", target: { type: "settings", section: "appearance" } } };
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
  expect(JSON.parse(localStorage.getItem(canvasKey("a"))!).pending).toHaveLength(0); store.dispose();
});
test("legacy import remains intact until canonical confirmation even if another device initialized", async () => {
  const legacy = document(); reduce(legacy, opened); localStorage.setItem(canvasKey("a"), JSON.stringify(legacy));
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); expect(await store.load()).toEqual(legacy);
  transport.snapshot(); await tick(); store.flush();
  expect(transport.calls[0]!.action).toBe("canvas.layout.initialize");
  expect(JSON.parse(localStorage.getItem(canvasKey("a"))!).migration.document).toEqual(legacy);
  transport.calls[0]!.resolve({ revision: 1 }); await tick(); store.flush();
  expect(JSON.parse(localStorage.getItem(canvasKey("a"))!).migration.revision).toBe(1);
  const confirmed = structuredClone(legacy); confirmed.revision = 1; transport.snapshot(confirmed); store.flush();
  expect(JSON.parse(localStorage.getItem(canvasKey("a"))!).migration).toBeUndefined(); store.dispose();
});
test("dispose cancels late cache writes after sign-out", async () => {
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
  store.flush(); expect(JSON.stringify(JSON.parse(localStorage.getItem(canvasKey("a"))!).pending)).not.toContain('"id":"pending"'); store.dispose();
});
test("an acknowledgement after its ordered event does not repaint the same layout", async () => {
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); transport.snapshot();
  let paints = 0; store.subscribe(() => { paints++; });
  const next = document(); reduce(next, opened); await store.save(next);
  const call = transport.calls[0]!;
  transport.event({ type: "canvas.layout.operation", revision: 1, op_id: call.input.op_id, intent: opened });
  expect(paints).toBe(2); call.resolve({ revision: 1 }); await tick(); expect(paints).toBe(2); store.dispose();
});

test("a bootstrap receipt before its canonical snapshot keeps the legacy layout drawable", async () => {
  const legacy = document(); reduce(legacy, opened); localStorage.setItem(canvasKey("a"), JSON.stringify(legacy));
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); transport.snapshot(document(), false);
  const call = transport.calls[0]!; call.resolve({ revision: 1 }); await tick();
  expect(store.current().views[0]!.layout).toEqual(legacy.views[0]!.layout);
  store.dispose();
  const restored = new ServerCanvasStore(new Transport(), "a");
  expect((await restored.load())!.views[0]!.layout).toEqual(legacy.views[0]!.layout); restored.dispose();
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

test("an interrupted first load does not turn a revision-zero cache into an intentional empty layout", async () => {
  const empty: CanvasDocument = { format: "infraternal.canvas", version: 1, revision: 0, views: [] };
  localStorage.setItem(canvasKey("a"), JSON.stringify({ cacheVersion: 2, canonical: empty, document: empty, pending: [] }));
  const first = new ServerCanvasStore(new Transport(), "a"); expect(await first.load()).toBeUndefined(); first.dispose();
  empty.revision = 2;
  localStorage.setItem(canvasKey("a"), JSON.stringify({ cacheVersion: 2, canonical: empty, document: empty, pending: [] }));
  const intentional = new ServerCanvasStore(new Transport(), "a"); expect((await intentional.load())?.views).toEqual([]); intentional.dispose();
  const transport = new Transport(), live = new ServerCanvasStore(transport, "b");
  empty.revision = 0; transport.snapshot(empty, false);
  transport.event({ type: "canvas.layout.operation", revision: 1, op_id: "close", noop: true, intent: { type: "close", window_id: "missing" } });
  expect((await live.load())?.views).toEqual([]); live.dispose();
});
