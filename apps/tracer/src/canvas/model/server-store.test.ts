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
const tick = async (): Promise<void> => { await Promise.resolve(); await Promise.resolve(); };
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
  const head = document(); reduce(head, opened); head.revision = 2; transport.snapshot(head);
  const retry = transport.calls[1]!; expect(retry.input).toEqual(first.input);
  retry.resolve({ revision: 1 }); await tick(); store.flush();
  expect(JSON.parse(localStorage.getItem(canvasKey("a"))!).pending).toHaveLength(0); store.dispose();
});
test("legacy import remains intact until acknowledged even if another device initialized", async () => {
  const legacy = document(); reduce(legacy, opened); localStorage.setItem(canvasKey("a"), JSON.stringify(legacy));
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); expect(await store.load()).toEqual(legacy);
  transport.snapshot(); store.flush();
  expect(transport.calls[0]!.action).toBe("canvas.layout.initialize");
  expect(JSON.parse(localStorage.getItem(canvasKey("a"))!).migration.document).toEqual(legacy);
  transport.calls[0]!.resolve({ revision: 1 }); await tick(); store.flush();
  expect(JSON.parse(localStorage.getItem(canvasKey("a"))!).migration).toBeUndefined(); store.dispose();
});
test("dispose cancels late cache writes after sign-out", async () => {
  const transport = new Transport(), store = new ServerCanvasStore(transport, "a"); transport.snapshot();
  const next = document(); reduce(next, opened); await store.save(next); store.dispose(); clearAccountStorage("a");
  transport.calls[0]!.resolve({ revision: 1 }); await tick(); store.flush(); expect(localStorage.getItem(canvasKey("a"))).toBeNull();
});
