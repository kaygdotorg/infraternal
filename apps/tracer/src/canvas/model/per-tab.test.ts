/** D312 replacement controls for all storage-specific hunt/R1/R2/R3 failure sequences; originals stay on review branches. */
import { afterEach, beforeEach, expect, test } from "bun:test";
import { ServerCanvasStore, type LayoutTransport } from "./server-store";
import { ActionRefused } from "../../connection";
import type { CanvasDocument } from "./schema";
const document = (revision = 1, name = "Console"): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision, views: [{ id: "console", kind: "console", name, cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }] });
const tick = async () => { for (let i = 0; i < 16; i++) await Promise.resolve(); };
class Transport implements LayoutTransport {
  isWelcomed = true;
  event: (event: Record<string, unknown>) => void = () => {};
  open = () => {};
  calls: Array<{ input: Record<string, unknown>; resolve: (value: Record<string, unknown>) => void; reject: (error: Error) => void }> = [];
  call(_action: string, input: Record<string, unknown>): Promise<Record<string, unknown>> { return new Promise((resolve, reject) => this.calls.push({ input: structuredClone(input), resolve, reject })); }
  subscribe(_filter: { topic: string }, event: (event: Record<string, unknown>) => void, open?: () => void) {
    this.event = event; this.open = open ?? (() => {}); this.open();
    return Object.assign(() => { this.event = () => {}; }, { resync: () => this.open() });
  }
  snapshot(revision = 1, name = "Console") { this.event({ type: "canvas.layout.snapshot", revision, document: document(revision, name), initialized: true }); }
}
const stores: ServerCanvasStore[] = [];
let reads = 0, writes = 0;
const values = new Map<string, string>();
beforeEach(() => {
  reads = 0; writes = 0; values.clear();
  const storage = { getItem: (key: string) => { reads++; return values.get(key) ?? null; }, setItem: (key: string, value: string) => { writes++; values.set(key, value); }, removeItem: (key: string) => values.delete(key), key: (i: number) => { reads++; return [...values.keys()][i] ?? null; }, get length() { reads++; return values.size; } };
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: storage });
});
afterEach(() => { for (const store of stores.splice(0)) store.dispose(); });
function setup(account = "a") { const transport = new Transport(), store = new ServerCanvasStore(transport, account); stores.push(store); transport.snapshot(); return { store, transport }; }
async function rename(store: ServerCanvasStore, name: string) { const before = store.current(), next = structuredClone(before); next.views[0]!.name = name; await store.save(next, undefined, before); }
test("Hunt 1 / R1 adoption: online peers cannot overwrite or retire a live offline queue", async () => {
  const a = setup(), b = setup(); const initialReads = reads;
  a.transport.isWelcomed = false; await rename(a.store, "A offline"); await rename(b.store, "B online");
  b.transport.calls[0]!.resolve({ revision: 2 }); b.transport.snapshot(2, "B online"); await tick();
  b.store.dispose(); a.store.flush();
  expect(a.store.current().views[0]!.name).toBe("A offline"); expect(a.store.pending).toBe(true);
  expect(reads).toBe(initialReads); expect(writes).toBe(0);
});
test("R1 failed replacement / R2 unreadable source / 33+33 legacy columns: sources never retire without import confirmation", async () => {
  const oversized = document(); const view = oversized.views[0]!;
  view.layout = { type: "tiled", columns: Array.from({ length: 66 }, (_, n) => ({ id: `c${n}`, weight: 1, windows: [] })) };
  for (const source of ["unreadable", JSON.stringify(oversized)]) {
    values.set("infraternal.canvas.a", source);
    const { store, transport } = setup(); await rename(store, "Independent"); store.flush();
    expect(transport.calls).toHaveLength(1); expect(values.get("infraternal.canvas.a")).toBe(source); expect(writes).toBe(0);
    store.dispose();
  }
});
for (const count of [8192, 32768]) test(`R2 full-history flush / R3 refused cleanup: ${count} queued intents do zero storage work`, async () => {
  for (let n = 0; n < 8195; n++) values.set(`infraternal.canvas-journal.a.old-${n}`, "unreadable");
  const { store, transport } = setup(); transport.isWelcomed = false; const initialReads = reads;
  for (let n = 0; n < count; n++) {
    const before = store.current(), next = structuredClone(before);
    if (n % 2) next.views[0]!.cell.x = n % 1000; else next.views[0]!.name = `Name ${n}`;
    await store.save(next, undefined, before);
  }
  for (let n = 0; n < 3; n++) store.flush();
  expect(store.pending).toBe(true); expect(reads).toBe(initialReads); expect(writes).toBe(0); expect(values.size).toBe(8195);
}, 120_000);
test("R2 concurrent first tabs / failed marker / R3 missing locks: no lifetime creation or lock fallback exists", async () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, "navigator"); let lockReads = 0;
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { get locks() { lockReads++; throw Error("unavailable"); } } });
  try {
    const a = setup(), b = setup(); await rename(a.store, "A"); await rename(b.store, "B");
    expect(a.store.pending).toBe(true); expect(b.store.pending).toBe(true); expect(lockReads).toBe(0); expect(writes).toBe(0);
  } finally { if (original) Object.defineProperty(globalThis, "navigator", original); else Reflect.deleteProperty(globalThis, "navigator"); }
});
test("R2 sign-out between check/write / R3 delayed startup: teardown invalidates old callbacks before later login", async () => {
  for (let n = 0; n < 21; n++) values.set(`infraternal.canvas-journal.a.old-${n}`, "unreadable");
  const old = setup(); await rename(old.store, "Old"); const late = old.transport.calls[0]!;
  const callback = old.transport.event; old.store.dispose(); const fresh = setup();
  callback({ type: "canvas.layout.snapshot", revision: 2, initialized: true, document: document(2, "Old") });
  late.resolve({ revision: 2 }); await old.store.save(document(2, "Late")); await tick();
  expect(old.store.current().views).toEqual([]); expect(fresh.store.current().views[0]!.name).toBe("Console");
  expect(values.size).toBe(21); expect(writes).toBe(0);
});
test("R2 completed capture before 300 ms: unconfirmed tab loss is explicit; confirmed state restores from server", async () => {
  const a = setup(); await rename(a.store, "Unconfirmed"); expect(a.store.pending).toBe(true); a.store.dispose();
  const b = setup(); expect(b.store.current().views[0]!.name).toBe("Console"); expect(b.store.pending).toBe(false);
  await rename(b.store, "Confirmed"); const call = b.transport.calls[0]!;
  b.transport.event({ type: "canvas.layout.operation", revision: 2, op_id: call.input.op_id, intent: call.input.intent });
  expect(b.store.pending).toBe(false); b.store.dispose();
  const c = setup(); c.transport.snapshot(2, "Confirmed"); expect(c.store.current().views[0]!.name).toBe("Confirmed"); expect(writes).toBe(0);
});
test("R2 100 snapshots and 50 ms do not establish a receipt identity or expire uncertainty", async () => {
  const { store, transport } = setup(); await rename(store, "Mine"); const input = transport.calls[0]!.input;
  for (let n = 0; n < 100; n++) { transport.open(); transport.snapshot(n + 2, "Mine"); expect(store.pending).toBe(true); expect(transport.calls.at(-1)!.input).toEqual(input); }
  await new Promise((resolve) => setTimeout(resolve, 60)); expect(store.pending).toBe(true);
  transport.calls.at(-1)!.resolve({ revision: 2 }); await tick(); expect(store.pending).toBe(false);
});
test("absent, throwing and recovered storage cannot change live edit acceptance", async () => {
  const available = Object.getOwnPropertyDescriptor(globalThis, "localStorage")!;
  for (const kind of ["absent", "throwing", "recovered"]) {
    if (kind === "absent") Reflect.deleteProperty(globalThis, "localStorage");
    else Object.defineProperty(globalThis, "localStorage", { configurable: true, get: () => { throw Error(kind); } });
    const { store } = setup();
    if (kind === "recovered") Object.defineProperty(globalThis, "localStorage", available);
    await rename(store, kind); store.flush(); expect(store.current().views[0]!.name).toBe(kind); expect(store.pending).toBe(true); store.dispose();
  }
  Object.defineProperty(globalThis, "localStorage", available);
});
test("refused individual intents leave independent tabs and later edits live", async () => {
  const a = setup(), b = setup("b"); await rename(a.store, "Refused"); a.transport.calls[0]!.reject(new ActionRefused(undefined, "invalid input")); await tick();
  expect(a.store.pending).toBe(false); await rename(b.store, "Independent"); await rename(a.store, "Later");
  expect(b.store.current().views[0]!.name).toBe("Independent"); expect(a.transport.calls).toHaveLength(2);
});
test("R1 stale unresolved duplicate cannot suppress a completed same-tab birth", async () => {
  for (const unresolved of [[], ["w"]]) values.set(`infraternal.canvas-journal.a.${unresolved.length}`, JSON.stringify({ pending: [{ op_id: "old", intent: { type: "open", window: { id: "w" } } }], unresolved }));
  const { store, transport } = setup(), before = store.current(), shell = structuredClone(before);
  const layout = shell.views[0]!.layout; if (layout.type !== "tiled") throw Error("expected tiled view");
  layout.columns.push({ id: "c", weight: 1, windows: [{ id: "w", target: { type: "settings", section: "pending" } }] });
  await store.save(shell, undefined, before, new Set(["w"])); expect(transport.calls).toHaveLength(0);
  const completed = store.current(), completedLayout = completed.views[0]!.layout;
  if (completedLayout.type !== "tiled") throw Error("expected tiled view");
  completedLayout.columns[0]!.windows[0]!.target = { type: "settings", section: "appearance" };
  await store.save(completed);
  expect(transport.calls).toHaveLength(1);
  expect((transport.calls[0]!.input.intent as { window: { target: unknown } }).window.target).toEqual({ type: "settings", section: "appearance" });
  expect(values.size).toBe(2); expect(writes).toBe(0);
});
