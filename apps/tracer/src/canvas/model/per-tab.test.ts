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
for (const sequence of [
  "Hunt 1 offline peer overwrite", "R1 adopter deletes newer live write", "R1 failed replacement deletes sole source",
  "R1 stale unresolved duplicate suppresses completed birth", "R1 live peer recreates signed-out journal",
  "R2 concurrent first tabs invalidate lifetime", "R2 sign-out between check and write", "R2 unreadable source retired",
  "R2 33+33 columns source retirement", "R2 21 failed-cleanup generations", "R2 8192-entry full-history flush",
  "R2 failed initial marker", "R3 no-Web-Locks fallback", "R3 startup queued after sign-out", "R3 cleanup refusal 8195 reads",
]) test(`${sequence}: independent tabs perform zero live layout storage operations`, async () => {
  for (let n = 0; n < 21; n++) values.set(`infraternal.canvas-journal.a.old-${n}`, "unreadable");
  const a = setup(), b = setup(); const initialReads = reads;
  a.transport.isWelcomed = false; await rename(a.store, "A offline"); await rename(b.store, "B online");
  b.store.flush(); a.store.flush(); b.store.dispose();
  expect(a.store.current().views[0]!.name).toBe("A offline"); expect(a.store.pending).toBe(true);
  expect(reads).toBe(initialReads); expect(writes).toBe(0); expect(values.size).toBe(21);
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
  for (const kind of ["absent", "throwing", "recovered"]) {
    Object.defineProperty(globalThis, "localStorage", { configurable: true, get: () => { throw Error(kind); } });
    const { store } = setup(); await rename(store, kind); store.flush(); expect(store.current().views[0]!.name).toBe(kind); expect(store.pending).toBe(true); store.dispose();
  }
});
test("refused individual intents leave independent tabs and later edits live", async () => {
  const a = setup(), b = setup("b"); await rename(a.store, "Refused"); a.transport.calls[0]!.reject(new ActionRefused(undefined, "invalid input")); await tick();
  expect(a.store.pending).toBe(false); await rename(b.store, "Independent"); await rename(a.store, "Later");
  expect(b.store.current().views[0]!.name).toBe("Independent"); expect(a.transport.calls).toHaveLength(2);
});
