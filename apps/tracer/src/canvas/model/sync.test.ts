/** Local input reaches the semantic journal before a paint, independent of network or new-session readiness (#243). */
import { expect, test } from "bun:test";
import type { Ctx } from "../context";
import { metricsFor } from "../layout/geometry";
import { ServerCanvasStore } from "./server-store";
import { toDocument, documentWindows } from "./document";
import { createDocumentSync } from "./sync";
import type { CanvasDocument } from "./document";
import type { ViewModel } from "./types";

test("a pending session never delays other edits or waits for a network receipt", async () => {
  const metrics = metricsFor(1440, 900, false);
  const view: ViewModel = { id: "console", name: "Console", layout: "tiled", x: 0, y: 0, nodes: [], cols: [{ id: "c", w: metrics.colW, wins: [{ id: "new", kind: "terminal", host: "local" }] }] };
  const saves: Array<{ doc: CanvasDocument; unresolved: ReadonlySet<string> }> = [];
  const cx = { views: new Map([[view.id, { view, wins: new Map([["new", { model: view.cols[0]!.wins[0]! }]]) }]]), state: { metrics }, adapters: { store: {
    acceptsPendingReferences: true,
    save(doc: CanvasDocument, _hints: unknown, _before: unknown, unresolved: ReadonlySet<string>) { saves.push({ doc, unresolved }); return new Promise<void>(() => {}); },
  } } } as unknown as Ctx;
  const sync = createDocumentSync(cx); sync.reset();
  view.x = 360; sync.changed();
  await Promise.resolve();
  expect(saves).toHaveLength(1); expect(saves[0]!.unresolved.has("new")).toBe(true); expect(saves[0]!.doc.views[0]!.cell.x).toBe(3);
  view.name = "Renamed"; sync.changed(); sync.flush(); await Promise.resolve();
  expect(saves).toHaveLength(2); expect(saves[1]!.doc.views[0]!.name).toBe("Renamed");
  sync.dispose(); sync.changed(); await Promise.resolve(); expect(saves).toHaveLength(2);
});

test("inventory includes shared memberships that this device cannot render", async () => {
  const metrics = metricsFor(1440, 900, false);
  const view: ViewModel = { id: "console", name: "Console", layout: "tiled", x: 0, y: 0, nodes: [], cols: [{ id: "c", w: metrics.colW, wins: [{ id: "visible", kind: "terminal", host: "local", sessionId: "known" }] }] };
  const remote = structuredClone(view); remote.cols[0]!.wins.push({ id: "hidden", kind: "terminal", host: "unavailable", sessionId: "other" });
  let event: (value: Record<string, unknown>) => void = () => {};
  const store = new ServerCanvasStore({ call: () => new Promise(() => {}), subscribe: (_filter, receive) => { event = receive; return Object.assign(() => {}, { resync() {} }); } }, "inventory-scope");
  const shared = toDocument([remote], metrics, 1); event({ type: "canvas.layout.snapshot", revision: 1, initialized: true, document: shared });
  let inventory: CanvasDocument | undefined;
  const cx = { views: new Map([[view.id, { view, wins: new Map([["visible", { model: view.cols[0]!.wins[0]! }]]) }]]), state: { metrics }, adapters: { store, inventory: { setLayout: (document: CanvasDocument) => { inventory = document; } } } } as unknown as Ctx;
  const sync = createDocumentSync(cx); sync.reset(); view.x = 360; sync.changed(); await Promise.resolve();
  expect(documentWindows(inventory!).map((window) => window.id)).toEqual(["visible", "hidden"]);
  expect(inventory!.views[0]!.cell.x).toBe(3); sync.dispose();
});

for (const kind of ["flow", "app", "screen"] as const) test(`temporary ${kind} windows are never treated as unsubmitted shared windows`, () => {
  const metrics = metricsFor(1440, 900, false);
  const view: ViewModel = { id: "console", name: "Console", layout: "tiled", x: 0, y: 0, nodes: [], cols: [] };
  const cx = { views: new Map([[view.id, { view, wins: new Map([["flow", { model: { id: "flow", kind, host: "local" } }]]) }]]), state: { metrics }, adapters: { store: {} } } as unknown as Ctx;
  const sync = createDocumentSync(cx); sync.reset(); expect(sync.uncommittedWindows().size).toBe(0); sync.dispose();
});

/**
 * #395: a shell the host refused never gets a session, so its window must leave the saved layout instead of holding its
 * birth (and every edit behind it) as "unresolved" forever. That kept "Not saved — keep this tab open" up for as long
 * as the refused window stayed open. A later successful shell in the same window is saved as an ordinary birth.
 */
test("a refused shell's window leaves the saved layout and stops holding the queue", async () => {
  const metrics = metricsFor(1440, 900, false);
  const empty = toDocument([{ id: "console", name: "Console", layout: "tiled", x: 0, y: 0, nodes: [], cols: [] }], metrics, 1);
  const calls: Array<{ action: string; input: Record<string, unknown> }> = [];
  const store = new ServerCanvasStore({
    isWelcomed: true,
    call: (action, input) => { calls.push({ action, input: structuredClone(input) }); return new Promise(() => {}); },
    subscribe: (_filter, receive, open) => { open?.(); receive({ type: "canvas.layout.snapshot", revision: 1, initialized: true, document: empty }); return Object.assign(() => {}, { resync() {} }); },
  }, "refused-shell");
  const model: ViewModel["cols"][number]["wins"][number] = { id: "refused", kind: "terminal", host: "local" };
  const view: ViewModel = { id: "console", name: "Console", layout: "tiled", x: 0, y: 0, nodes: [], cols: [{ id: "c", w: metrics.colW, wins: [] }] };
  const wins = new Map<string, { model: typeof model }>();
  const cx = { views: new Map([[view.id, { view, wins }]]), state: { metrics }, adapters: { store } } as unknown as Ctx;
  const sync = createDocumentSync(cx); sync.reset();
  view.cols[0]!.wins.push(model); wins.set(model.id, { model });
  // Before the answer the birth waits for its session id: pending, and nothing is sent yet.
  sync.changed(); await Promise.resolve();
  expect(store.pending).toBe(true); expect(calls).toHaveLength(0);
  // The refusal is final for this shell: the window keeps showing why, but it is no longer a layout change in waiting.
  model.openRefused = true; sync.changed(); await Promise.resolve();
  // A shared repaint must not keep scheduling saves for a shell that cannot acquire a saved reference (#507).
  expect(sync.uncommittedWindows().size).toBe(0);
  expect(store.pending).toBe(false); expect(store.unresolvedWindow("refused")).toBe(false); expect(calls).toHaveLength(0);
  expect(documentWindows(store.current()).map((w) => w.id)).toEqual([]);
  // A new shell in the same window that does start is an ordinary birth with its session id.
  delete model.openRefused; model.sessionId = "0f6b1d3e-8d5c-4a5e-9c1b-2f3a4b5c6d7e"; sync.changed(); await Promise.resolve();
  expect(calls).toHaveLength(1); expect(calls[0]!.action).toBe("canvas.layout.apply");
  const intent = calls[0]!.input.intent as { type: string; window: { id: string; target: { id: string } } };
  expect(intent.window.id).toBe("refused"); expect(intent.window.target.id).toBe(model.sessionId);
  sync.dispose(); store.dispose();
});
