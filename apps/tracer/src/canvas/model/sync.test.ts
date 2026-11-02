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
