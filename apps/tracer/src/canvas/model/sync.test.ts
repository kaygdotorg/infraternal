/** Local input reaches the semantic journal before a paint, independent of network or new-session readiness (#243). */
import { expect, test } from "bun:test";
import type { Ctx } from "../context";
import { metricsFor } from "../layout/geometry";
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
