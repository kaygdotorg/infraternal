/** Cache hydration and live reference completion use the same journal projection and stable operation identity (#243). */
import { expect, test } from "bun:test";
import { LayoutJournal } from "./journal";
import { reduce } from "./operations";
import type { CanvasDocument } from "./schema";
const document = (): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision: 0, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }] });
test("an offline birth keeps its identity through same-tab reference completion", () => {
  const journal = new LayoutJournal({ canonical: document(), pending: [], unresolved: new Set() });
  const next = document(); reduce(next, { type: "open", view_id: "console", column_id: "c", window: { id: "w", target: { type: "session", id: "w", host: "local" } } });
  journal.capture(next, undefined, document(), new Set(["w"]));
  const op = journal.pending[0]!.op_id;
  const restored = journal;
  const resolved = restored.current(), layout = resolved.views[0]!.layout;
  if (layout.type !== "tiled") throw Error("tiled layout expected");
  layout.columns[0]!.windows[0]!.target = { type: "session", id: "live", host: "local" };
  restored.capture(resolved, undefined, restored.current());
  expect(restored.pending).toHaveLength(1); expect(restored.pending[0]!.op_id).toBe(op);
  const intent = restored.pending[0]!.intent;
  if (intent.type !== "open") throw Error("open intent expected");
  expect(intent.window.target).toEqual({ type: "session", id: "live", host: "local" });
});
