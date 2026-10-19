/** Checks transitive span-group row insertion against the canonical run invariant (D183, D212; #243). */
import { expect, test } from "bun:test";
import { reduce } from "./reducer";
import type { CanvasDocument, DocTarget } from "./schema";

test("a down split shifts every column in a transitively connected group", () => {
  const target: DocTarget = { type: "settings", section: "appearance" };
  const doc: CanvasDocument = { format: "infraternal.canvas", version: 1, revision: 1, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [
    { id: "a", weight: 1, windows: [{ id: "left", target, span: 2, row: 0, rows: 1 }] },
    { id: "b", weight: 1, windows: [{ id: "middle", target, span: 2, row: 1, rows: 1 }] },
    { id: "c", weight: 1, windows: [{ id: "right", target, span: 1, row: 0, rows: 1 }] },
  ] } }] };
  reduce(doc, { type: "split", view_id: "console", anchor_id: "right", axis: "down", column_id: "c", window: { id: "new", target } });
  const layout = doc.views[0]!.layout;
  if (layout.type !== "tiled") throw Error("expected tiled layout");
  // The left window crosses the inserted boundary in the same group and must grow with it.
  expect(layout.columns[0]!.windows[0]!.rows).toBe(2);
  expect(layout.columns[1]!.windows[0]!.row).toBe(2);
});
