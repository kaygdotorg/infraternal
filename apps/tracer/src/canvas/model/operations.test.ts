/** Stable-neighbour and shared-band layout regressions (#243). */
import { expect, test } from "bun:test";
import { edits, reduce, type Intent } from "./operations";
import type { CanvasDocument } from "./document";
const doc = (): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision: 0, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }] });
const open = (id: string): Intent => ({ type: "open", view_id: "console", column_id: "c", window: { id, target: { type: "settings", section: "appearance" } } });
test("independent resize and move commute; close survives a stale move", () => {
  const a = doc(); reduce(a, open("a")); reduce(a, open("b")); const b = structuredClone(a);
  const resize: Intent = { type: "resize", window_id: "a", height: 2 };
  const move: Intent = { type: "move", view_id: "console", column_id: "c", window_id: "b", after: "a" };
  reduce(a, resize); reduce(a, move); reduce(b, move); reduce(b, resize); expect(a).toEqual(b);
  reduce(a, { type: "close", window_id: "b" }); reduce(a, move); expect(JSON.stringify(a)).not.toContain('"id":"b"');
});
test("right split of a stack preserves the upper band", () => {
  const a = doc(); reduce(a, open("b")); reduce(a, open("a"));
  reduce(a, { type: "split", view_id: "console", anchor_id: "b", axis: "right", column_id: "right", window: { id: "new", target: { type: "settings", section: "appearance" } } });
  const layout = a.views[0]!.layout; if (layout.type !== "tiled") throw Error("tiled");
  expect(layout.columns[0]!.windows[0]).toMatchObject({ id: "a", span: 2 }); expect(layout.columns[1]!.windows[0]).toMatchObject({ id: "new", row: 1 });
});
test("reorder uses stable neighbours and emits no document", () => {
  const a = doc(); reduce(a, open("b")); reduce(a, open("a")); const b = structuredClone(a);
  reduce(b, { type: "move", view_id: "console", column_id: "c", window_id: "b" });
  const changes = edits(a, b); expect(changes.every((i) => i.type === "move")).toBe(true);
  const replay = structuredClone(a); for (const change of changes) reduce(replay, change); expect(replay).toEqual(b);
});

test("a completed split emits its semantic intent rather than intermediate sizing edits", () => {
  const a = doc(); reduce(a, open("a")); const b = structuredClone(a);
  const split: Intent = { type: "split", view_id: "console", anchor_id: "a", axis: "right", column_id: "right", window: { id: "new", target: { type: "settings", section: "appearance" } } };
  reduce(b, split);
  const changes = edits(a, b, new Map([["new", { windowId: "new", anchorId: "a", axis: "right" }]]));
  expect(changes).toHaveLength(1); expect(changes[0]?.type).toBe("split");
  const replay = structuredClone(a); for (const edit of changes) reduce(replay, edit); expect(replay).toEqual(b);
});

test("a three-window reorder sends one semantic move", () => {
  const a = doc(); for (const id of ["c", "b", "a"]) reduce(a, open(id)); const b = structuredClone(a);
  reduce(b, { type: "move", view_id: "console", column_id: "c", window_id: "c" });
  expect(edits(a, b)).toHaveLength(1);
});
