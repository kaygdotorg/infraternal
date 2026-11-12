/** Stable-neighbour and shared-band layout regressions (#243). */
import { expect, test } from "bun:test";
import { edits, reduce, type Intent } from "./operations";
import type { CanvasDocument } from "./document";
import { parseLook } from "./schema";
import { createThemeStore } from "../themes/model";
const doc = (): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision: 0, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }] });
const open = (id: string): Intent => ({ type: "open", view_id: "console", column_id: "c", window: { id, target: { type: "settings", section: "appearance" } } });

/** Server decoding and local theme snapshots use different field order for the same account appearance (#507). */
test("equivalent server and local looks do not create another appearance edit", () => {
  const before = doc(), after = doc();
  after.look = { ...createThemeStore({ colors: "ink", font: "maple-mono-nf", uiSize: 100 }).snapshot(), uiFont: "mono", windowSizes: { phone: "edge", desktop: "comfortable" }, extendedInfo: false };
  before.look = parseLook(after.look)!;
  expect(edits(before, after)).toEqual([]);
  after.look.extendedInfo = true;
  expect(edits(before, after).map((intent) => intent.type)).toEqual(["look.set"]);
});
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

test("a split before the first reference is journalled opens its anchor before splitting", () => {
  const before = doc(), after = doc(); reduce(after, open("anchor"));
  reduce(after, { type: "split", view_id: "console", column_id: "right", anchor_id: "anchor", axis: "right", window: { id: "child", target: { type: "settings", section: "appearance" } } });
  const changes = edits(before, after, new Map([["child", { windowId: "child", anchorId: "anchor", axis: "right" }]]));
  expect(changes.map((i) => i.type)).toEqual(["open", "split"]);
  const replay = structuredClone(before); for (const change of changes) reduce(replay, change);
  expect(replay).toEqual(after);
});

test("a drop sends the moved membership once, without derived neighbour geometry", () => {
  const before = doc(); for (const id of ["c", "b", "a"]) reduce(before, open(id));
  const after = structuredClone(before); reduce(after, { type: "move", view_id: "console", column_id: "c", window_id: "a", after: "c" });
  const layout = after.views[0]!.layout;
  if (layout.type === "tiled") for (const col of layout.columns) for (const w of col.windows) w.height = 200;
  const changes = edits(before, after, new Map([["a", { windowId: "a", move: true as const }]]));
  expect(changes).toEqual([{ type: "move", view_id: "console", window_id: "a", column_id: "c", after: "c", column_after: null }]);
});

test("a narrow right split widens first so both halves remain valid", () => {
  const before = doc(); reduce(before, open("anchor"));
  const layout = before.views[0]!.layout; if (layout.type !== "tiled") throw Error("tiled");
  layout.columns[0]!.weight = 0.125;
  const after = structuredClone(before);
  const split: Intent = { type: "split", view_id: "console", anchor_id: "anchor", axis: "right", column_id: "right", window: { id: "child", target: { type: "settings", section: "appearance" } } };
  reduce(after, split);
  const changes = edits(before, after, new Map([["child", { windowId: "child", anchorId: "anchor", axis: "right" }]]));
  const replay = structuredClone(before); for (const change of changes) reduce(replay, change);
  const result = replay.views[0]!.layout; if (result.type !== "tiled") throw Error("tiled");
  expect(result.columns.map((c) => c.weight)).toEqual([0.1, 0.1]);
  expect(changes.map((i) => i.type)).toEqual(["weight", "split"]);
});

test("a short down split grows the anchor first so both halves meet the height floor", () => {
  const before = doc(); reduce(before, open("anchor"));
  reduce(before, { type: "resize", window_id: "anchor", height: 0.05 });
  const after = structuredClone(before);
  const split: Intent = { type: "split", view_id: "console", anchor_id: "anchor", axis: "down", column_id: "c", window: { id: "child", target: { type: "settings", section: "appearance" } } };
  reduce(after, split);
  const changes = edits(before, after, new Map([["child", { windowId: "child", anchorId: "anchor", axis: "down" }]]));
  const replay = structuredClone(before); for (const change of changes) reduce(replay, change);
  const result = replay.views[0]!.layout; if (result.type !== "tiled") throw Error("tiled");
  expect(result.columns[0]!.windows.map((w) => w.height)).toEqual([0.05, 0.05]);
  expect(changes.map((i) => i.type)).toEqual(["resize", "split"]);
});
