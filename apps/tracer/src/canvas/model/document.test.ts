/** The canvas document (model/document.ts): round trip, references only, and hostile input. */
import { expect, test } from "bun:test";
import { CELL, metricsFor } from "../layout/geometry";
import { FORMAT, VERSION, columnsFromDocument, parseDocument, toDocument } from "./document";
import type { ViewModel } from "./types";

const m = metricsFor(1440, 900, false);
const console_: ViewModel = {
  id: "console", name: "Console", layout: "tiled", nodes: [], x: 2 * CELL, y: CELL,
  cols: [
    { id: "c1", w: m.colW, wins: [{ id: "w1", kind: "terminal", host: "build-01", sessionId: "abc", session: "zsh", lines: ["secret scrollback"] }] },
    { id: "c2", w: m.colW * 2, wins: [{ id: "w2", kind: "terminal", host: "edge-arm", sessionId: "def", h: 0.6 }, { id: "w3", kind: "terminal", host: "edge-arm" }] },
  ],
};

test("a document holds references and layout, never content", () => {
  const doc = toDocument([console_], m, 3);
  const json = JSON.stringify(doc);
  expect(json).not.toContain("secret scrollback");
  expect(doc.format).toBe(FORMAT);
  expect(doc.version).toBe(VERSION);
  expect(doc.revision).toBe(3);
  expect(doc.views[0]!.cell).toEqual({ x: 2, y: 1 });
  // A terminal window without a session id has nothing to reference and is not saved.
  const ids = doc.views[0]!.layout.type === "tiled" ? doc.views[0]!.layout.columns.flatMap((c) => c.windows.map((w) => w.id)) : [];
  expect(ids).toEqual(["w1", "w2"]);
});

test("a document survives JSON and rebuilds the same columns", () => {
  const doc = parseDocument(JSON.parse(JSON.stringify(toDocument([console_], m, 1))));
  expect(doc).toBeDefined();
  const layout = doc!.views[0]!.layout;
  if (layout.type !== "tiled") throw new Error("tiled");
  const cols = columnsFromDocument(layout, m, (t) => (t.type === "session" ? { host: t.host, sessionId: t.id, ...(t.name ? { session: t.name } : {}) } : undefined));
  expect(cols.map((c) => [c.id, c.w, c.wins.map((w) => w.id)])).toEqual([["c1", m.colW, ["w1"]], ["c2", m.colW * 2, ["w2"]]]);
  expect(cols[1]!.wins[0]!.h).toBe(0.6);
});

test("a target that no longer exists is dropped, and an emptied column with it", () => {
  const doc = parseDocument(toDocument([console_], m, 1))!;
  const layout = doc.views[0]!.layout;
  if (layout.type !== "tiled") throw new Error("tiled");
  expect(columnsFromDocument(layout, m, (t) => (t.type === "session" && t.id === "def" ? { host: t.host } : undefined)).map((c) => c.id)).toEqual(["c2"]);
});

test("parseDocument rejects anything that is not a document of this format", () => {
  const good = toDocument([console_], m, 1);
  for (const bad of [null, 1, "x", [], {}, { ...good, format: "other" }, { ...good, version: 2 }, { ...good, revision: -1 }, { ...good, views: "no" },
    { ...good, views: [{ ...good.views[0], cell: { x: 1e9, y: 0 } }] },
    { ...good, views: [{ ...good.views[0], layout: { type: "tiled", columns: [{ id: "c", weight: 0, windows: [] }] } }] },
    { ...good, views: [{ ...good.views[0], layout: { type: "tiled", columns: [{ id: "c", weight: 1, windows: [{ id: "w", target: { type: "session" } }] }] } }] },
    { ...good, views: Array.from({ length: 65 }, () => good.views[0]) }]) {
    expect(parseDocument(bad)).toBeUndefined();
  }
  expect(parseDocument(good)).toEqual(good);
});
