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

test("manual-name pins survive document serialization while old targets stay unpinned", () => {
  const view = structuredClone(console_);
  view.cols[0]!.wins[0]!.sessionPinned = true;
  const doc = parseDocument(toDocument([view], m, 1))!;
  const layout = doc.views[0]!.layout;
  if (layout.type !== "tiled") throw new Error("tiled");
  expect(layout.columns[0]!.windows[0]!.target).toMatchObject({ name: "zsh", pinned: true });
  expect(layout.columns[1]!.windows[0]!.target).not.toHaveProperty("pinned");
  const malformed = JSON.parse(JSON.stringify(doc));
  malformed.views[0].layout.columns[0].windows[0].target.pinned = "true";
  expect(parseDocument(malformed)).toBeUndefined();
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

test("remote affinity survives reload and invalid UUIDs cannot become local references", () => {
  const hostId = "11111111-2222-3333-4444-555555555555";
  const remote: ViewModel = { ...console_, cols: [{ id: "remote", w: m.colW, wins: [{ id: "rw", kind: "terminal", host: "worker", hostId, user: "operator", address: "worker:22", sessionId: "retained" }] }] };
  const document = toDocument([remote], m, 1);
  const parsed = parseDocument(document)!;
  const layout = parsed.views[0]!.layout;
  if (layout.type !== "tiled") throw new Error("tiled");
  expect(layout.columns[0]!.windows[0]!.target).toEqual({ type: "session", id: "retained", host: "worker", hostId, user: "operator", address: "worker:22" });
  const bad = JSON.parse(JSON.stringify(document));
  bad.views[0].layout.columns[0].windows[0].target.hostId = "not-a-uuid";
  expect(parseDocument(bad)).toBeUndefined();
});

/**
 * A document saved before D212, written by hand in the v1 shape, still loads unchanged: no field was added, so the
 * four window actions need no migration. A split pair is two columns with weights that add up to the old column, and a
 * full-size window is a window with `height` 1 (one column height).
 */
test("a version 1 document from before D212 loads, with its split pair and a full-size window", () => {
  const old = {
    format: FORMAT, version: VERSION, revision: 7,
    views: [{
      id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 },
      layout: {
        type: "tiled",
        columns: [
          { id: "c1", weight: 0.5, windows: [{ id: "w1", target: { type: "session", id: "s1", host: "build-01", name: "zsh" } }] },
          { id: "c2", weight: 0.5, windows: [{ id: "w2", target: { type: "session", id: "s2", host: "build-01" } }] },
          { id: "c3", weight: 1, windows: [{ id: "w3", target: { type: "session", id: "s3", host: "edge-arm" }, height: 1 }, { id: "s-appearance", target: { type: "settings", section: "appearance" } }] },
        ],
      },
    }],
  };
  const doc = parseDocument(old);
  expect(doc).toBeDefined();
  const layout = doc!.views[0]!.layout;
  if (layout.type !== "tiled") throw new Error("tiled");
  const cols = columnsFromDocument(layout, m, (t) => (t.type === "session" ? { host: t.host, sessionId: t.id, ...(t.name ? { session: t.name } : {}) } : t.type === "settings" ? { host: "" } : undefined));
  expect(cols.map((c) => [c.id, c.w, c.wins.map((w) => w.id)])).toEqual([["c1", Math.round(0.5 * m.colW), ["w1"]], ["c2", Math.round(0.5 * m.colW), ["w2"]], ["c3", m.colW, ["w3", "s-appearance"]]]);
  expect(cols[2]!.wins[0]!.h).toBe(1);
  // Saving it again writes the same shape back.
  const again: unknown = JSON.parse(JSON.stringify(toDocument([{ ...console_, cols }], m, 8).views[0]!.layout));
  expect(again).toEqual(JSON.parse(JSON.stringify(old.views[0]!.layout)));
});

test("a grouped view saves its spans and bands and loads back to the same grid (D212)", () => {
  // The model as the canvas holds it at a save: a group's windows carry their settled spans and bands.
  const grouped: ViewModel = {
    ...console_,
    cols: [
      { id: "g1", w: 300, wins: [
        { id: "a", kind: "terminal", host: "h1", sessionId: "s1", session: "one", span: 2, row: 0 },
        { id: "b", kind: "terminal", host: "h1", sessionId: "s2", session: "two", h: 0.4, row: 1 },
        { id: "c", kind: "terminal", host: "h1", sessionId: "s3", session: "three", span: 2, row: 2 },
      ] },
      { id: "g2", w: 300, wins: [{ id: "d", kind: "terminal", host: "h2", sessionId: "s4", session: "four", row: 1 }] },
    ],
  };
  const doc = parseDocument(JSON.parse(JSON.stringify(toDocument([grouped], m, 2))));
  expect(doc).toBeDefined();
  const layout = doc!.views[0]!.layout;
  if (layout.type !== "tiled") throw new Error("tiled expected");
  const saved = layout.columns.map((c) => c.windows.map((w) => [w.id, w.span, w.rows, w.row]));
  // "a" spans both columns on band 0, so "d" lands on band 1: the bands are the ones the grid derives.
  expect(saved).toEqual([[["a", 2, undefined, 0], ["b", undefined, undefined, 1], ["c", 2, undefined, 2]], [["d", undefined, undefined, 1]]]);
  const back = columnsFromDocument(layout, m, (t) => (t.type === "session" ? { host: t.host, sessionId: t.id, ...(t.name ? { session: t.name } : {}) } : undefined));
  expect(back.map((c) => c.wins.map((w) => [w.id, w.span ?? 1, w.row]))).toEqual([[["a", 2, 0], ["b", 1, 1], ["c", 2, 2]], [["d", 1, 1]]]);
});

test("a plain view is saved without spans or bands, exactly as before D212", () => {
  const json = JSON.stringify(toDocument([console_], m, 1));
  expect(json).not.toContain("\"span\"");
  expect(json).not.toContain("\"rows\"");
  expect(json).not.toContain("\"row\"");
});

test("D309: the saved weights do not depend on how a touch screen draws the columns", () => {
  // A desktop saved a weight-floor column and a full one. The phone loads them, draws them (the floor widens the drawn
  // column only) and saves nothing different: the weights that come out are the weights that went in.
  const phone = metricsFor(393, 852, true);
  expect(phone.minW).toBeGreaterThan(0);
  const saved = toDocument([{ ...console_, cols: [{ ...console_.cols[0]!, w: m.colW }, { ...console_.cols[1]!, w: Math.round(0.1 * m.colW) }] }], m, 1);
  const layout = saved.views[0]!.layout;
  if (layout.type !== "tiled") throw new Error("tiled");
  const weights = layout.columns.map((c) => c.weight);
  expect(weights).toEqual([1, 0.1]);
  const resolve = (t: { type: string; host?: string; id?: string }) => (t.type === "session" ? { host: t.host ?? "", sessionId: t.id ?? "" } : undefined);
  const roundTrip = (metrics: typeof phone): number[] => {
    const cols = columnsFromDocument(layout, metrics, resolve as never);
    const again = toDocument([{ ...console_, cols }], metrics, 2).views[0]!.layout;
    if (again.type !== "tiled") throw new Error("tiled");
    return again.columns.map((c) => c.weight);
  };
  const cols = columnsFromDocument(layout, phone, resolve as never);
  expect(cols[1]!.w).toBeLessThan(phone.minW); // the model keeps the saved width, not the drawn one
  // Whatever pixel rounding the screen's own width brings, the floor adds nothing: the same weights with and without it.
  expect(roundTrip(phone)).toEqual(roundTrip({ ...phone, minW: 0 }));
  expect(roundTrip(phone)[0]).toBe(1);
});

test("D309: a view this device pushed clear for display is saved where the layout has it", () => {
  const pushed: ViewModel = { ...console_, x: 6 * CELL, y: 3 * CELL, home: { x: 2 * CELL, y: CELL } };
  expect(toDocument([pushed], m, 1).views[0]!.cell).toEqual({ x: 2, y: 1 });
  // Without a push the drawn position is the saved one, as before.
  const { home: _home, ...drawnHere } = pushed;
  expect(toDocument([drawnHere], m, 1).views[0]!.cell).toEqual({ x: 6, y: 3 });
});

test("an offscreen graph keeps its shared pins before any nodes are rendered", () => {
  const graph: ViewModel & { graphPins: Record<string, { x: number; y: number }> } = { id: "mesh", name: "Mesh", layout: "graph", cols: [], nodes: [], x: 0, y: 0, graphPins: { host: { x: 40, y: 80 } } };
  expect(toDocument([graph], m, 2).views[0]?.layout).toEqual({ type: "graph", pinned: graph.graphPins });
});

test("a captured graph document is independent of the next pin drag", () => {
  const graph: ViewModel = { id: "mesh", name: "Mesh", layout: "graph", cols: [], nodes: [], x: 0, y: 0, graphPins: { host: { x: 40, y: 80 } } };
  const before = toDocument([graph], m, 2);
  graph.graphPins!.host!.x = 200;
  expect(before.views[0]?.layout).toEqual({ type: "graph", pinned: { host: { x: 40, y: 80 } } });
});
