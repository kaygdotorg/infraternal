/** Distinct valid field identities must retain both accepted edits until server confirmation (D312, #250). */
import { expect, test } from "bun:test";
import { LayoutJournal } from "../src/canvas/model/journal";
import type { CanvasDocument } from "../src/canvas/model/schema";

test("distinct view and column identifiers cannot supersede each other's unsent weights", () => {
  const canonical: CanvasDocument = {
    format: "infraternal.canvas", version: 1, revision: 1,
    views: [
      { id: "a", kind: "console", name: "First", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [{ id: "/b", weight: 1, windows: [{ id: "first-window", target: { type: "settings", section: "appearance" } }] }] } },
      { id: "a/", kind: "console", name: "Second", cell: { x: 1, y: 0 }, layout: { type: "tiled", columns: [{ id: "b", weight: 1, windows: [{ id: "second-window", target: { type: "settings", section: "shortcuts" } }] }] } },
    ],
  };
  const journal = new LayoutJournal();
  expect(journal.accept({ type: "canvas.layout.snapshot", revision: 1, initialized: true, document: canonical })).toBe(true);
  const first = journal.current(), firstLayout = first.views[0]!.layout;
  if (firstLayout.type !== "tiled") throw Error("expected tiled view");
  firstLayout.columns[0]!.weight = 2; journal.capture(first);
  const second = journal.current(), secondLayout = second.views[1]!.layout;
  if (secondLayout.type !== "tiled") throw Error("expected tiled view");
  secondLayout.columns[0]!.weight = 3; journal.capture(second);
  expect(journal.current()).toEqual(second);
  // Apply every request the server can see, without a disconnect or refusal.
  let revision = 1;
  for (let request = journal.next(); request; request = journal.next()) {
    if (!("intent" in request)) throw Error("expected layout intent");
    expect(journal.accept({ type: "canvas.layout.operation", revision: ++revision, op_id: request.op_id, intent: request.intent })).toBe(true);
  }
  const confirmed = journal.current(); confirmed.revision = second.revision;
  expect(confirmed, "confirming both accepted changes preserves the first column weight").toEqual(second);
});
