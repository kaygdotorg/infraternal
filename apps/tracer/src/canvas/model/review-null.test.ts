/** An accepted mixed resize must keep the drawing cache decodable for offline startup (D180, D183, D245; #243). */
import { expect, test } from "bun:test";
import { LayoutJournal } from "./journal";
import { parseDocument, type CanvasDocument } from "./schema";

test("a mixed nullable resize cannot invalidate the canonical drawing document", () => {
  const doc: CanvasDocument = { format: "infraternal.canvas", version: 1, revision: 1, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [{ id: "a", weight: 1, windows: [{ id: "w", target: { type: "settings", section: "appearance" } }] }] } }] };
  const journal = new LayoutJournal();
  expect(journal.accept({ type: "canvas.layout.snapshot", revision: 1, initialized: true, document: doc })).toBe(true);
  // The real server accepts this request, ignores null height, and publishes it with noop=false.
  expect(journal.accept({ type: "canvas.layout.operation", revision: 2, op_id: "mixed", noop: false, intent: { type: "resize", window_id: "w", height: null, rows: 2 } })).toBe(true);
  expect(parseDocument(journal.current())).toBeDefined();
});
