/** Adjacent unsent coalescing and explicit byte backpressure never mutate sent identities or evict pending edits (D312). */
import { expect, test } from "bun:test";
import { LayoutJournal, LayoutQueueFull } from "./journal";
import type { CanvasDocument } from "./schema";
const document = (name = "Console"): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision: 1, views: [{ id: "console", kind: "console", name, cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }] });
test("adjacent same-field unsent edits coalesce; sent requests retain identical identity and input", () => {
  const journal = new LayoutJournal({ canonical: document(), pending: [], unresolved: new Set() });
  journal.capture(document("First")); const id = journal.pending[0]!.op_id;
  journal.capture(document("Second")); expect(journal.pending).toHaveLength(1); expect(journal.pending[0]!.op_id).toBe(id);
  journal.accept({ type: "canvas.layout.snapshot", revision: 1, document: document(), initialized: true });
  const request = journal.next();
  if (!request || !("intent" in request)) throw Error("expected pending request");
  const sent = structuredClone(request); journal.capture(document("Third"));
  expect(journal.pending).toHaveLength(2); expect(journal.pending[0]).toEqual(sent);
});
test("byte backpressure reports refusal before changing projection or silently dropping older work", () => {
  const journal = new LayoutJournal({ canonical: document(), pending: [], unresolved: new Set() }, 700);
  journal.capture(document("Accepted")); const accepted = journal.current();
  const next = structuredClone(accepted); next.views[0]!.cell.x = 4;
  expect(() => journal.capture(next)).toThrow(LayoutQueueFull);
  expect(journal.current()).toEqual(accepted); expect(journal.pending).toHaveLength(1);
});
test("rejected placeholder cancellation preserves the accepted birth and unresolved dependency", () => {
  const journal = new LayoutJournal({ canonical: document(), pending: [], unresolved: new Set() }, 1000);
  const shell = document();
  const layout = shell.views[0]!.layout; if (layout.type !== "tiled") throw Error("expected tiled view");
  layout.columns.push({ id: "c", weight: 1, windows: [{ id: "shell", target: { type: "settings", section: "pending" } }] });
  journal.capture(shell, undefined, undefined, new Set(["shell"]));
  const accepted = journal.current(), pending = structuredClone(journal.pending);
  const replacement = document("x".repeat(1000));
  expect(() => journal.capture(replacement)).toThrow(LayoutQueueFull);
  expect(journal.current()).toEqual(accepted); expect(journal.pending).toEqual(pending); expect(journal.unresolved.has("shell")).toBe(true);
});
test("completed reference size counts toward backpressure without mutating a refused completion", () => {
  const journal = new LayoutJournal({ canonical: document(), pending: [], unresolved: new Set() }, 1000);
  const shell = document(), layout = shell.views[0]!.layout; if (layout.type !== "tiled") throw Error("expected tiled view");
  layout.columns.push({ id: "c", weight: 1, windows: [{ id: "shell", target: { type: "settings", section: "pending" } }] });
  journal.capture(shell, undefined, undefined, new Set(["shell"]));
  const accepted = journal.current(); layout.columns[0]!.windows[0]!.target = { type: "settings", section: "x".repeat(1000) };
  expect(() => journal.capture(shell)).toThrow(LayoutQueueFull);
  expect(journal.current()).toEqual(accepted); expect(journal.unresolved.has("shell")).toBe(true);
});
