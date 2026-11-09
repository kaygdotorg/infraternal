/** Receipt identity and optimistic projection controls retained from the #250 hunt and reviews (D312). */
import { expect, test } from "bun:test";
import { LayoutJournal, type Pending } from "./journal";
import type { CanvasDocument } from "./schema";
const document = (revision = 1, name = "Console"): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision, views: [{ id: "console", kind: "console", name, cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }] });
function setup() {
  const journal = new LayoutJournal();
  const snapshot = (revision = 1, name = "Console") => journal.accept({ type: "canvas.layout.snapshot", revision, document: document(revision, name), initialized: true });
  snapshot(); journal.capture(document(1, "Mine")); const entry = journal.next()!;
  return { journal, entry, snapshot };
}
test("hunt 2: uncertain sent edit stays hidden over a newer snapshot until its receipt", () => {
  const { journal, entry, snapshot } = setup(); journal.restart(); snapshot(3, "Theirs");
  expect(journal.current().views[0]!.name).toBe("Theirs");
  expect(journal.next()).toBe(entry); expect("base_revision" in entry && entry.base_revision).toBe(1);
  journal.acknowledge(entry, 2, false); expect(journal.current().views[0]!.name).toBe("Theirs"); expect(journal.pending).toHaveLength(0);
});
test("R1 held notification: a receipt above canonical explicitly reveals the overlay", () => {
  const { journal, entry, snapshot } = setup(); journal.restart(); snapshot();
  expect(journal.current().views[0]!.name).toBe("Console");
  expect(journal.acknowledge(entry, 2, false)).toBe(true); expect(journal.current().views[0]!.name).toBe("Mine");
  snapshot(2, "Mine"); expect(journal.pending).toHaveLength(0);
});
test("R2 receiptless identity survives 100 matching snapshots without silent confirmation", () => {
  const { journal, entry, snapshot } = setup();
  for (let n = 0; n < 100; n++) { journal.restart(); snapshot(n + 2, "Mine"); expect(journal.pending).toHaveLength(1); expect(journal.next()).toBe(entry); }
  expect(journal.current().views[0]!.name).toBe("Mine");
  journal.acknowledge(entry, 2, false); expect(journal.pending).toHaveLength(0);
});
test("R1 covered receipt is pruned before projecting canonical revision 3", () => {
  const { journal, entry, snapshot } = setup(); journal.acknowledge(entry, 2, false); snapshot(3, "Theirs");
  expect(journal.current().views[0]!.name).toBe("Theirs"); expect(journal.pending).toHaveLength(0);
});
test("duplicate event then late refusal cannot discard independent work", () => {
  const { journal, entry } = setup(); const epoch = journal.epoch;
  const event = { type: "canvas.layout.operation", revision: 2, op_id: entry.op_id, intent: "intent" in entry ? entry.intent : {} };
  expect(journal.accept(event)).toBe(true); expect(journal.accept(event)).toBe(false);
  journal.capture(document(2, "Later")); expect(journal.refuse(entry, epoch)).toBe(false); expect(journal.pending).toHaveLength(1);
});
/** A look queued behind this tab's own accepted look is rebased onto it, so quick successive theme edits never refuse each other (#400). */
test("an accepted look moves the base of the unsent looks queued behind it", () => {
  const { journal } = setup();
  const look = { type: "look.set", look: {} } as never;
  const first: Pending = { op_id: "look-1", base_revision: 1, intent: look }, second: Pending = { op_id: "look-2", base_revision: 1, intent: look };
  journal.pending.push(first, second);
  journal.acknowledge(first, 5, false);
  expect(second.base_revision).toBe(5);
  expect(first.base_revision).toBe(1);
});
