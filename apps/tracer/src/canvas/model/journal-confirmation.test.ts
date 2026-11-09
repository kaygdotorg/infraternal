/** Receipt identity and optimistic projection controls retained from the #250 hunt and reviews (D312). */
import { expect, test } from "bun:test";
import { LayoutJournal, type Pending } from "./journal";
import type { CanvasDocument } from "./schema";
import { createThemeStore } from "../themes/model";
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

/** A look is not sent while another of ours is unacknowledged; it leaves after the receipt, rebased onto it (#400, J425 R1). */
test("a second look waits for the first look's receipt and then goes out on its revision", () => {
  const { journal, entry } = setup();
  journal.acknowledge(entry, 2, false);
  const look = { type: "look.set", look: {} } as never;
  const first: Pending = { op_id: "look-1", base_revision: 2, intent: look }, second: Pending = { op_id: "look-2", base_revision: 2, intent: look };
  journal.pending.push(first, second);
  expect(journal.next()).toBe(first);
  expect(journal.next()).toBeUndefined();
  journal.acknowledge(first, 3, false);
  expect(journal.next()).toBe(second);
  expect(second.base_revision).toBe(3);
});

/** Looks that have not left yet are one change, so three quick picks queue at most two looks: the one in flight and the latest. */
test("quick successive looks coalesce into the latest one while the first is in flight", () => {
  const { journal, entry } = setup();
  journal.acknowledge(entry, 2, false);
  const doc = (selected: string): CanvasDocument => {
    const next = document(2, "Mine");
    next.look = createThemeStore({ colors: "mocha", font: "maple-mono-nf", uiSize: 100 }).snapshot();
    next.look.selected = selected;
    return next;
  };
  journal.capture(doc("frosted"));
  const first = journal.next()!;
  expect("intent" in first && first.intent.type).toBe("look.set");
  journal.capture(doc("tinted"));
  journal.capture(doc("solid"));
  const looks = journal.pending.filter((p) => p.intent.type === "look.set");
  expect(looks).toHaveLength(2);
  expect(looks[1]!.intent.type === "look.set" && looks[1]!.intent.look.selected).toBe("solid");
});

/** The event for our own look can reach the tab before its receipt; the look queued behind it must still be rebased (J425, #400). */
test("a look queued behind our own look is rebased when that look's event arrives before its receipt", () => {
  const { journal, entry } = setup();
  journal.acknowledge(entry, 2, false);
  const doc = (selected: string): CanvasDocument => {
    const next = document(2, "Mine");
    next.look = createThemeStore({ colors: "mocha", font: "maple-mono-nf", uiSize: 100 }).snapshot();
    next.look.selected = selected;
    return next;
  };
  journal.capture(doc("frosted"));
  const first = journal.next()!;
  journal.capture(doc("solid"));
  const intent = "intent" in first ? first.intent : undefined;
  expect(journal.accept({ type: "canvas.layout.operation", revision: 3, op_id: first.op_id, intent, noop: false })).toBe(true);
  const second = journal.next()!;
  expect("intent" in second && second.intent.type).toBe("look.set");
  expect("base_revision" in second && second.base_revision).toBe(3);
});

/** A look from another device must not rebase ours: the compare-and-set has to keep refusing a look written from before it. */
test("a look from another device does not rebase a queued look", () => {
  const { journal, entry } = setup();
  journal.acknowledge(entry, 2, false);
  const look = { type: "look.set", look: createThemeStore({ colors: "mocha", font: "maple-mono-nf", uiSize: 100 }).snapshot() } as never;
  const mine: Pending = { op_id: "look-mine", base_revision: 2, intent: look };
  journal.pending.push(mine);
  expect(journal.accept({ type: "canvas.layout.operation", revision: 3, op_id: "someone-else", intent: look, noop: false })).toBe(true);
  expect(mine.base_revision).toBe(2);
});
