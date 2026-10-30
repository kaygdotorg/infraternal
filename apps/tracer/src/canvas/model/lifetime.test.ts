/** Logout freeze/failure and session-bound late callbacks cannot resurrect per-tab edits (D312). */
import { expect, test } from "bun:test";
import { registerAccountWork, pauseAccountWork, forgetAccountWork } from "../../account-lifetime";
import { LayoutJournal } from "./journal";
test("logout freezes the initiating account; failure preserves its queue; success forgets only that lifetime", () => {
  const events: string[] = [];
  const off = registerAccountWork("a", { pause: (value) => events.push(`pause:${value}`), dispose: () => { events.push("disposed"); off(); } });
  const other = registerAccountWork("b", { pause: () => events.push("wrong"), dispose: () => events.push("wrong") });
  pauseAccountWork("a", true); pauseAccountWork("a", false);
  expect(events).toEqual(["pause:true", "pause:false"]);
  pauseAccountWork("a", true); forgetAccountWork("a");
  const fresh = registerAccountWork("a", { pause: () => events.push("fresh"), dispose: () => {} });
  expect(events).toEqual(["pause:true", "pause:false", "pause:true", "disposed"]);
  fresh(); other();
});
test("dropping a session clears canonical drawing, placeholders and pending callbacks permanently", () => {
  const journal = new LayoutJournal();
  journal.accept({ type: "canvas.layout.snapshot", initialized: true, revision: 1, document: { format: "infraternal.canvas", version: 1, revision: 1, views: [{ id: "console", kind: "console", name: "Private", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }] } });
  const next = journal.current(); next.views[0]!.name = "Waiting"; journal.capture(next); const entry = journal.next()!, epoch = journal.epoch;
  journal.clear(); expect(journal.current().views).toEqual([]); expect(journal.pending).toEqual([]);
  expect(journal.release(entry, epoch)).toBe(false); expect(journal.acknowledge(entry, 2, false)).toBe(false);
});
