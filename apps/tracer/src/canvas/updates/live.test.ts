/** Tests of the live Updates source against a scripted server: what the state means, the history, refusals and the passkey retry. */
import { describe, expect, test } from "bun:test";
import { connectUpdates, historyOf, stateOf, type UpdatesLink } from "./live";

/** A fixed time (seconds) the scripted statuses are measured from. */
const NOW = 1_800_000_000;

/** A link with a scripted server: `answers` by action id, every call recorded, and a way to push a topic event. */
function link(answers: Record<string, () => Record<string, unknown>>, refuseFirst: string[] = []) {
  const calls: Array<[string, Record<string, unknown>]> = [];
  let push: ((event: Record<string, unknown>) => void) | undefined;
  let confirmed = 0;
  const refused = new Set(refuseFirst);
  const l: UpdatesLink = {
    async call(id, input) {
      calls.push([id, input]);
      if (refused.delete(id)) throw new Error("not permitted");
      const answer = answers[id];
      if (!answer) throw new Error(`no answer for ${id}`);
      return answer();
    },
    subscribe(_filter, onEvent) { push = onEvent; return () => { push = undefined; }; },
    async confirmAndReconnect() { confirmed++; },
  };
  return { l, calls, confirmed: () => confirmed, push: (e: Record<string, unknown>) => push?.(e) };
}

/** A scripted `release.update.status` answer: a healthy stable server with `over` changed. */
const status = (over: Record<string, unknown> = {}) => (): Record<string, unknown> => ({
  current: "0.4.2", channel: "stable", staged: null, last_check: NOW - 120, last_error: null, applied: null, mode: "auto", reason: null, quiet_minutes: 5, rollback: null, ...over,
});

describe("what the server's state means in the window", () => {
  test("off says why; a staged release is ready; an undone switch says so until the next check; a clean check is current", () => {
    expect(stateOf({ mode: "off", reason: "Not root." }, undefined)).toEqual({ kind: "off", reason: "Not root." });
    expect(stateOf({ staged: "0.5.0", last_check: 5 }, undefined)).toEqual({ kind: "ready", version: "0.5.0" });
    expect(stateOf({ current: "0.4.2", last_check: 5, applied: { version: "0.5.0", outcome: "undone", reason: "It failed its health check.", at: 9 } }, undefined))
      .toMatchObject({ kind: "rolled-back", version: "0.5.0" });
    expect(stateOf({ last_check: 10, applied: { version: "0.5.0", outcome: "undone", at: 9 } }, undefined)).toEqual({ kind: "current" });
    expect(stateOf({ last_check: null }, undefined)).toEqual({ kind: "never" });
    expect(stateOf({ last_check: 5, last_error: "The release server did not answer." }, undefined)).toEqual({ kind: "failed", reason: "The release server did not answer." });
    expect(stateOf({ last_check: 5 }, "checking")).toEqual({ kind: "checking" });
  });

  test("history keeps what was installed, undone or failed, newest first, and drops staging noise", () => {
    const rows = historyOf([
      { at: 30, kind: "applied", version: "0.5.0", detail: null },
      { at: 20, kind: "staged", version: "0.5.0", detail: null },
      { at: 10, kind: "rolled_back", version: "0.4.0", detail: "It failed." },
    ]);
    expect(rows.map((r) => [r.version, r.outcome, r.at])).toEqual([["0.5.0", "applied", 30_000], ["0.4.0", "rolled-back", 10_000]]);
    expect(rows[1]!.reason).toBe("It failed.");
  });
});

describe("the live source", () => {
  test("reads status and history, and offers Roll back only inside 24 hours of the copy", async () => {
    const fresh = link({ "release.update.status": status({ rollback: { to: "0.4.1", copy_taken_at: Math.floor(Date.now() / 1000) - 3600 } }), "release.update.history": () => ({ entries: [] }) });
    const a = await connectUpdates(fresh.l);
    expect(a.facts()).toMatchObject({ running: "0.4.2", channel: "stable", quietMinutes: 5, rollback: { available: true, to: "0.4.1" } });
    const old = link({ "release.update.status": status({ rollback: { to: "0.4.1", copy_taken_at: Math.floor(Date.now() / 1000) - 25 * 3600 } }), "release.update.history": () => ({ entries: [] }) });
    expect((await connectUpdates(old.l)).facts().rollback).toEqual({ available: false });
  });

  test("a refused status rejects, so the product registers nothing for a person who is not the owner", async () => {
    const l = link({}, ["release.update.status"]);
    await expect(connectUpdates(l.l)).rejects.toThrow();
  });

  test("a topic event repaints; a call that is refused asks for the passkey once and tries again", async () => {
    let state = status()();
    const l = link({ "release.update.status": () => state, "release.update.history": () => ({ entries: [] }), "release.update.settings": () => state }, ["release.update.settings"]);
    const source = await connectUpdates(l.l);
    let repaints = 0;
    source.onChange(() => repaints++);
    state = { ...state, staged: "0.5.0" };
    l.push(state);
    expect(source.facts().state).toEqual({ kind: "ready", version: "0.5.0" });
    expect(repaints).toBeGreaterThan(0);
    await source.setQuietMinutes(30);
    expect(l.confirmed()).toBe(1);
    expect(l.calls.filter(([id]) => id === "release.update.settings")).toEqual([["release.update.settings", { quiet_minutes: 30 }], ["release.update.settings", { quiet_minutes: 30 }]]);
  });

  test("a second refusal is said in a sentence and Update now shows no work left behind", async () => {
    const l = link({ "release.update.status": status({ staged: "0.5.0" }), "release.update.history": () => ({ entries: [] }) }, ["release.update.apply"]);
    const source = await connectUpdates({ ...l.l, call: async (id, input) => { if (id === "release.update.apply") throw new Error("Confirm with your passkey first."); return l.l.call(id, input); } });
    await expect(source.apply()).rejects.toThrow("Confirm with your passkey first.");
    expect(source.facts().state).toEqual({ kind: "ready", version: "0.5.0" });
  });

  test("Edge is sent confirmed (the person confirmed it in the window); Stable is not", async () => {
    const l = link({ "release.update.status": status(), "release.update.history": () => ({ entries: [] }), "release.channel.set": () => ({}) });
    const source = await connectUpdates(l.l);
    await source.setChannel("edge");
    await source.setChannel("stable");
    expect(l.calls.filter(([id]) => id === "release.channel.set").map(([, i]) => i)).toEqual([{ channel: "edge", confirmed: true }, { channel: "stable" }]);
  });
});
