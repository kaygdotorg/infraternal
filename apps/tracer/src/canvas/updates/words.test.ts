import { describe, expect, test } from "bun:test";
import { createUpdatesDouble, UPDATE_SCENARIOS } from "../mock/updates/double";
import { ago, buttons, historyLine, inboxTitle, rollbackConfirm, statusLine } from "./words";

const NOW = Date.UTC(2026, 10, 21, 12, 0, 0);

describe("Updates words", () => {
  test("times read as a person says them", () => {
    expect(ago(NOW - 20_000, NOW)).toBe("just now");
    expect(ago(NOW - 60_000, NOW)).toBe("1 minute ago");
    expect(ago(NOW - 2 * 3_600_000, NOW)).toBe("2 hours ago");
    expect(ago(NOW - 3 * 86_400_000, NOW)).toBe("3 days ago");
  });

  test("every scenario of the double has a status sentence, and no status leaks an enum name", () => {
    for (const scenario of UPDATE_SCENARIOS) {
      const facts = scenario.facts(NOW);
      const line = statusLine(facts.state, facts.quietMinutes);
      expect(line.value.length).toBeGreaterThan(0);
      expect(`${line.value} ${line.detail ?? ""}`).not.toMatch(/rolled-back|downloading|applying|switching|undefined/);
    }
  });

  test("the waiting state names the quiet window and Update now", () => {
    const line = statusLine({ kind: "ready", version: "0.5.0" }, 5);
    expect(line.value).toBe("0.5.0 is ready");
    expect(line.detail).toContain("5 min");
    expect(inboxTitle("0.5.0")).toBe("Update ready · 0.5.0");
  });

  test("download progress is the meter and the percentage", () => {
    expect(statusLine({ kind: "downloading", version: "0.5.0", percent: 61.6 }, 5)).toMatchObject({ meter: 61.6, detail: "62%", mark: "busy" });
  });

  test("an undone update keeps its reason on the history line", () => {
    const line = historyLine({ version: "0.4.0", from: "0.3.9", outcome: "rolled-back", at: NOW - 3_600_000, reason: "It failed its check." }, NOW);
    expect(line).toEqual({ title: "0.4.0 undone", sub: "from 0.3.9 · 1 hour ago\nIt failed its check." });
  });

  test("Roll back says what comes back and what is lost, with named buttons", () => {
    const text = rollbackConfirm("0.4.1", "Everything saved since 0.4.2 is lost.");
    expect(text).toMatchObject({ title: "Go back to 0.4.1?", confirmLabel: "Roll back", cancelLabel: "Keep this version" });
    expect(text.effect).toContain("lost");
  });

  test("buttons: nothing is pressable while work runs or updates are off; Update now only when one is staged", () => {
    const rollback = { available: true as const, to: "0.4.1", lost: "x" };
    expect(buttons({ state: { kind: "current" }, rollback })).toEqual({ check: true, apply: false, rollback: true });
    expect(buttons({ state: { kind: "ready", version: "1" }, rollback })).toEqual({ check: true, apply: true, rollback: true });
    expect(buttons({ state: { kind: "checking" }, rollback })).toEqual({ check: false, apply: false, rollback: false });
    expect(buttons({ state: { kind: "applying", version: "1", phase: "checking" }, rollback })).toEqual({ check: false, apply: false, rollback: false });
    expect(buttons({ state: { kind: "off", reason: "x" }, rollback })).toEqual({ check: false, apply: false, rollback: false });
    expect(buttons({ state: { kind: "current" }, rollback: { available: false } }).rollback).toBe(false);
  });
});

describe("the double plays the transitions the buttons cause", () => {
  test("Update now moves ready → installing → up to date on the new version, with a history line and a way back", async () => {
    const double = createUpdatesDouble("ready");
    const seen: string[] = [];
    double.onChange(() => seen.push(double.facts().state.kind));
    await double.apply();
    expect(seen).toEqual(["applying", "applying", "current"]);
    const facts = double.facts();
    expect(facts.running).toBe("0.5.0");
    expect(facts.history[0]).toMatchObject({ version: "0.5.0", from: "0.4.2", outcome: "applied" });
    expect(facts.rollback).toMatchObject({ available: true, to: "0.4.2" });
  });

  test("Roll back puts the previous version back and says so", async () => {
    const double = createUpdatesDouble("current");
    await double.rollback();
    expect(double.facts()).toMatchObject({ running: "0.4.1", state: { kind: "rolled-back", version: "0.4.2" }, rollback: { available: false } });
    expect(double.facts().history[0]).toMatchObject({ outcome: "rolled-back", reason: "You rolled it back." });
  });

  test("a refused call says why in a sentence and changes nothing", async () => {
    const double = createUpdatesDouble("current");
    double.refuseNext("Confirm with your passkey first.");
    await expect(double.rollback()).rejects.toThrow("Confirm with your passkey first.");
    expect(double.facts().running).toBe("0.4.2");
  });
});
