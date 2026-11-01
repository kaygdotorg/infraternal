import { describe, expect, test } from "bun:test";
import type { VersionFacts } from "./source";
import type { Fleet } from "./updates";
import { editionTag, endLine, licenceLabel, panelTitle, pillState, targetNames, updatesAvailable, updatesLine } from "./words";

const facts = (over: Partial<VersionFacts> = {}): VersionFacts => ({
  version: "0.4.2", copy: "0.4.2-abc", hosts: [], licence: { tier: "community" }, updates: { kind: "unknown" }, ...over,
});
const T = (name: string) => ({ name, from: "0.4.0", to: "0.4.2" });

describe("the Updates value", () => {
  test("each state says one thing, and a press is named by the tooltip", () => {
    expect(updatesLine({ kind: "unknown" })).toEqual({ value: "Check for updates", mark: undefined, tip: "Check this server and every host for updates" });
    expect(updatesLine({ kind: "current" }).value).toBe("Up to date");
    expect(updatesLine({ kind: "current" }).mark).toBe("ok");
    expect(updatesLine({ kind: "checking" })).toMatchObject({ value: "Checking for updates…", mark: "busy" });
    expect(updatesLine({ kind: "failed", reason: "The release server did not answer." })).toMatchObject({ value: "Couldn't check — try again", mark: "off" });
  });

  test("the count agrees with its noun and the question is asked once", () => {
    expect(updatesLine({ kind: "available", targets: [T("a")] }).value).toBe("1 update available — proceed?");
    expect(updatesLine({ kind: "available", targets: [T("a"), T("b"), T("c")] }).value).toBe("3 updates available — proceed?");
    expect(updatesLine({ kind: "updating", targets: [T("a"), T("b")] }).value).toBe("Updating 2…");
    expect(updatesAvailable(2)).toBe("2 updates available");
  });

  test("the tooltip names what a press will update, with this server first-class", () => {
    expect(targetNames([{ name: "this server", server: true, from: "1", to: "2" }, T("build-01"), T("nas")])).toBe("this server, build-01 and nas");
    expect(updatesLine({ kind: "available", targets: [T("nas")] }).tip).toBe("Update nas now");
  });

  test("no value repeats its key, and 'Hosts' is not a second key for the same thing", () => {
    const states: Fleet[] = [{ kind: "unknown" }, { kind: "current" }, { kind: "checking" }, { kind: "failed", reason: "x" }, { kind: "available", targets: [T("a")] }, { kind: "updating", targets: [T("a")] }];
    for (const fleet of states) {
      expect(updatesLine(fleet).value.toLowerCase()).not.toMatch(/^updates\b/);
      expect(updatesLine(fleet).value).not.toMatch(/\bhosts?\b/i);
    }
  });
});

describe("the pill", () => {
  test("up to date is a tick, an update is an exclamation, a failed check is a cross, and nothing known shows no mark", () => {
    expect(pillState(facts(), { kind: "current" }).status).toBe("current");
    expect(pillState(facts(), { kind: "available", targets: [T("a")] }).status).toBe("available");
    expect(pillState(facts(), { kind: "failed", reason: "x" }).status).toBe("offline");
    expect(pillState(facts(), { kind: "unknown" }).status).toBe("unknown");
  });

  test("the tip and the spoken name carry the status and the edition in words", () => {
    const s = pillState(facts(), { kind: "available", targets: [T("a"), T("b")] });
    expect(s.tip).toBe("2 updates available · Community");
    expect(s.label).toBe("Version 0.4.2. 2 updates available. Community edition. Opens version and updates");
    expect(pillState(facts(), { kind: "unknown" }).tip).toBe("Version 0.4.2 · Community");
  });

  test("a licence about to end tints the edition and the tip says when", () => {
    const f = facts({ licence: { tier: "team", days: 7 } });
    expect(pillState(f, { kind: "current" })).toMatchObject({ edition: "EE", attention: "soon" });
    expect(pillState(f, { kind: "current" }).tip).toBe("Up to date · Team, licence ends in 7 days");
    expect(pillState(facts({ licence: { tier: "team", days: -2, endedTier: "team" } }), { kind: "current" })).toMatchObject({ edition: "CE", attention: "ended" });
  });
});

describe("the licence lines", () => {
  test("the section is titled by the edition, and the heading says the version once", () => {
    expect(licenceLabel({ tier: "community" })).toBe("Community edition");
    expect(licenceLabel({ tier: "team", holder: "Northwind Labs" })).toBe("Team edition · Northwind Labs");
    expect(panelTitle(facts())).toBe("infraternal 0.4.2");
    expect(editionTag({ tier: "enterprise" })).toBe("EE");
  });

  test("a licence says when it ends in plain words", () => {
    const now = Date.UTC(2026, 9, 15);
    expect(endLine({ tier: "team" }, now)).toEqual({ key: "Valid", value: "Never ends" });
    expect(endLine({ tier: "team", days: 7 }, now).value).toMatch(/22 Oct 2026 · in 7 days/);
    expect(endLine({ tier: "team", days: 79 }, now).key).toBe("Renews");
    expect(endLine({ tier: "community", endedTier: "team", days: -7 }, now).value).toMatch(/^Team ended 8 Oct 2026$/);
  });

  test("no prices anywhere in the wording", () => {
    const all = [licenceLabel({ tier: "homelab" }), licenceLabel({ tier: "enterprise", holder: "X" }), pillState(facts(), { kind: "current" }).tip].join(" ");
    expect(all).not.toMatch(/[$€£]|\bprice|\bper (seat|month|year)/i);
  });
});
