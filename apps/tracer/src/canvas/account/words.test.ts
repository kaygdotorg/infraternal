import { describe, expect, test } from "bun:test";
import type { Login, LoginHost, Person } from "./model";
import { attention, CHIPS_SHOWN, healthRows, looksLikeEmail, loginChips, loginChipsText, num, passkeyReading, pillLabel, recoveryReading, RECOVERY_STALE_DAYS, shortDate, shownName, tagGroups } from "./words";

const DAY = 86_400_000;
/** Noon on 1 November 2026: far from any date line, so "3 Mar" is "3 Mar" in every time zone. */
const NOW = Date.UTC(2026, 10, 1, 12);
const daysAgo = (n: number): number => NOW - n * DAY;
const host = (name: string, ...tags: string[]): LoginHost => ({ name, platform: "ubuntu", tags });
const person = (over: Partial<Person> = {}): Person => ({ name: "Kay G", username: "kayg", ...over });

describe("a value says the state, and a concern says itself", () => {
  test("a recovery key verified recently is just \"Set up\"; there is no \"checked N days ago\" line anywhere", () => {
    for (const days of [0, 1, 6, 30, RECOVERY_STALE_DAYS]) {
      expect(recoveryReading({ setUp: true, verifiedAt: daysAgo(days) }, NOW)).toEqual({ value: "Set up", mark: "ok", tip: "Recovery key, in Settings" });
    }
    const all = healthRows(person({ passkeys: 2, recovery: { setUp: true, verifiedAt: daysAgo(6) }, devices: 4 }), NOW);
    expect(all.map((r) => [r.key, r.value, r.mark])).toEqual([["Passkeys", "2", "ok"], ["Recovery key", "Set up", "ok"], ["Devices", "4", "ok"]]);
    for (const row of all) expect(Object.keys(row)).not.toContain("hint");
    expect(JSON.stringify(all)).not.toMatch(/checked|ago/i);
  });

  test("a recovery key that is not set up, never verified, or stale says so in its value, with the way out", () => {
    expect(recoveryReading({ setUp: false, verifiedAt: null }, NOW)).toMatchObject({ value: "Not set up", mark: "warn" });
    expect(recoveryReading({ setUp: true, verifiedAt: null }, NOW)).toMatchObject({ value: "Never verified, verify now", mark: "warn" });
    const stale = recoveryReading({ setUp: true, verifiedAt: Date.UTC(2026, 2, 3, 12) }, NOW);
    expect(stale).toMatchObject({ value: "Not verified since 3 Mar, verify now", mark: "warn" });
    // A year ago names the year, so the date is never ambiguous.
    expect(recoveryReading({ setUp: true, verifiedAt: Date.UTC(2025, 9, 12, 12) }, NOW).value).toBe("Not verified since 12 Oct 2025, verify now");
    // One day past the limit is already a concern; the limit itself is not.
    expect(recoveryReading({ setUp: true, verifiedAt: daysAgo(RECOVERY_STALE_DAYS + 1) }, NOW).mark).toBe("warn");
  });

  test("unavailable verification history proves setup only, never age or possession", () => {
    expect(recoveryReading({ setUp: true }, NOW)).toEqual({ value: "Set up", mark: "ok", tip: "Set up; verification history unavailable" });
    expect(attention(person({ passkeys: 2, recovery: { setUp: true } }), NOW)).toBeUndefined();
    expect(recoveryReading({ setUp: false }, NOW).value).toBe("Not set up");
  });

  test("passkeys: the number when there are two or more, the concern when there are fewer", () => {
    expect(passkeyReading(2)).toMatchObject({ value: "2", mark: "ok" });
    expect(passkeyReading(12)).toMatchObject({ value: "12", mark: "ok" });
    expect(passkeyReading(1)).toMatchObject({ value: "Only one, add a second", mark: "warn" });
    expect(passkeyReading(0)).toMatchObject({ value: "None, add one", mark: "warn" });
  });

  test("a row whose fact the server cannot say yet is not drawn (the product knows only the name and the username today)", () => {
    expect(healthRows(person(), NOW)).toEqual([]);
    expect(healthRows(person({ passkeys: 3 }), NOW).map((r) => r.id)).toEqual(["passkeys"]);
    expect(healthRows(person({ devices: 0 }), NOW)[0]).toMatchObject({ value: "None" });
  });

  test("the pill's amber mark follows the values: the recovery key first, then the passkeys, and only when a value is a concern", () => {
    expect(attention(person(), NOW)).toBeUndefined();
    expect(attention(person({ passkeys: 2, recovery: { setUp: true, verifiedAt: daysAgo(6) } }), NOW)).toBeUndefined();
    expect(attention(person({ passkeys: 1, recovery: { setUp: true, verifiedAt: daysAgo(6) } }), NOW)).toMatchObject({ why: "passkey", tip: "You have only one passkey" });
    expect(attention(person({ passkeys: 0 }), NOW)).toMatchObject({ why: "passkey", tip: "You have no passkey" });
    expect(attention(person({ passkeys: 1, recovery: { setUp: true, verifiedAt: null } }), NOW)).toMatchObject({ why: "recovery", tip: "Recovery key: never verified, verify now" });
    expect(attention(person({ recovery: { setUp: false, verifiedAt: null } }), NOW)).toMatchObject({ why: "recovery", tip: "You have no recovery key" });
    expect(attention(person({ recovery: { setUp: true, verifiedAt: daysAgo(200) } }), NOW)?.tip).toMatch(/^Recovery key: not verified since \d+ \w+, verify now$/);
  });

  test("dates", () => {
    expect(shortDate(Date.UTC(2026, 2, 3, 12), NOW)).toBe("3 Mar");
    expect(shortDate(Date.UTC(2025, 11, 25, 12), NOW)).toBe("25 Dec 2025");
  });
});

describe("logs in as", () => {
  const login = (account: string, hosts: LoginHost[]): Login => ({ account, hosts });
  const many = (n: number, ...tags: string[]): LoginHost[] => Array.from({ length: n }, (_, i) => host(`h${i}`, ...tags));

  test("the row is a chip per account with its host count, the biggest first, never more than three, then +N", () => {
    expect(loginChips([login("kayg", many(12)), login("root", many(2))])).toEqual([{ text: "kayg", note: "12" }, { text: "root", note: "2" }]);
    const four = loginChips([login("a", many(1)), login("b", many(4)), login("c", many(3)), login("d", many(2)), login("e", many(1))]);
    expect(four).toHaveLength(CHIPS_SHOWN + 1);
    expect(four.at(-1)).toEqual({ text: "+2" });
    expect(loginChipsText([login("kayg", many(1202))])).toBe("kayg 1,202");
    expect(loginChips([])).toEqual([]);
  });

  test("each tag has its own group; the biggest first, then by name; the untagged last", () => {
    const groups = tagGroups(login("kayg", [host("a", "prod"), host("b", "prod", "db"), host("c", "lab"), host("d"), host("e", "db"), host("f", "prod")]));
    expect(groups.map((g) => [g.tag, g.hosts.map((h) => h.name)])).toEqual([
      ["prod", ["a", "b", "f"]],
      ["db", ["b", "e"]],
      ["lab", ["c"]],
      [null, ["d"]],
    ]);
  });

  test("a machine with several tags is in each of its tags' groups, once in each, and keeps all its tags", () => {
    const groups = tagGroups(login("kayg", [host("b", "prod", "db", "prod")]));
    expect(groups.map((g) => g.tag)).toEqual(["db", "prod"]);
    for (const g of groups) expect(g.hosts.map((h) => h.tags)).toEqual([["prod", "db", "prod"]]);
  });

  test("no tags at all is one untagged group; no machines is none", () => {
    expect(tagGroups(login("kayg", many(3))).map((g) => g.tag)).toEqual([null]);
    expect(tagGroups(login("kayg", []))).toEqual([]);
  });
});

describe("the rest", () => {
  test("numbers carry separators and a name falls back to the username", () => {
    expect(num(1284)).toBe("1,284");
    expect(shownName({ name: "", username: "kayg" })).toBe("kayg");
    expect(shownName({ name: "  ", username: "kayg" })).toBe("kayg");
    expect(shownName({ name: "Kay G", username: "kayg" })).toBe("Kay G");
  });

  test("the pill's spoken name says the person, then Account, then what needs attention", () => {
    const p = person();
    expect(pillLabel(p, undefined)).toBe("Kay G, kayg. Account");
    expect(pillLabel(person({ name: "" }), undefined)).toBe("kayg. Account");
    expect(pillLabel(p, { why: "passkey", tip: "You have only one passkey" })).toBe("Kay G, kayg. Account. You have only one passkey");
  });

  test("email check", () => {
    expect(looksLikeEmail("asha@northwind.example")).toBe(true);
    expect(["asha", "a@b", "a b@c.d", ""].some(looksLikeEmail)).toBe(false);
  });
});
