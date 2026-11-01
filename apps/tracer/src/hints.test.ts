import { beforeEach, expect, test } from "bun:test";
import { recordSignIn, teachOnce } from "./hints";

class FakeStorage {
  private map = new Map<string, string>();
  getItem(k: string): string | null { return this.map.get(k) ?? null; }
  setItem(k: string, v: string): void { this.map.set(k, v); }
}
const g = globalThis as unknown as { localStorage: unknown };
beforeEach(() => { g.localStorage = new FakeStorage(); });

test("sign-ins 1 to 5 show a hint once each; the sixth never does", () => {
  const shown: boolean[] = [];
  for (let n = 1; n <= 7; n++) {
    recordSignIn("a");
    shown.push(teachOnce("a", "close"), teachOnce("a", "close"), teachOnce("a", "close"));
  }
  expect(shown).toEqual([
    true, false, false, true, false, false, true, false, false, true, false, false, true, false, false,
    false, false, false, false, false, false,
  ]);
});

test("a reload inside a sign-in does not show the hint again, and different hints are independent and accounts share anonymous device counters", () => {
  recordSignIn("a");
  expect(teachOnce("a", "x")).toBe(true);
  expect(teachOnce("a", "x")).toBe(false);
  expect(teachOnce("a", "y")).toBe(true);
  expect(teachOnce("b", "x")).toBe(false);
});

test("an account without a counter is in its first sign-in", () => {
  expect(teachOnce("a", "x")).toBe(true);
  expect(teachOnce("a", "x")).toBe(false);
});

test("storage that throws or holds junk shows nothing and never throws", () => {
  g.localStorage = { getItem() { throw new Error("blocked"); }, setItem() { throw new Error("blocked"); } };
  expect(() => recordSignIn("a")).not.toThrow();
  expect(teachOnce("a", "x")).toBe(false);
  g.localStorage = new FakeStorage();
  (g.localStorage as FakeStorage).setItem("tracer.hints", "{not json");
  expect(teachOnce("a", "x")).toBe(false);
  g.localStorage = { getItem: () => null, setItem() { throw new Error("full"); } };
  expect(teachOnce("a", "x")).toBe(false);
});
