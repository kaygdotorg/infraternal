import { beforeEach, expect, test } from "bun:test";
import { canvasKey, clearAccountStorage, inventoryKey, lastAccountKey, tabSessionKey } from "./account-storage";

class FakeStorage {
  private map = new Map<string, string>();
  get length(): number { return this.map.size; }
  key(i: number): string | null { return [...this.map.keys()][i] ?? null; }
  getItem(k: string): string | null { return this.map.get(k) ?? null; }
  setItem(k: string, v: string): void { this.map.set(k, v); }
  removeItem(k: string): void { this.map.delete(k); }
  keys(): string[] { return [...this.map.keys()].sort(); }
}
const g = globalThis as unknown as { localStorage: FakeStorage; sessionStorage: FakeStorage };

beforeEach(() => { g.localStorage = new FakeStorage(); g.sessionStorage = new FakeStorage(); });

function fill(account: string): void {
  g.localStorage.setItem(canvasKey(account), "{}");
  g.localStorage.setItem(inventoryKey(account), "[]");
  g.sessionStorage.setItem(tabSessionKey(account), "s1");
}

test("clearing one account leaves a second account and device preferences alone", () => {
  fill("a"); fill("b");
  g.localStorage.setItem("tracer.theme", "mocha");
  g.localStorage.setItem(lastAccountKey, "a");
  clearAccountStorage("a");
  expect(g.localStorage.keys()).toEqual([canvasKey("b"), inventoryKey("b"), "tracer.theme"].sort());
  expect(g.sessionStorage.keys()).toEqual([tabSessionKey("b")]);
});

test("the last-account pointer of another account stays", () => {
  g.localStorage.setItem(lastAccountKey, "b");
  clearAccountStorage("a");
  expect(g.localStorage.getItem(lastAccountKey)).toBe("b");
});

test("an unknown account clears every account's data and keeps preferences", () => {
  fill("a"); fill("b");
  g.localStorage.setItem("tracer.theme", "mocha");
  clearAccountStorage(undefined);
  expect(g.localStorage.keys()).toEqual(["tracer.theme"]);
  expect(g.sessionStorage.keys()).toEqual([]);
});
