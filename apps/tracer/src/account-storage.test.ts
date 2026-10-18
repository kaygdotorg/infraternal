/** Account cache isolation and sign-out cleanup, including offline drawing labels (D245). */
import { beforeEach, expect, test } from "bun:test";
import { canvasKey, clearAccountStorage, createStoredJsonCache, drawingIdentityKey, inventoryKey, lastAccountKey, tabSessionKey } from "./account-storage";

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
  g.localStorage.setItem(drawingIdentityKey(account), "{}");
  g.localStorage.setItem(inventoryKey(account), "[]");
  g.sessionStorage.setItem(tabSessionKey(account), "s1");
}

test("clearing one account leaves a second account and device preferences alone", () => {
  fill("a"); fill("b");
  g.localStorage.setItem("tracer.theme", "mocha");
  g.localStorage.setItem(lastAccountKey, "a");
  clearAccountStorage("a");
  expect(g.localStorage.keys()).toEqual([canvasKey("b"), drawingIdentityKey("b"), inventoryKey("b"), "tracer.theme"].sort());
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

test("coalesced account writes stop permanently before sign-out clears storage", () => {
  const key = canvasKey("a"); let value = 1, reads = 0;
  const cache = createStoredJsonCache(key, () => { reads++; return { value }; });
  cache.schedule(); cache.schedule(); expect(g.localStorage.getItem(key)).toBeNull();
  value = 2; cache.flush(); expect(reads).toBe(1); expect(JSON.parse(g.localStorage.getItem(key)!)).toEqual({ value: 2 });
  let notified = 0; cache.subscribe(() => { notified++; }); cache.notify();
  cache.dispose(); clearAccountStorage("a"); value = 3; cache.schedule(); cache.flush(); cache.notify();
  expect(notified).toBe(1);
  expect(g.localStorage.getItem(key)).toBeNull(); expect(reads).toBe(1);
});
