/** Account cache isolation and sign-out cleanup, including offline drawing labels (D245). */
import { beforeEach, expect, test } from "bun:test";
import { canvasKey, clearAccountStorage, createAccountNotifications, drawingIdentityKey, inventoryKey, lastAccountKey, tabSessionKey } from "./account-storage";

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

/** Seeds account-local canvas and appearance values for cleanup assertions. */
function fill(account: string): void {
  g.localStorage.setItem(canvasKey(account), "{}");
  g.localStorage.setItem(`tracer.look.account.${encodeURIComponent(account)}`, "{}");
  g.localStorage.setItem(drawingIdentityKey(account), "{}");
  g.localStorage.setItem(inventoryKey(account), "[]");
  g.sessionStorage.setItem(tabSessionKey(account), "s1");
}

test("clearing one account leaves a second account and device preferences alone", () => {
  fill("a"); fill("b");
  g.localStorage.setItem("tracer.theme", "mocha");
  g.localStorage.setItem(lastAccountKey, "a");
  clearAccountStorage("a");
  expect(g.localStorage.keys()).toEqual([canvasKey("b"), `tracer.look.account.${encodeURIComponent("b")}`, drawingIdentityKey("b"), inventoryKey("b"), "tracer.theme"].sort());
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

test("account notifications cannot write before or after disposal", () => {
  const cache = createAccountNotifications(); let notified = 0;
  cache.subscribe(() => { notified++; }); cache.notify(); cache.dispose(); cache.notify();
  expect(notified).toBe(1); expect(g.localStorage.keys()).toEqual([]);
});
test("legacy generation sweep is account scoped and reports refused erasure", () => {
  g.localStorage.setItem("infraternal.canvas-journal.a.page.1", "old");
  g.localStorage.setItem("infraternal.canvas-journal.b.page.1", "other");
  expect(clearAccountStorage("a")).toBe(true);
  expect(g.localStorage.keys()).toEqual(["infraternal.canvas-journal.b.page.1"]);
  g.localStorage.removeItem = () => { throw Error("blocked"); };
  expect(clearAccountStorage("b")).toBe(false);
});
test("R2: 21 legacy generations survive refused cleanup and disappear only after a successful retry", () => {
  for (let n = 0; n < 21; n++) g.localStorage.setItem(`infraternal.canvas-journal.a.generation.${n}`, "old");
  const remove = g.localStorage.removeItem.bind(g.localStorage);
  g.localStorage.removeItem = () => { throw Error("blocked"); };
  expect(clearAccountStorage("a")).toBe(false); expect(g.localStorage.keys()).toHaveLength(21);
  g.localStorage.removeItem = remove;
  expect(clearAccountStorage("a")).toBe(true); expect(g.localStorage.keys()).toEqual([]);
});
