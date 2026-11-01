/** UI size (#283): the slider's range, the migration of sizes stored before the 1.1 base, and what is written where. */
import { beforeEach, expect, test } from "bun:test";
import { clampUiSize, migrateLegacy, readUiSize, setUiSize } from "./ui-scale";

let store: Map<string, string>;
let style: Map<string, string>;
let events: string[];

beforeEach(() => {
  store = new Map();
  style = new Map();
  events = [];
  const g = globalThis as unknown as Record<string, unknown>;
  g.localStorage = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => { store.set(k, v); }, removeItem: (k: string) => { store.delete(k); } };
  g.document = { documentElement: { style: { setProperty: (k: string, v: string) => { style.set(k, v); }, removeProperty: (k: string) => { style.delete(k); }, getPropertyValue: (k: string) => style.get(k) ?? "" } } };
  g.window = { dispatchEvent: (e: { type: string }) => { events.push(e.type); return true; }, addEventListener: () => undefined };
});

test("sizes snap to the 5 % steps and stay between 50 and 150", () => {
  expect([clampUiSize(97), clampUiSize(102.4), clampUiSize(10), clampUiSize(400), clampUiSize(55)]).toEqual([95, 100, 50, 150, 55]);
});

test("an old size keeps the pixels it showed: 110 % of 16 px is the new 100 %", () => {
  expect(migrateLegacy(110)).toBe(100);
  expect(migrateLegacy(120)).toBe(110);
  expect(migrateLegacy(130)).toBe(120);
  expect(migrateLegacy(150)).toBe(135);
  expect(migrateLegacy(75)).toBe(70);
  // Below the slider's floor and above its ceiling: the nearest end.
  expect(migrateLegacy(50)).toBe(50);
  expect(migrateLegacy(200)).toBe(150);
});

test("an old 100 % was the default, so it gets the new default", () => {
  expect(migrateLegacy(100)).toBe(100);
});

test("nothing stored, or nonsense, is the standard size", () => {
  expect(readUiSize()).toBe(100);
  store.set("tracer.ui-size.v2", "abc");
  expect(readUiSize()).toBe(100);
  store.set("tracer.ui-size.v2", "-5");
  expect(readUiSize()).toBe(100);
});

test("the new key is read as it is (to the step), and wins over an old one", () => {
  store.set("tracer.ui-size.v2", "120");
  store.set("tracer.ui-size", "150");
  expect(readUiSize()).toBe(120);
  expect(store.get("tracer.ui-size")).toBe("150");
});

test("an old key is migrated once: written under the new key, then gone", () => {
  store.set("tracer.ui-size", "120");
  expect(readUiSize()).toBe(110);
  expect(store.get("tracer.ui-size.v2")).toBe("110");
  expect(store.has("tracer.ui-size")).toBe(false);
  expect(readUiSize()).toBe(110);
});

test("an old key that is not a number is ignored", () => {
  store.set("tracer.ui-size", "wide");
  expect(readUiSize()).toBe(100);
});

test("setting a size remembers it, paints it and says so; the standard size leaves no property", () => {
  expect(setUiSize(120)).toBe(120);
  expect(store.get("tracer.ui-size.v2")).toBe("120");
  expect(style.get("--ui-scale")).toBe("1.2");
  expect(events).toEqual(["tracer:ui-size"]);
  expect(setUiSize(97)).toBe(95);
  expect(style.get("--ui-scale")).toBe("0.95");
  expect(setUiSize(100)).toBe(100);
  expect(style.has("--ui-scale")).toBe(false);
});
