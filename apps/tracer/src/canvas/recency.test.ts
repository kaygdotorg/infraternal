/** The per-view recency list behind the view's hover card (#121): what counts as used, the order and the fallback. */
import { expect, test } from "bun:test";
import { RecentList, recentRows } from "./recency";

test("touch moves an item to the front and never duplicates it", () => {
  const list = new RecentList<string>();
  for (const id of ["a", "b", "c", "a"]) list.touch(id);
  expect(list.top(10, () => true)).toEqual(["a", "c", "b"]);
  expect(list.size).toBe(3);
});

test("repeating the front item changes nothing", () => {
  const list = new RecentList<string>();
  list.touch("a");
  list.touch("b");
  list.touch("b");
  expect(list.top(10, () => true)).toEqual(["b", "a"]);
});

test("the list is capped, so the oldest items fall off", () => {
  const list = new RecentList<number>(3);
  for (let i = 0; i < 10; i++) list.touch(i);
  expect(list.top(10, () => true)).toEqual([9, 8, 7]);
});

test("top skips items that are no longer live, without losing them", () => {
  const list = new RecentList<string>();
  for (const id of ["a", "b", "c"]) list.touch(id);
  expect(list.top(2, (id) => id !== "c")).toEqual(["b", "a"]);
  expect(list.top(3, () => true)).toEqual(["c", "b", "a"]);
});

test("recentRows: five used windows in reverse order of use, from 54 windows", () => {
  const all = new Map<string, string>();
  for (let i = 1; i <= 54; i++) all.set(`w${i}`, `w${i}`);
  const list = new RecentList<string>();
  for (const id of ["w3", "w9", "w1", "w40", "w22", "w7", "w30"]) list.touch(id);
  expect(recentRows(list, all, 5)).toEqual(["w30", "w7", "w22", "w40", "w1"]);
});

test("recentRows: a view with three windows and no use shows them in order", () => {
  const all = new Map<string, string>([["a", "a"], ["b", "b"], ["c", "c"]]);
  expect(recentRows(undefined, all, 5)).toEqual(["a", "b", "c"]);
});

test("recentRows: used windows lead, the rest fill up to five in window order", () => {
  const all = new Map<string, string>();
  for (let i = 1; i <= 8; i++) all.set(`w${i}`, `w${i}`);
  const list = new RecentList<string>();
  list.touch("w6");
  list.touch("w2");
  list.touch("gone");
  expect(recentRows(list, all, 5)).toEqual(["w2", "w6", "w1", "w3", "w4"]);
});
