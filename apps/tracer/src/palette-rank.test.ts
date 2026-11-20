// SPDX-License-Identifier: AGPL-3.0-only
/** The palette's one ranking rule: a group with a row whose title is, or starts with, what was typed is listed first. */
import { expect, test } from "bun:test";
import { rankByTitle, titleMatches } from "./palette-rank";

test("a title matches when it equals the query or starts with it, ignoring case and a leading article", () => {
  expect(titleMatches("The Infraternal Multiplexer", "infraternal multiplexer")).toBe(true);
  expect(titleMatches("The Infraternal Multiplexer", "the infraternal")).toBe(true);
  expect(titleMatches("Keys and how long they last", "KEYS")).toBe(true);
  expect(titleMatches("Keys and how long they last", "keys and how long they last")).toBe(true);
  expect(titleMatches("A guide to keys", "guide")).toBe(true);
});

test("a title that only contains the query somewhere does not match", () => {
  expect(titleMatches("The Infraternal Multiplexer", "multiplexer")).toBe(false);
  expect(titleMatches("Keys and how long they last", "long")).toBe(false);
  expect(titleMatches("Keys", "")).toBe(false);
  expect(titleMatches("Keys", "   ")).toBe(false);
});

test("the group of a matching row moves to the front; every other order is kept", () => {
  const rows = [
    { group: "Settings", label: "Offer To Switch" },
    { group: "Settings", label: "Theme" },
    { group: "Docs", label: "Terminal › The Infraternal Multiplexer", title: "The Infraternal Multiplexer" },
    { group: "Docs", label: "Offer to switch", title: undefined },
    { group: "Fonts", label: "Geist Mono" },
  ];
  expect(rankByTitle(rows, "infraternal multiplexer").map((row) => row.label)).toEqual([
    "Terminal › The Infraternal Multiplexer", "Offer to switch", "Offer To Switch", "Theme", "Geist Mono",
  ]);
});

test("with no title match the very same list comes back", () => {
  const rows = [{ group: "Settings", label: "Offer To Switch" }, { group: "Docs", label: "Terminal › The Infraternal Multiplexer", title: "The Infraternal Multiplexer" }];
  expect(rankByTitle(rows, "switch")).toBe(rows);
  expect(rankByTitle(rows, "")).toBe(rows);
});
