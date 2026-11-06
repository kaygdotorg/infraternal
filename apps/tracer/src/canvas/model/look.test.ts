// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The account's look in the canvas document (D322, D178, #323): it is read with the server's bounds, saved by one `look.set` edit, applied by the
 * same reducer as every other edit, and the theme store's own snapshot is exactly what the document accepts, so a page can never produce a look the
 * server would refuse.
 */
import { expect, test } from "bun:test";
import { edits, reduce } from "./operations";
import { FORMAT, MAX_THEMES, parseDocument, parseLook, VERSION, type CanvasDocument, type DocLook } from "./schema";
import { createThemeStore } from "../themes/model";

const basics = { colors: "mocha", font: "maple-mono-nf", uiSize: 100 };
const empty = (): CanvasDocument => ({ format: FORMAT, version: VERSION, revision: 1, views: [] });
const look = (): DocLook => ({
  ...structuredClone(createThemeStore(basics).snapshot()),
  windowSizes: { phone: "edge", desktop: "comfortable" },
  extendedInfo: false,
});

test("a document with a look is read whole, and one without a look is still a document", () => {
  expect(parseDocument(empty())).toEqual(empty());
  const doc = { ...empty(), look: look() };
  expect(parseDocument(structuredClone(doc))).toEqual(doc);
});

test("a look out of the server's bounds makes the document unreadable, field by field", () => {
  const bad = (edit: (l: DocLook) => void): unknown => { const l = look(); edit(l); return parseDocument({ ...empty(), look: l }); };
  expect(bad((l) => { l.themes[0]!.tint = 101; })).toBeUndefined();
  expect(bad((l) => { l.themes[0]!.blur = -1; })).toBeUndefined();
  expect(bad((l) => { l.themes[0]!.grain = 12.5; })).toBeUndefined();
  expect(bad((l) => { l.themes[0]!.uiSize = 10; })).toBeUndefined();
  expect(bad((l) => { l.basics.uiSize = 900; })).toBeUndefined();
  expect(bad((l) => { l.themes[0]!.customSolid = "red"; })).toBeUndefined();
  expect(bad((l) => { l.themes[0]!.custom.stops = ["#ffffff"]; })).toBeUndefined();
  expect(bad((l) => { l.themes[0]!.custom.angle = 361; })).toBeUndefined();
  expect(bad((l) => { l.themes[0]!.name = "x".repeat(201); })).toBeUndefined();
  expect(bad((l) => { l.themes[1]!.id = l.themes[0]!.id; })).toBeUndefined();
  expect(bad((l) => { (l as { v: number }).v = 2; })).toBeUndefined();
  expect(bad((l) => { l.windowSizes!.phone = "tablet" as NonNullable<DocLook["windowSizes"]>["phone"]; })).toBeUndefined();
  expect(bad((l) => { l.windowSizes!.desktop = "compact" as NonNullable<DocLook["windowSizes"]>["desktop"]; })).toBeUndefined();
  expect(bad((l) => { l.extendedInfo = "yes" as unknown as boolean; })).toBeUndefined();
  expect(parseLook({ ...look(), uiFont: "sans" })).toBeUndefined();
  expect(bad((l) => { while (l.themes.length <= MAX_THEMES) l.themes.push({ ...structuredClone(l.themes[0]!), id: `n${l.themes.length}` }); })).toBeUndefined();
  expect(parseLook(null)).toBeUndefined();
  const earlier = look(); delete earlier.windowSizes; delete earlier.extendedInfo;
  expect(parseLook(earlier)).toEqual(earlier);
});

test("a changed look is one look.set edit, an unchanged one is none, and the reducer replaces the look whole", () => {
  const before = { ...empty(), look: look() };
  const after = structuredClone(before);
  expect(edits(before, after)).toEqual([]);
  after.look!.themes[0]!.tint = 40;
  after.look!.selected = "frosted";
  const out = edits(before, after);
  expect(out).toEqual([{ type: "look.set", look: after.look! }]);
  const doc = structuredClone(before);
  reduce(doc, out[0]!);
  expect(doc.look).toEqual(after.look);
  // The edit carries its own copy: changing the source afterwards does not change what was applied.
  after.look!.themes[0]!.tint = 90;
  expect(doc.look!.themes[0]!.tint).toBe(40);
  // An account with no look yet gets this page's.
  const first = edits(empty(), { ...empty(), look: look() });
  expect(first.map((e) => e.type)).toEqual(["look.set"]);
});

test("the theme store's snapshot is what the document accepts, whatever the person has done to it", () => {
  const store = createThemeStore(basics);
  store.edit({ tint: 33, blur: 7, grain: 12, font: "fantasque-sans-mono", colors: "kanagawa-wave", background: "custom", customSolid: "#123456", custom: { stops: ["#112233", "#445566", "#778899"], angle: 40 } });
  store.add();
  store.edit({ name: "Night", background: "solid-red" });
  while (store.themes().length < MAX_THEMES) store.add();
  expect(store.themes().length).toBe(MAX_THEMES);
  expect(parseLook(store.snapshot())).toEqual(store.snapshot());
  // One more is refused by the store, so a page never builds a look the server would turn down.
  store.add();
  expect(store.themes().length).toBeLessThanOrEqual(MAX_THEMES);
});

test("a full look fits in one edit (the server's bound is 8 KiB)", () => {
  const store = createThemeStore(basics);
  store.edit({ font: "fantasque-sans-mono", colors: "kanagawa-wave" });
  while (store.themes().length < MAX_THEMES) { store.add(); store.edit({ name: "A theme with a long name" }); }
  expect(JSON.stringify({ type: "look.set", look: store.snapshot() }).length).toBeLessThan(8 * 1024);
});
