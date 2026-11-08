// SPDX-License-Identifier: AGPL-3.0-only
/** The theme rules of D322 and D338 hold, whoever edits the model next. */
import { expect, test } from "bun:test";
import { blurPercent, blurPx, createThemeStore, restore } from "./model";
import { THEMES } from "../../../../../packages/ui/src/themes";
import { backgroundCss, customGradient, GRADIENT_IDS, gradientColours, gradientsFor, isSolid, SOLID_IDS, solidsFor } from "./gradients";

/** Standard appearance used as the starting point for store behavior tests. */
const basics = { colors: "mocha", font: "maple-mono-nf", uiSize: 100 };

test("blur is a percentage: 0 px is 0% and 24 px is 100%", () => {
  expect(blurPx(0)).toBe(0);
  expect(blurPx(100)).toBe(24);
  expect(blurPx(50)).toBe(12);
  expect(blurPercent(24)).toBe(100);
  expect(blurPercent(0)).toBe(0);
  expect(blurPercent(6)).toBe(25);
});

test("the three built-in themes have the owner's numbers (D338) and a new person starts on Tinted", () => {
  const store = createThemeStore(basics);
  expect(store.themes().map((p) => [p.id, p.name, p.tint, p.blur])).toEqual([["solid", "Solid", 100, 0], ["tinted", "Tinted", 75, 25], ["frosted", "Frosted", 50, 50]]);
  expect(store.selectedId()).toBe("tinted");
  expect(store.themes().every((p) => p.colors === "mocha" && p.font === "maple-mono-nf" && p.uiSize === 100)).toBe(true);
});

test("a built-in theme can be changed; it is 'changed' only while it differs, and Reset puts its numbers back", () => {
  const store = createThemeStore(basics);
  expect(store.changed("tinted")).toBe(false);
  store.edit({ tint: 60 });
  expect(store.changed("tinted")).toBe(true);
  expect(store.changed("solid")).toBe(false);
  store.edit({ tint: 75 });
  expect(store.changed("tinted")).toBe(false); // back to the numbers: nothing to reset
  store.edit({ blur: 40, font: "geist-mono", colors: "rosepine", uiSize: 120 });
  expect(store.changed("tinted")).toBe(true);
  store.reset("tinted");
  expect(store.selected()).toEqual({ id: "tinted", name: "Tinted", tint: 75, blur: 25, grain: 0, ...basics, background: "aurora", custom: { stops: ["#7a9cff", "#cba6f7"], angle: 135 }, customSolid: "#3b4252" });
  expect(store.changed("tinted")).toBe(false);
});

test("Add copies the selected theme, selects the copy and gives it a name that can change; a built-in name cannot", () => {
  const store = createThemeStore(basics);
  store.edit({ blur: 30 });
  const made = store.add();
  expect(store.themes()).toHaveLength(4);
  expect(store.selectedId()).toBe(made.id);
  expect(made).toMatchObject({ tint: 75, blur: 30, font: "maple-mono-nf", colors: "mocha", uiSize: 100 });
  expect(made.name).toBe("Theme 4");
  expect(store.changed(made.id)).toBe(false); // a theme the person made has nothing to go back to
  expect(store.isBuiltIn(made.id)).toBe(false);
  store.edit({ name: "Night" });
  expect(store.selected().name).toBe("Night");
  store.select("solid");
  store.edit({ name: "Renamed" });
  expect(store.selected().name).toBe("Solid");
  // the copy did not alias the source
  store.select(made.id);
  store.edit({ tint: 10 });
  expect(store.themes().find((p) => p.id === "tinted")!.tint).toBe(75);
  expect(store.add().name).toBe("Theme 5");
});

test("every change is announced once, and a no-op select is not a change", () => {
  const store = createThemeStore(basics);
  let n = 0;
  const off = store.onChange(() => { n += 1; });
  store.select("tinted");
  expect(n).toBe(0);
  store.select("frosted");
  store.edit({ tint: 40 });
  store.reset("frosted");
  store.add();
  expect(n).toBe(4);
  off();
  store.select("solid");
  expect(n).toBe(4);
});

test("a theme holds its background: Solid starts solid, the others a gradient; it is part of what Reset restores and what Add copies", () => {
  const store = createThemeStore(basics);
  expect(store.themes().map((p) => p.background)).toEqual(["solid", "aurora", "aurora"]);
  store.edit({ background: "dusk" });
  expect(store.changed("tinted")).toBe(true);
  const made = store.add();
  expect(made.background).toBe("dusk");
  store.edit({ background: "custom", custom: { stops: ["#112233", "#445566", "#778899"], angle: 40 } });
  expect(store.themes().find((p) => p.id === "tinted")!.custom.stops).toEqual(["#7a9cff", "#cba6f7"]); // the copy did not alias the source
  store.select("tinted");
  store.reset("tinted");
  expect(store.selected().background).toBe("aurora");
  store.edit({ custom: { stops: ["#7a9cff", "#cba6f7"], angle: 135 } });
  expect(store.changed("tinted")).toBe(false);
  store.edit({ custom: { stops: ["#7a9cff", "#cba6f7"], angle: 90 } });
  expect(store.changed("tinted")).toBe(true);
});

test("every scheme gets the same nine gradients, recoloured from its own palette, and text keeps its contrast over them", () => {
  const lum = (hex: string): number => { const f = (v: number): number => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(parseInt(hex.slice(1, 3), 16)) + 0.7152 * f(parseInt(hex.slice(3, 5), 16)) + 0.0722 * f(parseInt(hex.slice(5, 7), 16)); };
  const ratio = (a: string, b: string): number => (Math.max(lum(a), lum(b)) + 0.05) / (Math.min(lum(a), lum(b)) + 0.05);
  for (const [id, theme] of Object.entries(THEMES)) {
    const list = gradientsFor(theme);
    expect(list.map((g) => g.id), id).toEqual([...GRADIENT_IDS]);
    expect(new Set(list.map((g) => g.css)).size, `${id}: no two gradients are the same`).toBe(list.length);
    for (const g of list) expect(g.css.length).toBeGreaterThan(20);
    // The scheme's text over the strongest colour any gradient puts behind it, at full strength (the worst case).
    for (const colour of gradientColours(theme)) expect(ratio(theme.fg, colour), `${id}: primary text over ${colour}`).toBeGreaterThanOrEqual(4.5);
  }
  expect(gradientsFor(THEMES.mocha!)[0]!.css).not.toBe(gradientsFor(THEMES.latte!)[0]!.css);
});

test("backgrounds resolve to CSS: Solid to nothing, an id to its gradient, custom to the person's stops in OKLab", () => {
  const theme = THEMES.mocha!, custom = { stops: ["#ff0000", "#0000ff"], angle: 200 };
  expect(backgroundCss("solid", custom, theme)).toBe("");
  expect(backgroundCss("dusk", custom, theme)).toBe(gradientsFor(theme).find((g) => g.id === "dusk")!.css);
  expect(backgroundCss("custom", custom, theme)).toBe("linear-gradient(200deg in oklab, #ff0000, #0000ff)");
  expect(customGradient({ stops: ["#fff"], angle: 10 })).toContain("#7a9cff"); // fewer than two stops: the default, never a broken image
});

test("Solid has options too: the scheme's own colour, seven solids from its palette, and your own colour", () => {
  for (const [id, theme] of Object.entries(THEMES)) {
    const list = solidsFor(theme);
    // The ids are in the fixed order; a scheme whose palette repeats a colour (Rose Pine: cyan is its accent) offers it once.
    expect(list.map((s) => s.id), id).toEqual(SOLID_IDS.filter((x) => list.some((s) => s.id === x)));
    expect(list.length, `${id}: at least six solids besides Default`).toBeGreaterThanOrEqual(7);
    expect(list.map((s) => s.name).slice(0, 3)).toEqual(["Default", "Accent", "Red"]);
    expect(list[0]!.colour, "Default is the scheme's own colour: nothing is drawn").toBe("");
    expect(new Set(list.slice(1).map((s) => s.colour)).size, `${id}: no two solids are the same`).toBe(list.length - 1);
    expect(backgroundCss("solid", DEFAULT_CUSTOM_FOR_TEST, theme)).toBe("");
    const red = list.find((s) => s.id === "solid-red")!;
    expect(backgroundCss("solid-red", DEFAULT_CUSTOM_FOR_TEST, theme)).toBe(`linear-gradient(${red.colour}, ${red.colour})`);
  }
  expect(backgroundCss("solid-custom", DEFAULT_CUSTOM_FOR_TEST, THEMES.mocha!, "#123456")).toBe("linear-gradient(#123456, #123456)");
  expect(["solid", "solid-red", "solid-custom"].every(isSolid) && !["aurora", "custom"].some(isSolid)).toBe(true);
});

test("a solid choice takes part in Reset and Add like any other", () => {
  const store = createThemeStore(basics);
  store.select("solid");
  store.edit({ background: "solid-custom", customSolid: "#abcdef" });
  expect(store.changed("solid")).toBe(true);
  const made = store.add();
  expect([made.background, made.customSolid]).toEqual(["solid-custom", "#abcdef"]);
  store.reset("solid");
  expect(store.themes().find((p) => p.id === "solid")).toMatchObject({ background: "solid", customSolid: "#3b4252" });
});
/** Expected starting custom gradient shared with the model defaults. */
const DEFAULT_CUSTOM_FOR_TEST = { stops: ["#7a9cff", "#cba6f7"], angle: 135 };

test("grain is part of a theme: none to start, in Reset and in Add", () => {
  const store = createThemeStore(basics);
  expect(store.themes().map((p) => p.grain)).toEqual([0, 0, 0]);
  store.edit({ grain: 40 });
  expect(store.changed("tinted")).toBe(true);
  expect(store.add().grain).toBe(40);
  store.select("tinted");
  store.reset("tinted");
  expect(store.selected().grain).toBe(0);
  expect(store.changed("tinted")).toBe(false);
});

test("a saved list comes back as it was, and Reset still goes to the starting point the themes were made from", () => {
  const store = createThemeStore(basics);
  store.edit({ tint: 40, colors: "rosepine" });
  const made = store.add();
  store.edit({ name: "Night", grain: 30 });
  const again = createThemeStore({ ...basics, colors: "latte" }, JSON.parse(JSON.stringify(store.snapshot())));
  expect(again.themes()).toEqual(store.themes());
  expect(again.selectedId()).toBe(made.id);
  // The saved starting point wins over today's: "changed" is measured against what Tinted started as, so it is still changed.
  expect(again.changed("tinted")).toBe(true);
  again.reset("tinted");
  expect(again.themes().find((t) => t.id === "tinted")!.colors).toBe("mocha");
});

/** A remote account look supplies both the theme list and the built-in Reset baseline on every device. */
test("loading an account look replaces device basics and uses them for Reset", () => {
  const accountBasics = { colors: "latte", font: "maple-mono-nf", uiSize: 100 };
  const deviceBasics = { colors: "mocha", font: "geist-mono", uiSize: 125 };
  const saved = createThemeStore(accountBasics).snapshot();
  const store = createThemeStore(deviceBasics);

  expect(store.load(saved)).toBe(true);
  expect(store.snapshot().basics).toEqual(accountBasics);
  expect(store.changed("tinted")).toBe(false);
  store.select("tinted");
  store.edit({ tint: 60 });
  store.reset("tinted");
  expect(store.selected()).toMatchObject(accountBasics);
  expect(store.changed("tinted")).toBe(false);
});

test("a damaged saved list is mended, never trusted: numbers are clamped, unknown things fall back, built-in themes come back", () => {
  expect(restore(null)).toBeUndefined();
  expect(restore({ v: 2, basics, themes: [] })).toBeUndefined();
  const r = restore({
    v: 1, selected: "nope", basics: { colors: "nope", font: "nope", uiSize: 900 },
    themes: [
      { id: "tinted", name: "Hacked", tint: 400, blur: -5, grain: "x", font: "nope", colors: "nope", uiSize: 10, background: "nope", customSolid: "red", custom: { stops: ["#fff", "#112233"], angle: 999 } },
      { id: "custom-7", name: "  ", tint: 20.4 },
      { id: "custom-7", name: "twice" },
      { id: 5 },
    ],
  })!;
  expect(r.basics).toEqual({ colors: "mocha", font: "maple-mono-nf", uiSize: 150 });
  expect(r.selected).toBe("tinted");
  expect(r.themes.map((t) => t.id)).toEqual(["solid", "tinted", "frosted", "custom-7"]);
  const tinted = r.themes.find((t) => t.id === "tinted")!;
  expect(tinted).toMatchObject({ name: "Tinted", tint: 100, blur: 0, grain: 0, font: "maple-mono-nf", colors: "mocha", uiSize: 50, background: "aurora", customSolid: "#3b4252" });
  expect(tinted.custom).toEqual({ stops: ["#7a9cff", "#cba6f7"], angle: 360 }); // one bad stop leaves one: the default pair is used
  expect(r.themes.find((t) => t.id === "custom-7")).toMatchObject({ name: "Theme", tint: 20 });
});

test("prototype-named Colours are treated as unknown saved ids", () => {
  for (const id of ["toString", "__proto__", "constructor"]) {
    const saved = createThemeStore(basics).snapshot();
    saved.basics.colors = id;
    saved.themes.find((theme) => theme.id === "tinted")!.colors = id;
    const restored = restore(saved)!;
    expect(restored.basics.colors, `basics ${id}`).toBe("mocha");
    expect(restored.themes.find((theme) => theme.id === "tinted")!.colors, `theme ${id}`).toBe("mocha");
  }
});

test("removing a theme the person made keeps the built-in ones and falls back to Tinted when it was selected", () => {
  const store = createThemeStore(basics);
  const made = store.add();
  store.remove("solid");
  expect(store.themes()).toHaveLength(4);
  store.remove(made.id);
  expect(store.themes().map((t) => t.id)).toEqual(["solid", "tinted", "frosted"]);
  expect(store.selectedId()).toBe("tinted");
  // The next made theme does not reuse a number that is in use.
  expect(store.add().id).toBe("custom-1");
});
