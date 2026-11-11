// SPDX-License-Identifier: AGPL-3.0-only
/** The Colour list of D338: one row for a scheme with a light and a dark version, with a circle for each; a one-version scheme has one. */
import { expect, test } from "bun:test";
import { THEMES } from "../../../../../packages/ui/src/themes";
import { FAMILIES, familyOf, hasBoth, versionIn } from "./colors";

test("a scheme with a light and a dark version is one row; the others stay as they are", () => {
  expect(FAMILIES.filter(hasBoth).map((f) => [f.name, f.light, f.dark])).toEqual([
    ["Ink and Paper", "paper", "ink"], ["Catppuccin", "latte", "mocha"], ["Rosé Pine", "dawn", "rosepine"], ["Tokyo Night", "tokyo-day", "tokyo"], ["Gruvbox", "gruvbox-light", "gruvbox"],
    ["Solarized", "solarized-light", "solarized-dark"], ["Everforest", "everforest-light", "everforest-dark"], ["Kanagawa", "kanagawa-lotus", "kanagawa-wave"],
    ["Ayu", "ayu-light", "ayu-dark"], ["GitHub", "github-light", "github-dark"], ["Flexoki", "flexoki-light", "flexoki-dark"], ["Night Owl", "owl-light", "owl-night"],
  ]);
  // The ones with one version only: Nord and Dracula (dark), and Catppuccin's Frappé and Macchiato (dark, beside the Catppuccin row).
  expect(FAMILIES.filter((f) => !hasBoth(f)).map((f) => f.name)).toEqual(["Nord", "Dracula", "Catppuccin Frappé", "Catppuccin Macchiato"]);
  // Every theme of the product is in exactly one row, nothing is lost and nothing is listed twice.
  expect(FAMILIES.flatMap((f) => [f.light, f.dark]).filter(Boolean).sort()).toEqual(Object.keys(THEMES).sort());
  // A one-version scheme has one circle: the light or the dark one that it has, never both.
  for (const f of FAMILIES.filter((x) => !hasBoth(x))) expect([f.light, f.dark].filter(Boolean)).toHaveLength(1);
  // The light circle of a row is a light scheme and the dark circle a dark one.
  for (const f of FAMILIES) { if (f.light) expect(THEMES[f.light]!.dark, f.name).toBe(false); if (f.dark) expect(THEMES[f.dark]!.dark, f.name).toBe(true); }
});

test("each theme belongs to its row, and a click on a name picks the version in the mode the person is in", () => {
  expect(familyOf("latte").id).toBe("catppuccin");
  expect(familyOf("mocha").id).toBe("catppuccin");
  expect(familyOf("dracula").id).toBe("dracula");
  const cat = familyOf("mocha");
  expect(versionIn(cat, true)).toBe("mocha");
  expect(versionIn(cat, false)).toBe("latte");
  expect(versionIn(familyOf("nord"), false)).toBe("nord"); // one version: that one in either mode
  expect(versionIn(familyOf("tokyo"), false)).toBe("tokyo-day");
});
