// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The Colour list of the Appearance themes (D329, D338, #323). Pure.
 *
 * A scheme that has both a light and a dark version is ONE row with two small circles, the light version's and the dark version's, and
 * the person clicks the one they want: that is how a person chooses light or dark (owner: "instead of light/dark, just show the
 * light/dark colours in two circles and the user can select any one"). A scheme with one version has one circle. A theme (the whole look: Colour,
 * backgrounds, windows, font) therefore stores the Colour's version (a colour-scheme id of `packages/ui/src/themes.ts`), not the row: "if dark show dark cards, if light then show light
 * cards" (D322 round 2) holds because the theme *is* one or the other.
 *
 * The pairs: Catppuccin Latte and Mocha, Rose Pine Dawn and Rose Pine, Paper and Ink (the two monochrome schemes; that they are a pair is a
 * reading to be confirmed on #323), and D329's schemes that come in both versions (Gruvbox, Tokyo Night, Solarized, Everforest, Kanagawa Lotus
 * and Wave, Ayu, GitHub, Flexoki, Light Owl and Night Owl). Catppuccin Frappé and Macchiato are dark only and are rows of their own.
 */
import { THEMES } from "../../../../../packages/ui/src/themes";

export interface Family {
  id: string;
  name: string;
  /** Theme ids of the two versions; one is absent for a scheme that has only one. */
  light?: string;
  dark?: string;
}

const PAIRS: ReadonlyArray<{ id: string; name: string; light: string; dark: string }> = [
  { id: "catppuccin", name: "Catppuccin", light: "latte", dark: "mocha" },
  { id: "rosepine", name: "Rosé Pine", light: "dawn", dark: "rosepine" },
  { id: "ink-paper", name: "Ink and Paper", light: "paper", dark: "ink" },
  { id: "gruvbox", name: "Gruvbox", light: "gruvbox-light", dark: "gruvbox" },
  { id: "tokyo", name: "Tokyo Night", light: "tokyo-day", dark: "tokyo" },
  { id: "solarized", name: "Solarized", light: "solarized-light", dark: "solarized-dark" },
  { id: "everforest", name: "Everforest", light: "everforest-light", dark: "everforest-dark" },
  { id: "kanagawa", name: "Kanagawa", light: "kanagawa-lotus", dark: "kanagawa-wave" },
  { id: "ayu", name: "Ayu", light: "ayu-light", dark: "ayu-dark" },
  { id: "github", name: "GitHub", light: "github-light", dark: "github-dark" },
  { id: "flexoki", name: "Flexoki", light: "flexoki-light", dark: "flexoki-dark" },
  { id: "owl", name: "Night Owl", light: "owl-light", dark: "owl-night" },
];

/** The rows in the order of the product's own list, a pair at the place of its first version. */
export const FAMILIES: readonly Family[] = (() => {
  const out: Family[] = [], done = new Set<string>();
  for (const [id, theme] of Object.entries(THEMES)) {
    const pair = PAIRS.find((p) => p.light === id || p.dark === id);
    if (pair) { if (!done.has(pair.id)) { done.add(pair.id); out.push({ ...pair }); } continue; }
    out.push({ id, name: theme.name, ...(theme.dark ? { dark: id } : { light: id }) });
  }
  return out;
})();

/** The row a theme belongs to. */
export const familyOf = (themeId: string): Family => FAMILIES.find((f) => f.light === themeId || f.dark === themeId) ?? FAMILIES[0]!;
export const hasBoth = (f: Family): boolean => Boolean(f.light && f.dark);
/** The version a click on a scheme's name picks: the one in the mode the person is in now, or the only one the scheme has. */
export const versionIn = (f: Family, dark: boolean): string => ((dark ? f.dark ?? f.light : f.light ?? f.dark))!;
