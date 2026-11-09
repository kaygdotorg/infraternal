// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The glass contrast audit (D365 on translucent surfaces).
 *
 * For every theme and every card level, every text role of the glass reaches 4.5:1 over the worst-case backdrops: pure
 * white, pure black, a grey ramp between them, the theme's own extremes (its background and its text colour), and the
 * theme's own terminal backdrop. The check composites the tint over each backdrop itself (`composite`, then WCAG
 * luminance) and does not call `worstRatio`, so a mistake in the solver's closed form cannot hide from it.
 *
 * Two sets are audited, the two the shipped sheet carries (`themes.ts` `installGlassRules`): the *static* set (anything
 * can be behind the card, so every backdrop above) and the *themed* set (the backdrop is the theme's own, so the
 * theme's extremes and the terminal range). A regression in a theme's colours, a level's opacity or the solver fails
 * here before it reaches a screen.
 */
import { describe, expect, test } from "bun:test";
import { ANY_BACKDROP, GLASS_CEILING, composite, hexToRgb, luminanceOf, ratioOf, worstRatio, type Rgb } from "./glass-contrast";
import { CARD_LEVELS, THEMES, glassFor, glassRoles, glassTint, levelName, levelOpacity, themedBackdrop } from "./themes";

const LINE = 4.5;
const grey = (v: number): Rgb => [v, v, v];
/** Black, white and a 16-step grey ramp: the backdrops that decide a luminance-monotone material. */
const RAMP: Rgb[] = [0, ...Array.from({ length: 16 }, (_, i) => (i + 1) * 16 - 1)].map(grey);

/** Lowest contrast of `text` on the tint at `alpha` over each backdrop, with the backdrop that gave it. */
function lowest(text: string, tint: Rgb, alpha: number, backdrops: readonly Rgb[]): { ratio: number; at: Rgb } {
  let out = { ratio: Infinity, at: backdrops[0]! };
  for (const at of backdrops) {
    const ratio = ratioOf(luminanceOf(hexToRgb(text)), luminanceOf(composite(tint, alpha, at)));
    if (ratio < out.ratio) out = { ratio, at };
  }
  return out;
}

const LEVELS = Object.keys(CARD_LEVELS).map(Number);

describe("glass text reaches 4.5:1 over worst-case backdrops (D365)", () => {
  for (const [id, theme] of Object.entries(THEMES)) {
    const tint = hexToRgb(glassTint(theme));
    const extremes = [hexToRgb(theme.bg), hexToRgb(theme.fg)];
    const range = themedBackdrop(theme);
    for (const level of LEVELS) {
      const label = `${id} / ${levelName(level)}`;
      test(`${label}: static set over white, black, the grey ramp and the theme's extremes`, () => {
        const sol = glassFor(theme, level, ANY_BACKDROP);
        expect(sol.ok).toBe(true);
        for (const { role } of glassRoles(theme)) {
          const got = lowest(sol.colours[role]!, tint, sol.alpha, [...RAMP, ...extremes]);
          expect(got.ratio, `${label} ${role} ${sol.colours[role]} at alpha ${sol.alpha} over rgb(${got.at})`).toBeGreaterThanOrEqual(LINE);
        }
      });
      test(`${label}: themed set over the theme's terminal backdrop (its background up to a third toward its text)`, () => {
        const sol = glassFor(theme, level);
        expect(sol.ok).toBe(true);
        const sweep = Array.from({ length: 9 }, (_, i) => composite(range.dark, i / 8, range.light) as Rgb);
        for (const { role } of glassRoles(theme)) {
          const got = lowest(sol.colours[role]!, tint, sol.alpha, sweep);
          expect(got.ratio, `${label} ${role} ${sol.colours[role]} at alpha ${sol.alpha} over rgb(${got.at})`).toBeGreaterThanOrEqual(LINE);
        }
      });
      test(`${label}: opacity stays at or above the level's own and below opaque (D160, D375)`, () => {
        for (const range of [ANY_BACKDROP, themedBackdrop(theme)]) {
          const sol = glassFor(theme, level, range);
          expect(sol.alpha).toBeGreaterThanOrEqual(levelOpacity(theme, level));
          expect(sol.alpha).toBeLessThanOrEqual(Math.max(levelOpacity(theme, level), GLASS_CEILING));
        }
      });
    }
  }

  test("the check bites: today's unadjusted Paper Tinted label colour is under the line over black", () => {
    const paper = THEMES.paper!;
    const tint = hexToRgb(glassTint(paper));
    expect(lowest(paper.fg3, tint, levelOpacity(paper, 2), [grey(0)]).ratio).toBeLessThan(LINE);
    expect(worstRatio(paper.fg3, tint, levelOpacity(paper, 2), ANY_BACKDROP)).toBeLessThan(LINE);
  });

  test("a narrower, darker backdrop asks for less tint than the static floor (dark keeps its lightness)", () => {
    const ink = THEMES.ink!;
    const dark = glassFor(ink, 4, { dark: grey(0), light: grey(40) });
    expect(dark.alpha).toBeLessThan(glassFor(ink, 4, ANY_BACKDROP).alpha);
  });
});
