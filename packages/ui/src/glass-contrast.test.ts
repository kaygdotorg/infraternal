// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The glass contrast audit (D365 on translucent surfaces).
 *
 * Two sets ship, and both are audited here for every theme and every card level, against the same fill states the
 * stylesheet really paints under labels (hover, chip, selected, selected and hovered). The check composites the tint over
 * each backdrop and fill itself (`composite`, then WCAG luminance) and does not call `worstRatio`, so a mistake in the
 * solver's closed form cannot hide from it.
 *
 * - The *static floor* (a picture the theme knows nothing about): every role reaches 4.5:1 over pure white, pure black, a
 *   grey ramp and the theme's extremes.
 * - The *themed set* (the theme's own terminal and canvas): every role reaches 4.5:1 over a block of any colour the
 *   terminal can paint, from its 16 ANSI colours to its text and background colours, covering up to
 *   `THEMED_COVERAGE` of the card, and at every coverage below that. The owner's opacities are kept except for the pairs
 *   listed in `RAISED`, where no text colour can reach the line at the approved value.
 */
import { describe, expect, test } from "bun:test";
import { ADAPT_LIMIT, ANY_BACKDROP, GLASS_CEILING, MAX_DRIFT, composite, hexToRgb, luminanceOf, ratioOf, surfaceOver, type GlassFills, type Rgb } from "./glass-contrast";
import { hexToOklab } from "./color";
import { THEMED_COVERAGE, glassFills, glassFloor, glassFor, glassRoles, glassSeen, themedBackdrop } from "./glass-rules.on-demand";
import { CARD_LEVELS, THEMES, glassTint, levelName, levelOpacity } from "./themes";
import { SOLID_HYSTERESIS, solveFor } from "./glass-adapt.on-demand";

/** The line every text role must reach (D365). */
const LINE = 4.5;
/** A grey of equal channels. */
const grey = (v: number): Rgb => [v, v, v];
/** Black, white and a 16-step grey ramp: the backdrops that decide a luminance-monotone material. */
const RAMP: Rgb[] = [0, ...Array.from({ length: 16 }, (_, i) => (i + 1) * 16 - 1)].map(grey);
/** Every card level, Solid to Frosted. */
const LEVELS = Object.keys(CARD_LEVELS).map(Number);

/**
 * The theme and level pairs whose approved opacity had to be raised, because no text colour reaches 4.5:1 at the approved
 * value over a bright block at the coverage bound. Each is listed on #448 with its numbers; a new entry needs the same.
 */
const RAISED = new Set(["dracula/Frosted"]);

/** Lowest contrast of `text` on the tint at `alpha` over each backdrop, in every fill state and with none. */
function lowest(text: string, tint: Rgb, alpha: number, backdrops: readonly Rgb[], fills: GlassFills): { ratio: number; at: Rgb } {
  let out = { ratio: Infinity, at: backdrops[0]! };
  for (const at of backdrops) for (const stack of [[], ...fills]) {
    const ratio = ratioOf(luminanceOf(hexToRgb(text)), luminanceOf(surfaceOver(tint, alpha, at, stack)));
    if (ratio < out.ratio) out = { ratio, at };
  }
  return out;
}

/** Every backdrop a block of one terminal colour can make at every coverage up to `coverage` (steps of 5%). */
function blocks(theme: (typeof THEMES)[string], coverage: number): Rgb[] {
  const bg = hexToRgb(theme.bg), out: Rgb[] = [bg];
  for (const colour of [theme.fg, ...theme.ansi, ...theme.bright]) for (let c = 0.05; c <= coverage + 1e-9; c += 0.05) out.push(composite(bg, 1 - c, hexToRgb(colour)));
  return out;
}

describe("glass text reaches 4.5:1 over worst-case backdrops (D365)", () => {
  for (const [id, theme] of Object.entries(THEMES)) {
    const tint = hexToRgb(glassTint(theme));
    const fills = glassFills(theme);
    const extremes = [hexToRgb(theme.bg), hexToRgb(theme.fg)];
    for (const level of LEVELS) {
      const label = `${id} / ${levelName(level)}`;
      test(`${label}: static floor over white, black, the grey ramp and the theme's extremes`, () => {
        const sol = glassFloor(theme, level);
        expect(sol.ok).toBe(true);
        for (const { role } of glassRoles(theme)) {
          const got = lowest(sol.colours[role]!, tint, sol.alpha, [...RAMP, ...extremes], fills);
          expect(got.ratio, `${label} ${role} ${sol.colours[role]} at alpha ${sol.alpha} over rgb(${got.at})`).toBeGreaterThanOrEqual(LINE);
        }
        // Glass stays within the adaptive limit; anything beyond is the solid card (opaque, with the theme's own text colours).
        if (sol.solid) expect(sol.alpha).toBe(1); else expect(sol.alpha).toBeLessThanOrEqual(Math.max(levelOpacity(theme, level), ADAPT_LIMIT));
      });
      test(`${label}: static floor keeps the tint's lightness over either extreme (no grey slab)`, () => {
        const sol = glassFloor(theme, level);
        const [tintL] = hexToOklab(glassTint(theme));
        for (const end of [grey(0), grey(255)]) {
          const [l] = hexToOklab(`#${composite(tint, sol.alpha, end).map((c) => Math.round(c).toString(16).padStart(2, "0")).join("")}`);
          expect(Math.abs(l - tintL)).toBeLessThanOrEqual(MAX_DRIFT + 0.005);
        }
      });
      test(`${label}: themed set over a block of any terminal colour up to ${THEMED_COVERAGE * 100}% of the card, in every fill state`, () => {
        const sol = glassFor(theme, level);
        expect(sol.ok).toBe(true);
        for (const { role } of glassRoles(theme)) {
          const got = lowest(sol.colours[role]!, tint, sol.alpha, blocks(theme, THEMED_COVERAGE), fills);
          expect(got.ratio, `${label} ${role} ${sol.colours[role]} at alpha ${sol.alpha} over rgb(${got.at})`).toBeGreaterThanOrEqual(LINE);
        }
      });
      test(`${label}: the approved opacity is kept unless listed in RAISED`, () => {
        const sol = glassFor(theme, level);
        const raised = sol.alpha > levelOpacity(theme, level) + 1e-9;
        expect(raised, `${label} opacity ${levelOpacity(theme, level)} -> ${sol.alpha}`).toBe(RAISED.has(label.replace(" / ", "/")));
        expect(sol.alpha).toBeLessThanOrEqual(Math.max(levelOpacity(theme, level), GLASS_CEILING));
      });
    }
    test(`${id}: Tinted, Clear and Frosted stay three different opacities, thickest first`, () => {
      const [tinted, clear, frosted] = [2, 3, 4].map((level) => glassFor(theme, level).alpha);
      expect(tinted).toBeGreaterThan(clear!);
      expect(clear).toBeGreaterThan(frosted!);
    });
  }

  test("the check bites: today's unadjusted Paper Tinted label colour is under the line over black", () => {
    const paper = THEMES.paper!;
    expect(lowest(paper.fg3, hexToRgb(glassTint(paper)), levelOpacity(paper, 2), [grey(0)], []).ratio).toBeLessThan(LINE);
  });

  test("the coverage bound is an assumption, and over a whole screen of a bright colour the approved Frosted fails", () => {
    const ink = THEMES.ink!;
    const sol = glassFor(ink, 4, themedBackdrop(ink, THEMED_COVERAGE));
    const bright = blocks(ink, 1);
    const worst = Math.min(...glassRoles(ink).map(({ role }) => lowest(sol.colours[role]!, hexToRgb(glassTint(ink)), sol.alpha, bright, glassFills(ink)).ratio));
    expect(worst).toBeLessThan(LINE);
  });

  test("a narrower, darker backdrop asks for less tint than the static floor (dark keeps its lightness)", () => {
    const ink = THEMES.ink!;
    expect(glassFor(ink, 4, { dark: grey(0), light: grey(40) }).alpha).toBeLessThan(glassFloor(ink, 4).alpha);
    expect(ANY_BACKDROP.light[0]).toBe(255);
  });
});

/**
 * The solid fallback (#448, D365, 2026-11-20). Over a hard backdrop (a light theme over black, a dark theme over white) glass
 * cannot hold 4.5:1 without a flat grey slab or a glow behind the text, so the card turns solid: opaque tint, the theme's own
 * text colours, no blur. Over a moderate backdrop it stays glass, and it never needs a glow (there is none).
 */
describe("a card that cannot stay readable turns solid, never grey and never glowing", () => {
  const darkPicture = { dark: grey(0), light: grey(0) }, lightPicture = { dark: grey(255), light: grey(255) };
  for (const [id, theme] of Object.entries(THEMES)) {
    const over = theme.dark ? lightPicture : darkPicture;
    for (const level of [2, 3, 4]) test(`${id} / ${levelName(level)}: over a ${theme.dark ? "white" : "black"} picture the card is solid and every role reaches ${LINE}:1 on it`, () => {
      const sol = glassSeen(theme, level, over);
      expect(sol.solid).toBe(true);
      expect(sol.alpha).toBe(1);
      const tint = hexToRgb(glassTint(theme));
      for (const { role } of glassRoles(theme)) {
        const got = lowest(sol.colours[role]!, tint, 1, [grey(0), grey(255)], glassFills(theme));
        expect(got.ratio, `${id} ${role} ${sol.colours[role]}`).toBeGreaterThanOrEqual(LINE);
      }
    });
    test(`${id}: over a picture of its own kind the card stays glass at the approved opacity`, () => {
      const same = theme.dark ? darkPicture : lightPicture;
      const sol = glassSeen(theme, 3, same);
      expect(sol.solid).toBe(false);
      expect(sol.alpha).toBeLessThanOrEqual(ADAPT_LIMIT);
    });
  }

  test("going solid has hysteresis: a card that was solid needs a clearly easier backdrop to return to glass", () => {
    const paper = THEMES.paper!;
    // Find a backdrop level where glass just holds, then check that a solid card does not return there but does well inside it.
    let edge = 0;
    for (let v = 0; v <= 255; v++) if (!glassSeen(paper, 3, { dark: grey(v), light: grey(v) }).solid) { edge = v; break; }
    expect(edge).toBeGreaterThan(0);
    expect(solveFor(paper, 3, { dark: grey(edge), light: grey(edge) }, false).solid).toBe(false);
    expect(solveFor(paper, 3, { dark: grey(edge), light: grey(edge) }, true).solid).toBe(true);
    expect(solveFor(paper, 3, { dark: grey(Math.min(255, edge + 2 * SOLID_HYSTERESIS)), light: grey(Math.min(255, edge + 2 * SOLID_HYSTERESIS)) }, true).solid).toBe(false);
  });
});
