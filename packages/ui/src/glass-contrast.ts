// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Contrast of text on glass (D365: 4.5:1 for all text), worked out ahead of time.
 *
 * The problem. A glass card is a tint at some opacity over whatever lies behind it, so the colour under its text is not
 * known when the theme is written: the same Send keys list sits over a dark terminal, a bright photo or a light app
 * window. A hint that reads well on one of them can be faint grey on light grey on another.
 *
 * What this module does. It treats the backdrop as a range (a darkest and a lightest colour it can have) and answers one
 * question exactly: what is the lowest contrast a text colour reaches on the glass anywhere in that range? The colour
 * under the text is the tint mixed over the backdrop, and its luminance only grows with the backdrop's, so the lowest
 * contrast is at one end of the range, or is 1:1 when the text's own luminance falls inside what the glass can look like
 * (no text colour is safe there, only more tint). {@link solveGlass} then finds the least tint density, and the smallest
 * nudge to each text colour (OKLab lightness only, hue and chroma kept), that bring every role to its line over the whole
 * range. {@link ANY_BACKDROP} (pure black to pure white) is the static guarantee: it holds whatever is behind the card.
 * A narrower range, such as a terminal's own background, asks for less tint, so a dark backdrop keeps its lightness.
 *
 * Everything here is pure arithmetic on `#rrggbb` strings. It runs when a theme is applied (`themes.ts`) and when a
 * backdrop is sampled (`glass-adapt.ts`), never per frame. The audit test (`glass-contrast.test.ts`) calls the same
 * functions, so the guarantee and the shipped values cannot drift apart.
 */
import { hexToOklab, oklabToHex } from "./color";

/** A colour as three 0 to 255 channels. */
export type Rgb = readonly [number, number, number];

/** The darkest and the lightest colour a backdrop can have, channel by channel. */
export interface BackdropRange { dark: Rgb; light: Rgb }

/** The static guarantee's range: whatever is behind the card, from pure black to pure white. */
export const ANY_BACKDROP: BackdropRange = { dark: [0, 0, 0], light: [255, 255, 255] };

/** The WCAG line for text that is not primary (D365). */
export const TEXT_LINE = 4.5;
/** The margin added to a line so eight-bit rounding cannot drop a colour back under it. */
const MARGIN = 0.02;

/** Splits `#rrggbb` into channels. */
export const hexToRgb = (hex: string): Rgb => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)) as unknown as Rgb;
/** Joins channels (rounded and clamped) into `#rrggbb`. */
export const rgbToHex = (rgb: Rgb): string => `#${rgb.map((c) => Math.round(Math.min(255, Math.max(0, c))).toString(16).padStart(2, "0")).join("")}`;

/** Relative luminance (WCAG 2) of channels. */
export function luminanceOf(rgb: Rgb): number {
  const lin = (c: number): number => { const v = c / 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
  return 0.2126 * lin(rgb[0]) + 0.7152 * lin(rgb[1]) + 0.0722 * lin(rgb[2]);
}

/** The WCAG contrast of two luminances. */
export const ratioOf = (a: number, b: number): number => (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);

/** `tint` painted at `alpha` over `backdrop`, the way the browser composites a translucent fill (in sRGB, like CSS). */
export const composite = (tint: Rgb, alpha: number, backdrop: Rgb): Rgb =>
  [0, 1, 2].map((i) => tint[i]! * alpha + backdrop[i]! * (1 - alpha)) as unknown as Rgb;

/**
 * The lowest contrast `text` reaches on `tint` at `alpha` over any backdrop in `range`. Exact, not sampled: the glass's
 * luminance runs from its value over `range.dark` to its value over `range.light`; if the text's luminance is inside
 * that stretch some backdrop makes the text vanish (returns 1), otherwise the worse end decides.
 */
export function worstRatio(text: string, tint: Rgb, alpha: number, range: BackdropRange): number {
  const lo = luminanceOf(composite(tint, alpha, range.dark));
  const hi = luminanceOf(composite(tint, alpha, range.light));
  const t = luminanceOf(hexToRgb(text));
  if (t >= lo && t <= hi) return 1;
  return Math.min(ratioOf(t, lo), ratioOf(t, hi));
}

/** One text colour on glass: its role name (for reports), its colour and the line it must reach. */
export interface GlassRole { role: string; colour: string; need?: number }

/** The answer for one theme and one level: the opacity to paint and the colour each role should use on the glass. */
export interface GlassSolution {
  /** The tint's opacity, never below the level's own. */
  alpha: number;
  /** Role name to the colour to use on this glass (the original when it already passes). */
  colours: Record<string, string>;
  /** Whether every role reaches its line over the whole range. False only if even a fully opaque tint cannot. */
  ok: boolean;
}

/**
 * Moves `colour` in OKLab lightness, away from the surface, to the first value that reaches `need` over `range`, or
 * returns `undefined` when lightness alone cannot (the colour would pass white or black) or the move would exceed
 * `maxShift`. Hue and chroma stay, so a danger label is still red.
 */
function nudge(colour: string, lighter: boolean, need: number, tint: Rgb, alpha: number, range: BackdropRange, maxShift: number): string | undefined {
  if (worstRatio(colour, tint, alpha, range) >= need) return colour;
  const [l0, a, b] = hexToOklab(colour);
  for (let shift = 0.005; shift <= maxShift + 1e-9; shift += 0.005) {
    const l = Math.min(1, Math.max(0, l0 + (lighter ? shift : -shift)));
    const next = oklabToHex([l, a, b]);
    if (worstRatio(next, tint, alpha, range) >= need) return next;
    if (l <= 0 || l >= 1) return undefined;
  }
  return undefined;
}

/** The biggest lightness move a text colour may take before the tint is raised instead; keeps fg, fg2 and fg3 distinct. */
export const MAX_SHIFT = 0.15;

/**
 * The most opaque a glass level may be made to reach a line (D160, D375: an overlay is never opaque unless the person
 * chose Solid). Past this the text colours take the rest of the work, whatever it costs the hierarchy between them.
 */
export const GLASS_CEILING = 0.92;

/**
 * The answer for `range`: starting at `nominal` (the level's own opacity), the first opacity, in 1% steps up to
 * {@link GLASS_CEILING}, at which every role reaches its line over `range` with a lightness move of at most `maxShift`.
 * If none does, the ceiling is used and the colours move as far as they must. `lighter` says which way text moves away
 * from the tint: true on dark themes (light text), false on light themes. A `nominal` at or above the ceiling (Solid)
 * is kept as it is.
 */
export function solveGlass(tint: Rgb, nominal: number, lighter: boolean, rolesIn: readonly GlassRole[], range: BackdropRange = ANY_BACKDROP, maxShift = MAX_SHIFT): GlassSolution {
  // Stage 0: D365 on the plain page. A colour already below its line on the theme's own surface (the tint at full
  // opacity) is brought to it first, uncapped; the shift cap below then measures only what the glass itself costs.
  const solid: BackdropRange = { dark: tint, light: tint };
  const roles = rolesIn.map((r) => ({ ...r, colour: nudge(r.colour, lighter, (r.need ?? TEXT_LINE) + MARGIN, tint, 1, solid, 1) ?? r.colour }));
  const ceiling = Math.max(nominal, GLASS_CEILING);
  const attempt = (alpha: number, shift: number): GlassSolution | undefined => {
    const colours: Record<string, string> = {};
    for (const { role, colour, need } of roles) {
      const fixed = nudge(colour, lighter, (need ?? TEXT_LINE) + MARGIN, tint, alpha, range, shift);
      if (fixed === undefined) return undefined;
      colours[role] = fixed;
    }
    return { alpha, colours, ok: true };
  };
  for (let alpha = nominal; alpha < ceiling - 1e-9; alpha = Math.round((alpha + 0.01) * 100) / 100) {
    const found = attempt(alpha, maxShift);
    if (found) return found;
  }
  // The thinnest levels cannot get there by tint alone: stop at the ceiling and let the colours move as far as they need.
  return attempt(ceiling, 1) ?? { alpha: ceiling, colours: Object.fromEntries(roles.map((r) => [r.role, r.colour])), ok: false };
}
