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
 * (no text colour is safe there, only more tint). Fills that a surface paints under its own labels (hover, pressed,
 * selected) are part of the colour under the text, so the model takes them as stacks of layers.
 *
 * What it decides ({@link solveGlass}). The level's own opacity is the owner's approved value and is kept whenever some
 * text colour can reach the line at it: each role then moves in OKLab lightness only (hue and chroma kept), away from the
 * tint, as far as it must. Opacity is raised, in 1% steps, only for a theme and level where no text colour can, and never
 * past {@link GLASS_CEILING} (D160, D375). {@link ANY_BACKDROP} (pure black to pure white) is the static floor for a
 * picture the theme knows nothing about: there text keeps a limited move (so fg, fg2 and fg3 stay distinct), and the tint
 * may not drift far from its own lightness over the opposite extreme, so a light theme over a dark picture is a pale
 * card and not a grey slab.
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

/** The static floor's range: whatever is behind the card, from pure black to pure white. */
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

/** One layer a surface paints over the glass under its labels: a colour at an opacity (`--hover` is the text colour at 6%). */
export interface GlassFill { rgb: Rgb; alpha: number }

/**
 * The states that put a fill under a label, each a stack of layers painted in order: a hovered row, a pressed one, a
 * selected one and the two on top of each other. A fill moves the colour under the text toward its own, which only costs
 * contrast when it is the text's own side, so the audit takes the worst stack.
 */
export type GlassFills = readonly (readonly GlassFill[])[];

/** The colour under text: `tint` at `alpha` over `backdrop`, then the layers of one fill stack in order. */
export function surfaceOver(tint: Rgb, alpha: number, backdrop: Rgb, stack: readonly GlassFill[] = []): Rgb {
  let under = composite(tint, alpha, backdrop);
  for (const layer of stack) under = composite(under, 1 - layer.alpha, layer.rgb);
  return under;
}

/**
 * The lowest contrast `text` reaches on `tint` at `alpha` over any backdrop in `range`, in any state of `fills` (and with
 * none). Exact, not sampled: for each stack the glass's luminance runs from its value over `range.dark` to its value over
 * `range.light`; if the text's luminance is inside that stretch some backdrop makes the text vanish (1), otherwise the
 * worse end decides.
 */
export function worstRatio(text: string, tint: Rgb, alpha: number, range: BackdropRange, fills: GlassFills = []): number {
  const t = luminanceOf(hexToRgb(text));
  let worst = Infinity;
  for (const stack of [[], ...fills]) {
    const lo = luminanceOf(surfaceOver(tint, alpha, range.dark, stack));
    const hi = luminanceOf(surfaceOver(tint, alpha, range.light, stack));
    worst = Math.min(worst, t >= lo && t <= hi ? 1 : Math.min(ratioOf(t, lo), ratioOf(t, hi)));
  }
  return worst;
}

/** One text colour on glass: its role name (for reports), its colour and the line it must reach. */
export interface GlassRole { role: string; colour: string; need?: number }

/** The answer for one theme and one level. */
export interface GlassSolution {
  /** The tint's opacity: the level's own unless `raised`. */
  alpha: number;
  /** Role name to the colour to use on this glass (the original when it already passes). */
  colours: Record<string, string>;
  /** Whether every role reaches its line over the whole range. False only if even the ceiling opacity cannot. */
  ok: boolean;
  /** True when the opacity had to go above the level's own because no text colour could reach the line at it. */
  raised: boolean;
}

/**
 * Moves `colour` in OKLab lightness, away from the surface, to the first value that reaches `need` over `range`, or
 * returns `undefined` when lightness alone cannot (the colour would pass white or black) or the move would exceed
 * `maxShift`. Hue and chroma stay, so a danger label is still red.
 */
function nudge(colour: string, lighter: boolean, need: number, tint: Rgb, alpha: number, range: BackdropRange, maxShift: number, fills: GlassFills): string | undefined {
  if (worstRatio(colour, tint, alpha, range, fills) >= need) return colour;
  const [l0, a, b] = hexToOklab(colour);
  const at = (shift: number): string => oklabToHex([Math.min(1, Math.max(0, l0 + (lighter ? shift : -shift))), a, b]);
  // Moving away from the tint only ever helps, so the least sufficient move is found by halving; the end is the nearest of white and black.
  const far = Math.min(maxShift, lighter ? 1 - l0 : l0);
  if (far <= 0 || worstRatio(at(far), tint, alpha, range, fills) < need) return undefined;
  let lo = 0, hi = far;
  for (let i = 0; i < 9; i++) { const mid = (lo + hi) / 2; if (worstRatio(at(mid), tint, alpha, range, fills) >= need) hi = mid; else lo = mid; }
  return at(hi);
}

/** The biggest lightness move a text colour may take on the static floor before tint is raised instead; keeps fg, fg2 and fg3 distinct. */
export const MAX_SHIFT = 0.15;

/**
 * The most opaque a glass level may be made to reach a line (D160, D375: an overlay is never opaque unless the person
 * chose Solid). Past this the text colours take the rest of the work, whatever it costs the hierarchy between them.
 */
export const GLASS_CEILING = 0.92;

/** How far (OKLab lightness) the glass may drift from its own tint over the far end of the range on the static floor. */
export const MAX_DRIFT = 0.1;

/** What {@link solveGlass} may vary and what it must hold. */
export interface SolveOptions {
  /** The backdrops to hold over. Default {@link ANY_BACKDROP}. */
  range?: BackdropRange;
  /** The fill states under labels to hold in. Default none. */
  fills?: GlassFills;
  /** The most a text colour may move before tint is raised instead (OKLab lightness). Default 1, which is as far as it can go. */
  maxShift?: number;
  /** If set, the tint's opacity starts high enough that over either end of `range` its lightness is within this of the tint's own. */
  maxDrift?: number;
}

/**
 * The answer for one tint: starting at `nominal` (the level's own opacity), the first opacity, in 1% steps up to
 * {@link GLASS_CEILING}, at which every role reaches its line over `range` and `fills` with a lightness move of at most
 * `maxShift`; if none does, the ceiling with text moving as far as it must. `lighter` says which way text moves away from
 * the tint: true on dark themes (light text), false on light themes. A `nominal` at or above the ceiling (Solid) is kept.
 */
export function solveGlass(tint: Rgb, nominal: number, lighter: boolean, rolesIn: readonly GlassRole[], opts: SolveOptions = {}): GlassSolution {
  const range = opts.range ?? ANY_BACKDROP, fills = opts.fills ?? [], maxShift = opts.maxShift ?? 1;
  // Stage 0: D365 on the plain page. A colour already below its line on the theme's own surface (the tint at full
  // opacity) is brought to it first, uncapped; the shift cap below then measures only what the glass itself costs.
  const solid: BackdropRange = { dark: tint, light: tint };
  const roles = rolesIn.map((r) => ({ ...r, colour: nudge(r.colour, lighter, (r.need ?? TEXT_LINE) + MARGIN, tint, 1, solid, 1, fills) ?? r.colour }));
  const ceiling = Math.max(nominal, GLASS_CEILING);
  const attempt = (alpha: number, shift: number): GlassSolution | undefined => {
    const colours: Record<string, string> = {};
    for (const { role, colour, need } of roles) {
      const fixed = nudge(colour, lighter, (need ?? TEXT_LINE) + MARGIN, tint, alpha, range, shift, fills);
      if (fixed === undefined) return undefined;
      colours[role] = fixed;
    }
    return { alpha, colours, ok: true, raised: alpha > nominal + 1e-9 };
  };
  const [tintL] = hexToOklab(rgbToHex(tint));
  const drifts = (alpha: number): boolean => [range.dark, range.light].every((end) => Math.abs(hexToOklab(rgbToHex(composite(tint, alpha, end)))[0] - tintL) <= (opts.maxDrift ?? Infinity));
  // More tint only ever helps, so the least sufficient opacity (whole percents) is found by halving.
  const at = (percent: number): GlassSolution | undefined => (drifts(percent / 100) ? attempt(percent / 100, maxShift) : undefined);
  const first = Math.round(nominal * 100), last = Math.round(ceiling * 100);
  if (first < last) {
    let found = at(first);
    if (found) return found;
    let lo = first;   // known not to work
    let hi = last;
    if (at(last) === undefined) hi = -1;
    if (hi > 0) {
      while (hi - lo > 1) { const mid = (lo + hi) >> 1; if (at(mid)) hi = mid; else lo = mid; }
      found = at(hi);
      if (found) return found;
    }
  }
  // The thinnest levels cannot get there by tint alone: stop at the ceiling and let the colours move as far as they need.
  return attempt(ceiling, 1) ?? { alpha: ceiling, colours: Object.fromEntries(roles.map((r) => [r.role, r.colour])), ok: false, raised: ceiling > nominal + 1e-9 };
}
