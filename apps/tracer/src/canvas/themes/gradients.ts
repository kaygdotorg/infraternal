// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The backgrounds a theme can have (D322 round 2, D338, #323): gradients and solid colours. Pure: a Colour scheme in, CSS images out.
 *
 * Every scheme gets the same nine recipes, recoloured from its own palette in OKLab, so a gradient called "Aurora" is the scheme's
 * accent, cyan and magenta on Catppuccin Mocha and the same three on Paper, never a fixed picture that clashes with a scheme. Each
 * colour is moved to a lightness just off the scheme's background (a glow on a dark scheme, a wash on a light one) with its hue kept,
 * the way `packages/ui/src/backdrop.ts` tones the product's mesh, so text over the gradient keeps its contrast and a person's first
 * gradient is never garish. A gradient is layered radial blobs over the scheme's background, which is a mesh gradient in plain CSS:
 * no library, no script at paint time, and nothing to release. The person's own gradient is stops and an angle, interpolated in OKLab.
 *
 * Why not the product's WebGL painter (`paintMesh`): it renders one fixed recipe per scheme to a still image, which is what the
 * Gradient background is today. A theme's background must be cheap to draw on a card for every theme at once and to change while a
 * colour is being dragged, so a theme draws CSS. Teaching the WebGL painter more recipes instead, or using a library, would be a foundation choice for the owner (#323).
 */
import { hexToOklab, oklabToHex } from "../../../../../packages/ui/src/color";
import type { Theme } from "../../../../../packages/ui/src/themes";
import { CUSTOM_ID, DEFAULT_CUSTOM, DEFAULT_CUSTOM_SOLID, MIN_STOPS, SOLID_CUSTOM_ID, type CustomGradient } from "./backgrounds";

// The ids and defaults live in backgrounds.ts (they are on the critical path, this module is not); everything that used to import them from here still can.
export { CUSTOM_ID, DEFAULT_CUSTOM, DEFAULT_CUSTOM_SOLID, DEFAULT_GRADIENT, GRADIENT_IDS, isSolid, MAX_STOPS, MIN_STOPS, SOLID_CUSTOM_ID, SOLID_IDS, type CustomGradient } from "./backgrounds";

export interface NamedGradient { id: string; name: string; css: string }

export interface NamedSolid { id: string; name: string; /** "" for the scheme's own colour, else the colour. */ colour: string }


/** Where each blob sits (percent of the width and height) for the three colours of a recipe. */
type At = [number, number];
interface Recipe { id: string; name: string; /** Indices into the scheme's palette. */ colours: [number, number, number]; at: [At, At, At] }

/** The scheme's palette: 0 accent, 1 red, 2 green, 3 yellow, 4 blue, 5 magenta, 6 cyan. */
const palette = (theme: Theme): string[] => [theme.accent, theme.ansi[1], theme.ansi[2], theme.ansi[3], theme.ansi[4], theme.ansi[5], theme.ansi[6]];

const RECIPES: readonly Recipe[] = [
  { id: "aurora", name: "Aurora", colours: [0, 6, 5], at: [[15, 20], [85, 15], [55, 95]] },
  { id: "dusk", name: "Dusk", colours: [5, 1, 0], at: [[10, 85], [90, 60], [50, 5]] },
  { id: "lagoon", name: "Lagoon", colours: [6, 4, 2], at: [[80, 90], [15, 40], [60, 0]] },
  { id: "ember", name: "Ember", colours: [1, 3, 5], at: [[20, 95], [85, 30], [45, 0]] },
  { id: "meadow", name: "Meadow", colours: [2, 6, 3], at: [[10, 20], [90, 80], [50, 65]] },
  { id: "orchid", name: "Orchid", colours: [5, 4, 0], at: [[80, 10], [15, 75], [70, 100]] },
  { id: "sunrise", name: "Sunrise", colours: [3, 1, 0], at: [[85, 95], [20, 10], [55, 50]] },
  { id: "haze", name: "Haze", colours: [0, 4, 0], at: [[25, 30], [80, 70], [55, 5]] },
];

/** Moves a colour to a lightness just off the scheme's background and keeps its hue: a glow on dark, a wash on light. */
export function toned(theme: Theme, hex: string): string {
  const bgL = hexToOklab(theme.bg)[0];
  const [, a, b] = hexToOklab(hex);
  return oklabToHex([bgL + (theme.dark ? 0.13 : -0.07), a * 0.85, b * 0.85]);
}
const clear = (hex: string): string => `${hex}00`;

function meshOf(theme: Theme, recipe: Recipe): string {
  const colours = palette(theme);
  const layers = recipe.colours.map((index, i) => {
    const c = toned(theme, colours[index]!);
    const [x, y] = recipe.at[i]!;
    return `radial-gradient(70% 80% at ${x}% ${y}%, ${c} 0%, ${clear(c)} 72%)`;
  });
  // The scheme's own background underneath, as the last layer: `--mesh-image` is an image, and a colour cannot be one.
  return [...layers, `linear-gradient(${theme.bg}, ${theme.bg})`].join(", ");
}

/** The nine gradients of a scheme, in the order they are offered: eight meshes and a straight wash from the background to the accent. */
export function gradientsFor(theme: Theme): NamedGradient[] {
  const meshes = RECIPES.map((r) => ({ id: r.id, name: r.name, css: meshOf(theme, r) }));
  const horizon = `linear-gradient(160deg in oklab, ${theme.bg} 15%, ${toned(theme, theme.accent)} 100%)`;
  return [...meshes, { id: "horizon", name: "Horizon", css: horizon }];
}

/** The palette roles a solid colour can come from, with the plain name a tooltip shows. */
const SOLID_ROLES: ReadonlyArray<{ id: string; name: string; index: number }> = [
  { id: "solid-accent", name: "Accent", index: 0 }, { id: "solid-red", name: "Red", index: 1 }, { id: "solid-yellow", name: "Yellow", index: 3 },
  { id: "solid-green", name: "Green", index: 2 }, { id: "solid-cyan", name: "Cyan", index: 6 }, { id: "solid-blue", name: "Blue", index: 4 },
  { id: "solid-magenta", name: "Magenta", index: 5 },
];

/** A solid colour of the scheme: its background with a hue of its palette in it, close enough that the scheme's text keeps its contrast. */
function solidOf(theme: Theme, hex: string): string {
  const bgL = hexToOklab(theme.bg)[0];
  const [, a, b] = hexToOklab(hex);
  return oklabToHex([bgL + (theme.dark ? 0.05 : -0.04), a * 0.5, b * 0.5]);
}

/**
 * The solid colours of a scheme in the order they are offered: its own colour, then one for each hue of its palette. A colour is offered
 * once: Rose Pine's cyan is its accent, and two swatches of one colour would look like a mistake, so that scheme has six.
 */
export function solidsFor(theme: Theme): NamedSolid[] {
  const colours = palette(theme);
  const all = SOLID_ROLES.map((r) => ({ id: r.id, name: r.name, colour: solidOf(theme, colours[r.index]!) }));
  return [{ id: "solid", name: "Default", colour: "" }, ...all.filter((s, i) => all.findIndex((o) => o.colour === s.colour) === i)];
}
/** Every id a solid can have, in order; a scheme whose palette repeats a colour offers fewer (`solidsFor`). */
const flat = (colour: string): string => `linear-gradient(${colour}, ${colour})`;

/** The gradient a theme starts with: the first one, the scheme's own accent with its cyan and magenta. */

/** The person's own gradient: their stops, in OKLab (no grey dip between two bright colours), at their angle. */
export function customGradient(custom: CustomGradient): string {
  const stops = custom.stops.length >= MIN_STOPS ? custom.stops : DEFAULT_CUSTOM.stops;
  return `linear-gradient(${Math.round(custom.angle)}deg in oklab, ${stops.join(", ")})`;
}

/** The CSS image behind a theme's windows, or "" for Solid (the scheme's background alone). */
export function backgroundCss(background: string, custom: CustomGradient, theme: Theme, customSolid: string = DEFAULT_CUSTOM_SOLID): string {
  if (background === "solid") return "";
  if (background === SOLID_CUSTOM_ID) return flat(customSolid);
  if (background.startsWith("solid-")) { const s = solidsFor(theme).find((x) => x.id === background); return s?.colour ? flat(s.colour) : ""; }
  if (background === CUSTOM_ID) return customGradient(custom);
  return (gradientsFor(theme).find((g) => g.id === background) ?? gradientsFor(theme)[0]!).css;
}

/** Every colour a background can put behind text: the toned stops of every recipe, the scheme's solid colours, and a custom gradient's own stops. For contrast checks. */
export function gradientColours(theme: Theme, custom?: CustomGradient): string[] {
  const colours = palette(theme);
  const out = new Set<string>(solidsFor(theme).map((x) => x.colour).filter(Boolean));
  for (const r of RECIPES) for (const i of r.colours) out.add(toned(theme, colours[i]!));
  out.add(toned(theme, theme.accent));
  for (const s of custom?.stops ?? []) out.add(s);
  return [...out];
}
