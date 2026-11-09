// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The names of the backgrounds a theme can have, and their defaults (D322, D338, #323): only ids and numbers, no CSS. The model reads them to check a saved
 * theme and to build the built-in ones, and that happens on the critical path; the code that turns an id into an image (`gradients.ts`, with the colour maths
 * it needs) loads on demand, after the first paint. `gradients.test`-style checks in `model.test.ts` keep the two lists in step: every id here must have a gradient
 * or a solid there.
 */

/** A gradient the person made: two to four colours and an angle. */
export interface CustomGradient { stops: string[]; angle: number }

/** The minimum and maximum number of stops a custom gradient accepts. */
export const MIN_STOPS = 2, MAX_STOPS = 4;
/** The starting two-stop gradient for a new custom theme. */
export const DEFAULT_CUSTOM: CustomGradient = { stops: ["#7a9cff", "#cba6f7"], angle: 135 };
/** The serialized id reserved for a person's custom gradient. */
export const CUSTOM_ID = "custom";
/** A solid background has the ids "solid" (the scheme's own colour), "solid-<role>" (a colour drawn from the scheme's palette) and "solid-custom". */
export const SOLID_CUSTOM_ID = "solid-custom";
/** The initial custom solid colour for a new theme. */
export const DEFAULT_CUSTOM_SOLID = "#3b4252";
/** Reports whether an id names a solid background option. */
export const isSolid = (background: string): boolean => background === "solid" || background.startsWith("solid-");
/** The gradients every scheme gets, in the order they are offered (`gradients.ts` draws each). */
export const GRADIENT_IDS: readonly string[] = ["aurora", "dusk", "lagoon", "ember", "meadow", "orchid", "sunrise", "haze", "horizon"];
/** The solid colours a scheme may offer, in order: its own, then one for each hue of its palette. */
export const SOLID_IDS: readonly string[] = ["solid", "solid-accent", "solid-red", "solid-yellow", "solid-green", "solid-cyan", "solid-blue", "solid-magenta"];
/** The gradient a theme starts with: the first one, the scheme's own accent with its cyan and magenta. */
export const DEFAULT_GRADIENT = "aurora";
