// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Draws the image part of a theme's look: its background (a gradient of the colour scheme, a solid colour, or the person's own) and its grain (D322, D341, #323).
 *
 * On demand (the name says so for the transfer gate, D188): it holds the colour maths and the noise-tile maker, which the first paint does not need. `apply.ts`
 * sets everything that is cheap and sure at once (tint, blur, the background mode) and calls this when the look has an image; the image then arrives a moment later
 * with the backdrop's own fade, the way the mesh image always has. After the first call the module is held, so a slider drag paints in the same frame.
 */
import type { CoreScreen } from "../../core-screen";
import { THEMES } from "../../../../../packages/ui/src/themes";
import { backgroundCss } from "./gradients";
import { grainImage } from "./grain";
import type { AppearanceTheme } from "./model";

/** Puts the background image and the grain tile of `theme` on the page. */
export function paintLook(core: CoreScreen, theme: AppearanceTheme): void {
  core.setBackdrop(backgroundCss(theme.background, theme.custom, THEMES[theme.colors] ?? THEMES.mocha!, theme.customSolid));
  document.documentElement.style.setProperty("--look-grain-url", grainImage(theme.grain));
}
