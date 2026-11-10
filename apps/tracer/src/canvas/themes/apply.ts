// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Puts the selected theme on the page (D322, D338, D341, #323).
 *
 * Colour (a version of a scheme: light or dark), font and UI size go through the product's own actions (`theme:`, `font:`, the UI-size
 * setting), so everything they do already happens. Tint, blur and grain are the new part. The product's four literal levels could not
 * hold any percentage, so a theme's numbers are written as custom properties on the root and read by `clusters.css`
 * (section "Themes"): `--look-tint` (0 to 1), `--look-blur` (px), `--look-card-blur`, and the grain tile. The product's window level
 * is only told whether the terminal must paint its own background (level 1: Solid) or let the window's fill show (level 2).
 *
 * The **background** is the product's own backdrop layers: a theme's gradient (generated per scheme, or the person's own) or flat colour
 * is plain CSS written with `core.setBackdrop`, and the background mode `themed` shows it without ever running the mesh painter.
 * "Solid" with the scheme's own colour is the product's `none`. The image and the grain tile are drawn by `paint.on-demand.ts`, which loads after the first paint.
 *
 * Windows follow the theme, and so do the floating cards (popovers, palette, sidebar, pills, tooltips; the owner's answer in D322). A
 * floating card follows the tint but never blurs less than the shared overlay blur ({@link CARD_BLUR_FLOOR_PX}, D329), so Tinted shows no ghost
 * text behind the palette.
 *
 * Grain lies on the window surfaces and the floating cards, never on the canvas behind them (D341); only the root attribute and two
 * properties change here, and the rules in `clusters.css` do the rest.
 */
import type { CoreScreen } from "../../core-screen";
import { readUiSize, setUiSize } from "../../../../../packages/ui/src/ui-scale";
import { onDemand } from "../../on-demand";
import { blurPx, type AppearanceTheme } from "./model";

/** The shared overlay blur (D72): floating cards follow a theme's tint but never blur less than this (owner, D329). */
export const CARD_BLUR_FLOOR_PX = 16;

/**
 * Shows `theme` on the page. Cheap when little changed: an action runs only for what differs from what the screen shows, and the rest
 * is a few property writes on the root. Safe to call on every slider step.
 */
export function applyLook(core: CoreScreen, theme: AppearanceTheme): void {
  const root = document.documentElement;
  const now = core.appearance();
  if (now.theme !== theme.colors) core.act(`theme:${theme.colors}`);
  if (now.font !== theme.font) core.act(`font:${theme.font}`);
  if (readUiSize() !== theme.uiSize) setUiSize(theme.uiSize);
  // Level 2 only makes the terminal draw no background of its own; level 1 (Solid) keeps it opaque and paints no transparency.
  const level = theme.tint < 100 ? 2 : 1;
  if (now.windows !== level) core.act(`windows:${level}`);
  if (now.card !== 2) core.act("card:2");
  // Whether the look has an image at all is known from its id: only the scheme's own colour ("solid") is plain. The image itself is drawn on demand (`paint.on-demand.ts`).
  const mode = theme.background === "solid" ? "none" : "themed";
  if (now.background !== mode) core.act(`bg:${mode}`);
  // The tile's pixels are device pixels, so it is drawn at 128 / devicePixelRatio CSS pixels.
  root.style.setProperty("--look-grain-size", `${128 / devicePixelRatio}px`);
  root.toggleAttribute("data-look-grain", theme.grain > 0);
  root.dataset.look = theme.id;
  root.style.setProperty("--look-card-blur", `${Math.max(blurPx(theme.blur), CARD_BLUR_FLOOR_PX)}px`);
  root.style.setProperty("--look-tint", String(theme.tint / 100));
  root.style.setProperty("--look-blur", `${blurPx(theme.blur)}px`);
  // The blur is a layer per window that cannot be skipped once it is on, so the rule that adds it exists only for blur above 0.
  root.toggleAttribute("data-look-blur", theme.blur > 0);
  paint(core, theme);
}

/** The painter once it has loaded; after that a look is painted in the same call. */
let painter: typeof import("./paint.on-demand") | undefined;
/** Which look asked last while the painter was loading: an older request that arrives late is dropped. */
let latest = 0;

/** Draws the image part of `theme` (background and grain), loading the painter the first time a look has an image. */
function paint(core: CoreScreen, theme: AppearanceTheme): void {
  const mine = ++latest;
  if (theme.background === "solid" && theme.grain === 0) {
    // Nothing to draw: no image behind the windows and no grain, so the properties are cleared without loading anything.
    core.setBackdrop("");
    document.documentElement.style.setProperty("--look-grain-url", "none");
    return;
  }
  if (painter) { painter.paintLook(core, theme); return; }
  void onDemand(() => import("./paint.on-demand")).then((loaded) => { painter = loaded; if (mine === latest) loaded.paintLook(core, theme); });
}
