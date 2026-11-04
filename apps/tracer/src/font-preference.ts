/**
 * Which font the person chose, read the same way the theme choice is read: an explicit URL
 * parameter wins (it is how tests and screenshots pick a font, and it is never saved), then
 * the choice saved on this device, then the default (D87, D175). Saving goes through the
 * shared local-preference helper that the theme uses.
 */
import { DEFAULT_FONT_ID, fontById, type MonoFont } from "../../../packages/ui/src/fonts";
import { readLocal, writeLocal } from "../../../packages/ui/src/local-pref";

/** The browser-local key under which the chosen font id is saved. */
const FONT_KEY = "tracer.font";

/** The font to start with: `?font=`, else the saved choice, else the default. An unknown id falls through to the next source. */
export function initialFont(): MonoFont {
  return fontById(new URLSearchParams(location.search).get("font")) ?? fontById(readLocal(FONT_KEY)) ?? fontById(DEFAULT_FONT_ID)!;
}

/** Saves `font` as this device's choice. The next page load picks it up through {@link initialFont}. */
export function rememberFont(font: MonoFont): void {
  writeLocal(FONT_KEY, font.id);
}
