/**
 * Which font the person chose, read the same way the theme choice is read: an explicit URL
 * parameter wins (it is how tests and screenshots pick a font, and it is never saved), then
 * the choice saved on this device, then the default (D87, D175). Saving goes through the
 * shared local-preference helper that the theme uses.
 */
import { DEFAULT_FONT_ID, fontById, type MonoFont } from "../../../packages/ui/src/fonts";
import { readLocal, writeLocal } from "../../../packages/ui/src/local-pref";

const FONT_KEY = "tracer.font";

export function initialFont(): MonoFont {
  return fontById(new URLSearchParams(location.search).get("font")) ?? fontById(readLocal(FONT_KEY)) ?? fontById(DEFAULT_FONT_ID)!;
}

export function rememberFont(font: MonoFont): void {
  writeLocal(FONT_KEY, font.id);
}
