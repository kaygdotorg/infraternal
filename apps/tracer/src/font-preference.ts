/**
 * The terminal face comes from the signed-in account's canvas look (D352); the URL remains a page preview, then isolated pages may use the old
 * browser preference. The account cache is only for first paint while the canvas document is loading.
 */
import { DEFAULT_FONT_ID, fontById, type MonoFont } from "../../../packages/ui/src/fonts";
import { readLocal, writeLocal } from "../../../packages/ui/src/local-pref";
import { readCachedLook, readLegacyAppearance } from "./canvas/themes/persist";

/** The browser-local key under which the chosen font id is saved. */
const FONT_KEY = "tracer.font";

/** The font to start with: `?font=`, else the saved choice, else the default. An unknown id falls through to the next source. */
export function initialFont(accountId?: string): MonoFont {
  const preview = fontById(new URLSearchParams(location.search).get("font"));
  if (preview) return preview;
  if (accountId) {
    const legacy = readLegacyAppearance(accountId);
    const cached = readCachedLook(accountId);
    const selected = cached?.themes.find((theme) => theme.id === cached.selected);
    const saved = fontById(legacy?.font ?? selected?.font ?? null);
    return saved ?? fontById(DEFAULT_FONT_ID)!;
  }
  return fontById(readLocal(FONT_KEY)) ?? fontById(DEFAULT_FONT_ID)!;
}

/** Saves `font` as this device's choice. The next page load picks it up through {@link initialFont}. */
export function rememberFont(font: MonoFont): void {
  writeLocal(FONT_KEY, font.id);
}
