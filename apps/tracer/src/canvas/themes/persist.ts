// SPDX-License-Identifier: AGPL-3.0-only
/**
 * What this browser keeps of the look (D322, D178, D312, #323): a first-paint cache of the selected theme, and nothing else.
 *
 * The person's themes belong to the account, like the canvas: they live in the canvas document (`look`), the server is the only saved copy, and every device of
 * the account shows the same look (the controller's bridge, `controller.ts`, carries it in and out; only the camera stays per device). The browser keeps one
 * small thing for itself: the theme that was selected when the page last changed, so the first frame after a reload is painted with the right tint, blur and
 * Colour before the document arrives, the way the Colour and font already are (`tracer.theme`, `tracer.font`). It is read once at start and used to start the
 * page's store, so the page and its themes agree from the first frame; the document then replaces it. It never goes to the server on its own: what the account
 * holds is what the account's own pages saved.
 *
 * It is written as the same shape the document carries (`SavedThemes`) with only the selected theme in the list; `restore` in `model.ts` mends anything read back,
 * so a damaged or hand-edited copy can never put a theme out of range.
 */
import { readLocal, writeLocal } from "../../../../../packages/ui/src/local-pref";
import type { SavedThemes } from "./model";

/** The browser-local key under which the selected theme is cached for the first paint. */
export const CACHE_KEY = "tracer.look";

/** The cached look, still unchecked (give it to `createThemeStore`), or undefined when none is cached. */
export function readCache(): unknown {
  const raw = readLocal(CACHE_KEY);
  if (raw === null) return undefined;
  try { return JSON.parse(raw) as unknown; } catch { return undefined; }
}

/** Caches the selected theme of `saved` (and the starting point the built-in themes were made from) for the next first paint. */
export function writeCache(saved: SavedThemes): void {
  const selected = saved.themes.find((theme) => theme.id === saved.selected);
  if (selected) writeLocal(CACHE_KEY, JSON.stringify({ ...saved, themes: [selected] }));
}
