// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Where a person's Themes are kept (D322, #323): on this device, and on the account so every device of the person shows the same list.
 *
 * - **This device** (`tracer.themes` in browser storage) is what the page starts from, so a reload paints the right look at once,
 *   with no wait for the network.
 * - **The account** is the shared copy, read and written the way the toolbar layout is (`/__mock/account/...`). Today that endpoint
 *   exists in the test double only: the real server has no store for per-person settings yet, so there the account answers "not found",
 *   nothing is sent anywhere, and Themes stay on the device (#323 asks where per-person settings should live). When the server
 *   gains the store, only {@link ACCOUNT_URL} and the two functions below change.
 *
 * Both copies are written as {@link SavedThemes}. Anything read back is mended by `restore` in `model.ts`, so a copy from another
 * device, an old version or a hand edit can never put a theme out of range. The last write wins: two devices editing the same
 * moment is not worth a merge for a list of a few themes.
 */
import { readLocal, writeLocal } from "../../../../../packages/ui/src/local-pref";
import type { SavedThemes } from "./model";

/** The browser-local key under which the person's themes are saved on this device. */
export const LOCAL_KEY = "tracer.themes";
/** The account's copy of the person's themes (see the module note: the test double serves it, the real server not yet). */
export const ACCOUNT_URL = "/__mock/account/appearance";

/** The themes saved on this device, still unchecked (give them to `createThemeStore`), or undefined when none are saved. */
export function readDevice(): unknown {
  const raw = readLocal(LOCAL_KEY);
  if (raw === null) return undefined;
  try { return JSON.parse(raw) as unknown; } catch { return undefined; }
}

/** Saves the themes on this device. */
export function writeDevice(saved: SavedThemes): void { writeLocal(LOCAL_KEY, JSON.stringify(saved)); }

/** The account's themes, unchecked; undefined when the account has none or cannot be reached (then this device's stay as they are). */
export async function readAccount(): Promise<unknown> {
  try {
    const response = await fetch(ACCOUNT_URL, { credentials: "same-origin" });
    if (!response.ok) return undefined;
    const body = (await response.json()) as { themes?: unknown } | null;
    return body?.themes ?? undefined;
  } catch { return undefined; }
}

/** Sends the themes to the account. A failure is dropped: the device copy has them, and the next change sends again. */
export function writeAccount(saved: SavedThemes): void {
  void fetch(ACCOUNT_URL, { method: "PUT", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ themes: saved }) }).catch(() => undefined);
}
