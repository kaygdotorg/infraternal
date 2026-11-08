// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Reads and writes the appearance cache (D352, D178, D312, #323). The canvas document is the saved account copy; this module keeps only a derived
 * first-paint cache, scoped by account, and reads old device-wide preferences once for migration. A cache can make the first frame immediate but never
 * wins over the server document.
 */
import { readLocal, writeLocal } from "../../../../../packages/ui/src/local-pref";
import { clampUiSize, migrateLegacy, UI_SIZE } from "../../../../../packages/ui/src/ui-scale";
import { lastAccountKey } from "../../account-storage";
import { parseLook, type DocLook } from "../model/schema";

/** Keys moved into the account look and removed after server confirmation; the separate UI-font preference stays local. */
export const LEGACY_KEYS = [
  "tracer.look", "tracer.theme", "tracer.font", "tracer.ui-size.v2", "tracer.ui-size",
  "tracer.window-size.phone", "tracer.window-size.desktop", "tracer.extended-info", "tracer.card", "tracer.windows", "tracer.background",
] as const;
/** The old theme cache key, kept only to read previous releases and isolated mock pages. */
export const CACHE_KEY = "tracer.look";
/** Prefixes the first-paint cache with the authenticated account id. */
const ACCOUNT_CACHE_PREFIX = "tracer.look.account.";
/** Names the account that owns legacy device-wide appearance values during migration. */
const LEGACY_OWNER_KEY = "tracer.look.legacy-owner";

/** The old browser preferences, returned raw so the caller can validate each value against its own model. */
export interface LegacyAppearance {
  look: unknown;
  theme: string | null;
  font: string | null;
  uiSizeV2: string | null;
  uiSizeLegacy: string | null;
  phoneSize: string | null;
  desktopSize: string | null;
  extendedInfo: string | null;
  card: string | null;
  windows: string | null;
  background: string | null;
}

/** The account's cache key; the suffix can never collide with a legacy device-wide key. */
export function accountCacheKey(accountId: string): string { return `${ACCOUNT_CACHE_PREFIX}${encodeURIComponent(accountId)}`; }

/** Whether a cache already belongs to this account. Even an unreadable cache prevents another account's old values becoming its fallback. */
export function hasAccountCache(accountId: string): boolean { return readLocal(accountCacheKey(accountId)) !== null; }

/** Claims legacy device-wide preferences for the last account that used them, or the first signed-in account during the upgrade. */
function ownsLegacyValues(accountId: string): boolean {
  const owner = readLocal(LEGACY_OWNER_KEY);
  if (owner !== null) return owner === accountId;
  const priorAccount = readLocal(lastAccountKey);
  const claimed = priorAccount ?? accountId;
  writeLocal(LEGACY_OWNER_KEY, claimed);
  return claimed === accountId;
}

/** Reads older local values only for their one-time migration owner and only when no account cache exists. */
export function readLegacyAppearance(accountId: string): LegacyAppearance | undefined {
  if (hasAccountCache(accountId) || !ownsLegacyValues(accountId)) return undefined;
  const look = readLocal(CACHE_KEY);
  const theme = readLocal("tracer.theme"), font = readLocal("tracer.font");
  const uiSizeV2 = readLocal("tracer.ui-size.v2"), uiSizeLegacy = readLocal("tracer.ui-size");
  const phoneSize = readLocal("tracer.window-size.phone"), desktopSize = readLocal("tracer.window-size.desktop");
  const extendedInfo = readLocal("tracer.extended-info");
  const card = readLocal("tracer.card"), windows = readLocal("tracer.windows"), background = readLocal("tracer.background");
  if ([look, theme, font, uiSizeV2, uiSizeLegacy, phoneSize, desktopSize, extendedInfo, card, windows, background].every((value) => value === null)) return undefined;
  let parsedLook: unknown;
  try { parsedLook = look === null ? undefined : JSON.parse(look) as unknown; } catch { parsedLook = undefined; }
  return { look: parsedLook, theme, font, uiSizeV2, uiSizeLegacy, phoneSize, desktopSize, extendedInfo, card, windows, background };
}

/** The cached look, still unchecked for the theme store, or undefined when none belongs to this account. */
export function readCache(accountId?: string): unknown {
  if (accountId) {
    const scoped = readLocal(accountCacheKey(accountId));
    if (scoped !== null) {
      try { return JSON.parse(scoped) as unknown; } catch { return undefined; }
    }
    return readLegacyAppearance(accountId)?.look;
  }
  const raw = readLocal(CACHE_KEY);
  if (raw === null) return undefined;
  try { return JSON.parse(raw) as unknown; } catch { return undefined; }
}

/** Validates the cache before first-paint callers use its selected theme. */
export function readCachedLook(accountId?: string): DocLook | undefined { return parseLook(readCache(accountId)); }

/** The newest usable old UI-size choice, converted without rewriting or clearing its source before server confirmation. */
export function readLegacyUiSize(legacy: LegacyAppearance | undefined): number | undefined {
  if (!legacy) return undefined;
  const current = Number(legacy.uiSizeV2);
  if (legacy.uiSizeV2 !== null && Number.isFinite(current) && current > 0) return clampUiSize(current);
  const older = Number(legacy.uiSizeLegacy);
  if (legacy.uiSizeLegacy !== null && Number.isFinite(older) && older > 0) return older === UI_SIZE.standard ? UI_SIZE.standard : migrateLegacy(older);
  return undefined;
}

/** Caches only the selected theme and account settings, so theme application does not wait for the document or a second request. */
export function writeCache(accountId: string | undefined, look: DocLook): void {
  const selected = look.themes.find((theme) => theme.id === look.selected);
  if (!selected) return;
  const value = JSON.stringify({ ...look, themes: [selected] });
  writeLocal(accountId ? accountCacheKey(accountId) : CACHE_KEY, value);
}

/** Erases all old device-wide appearance values after a complete look is confirmed by the canvas document. */
export function clearLegacyAppearance(accountId: string): boolean {
  if (!ownsLegacyValues(accountId)) return true;
  try { for (const key of LEGACY_KEYS) localStorage.removeItem(key); return true; }
  catch { return false; }
}
