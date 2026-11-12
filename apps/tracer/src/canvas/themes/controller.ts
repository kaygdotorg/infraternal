// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Owns the page's active theme and appearance defaults (D322, D352, D178, #323). It applies one look to the product, exposes one bridge to the canvas
 * document, and never has its own server path. Themes, window widths and extended machine details travel together in the canvas document; the camera stays
 * on this device. The account-keyed browser cache is only for first paint while the existing canvas subscription is loading.
 *
 * A new or older account document may lack a look or the newer appearance fields. In that case the newest account cache or one-time browser values seed the
 * missing state. An existing account look wins over legacy device values; those values seed only a look the account has not saved yet. Once the complete look is
 * confirmed by the canvas store, this module refreshes its derived cache and removes old appearance keys. `uiFont` follows that same account-first migration
 * rule, so the first account value wins over any later device-local copy.
 *
 * D390: an account that never picked a theme follows each device's light or dark setting. Its look carries `themeChosen: false`, the first
 * load saves no look of its own, and the theme colours inside such a look are never applied; they are only the scheme one device showed.
 * The flag becomes true when the person selects a theme or changes its Colour, and from then on D352 applies: the account's theme wins on every device.
 */
import type { CoreScreen, PaletteEntry } from "../../core-screen";
import { parseLook, type DocLook, type DocWindowSizes } from "../model/schema";
import { THEMES } from "../../../../../packages/ui/src/themes";
import { applyStoredUiSize, bindUiSizePreference, readUiSize, UI_SIZE_EVENT } from "../../../../../packages/ui/src/ui-scale";
import { fontById } from "../../../../../packages/ui/src/fonts";
import { DEFAULT_SIZES, SIZE_EVENT, type WindowSizes } from "../window-sizes";
import { EXTENDED_INFO_EVENT } from "../windows/extended-info";
import { DEFAULT_GRADIENT } from "./backgrounds";
import { applyLook } from "./apply";
import { createThemeStore, restore, type AppearanceTheme, type SavedThemes, type ThemeStore } from "./model";
import {
  clearLegacyAppearance,
  readCache,
  cachedThemeChosen,
  readCachedLook,
  readLegacyAppearance,
  readLegacyUiFont,
  readLegacyUiSize,
  writeCache,
  type LegacyAppearance,
} from "./persist";

/** How long after the last change the canvas is told; a slider drag is one `look.set` after the person pauses. */
const ANNOUNCE_DELAY_MS = 600;
/** How long after a local change before the first-paint cache is rewritten. */
const CACHE_DELAY_MS = 150;
/** Phone sizes accepted when older browser preferences are migrated. */
const PHONE_SIZES: readonly string[] = ["full", "edge", "comfortable"];
/** Desktop sizes accepted when older browser preferences are migrated. */
const DESKTOP_SIZES: readonly string[] = ["comfortable", "wide", "full"];

/** The look settings that travel beside the theme list in the account's canvas document. */
interface AppearanceDefaults {
  windowSizes: WindowSizes;
  extendedInfo: boolean;
}

/** What the canvas needs: one complete look to save, a place to apply canonical look updates, and server-confirmation cleanup. */
export interface LookAdapter {
  snapshot(): DocLook | undefined;
  /** Reports whether this account's canvas document has supplied a valid look to this page. */
  hasAccountLook(): boolean;
  /** Applies the look from a canvas snapshot or revisioned edit; `undefined` means the account has none yet. */
  apply(look: DocLook | undefined): void;
  /** Confirms a complete canonical look after the canvas store has no unacknowledged edits. */
  confirmed(look: DocLook | undefined): void;
  /** A `look.set` was refused; forget only that local look while its fresh canvas snapshot is requested. */
  lookRefused(look: DocLook): void;
  /** The account's default window widths, shared by phone and desktop clients. */
  windowSizes(): WindowSizes;
  setWindowSize<K extends keyof WindowSizes>(kind: K, value: WindowSizes[K]): void;
  extendedInfo(): boolean;
  setExtendedInfo(on: boolean): void;
  /** Calls `listener` after a local change, not after `apply`; returns its remover. */
  onChange(listener: () => void): () => void;
}

/** The account that owns this page's canvas look and an optional mock-only preview. */
interface StartThemesOptions {
  accountId?: string;
  /** Preview accepted only on the test double; a preview neither applies nor writes the account look. */
  preview?: string;
}

/** The page's one theme store, shared by settings, palette, and canvas adapters. */
let shared: ThemeStore | undefined;
/** The active account-document adapter for this page's appearance. */
let bridge: LookAdapter | undefined;

/** The page's one theme store; undefined before {@link startThemes} has run. */
export const themeStore = (): ThemeStore | undefined => shared;

/** The bridge between this page's appearance and the canvas document; undefined before {@link startThemes} has run. */
export const lookBridge = (): LookAdapter | undefined => bridge;

/** Keeps valid phone and desktop sizes from the old browser keys; missing or invalid values use the caller's default. */
function oldWindowSize(legacy: LegacyAppearance | undefined): Partial<WindowSizes> {
  if (!legacy) return {};
  const phone = legacy.phoneSize && PHONE_SIZES.includes(legacy.phoneSize) ? legacy.phoneSize as WindowSizes["phone"] : undefined;
  const desktop = legacy.desktopSize && DESKTOP_SIZES.includes(legacy.desktopSize) ? legacy.desktopSize as WindowSizes["desktop"] : undefined;
  return { ...(phone ? { phone } : {}), ...(desktop ? { desktop } : {}) };
}

/** Reads the old on/off representation without treating an invalid value as an explicit choice. */
function oldExtendedInfo(legacy: LegacyAppearance | undefined): boolean | undefined {
  if (legacy?.extendedInfo === "1") return true;
  if (legacy?.extendedInfo === "0") return false;
  return undefined;
}

/** D322 replaced separate old window/card levels with one theme material; Windows wins if both old levels were saved. */
/** Maps the old window transparency first, falling back to card transparency when the window key is absent or invalid. */
function oldMaterial(legacy: LegacyAppearance | undefined): Pick<AppearanceTheme, "tint" | "blur"> | undefined {
  if (!legacy) return undefined;
  const validLevel = (value: string | null): number | undefined => {
    const level = Number(value);
    return value !== null && Number.isInteger(level) && level >= 1 && level <= 4 ? level : undefined;
  };
  const level = validLevel(legacy.windows) ?? validLevel(legacy.card);
  if (level === undefined) return undefined;
  return [
    { tint: 100, blur: 0 },
    { tint: 75, blur: 25 },
    { tint: 50, blur: 0 },
    { tint: 50, blur: 50 },
  ][level - 1];
}

/** Maps the old page backdrop modes to the matching built-in theme background. */
function oldBackground(legacy: LegacyAppearance | undefined): string | undefined {
  if (legacy?.background === "none") return "solid";
  if (legacy?.background === "soft" || legacy?.background === "mesh") return DEFAULT_GRADIENT;
  return undefined;
}

/** Finds the selected entry in a validated look for first-paint defaults. */
function selectedTheme(look: DocLook | undefined): DocLook["themes"][number] | undefined {
  return look?.themes.find((theme) => theme.id === look.selected);
}

/** Applies newer standalone Colour, font and size values, then seeds replaced material fields only for a fresh look. */
function legacyThemePatch(store: ThemeStore, legacy: LegacyAppearance | undefined, savedLook: DocLook | undefined): void {
  if (!legacy) return;
  const patch: Partial<AppearanceTheme> = {};
  if (legacy.theme && Object.hasOwn(THEMES, legacy.theme)) patch.colors = legacy.theme;
  if (legacy.font && fontById(legacy.font)) patch.font = legacy.font;
  const uiSize = readLegacyUiSize(legacy);
  if (uiSize !== undefined) patch.uiSize = uiSize;
  // These settings were replaced by the Themes model. They seed a fresh theme only; an existing saved theme is newer.
  if (!savedLook) {
    Object.assign(patch, oldMaterial(legacy));
    const background = oldBackground(legacy);
    if (background) patch.background = background;
  }
  if (Object.keys(patch).length) store.edit(patch);
}

/** Returns true once the account look contains every field needed to retire old browser values safely. */
function completeLook(look: DocLook | undefined): look is DocLook & { windowSizes: DocWindowSizes; extendedInfo: boolean; uiFont: "mono" | "sans" } {
  return Boolean(look?.windowSizes && typeof look.extendedInfo === "boolean" && (look.uiFont === "mono" || look.uiFont === "sans"));
}

/** Reads the one scheme this device's setting asks for: dark shows Mocha, light shows Latte (the same pair the first paint uses). */
function systemColors(): string { return matchMedia("(prefers-color-scheme: dark)").matches ? "mocha" : "latte"; }

/** Gives a never-chosen account's saved themes this device's own scheme, so a scheme another device saved never reaches this screen (D390). */
function withSystemColors(saved: SavedThemes): SavedThemes {
  const colors = systemColors();
  return { ...saved, basics: { ...saved.basics, colors }, themes: saved.themes.map((theme) => ({ ...theme, colors })) };
}

/**
 * Compares valid looks after the document schema normalizes their nested object field order. A look without `themeChosen` equals one
 * that says false: the page writes the flag explicitly, but a look saved by a page that never heard of it still has to count as confirmed.
 */
function sameLook(left: unknown, right: unknown): boolean {
  const canonicalLeft = parseLook(left), canonicalRight = parseLook(right);
  if (canonicalLeft === undefined || canonicalRight === undefined) return false;
  const normal = (look: DocLook): string => JSON.stringify({ ...look, themeChosen: look.themeChosen === true });
  return normal(canonicalLeft) === normal(canonicalRight);
}

/** Starts the page's Themes and look bridge. Calling it again stops the first instance. */
export function startThemes(core: CoreScreen, options: StartThemesOptions = {}): () => void {
  stopRunning?.();
  const { accountId, preview } = options;
  const legacy = accountId ? readLegacyAppearance(accountId) : undefined;
  const cache = readCache(accountId);
  const cachedLook = accountId ? readCachedLook(accountId) : parseLook(cache);
  const query = new URLSearchParams(location.search);
  const prototype = query.get("proto");
  const requestedUiFont = query.get("ui");
  const previewUiFont = prototype === "windows" || prototype === "addhost" || prototype === "clusters"
    ? "mono"
    : requestedUiFont === "mono" || requestedUiFont === "sans" ? requestedUiFont : undefined;
  let uiFont = cachedLook?.uiFont ?? readLegacyUiFont(accountId, cachedLook?.uiFont) ?? "mono";
  const selected = selectedTheme(cachedLook);
  const uiSize = (accountId ? readLegacyUiSize(legacy) : undefined) ?? selected?.uiSize ?? (accountId ? 100 : readUiSize());
  const now = core.appearance();
  // D390: has the person ever picked a theme? An old browser theme key was a pick, a cached look says so itself, and a `?theme=` preview
  // on the test double pins the colours. Anything else follows this device's light or dark setting.
  const urlTheme = query.get("theme") !== null;
  let themeChosen = Boolean(legacy?.theme && Object.hasOwn(THEMES, legacy.theme)) || cachedThemeChosen(cachedLook);
  const restoredCache = restore(cache);
  const startFollowing = !themeChosen && !urlTheme && restoredCache !== undefined;
  const store = createThemeStore({ colors: now.theme, font: now.font, uiSize }, startFollowing ? withSystemColors(restoredCache) : cache);
  legacyThemePatch(store, legacy, cachedLook);
  shared = store;

  const previewing = preview !== undefined && store.themes().some((theme) => theme.id === preview);
  if (previewing) store.select(preview!);
  const defaults: AppearanceDefaults = {
    windowSizes: {
      phone: oldWindowSize(legacy).phone ?? cachedLook?.windowSizes?.phone ?? DEFAULT_SIZES.phone,
      desktop: oldWindowSize(legacy).desktop ?? cachedLook?.windowSizes?.desktop ?? DEFAULT_SIZES.desktop,
    },
    extendedInfo: oldExtendedInfo(legacy) ?? cachedLook?.extendedInfo ?? false,
  };
  let applyingDocument = false;
  let applyingLook = false;
  // Once the canvas has supplied a valid account look, the OS scheme is no longer an appearance authority.
  let accountLookApplied = false;
  // A local look stays authoritative until the canvas document confirms that exact snapshot.
  let localLookPending = false;
  let appliedUiSize = store.selected().uiSize;
  /** Applies the page preview or the account's font to the document root. */
  const applyUiFont = (): void => {
    const next = previewUiFont ?? uiFont;
    if (document.documentElement.dataset.uiFont !== next) document.documentElement.dataset.uiFont = next;
  };
  const render = (): void => {
    applyingLook = true;
    try {
      applyUiFont();
      applyLook(core, store.selected());
      applyStoredUiSize();
      const nextUiSize = store.selected().uiSize;
      if (nextUiSize !== appliedUiSize) window.dispatchEvent(new Event(UI_SIZE_EVENT));
      appliedUiSize = nextUiSize;
    } finally { applyingLook = false; }
  };

  const releaseUiSize = accountId && !previewing ? bindUiSizePreference({
    read: () => store.selected().uiSize,
    write: (percent) => { if (store.selected().uiSize !== percent) store.edit({ uiSize: percent }); },
  }) : undefined;
  render();

  const listeners = new Set<() => void>();
  let cacheTimer = 0, announceTimer = 0;
  const snapshot = (): DocLook => ({ ...store.snapshot(), uiFont, windowSizes: { ...defaults.windowSizes }, extendedInfo: defaults.extendedInfo, themeChosen });
  const flushCache = (): void => { cacheTimer = 0; if (!previewing) writeCache(accountId, snapshot()); };
  const announce = (): void => { announceTimer = 0; for (const listener of [...listeners]) listener(); };
  const scheduleChange = (): void => {
    if (previewing) return;
    localLookPending = Boolean(accountId);
    window.clearTimeout(cacheTimer);
    cacheTimer = window.setTimeout(flushCache, CACHE_DELAY_MS);
    window.clearTimeout(announceTimer);
    announceTimer = window.setTimeout(announce, ANNOUNCE_DELAY_MS);
  };
  let lastSelected = store.selectedId(), lastColors = store.selected().colors;
  const off = store.onChange(() => {
    render();
    const selectedNow = store.selectedId(), colorsNow = store.selected().colors;
    const picked = selectedNow !== lastSelected || colorsNow !== lastColors;
    lastSelected = selectedNow; lastColors = colorsNow;
    if (applyingDocument || previewing) return;
    // Selecting a theme or changing its Colour is the person's pick (D390); a tint slider or a font is not.
    if (picked && !urlTheme) themeChosen = true;
    scheduleChange();
  });
  /** While no theme was picked, a change of this device's light or dark setting changes the shown scheme, and nothing is saved. */
  const system = matchMedia("(prefers-color-scheme: dark)");
  const followSystem = (): void => {
    if (themeChosen || previewing || urlTheme) return;
    const now = store.snapshot(), colors = systemColors();
    if (now.basics.colors === colors && now.themes.every((theme) => theme.colors === colors)) return;
    applyingDocument = true;
    try { store.load(withSystemColors(now)); } finally { applyingDocument = false; }
  };
  system.addEventListener("change", followSystem);
  // A page that is being hidden sends the final appearance edit now.
  const onHide = (): void => { if (announceTimer) { window.clearTimeout(announceTimer); announce(); } };
  window.addEventListener("pagehide", onHide);

  const mine: LookAdapter = {
    snapshot: () => (previewing ? undefined : snapshot()),
    hasAccountLook: () => accountLookApplied,
    apply(look) {
      if (previewing) return;
      if (look === undefined) {
        // D390: a first load saves nothing of its own. Only an upgrade from old browser values has something worth saving.
        if (themeChosen || legacy) { window.clearTimeout(announceTimer); announce(); }
        return;
      }
      const canonical = parseLook(look);
      const restoredAccount = canonical ? restore(canonical) : undefined;
      if (!canonical || !restoredAccount) return;
      accountLookApplied = Boolean(accountId);
      const chosenByAccount = canonical.themeChosen === true;
      const restored = chosenByAccount || urlTheme ? restoredAccount : withSystemColors(restoredAccount);
      const nextDefaults: AppearanceDefaults = {
        windowSizes: {
          phone: canonical.windowSizes?.phone ?? defaults.windowSizes.phone,
          desktop: canonical.windowSizes?.desktop ?? defaults.windowSizes.desktop,
        },
        extendedInfo: canonical.extendedInfo ?? defaults.extendedInfo,
      };
      const nextUiFont = canonical.uiFont ?? uiFont;
      const needsCompletion = canonical.windowSizes === undefined || canonical.extendedInfo === undefined || canonical.uiFont === undefined;
      const changedWindowSizes = nextDefaults.windowSizes.phone !== defaults.windowSizes.phone
        || nextDefaults.windowSizes.desktop !== defaults.windowSizes.desktop;
      const changedExtendedInfo = nextDefaults.extendedInfo !== defaults.extendedInfo;
      const next: DocLook = { ...restored, uiFont: nextUiFont, ...nextDefaults, themeChosen: chosenByAccount };
      if (localLookPending && !sameLook(next, snapshot())) {
        // Preserve the unsent local look until DocumentSync captures it. Its operation then uses the canvas journal's
        // current base revision and op id, so the server's ordinary document order decides the winner.
        return;
      }
      if (sameLook(next, snapshot()) && !needsCompletion) return;

      applyingDocument = true;
      defaults.windowSizes = { ...nextDefaults.windowSizes };
      defaults.extendedInfo = nextDefaults.extendedInfo;
      uiFont = nextUiFont;
      themeChosen = chosenByAccount;
      try {
        // Loading emits synchronously, so the store listener already renders this remote look once.
        store.load(restored);
      } finally { applyingDocument = false; }
      applyUiFont();
      if (changedWindowSizes) window.dispatchEvent(new CustomEvent(SIZE_EVENT));
      if (changedExtendedInfo) window.dispatchEvent(new CustomEvent(EXTENDED_INFO_EVENT));
      writeCache(accountId, snapshot());
      if (needsCompletion) { window.clearTimeout(announceTimer); announce(); }
    },
    confirmed(look) {
      if (!accountId || previewing || !completeLook(parseLook(look))) return;
      const canonical = parseLook(look)!;
      if (!sameLook(canonical, snapshot())) return;
      localLookPending = false;
      writeCache(accountId, canonical);
      clearLegacyAppearance(accountId);
    },
    lookRefused(look) {
      if (!accountId || previewing || !sameLook(look, snapshot())) return;
      localLookPending = false;
      window.clearTimeout(cacheTimer); cacheTimer = 0;
      window.clearTimeout(announceTimer); announceTimer = 0;
    },
    windowSizes: () => ({ ...defaults.windowSizes }),
    setWindowSize(kind, value) {
      if (defaults.windowSizes[kind] === value) return;
      defaults.windowSizes = { ...defaults.windowSizes, [kind]: value };
      scheduleChange();
    },
    extendedInfo: () => defaults.extendedInfo,
    setExtendedInfo(on) {
      if (defaults.extendedInfo === on) return;
      defaults.extendedInfo = on;
      scheduleChange();
    },
    onChange(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
  };
  bridge = mine;

  // A Colour or terminal font picked outside Themes is still an edit to the selected theme, so a later document update cannot undo it.
  const onAppearance = (): void => {
    if (applyingLook) return;
    const current = core.appearance(), theme = store.selected();
    if (current.theme !== theme.colors || current.font !== theme.font) store.edit({ colors: current.theme, font: current.font });
  };
  window.addEventListener("tracer:appearance", onAppearance);

  /** Saves a chosen page font through the existing account-look operation. */
  const onUiFont = (event: Event): void => {
    if (applyingDocument || previewUiFont !== undefined) return;
    const next = (event as CustomEvent<{ font?: unknown }>).detail?.font;
    if ((next !== "mono" && next !== "sans") || next === uiFont) return;
    uiFont = next;
    applyUiFont();
    scheduleChange();
  };
  window.addEventListener("tracer:ui-font", onUiFont);

  const removeProvider = core.addPaletteProvider((): PaletteEntry[] => store.themes().map((theme) => ({
    group: "Theme", glyph: "◫", label: `Theme: ${theme.name}`, hint: `${theme.tint}% tint · ${theme.blur}% blur`, action: `themes:${theme.id}`,
  })));
  const onAction = (event: Event): void => { const id = (event as CustomEvent<{ id?: string }>).detail?.id; if (id) store.select(id); };
  window.addEventListener("tracer:themes-action", onAction);

  const stop = (): void => {
    off();
    releaseUiSize?.();
    removeProvider();
    window.removeEventListener("tracer:themes-action", onAction);
    window.removeEventListener("tracer:appearance", onAppearance);
    window.removeEventListener("tracer:ui-font", onUiFont);
    window.removeEventListener("pagehide", onHide);
    system.removeEventListener("change", followSystem);
    if (cacheTimer) { window.clearTimeout(cacheTimer); flushCache(); }
    if (announceTimer) { window.clearTimeout(announceTimer); announce(); }
    if (shared === store) shared = undefined;
    if (bridge === mine) bridge = undefined;
    if (stopRunning === stop) stopRunning = undefined;
  };
  stopRunning = stop;
  return stop;
}

/** Cleanup for the current page theme controller, if it has started. */
let stopRunning: (() => void) | undefined;
