// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The one place a person's Themes come alive on a page (D322, #323): it makes the store from what is saved, keeps the page looking
 * like the selected theme, saves every change, shares it with the account, and offers the themes in the command palette.
 *
 * `startThemes` runs once when the screen mounts. The Themes window (loaded on demand) reaches the same store through
 * {@link themeStore}; nothing else needs to know how a theme is applied or saved.
 *
 * Start-up order, chosen so a reload shows the right look at once and never waits for the network: the device's saved list is
 * read and applied synchronously, then the account's copy is fetched; if the account has a different list it replaces this device's
 * (the account is the shared one), and if the account has none, this device's list is sent up.
 *
 * A person who has never chosen starts on Tinted (D322), built from the Colour, font and size the product already shows them. `?look=` picks a theme for
 * one page load without saving it (tests and screenshots).
 */
import type { CoreScreen, PaletteEntry } from "../../core-screen";
import { readUiSize } from "../../../../../packages/ui/src/ui-scale";
import { applyLook } from "./apply";
import { createThemeStore, type ThemeStore } from "./model";
import { readAccount, readDevice, writeAccount, writeDevice } from "./persist";

/** How long after the last change the account is written (a slider drag changes the theme on every step; the device copy is written sooner). */
const ACCOUNT_DELAY_MS = 600;
/** How long after the last change the device copy is written. */
const DEVICE_DELAY_MS = 150;

let shared: ThemeStore | undefined;

/** The page's one store of themes; undefined before {@link startThemes} has run. */
export const themeStore = (): ThemeStore | undefined => shared;

/**
 * Starts the Themes of this page. Returns the way out (it stops following the store and removes the palette rows).
 * Calling it again while one is running stops the first.
 */
export function startThemes(core: CoreScreen): () => void {
  stopRunning?.();
  const now = core.appearance();
  const store = createThemeStore({ colors: now.theme, font: now.font, uiSize: readUiSize() }, readDevice());
  shared = store;
  // `?look=<theme id>` starts on that theme and never saves it, the way `?theme=`, `?font=` and `?bg=` pick a look for a test or a screenshot. It is taken before the
  // store is followed, so choosing it writes nothing; an id that is not a theme is ignored.
  const forced = new URLSearchParams(location.search).get("look");
  if (forced) store.select(forced);
  // True while this module is changing the page itself, so the change events it causes are not mistaken for the person's own picks.
  let applying = false;
  const show = (): void => { applying = true; try { applyLook(core, store.selected()); } finally { applying = false; } };
  show();

  let deviceTimer = 0, accountTimer = 0, fromAccount = false;
  const flushDevice = (): void => { deviceTimer = 0; writeDevice(store.snapshot()); };
  const flushAccount = (): void => { accountTimer = 0; writeAccount(store.snapshot()); };
  const off = store.onChange(() => {
    show();
    window.clearTimeout(deviceTimer);
    deviceTimer = window.setTimeout(flushDevice, DEVICE_DELAY_MS);
    // A list that has just come from the account is not sent straight back.
    if (fromAccount) { fromAccount = false; return; }
    window.clearTimeout(accountTimer);
    accountTimer = window.setTimeout(flushAccount, ACCOUNT_DELAY_MS);
  });

  // The account's copy: the shared one. If it differs, it replaces this device's; if it has nothing, this device's is sent up.
  let live = true;
  void readAccount().then((account) => {
    if (!live) return;
    if (account === undefined) { if (readDevice() !== undefined) flushAccount(); return; }
    if (JSON.stringify(account) === JSON.stringify(store.snapshot())) return;
    fromAccount = true;
    if (!store.load(account)) fromAccount = false;
  });

  // A Colour or a font picked somewhere else (⌘K, a shortcut) is a change to the selected theme, because a theme holds both: without this the next
  // load would show the saved theme's own Colour and font again, and the account's copy would undo the pick on every other device.
  const onAppearance = (): void => {
    if (applying) return;
    const now = core.appearance(), theme = store.selected();
    if (now.theme !== theme.colors || now.font !== theme.font) store.edit({ colors: now.theme, font: now.font });
  };
  window.addEventListener("tracer:appearance", onAppearance);

  // The themes in ⌘K: "Theme: Solid", "Theme: Tinted", …, then the person's own, each with its tint and blur.
  const removeProvider = core.addPaletteProvider((): PaletteEntry[] => store.themes().map((theme) => ({
    group: "Theme", glyph: "◫", label: `Theme: ${theme.name}`, hint: `${theme.tint}% tint · ${theme.blur}% blur`, action: `themes:${theme.id}`,
  })));
  const onAction = (event: Event): void => { const id = (event as CustomEvent<{ id?: string }>).detail?.id; if (id) store.select(id); };
  window.addEventListener("tracer:themes-action", onAction);

  const stop = (): void => {
    live = false;
    off();
    removeProvider();
    window.removeEventListener("tracer:themes-action", onAction);
    window.removeEventListener("tracer:appearance", onAppearance);
    // Anything not written yet is written now, so the way out loses no edit.
    if (deviceTimer) { window.clearTimeout(deviceTimer); flushDevice(); }
    if (accountTimer) { window.clearTimeout(accountTimer); flushAccount(); }
    if (shared === store) shared = undefined;
    if (stopRunning === stop) stopRunning = undefined;
  };
  stopRunning = stop;
  return stop;
}

let stopRunning: (() => void) | undefined;
