// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The one place a person's Themes come alive on a page (D322, D178, #323): it makes the store, keeps the page looking like the selected theme, offers the
 * themes in the command palette, and hands the look to the canvas document, which is where the account keeps it.
 *
 * `startThemes` runs once when the screen mounts. The Themes window (loaded on demand) reaches the same store through {@link themeStore}; nothing else needs to
 * know how a theme is applied. The canvas (which loads a moment later) reaches it through {@link lookBridge}.
 *
 * **Where the look lives.** The themes belong to the account, like the canvas: they are the `look` of the canvas document (D180), saved by the same edits and the
 * same server as the layout, so every device of the account shows the same look and only the camera stays per device. This module never talks to a server. The
 * bridge gives the canvas what to save (`snapshot`), takes what the document carries (`apply`) and says when the person changed something (`onChange`); the canvas
 * does the rest. Until the canvas has loaded, the page starts from a first-paint cache of the selected theme (`persist.ts`), so the first frame is right and the
 * store agrees with the page; when the document arrives, the account's look replaces it, and when the account has none yet, this page's look becomes the account's.
 *
 * A person who has never chosen starts on Tinted (D322), built from the Colour, font and size the product already shows them. A test page can preview a theme
 * (see `startThemes`).
 */
import type { CoreScreen, PaletteEntry } from "../../core-screen";
import type { DocLook } from "../model/schema";
import { readUiSize } from "../../../../../packages/ui/src/ui-scale";
import { applyLook } from "./apply";
import { createThemeStore, restore, type ThemeStore } from "./model";
import { readCache, writeCache } from "./persist";

/** How long after the last change the canvas is told (a slider drag changes the theme on every step; one edit of the look is sent when the person pauses). */
const ANNOUNCE_DELAY_MS = 600;
/** How long after the last change the first-paint cache is written. */
const CACHE_DELAY_MS = 150;

/**
 * What the canvas needs of the look: the look to save with the layout, a place to put the look the document carries, and a way to hear that the person changed it.
 * `snapshot` is undefined on a preview page, which saves nothing.
 */
export interface LookAdapter {
  snapshot(): DocLook | undefined;
  /** Shows the look the account's document carries; `undefined` means the account has none yet, so this page's look is offered to become the account's. */
  apply(look: DocLook | undefined): void;
  /** Calls `listener` after the person changed the look here (not after `apply`), once they pause. Returns the remover. */
  onChange(listener: () => void): () => void;
}

let shared: ThemeStore | undefined;
let bridge: LookAdapter | undefined;

/** The page's one store of themes; undefined before {@link startThemes} has run. */
export const themeStore = (): ThemeStore | undefined => shared;

/** The bridge between this page's themes and the canvas document; undefined before {@link startThemes} has run. */
export const lookBridge = (): LookAdapter | undefined => bridge;

/**
 * Starts the Themes of this page. Returns the way out (it stops following the store and removes the palette rows).
 * Calling it again while one is running stops the first.
 *
 * `preview` is a theme id a test or a screenshot asks for (`?look=`, read by the caller and only on the test double). The page then shows that theme
 * and is a **preview**: its bridge saves nothing and takes nothing from the document, and nothing is written to the first-paint cache, however it is edited
 * afterwards, so the saved look of the person is never touched by it. An id that is not a theme is ignored and the page starts normally.
 */
export function startThemes(core: CoreScreen, preview?: string): () => void {
  stopRunning?.();
  const now = core.appearance();
  const store = createThemeStore({ colors: now.theme, font: now.font, uiSize: readUiSize() }, readCache());
  shared = store;
  const previewing = preview !== undefined && store.themes().some((theme) => theme.id === preview);
  if (previewing) store.select(preview);
  // True while this module is changing the page itself, so the change events it causes are not mistaken for the person's own picks.
  let applying = false;
  const show = (): void => { applying = true; try { applyLook(core, store.selected()); } finally { applying = false; } };
  show();

  const listeners = new Set<() => void>();
  let cacheTimer = 0, announceTimer = 0, fromDocument = false;
  const flushCache = (): void => { cacheTimer = 0; if (!previewing) writeCache(store.snapshot()); };
  const announce = (): void => { announceTimer = 0; for (const listener of [...listeners]) listener(); };
  const off = store.onChange(() => {
    show();
    window.clearTimeout(cacheTimer);
    cacheTimer = window.setTimeout(flushCache, CACHE_DELAY_MS);
    // A look that has just come from the document is not sent straight back.
    if (fromDocument) { fromDocument = false; return; }
    if (previewing) return;
    window.clearTimeout(announceTimer);
    announceTimer = window.setTimeout(announce, ANNOUNCE_DELAY_MS);
  });
  // A page that is being hidden tells the canvas now, so a change made a moment ago is not left behind.
  const onHide = (): void => { if (announceTimer) { window.clearTimeout(announceTimer); announce(); } };
  window.addEventListener("pagehide", onHide);

  const mine: LookAdapter = {
    snapshot: () => (previewing ? undefined : store.snapshot()),
    apply(look) {
      if (previewing) return;
      if (look === undefined) { window.clearTimeout(announceTimer); announce(); return; }
      const mended = restore(look);
      if (!mended || JSON.stringify(mended) === JSON.stringify(store.snapshot())) return;
      fromDocument = true;
      if (!store.load(mended)) fromDocument = false;
    },
    onChange(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
  };
  bridge = mine;

  // A Colour or a font picked somewhere else (⌘K, a shortcut) is a change to the selected theme, because a theme holds both: without this the next
  // load would show the saved theme's own Colour and font again, and the account's look would undo the pick on every other device.
  const onAppearance = (): void => {
    if (applying) return;
    const current = core.appearance(), theme = store.selected();
    if (current.theme !== theme.colors || current.font !== theme.font) store.edit({ colors: current.theme, font: current.font });
  };
  window.addEventListener("tracer:appearance", onAppearance);

  // The themes in ⌘K: "Theme: Solid", "Theme: Tinted", …, then the person's own, each with its tint and blur.
  const removeProvider = core.addPaletteProvider((): PaletteEntry[] => store.themes().map((theme) => ({
    group: "Theme", glyph: "◫", label: `Theme: ${theme.name}`, hint: `${theme.tint}% tint · ${theme.blur}% blur`, action: `themes:${theme.id}`,
  })));
  const onAction = (event: Event): void => { const id = (event as CustomEvent<{ id?: string }>).detail?.id; if (id) store.select(id); };
  window.addEventListener("tracer:themes-action", onAction);

  const stop = (): void => {
    off();
    removeProvider();
    window.removeEventListener("tracer:themes-action", onAction);
    window.removeEventListener("tracer:appearance", onAppearance);
    window.removeEventListener("pagehide", onHide);
    // Anything not written yet is written now, so the way out loses no edit.
    if (cacheTimer) { window.clearTimeout(cacheTimer); flushCache(); }
    if (announceTimer) { window.clearTimeout(announceTimer); announce(); }
    if (shared === store) shared = undefined;
    if (bridge === mine) bridge = undefined;
    if (stopRunning === stop) stopRunning = undefined;
  };
  stopRunning = stop;
  return stop;
}

let stopRunning: (() => void) | undefined;
