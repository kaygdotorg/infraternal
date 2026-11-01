/**
 * UI size (#283, TASTE "The size of the whole UI is the person's to set"): one number, 50 % to 150 %, that scales the whole
 * interface. It is the root font size, and every length in the stylesheets is in rem, so type, rows, pills, icons, popovers and
 * hit areas scale together and stay on the pixel grid of their own size. Never CSS `zoom`: it blurs hairlines, scales hit areas
 * unevenly and breaks measuring code.
 *
 *   root font size = 16 px x `--ui-base` x `--ui-scale`         (styles.css)
 *
 * - `--ui-base` is the interface's base size: 1.1 on a desktop (owner, 2026-11-01: "110% should be the new 100% and default"),
 *   1 on a touch screen (a phone already has larger text and 44 px rows of its own).
 * - `--ui-scale` is the slider, relative to that base: 100 % is the standard and the default, and then the property is removed.
 * - The choice is remembered in this browser (`readLocal`), applied before the first paint (`applyStoredUiSize` in main.ts).
 * - The terminal's own font size is a separate setting (it is measured in device pixels for the cell grid) and does not follow.
 * - Code that reads a length from a CSS custom property must resolve it to pixels (`cssPx`), because the property holds rem.
 * - Code that sets a length in pixels from a constant (a popover's widest width, a window's default width) multiplies it by
 *   `currentUiScale()`: the factor the page shows now, base and slider together.
 *
 * Migration: before the base existed the slider was relative to 16 px and stored under `tracer.ui-size`. It is now stored under
 * `tracer.ui-size.v2`, relative to the base, and an old value keeps the size it showed: 110 % of 16 px is today's 100 %
 * (`migrateLegacy`). Someone who left the old slider at 100 % was on the default, and gets the new default.
 */
import { readLocal, writeLocal } from "./local-pref";

export const UI_SIZE = { min: 50, max: 150, step: 5, standard: 100 } as const;
export const UI_SIZE_EVENT = "tracer:ui-size";
/** The base a desktop is drawn at (styles.css `--ui-base`), and what the legacy values were relative to being 1. */
export const UI_BASE = 1.1;
const KEY = "tracer.ui-size.v2";
const LEGACY_KEY = "tracer.ui-size";

/** A size snapped to the slider's steps and kept in range. */
export const clampUiSize = (percent: number): number => Math.min(UI_SIZE.max, Math.max(UI_SIZE.min, Math.round(percent / UI_SIZE.step) * UI_SIZE.step));

/** An old stored size (a percentage of 16 px) as a size relative to the base: the same pixels, to the slider's step. */
export const migrateLegacy = (legacy: number): number => legacy === UI_SIZE.standard ? UI_SIZE.standard : clampUiSize(legacy / UI_BASE);

export function readUiSize(): number {
  const stored = Number(readLocal(KEY));
  if (readLocal(KEY) !== null && Number.isFinite(stored) && stored > 0) return clampUiSize(stored);
  const legacy = Number(readLocal(LEGACY_KEY));
  if (readLocal(LEGACY_KEY) === null || !Number.isFinite(legacy) || legacy <= 0) return UI_SIZE.standard;
  const size = migrateLegacy(legacy);
  // Rewritten once under the new key, so the old one is never read again.
  writeLocal(KEY, String(size));
  try { localStorage.removeItem(LEGACY_KEY); } catch { /* storage may be blocked */ }
  return size;
}

function paint(percent: number): void {
  const root = document.documentElement;
  if (percent === UI_SIZE.standard) root.style.removeProperty("--ui-scale");
  else root.style.setProperty("--ui-scale", String(percent / 100));
}

let factor: number | undefined;
let watching = false;
/**
 * The factor the page shows now (the root's font size over 16 px: the base and the slider together, 1.1 at the default on a
 * desktop). Cached: it only changes with the slider or when the pointer kind flips (a base of 1 on touch).
 */
export function currentUiScale(): number {
  if (!watching) {
    watching = true;
    const forget = (): void => { factor = undefined; };
    window.addEventListener(UI_SIZE_EVENT, forget);
    matchMedia("(pointer: coarse)").addEventListener("change", forget);
  }
  return factor ??= Number.parseFloat(getComputedStyle(document.documentElement).fontSize) / 16 || 1;
}

/** Applies the remembered size. Call once at startup, before the first paint. */
export function applyStoredUiSize(): void { paint(readUiSize()); }

/** Sets, remembers and applies a size; returns the size actually used. */
export function setUiSize(percent: number): number {
  const size = clampUiSize(percent);
  writeLocal(KEY, String(size));
  paint(size);
  factor = undefined;
  window.dispatchEvent(new Event(UI_SIZE_EVENT));
  return size;
}

/**
 * A CSS length held in a custom property (`--bm-x`), in CSS pixels: a probe element takes the length as its width and the browser
 * resolves it. The resolved width, not a rect: a rect includes any transform on the way up (a sidebar that is still scaling open
 * would measure 12 px as 11.8), and a length in a custom property is a layout length.
 */
export function cssPx(el: Element, name: string, fallback: number): number {
  const probe = document.createElement("span");
  probe.style.cssText = `position:absolute;visibility:hidden;pointer-events:none;width:var(${name}, ${fallback}px);height:0`;
  el.append(probe);
  const px = Number.parseFloat(getComputedStyle(probe).width);
  probe.remove();
  return Number.isFinite(px) && px > 0 ? px : fallback;
}
