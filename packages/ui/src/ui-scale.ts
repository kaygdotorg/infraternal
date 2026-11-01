/**
 * UI size (#283, TASTE "The size of the whole UI is the person's to set"): one number, 50 % to 150 %, that scales the whole
 * interface. It is the root font size (`:root { font-size: calc(16px * var(--ui-scale, 1)) }` in styles.css), and every length
 * in the stylesheets is in rem, so type, rows, pills, icons, popovers and hit areas scale together and stay on the pixel
 * grid of their own size. Never CSS `zoom`: it blurs hairlines, scales hit areas unevenly and breaks measuring code.
 *
 * - 100 % is the standard and the default: the custom property is removed, so the page is exactly as it was without this.
 * - The choice is remembered in this browser (`readLocal`), applied before the first paint (`applyStoredUiSize` in main.ts).
 * - The terminal's own font size is a separate setting (it is measured in device pixels for the cell grid) and does not follow.
 * - Code that reads a length from a CSS custom property must resolve it to pixels (`cssPx`), because the property now holds rem.
 */
import { readLocal, writeLocal } from "./local-pref";

export const UI_SIZE = { min: 50, max: 150, step: 5, standard: 100 } as const;
export const UI_SIZE_EVENT = "tracer:ui-size";
const KEY = "tracer.ui-size";

/** A size snapped to the slider's steps and kept in range. */
export const clampUiSize = (percent: number): number => Math.min(UI_SIZE.max, Math.max(UI_SIZE.min, Math.round(percent / UI_SIZE.step) * UI_SIZE.step));

export function readUiSize(): number {
  const raw = Number(readLocal(KEY));
  return Number.isFinite(raw) && raw > 0 ? clampUiSize(raw) : UI_SIZE.standard;
}

function paint(percent: number): void {
  const root = document.documentElement;
  if (percent === UI_SIZE.standard) root.style.removeProperty("--ui-scale");
  else root.style.setProperty("--ui-scale", String(percent / 100));
}

/**
 * The factor in force now (1 at 100 %), read from the root's custom property so it is always what the page shows. For code
 * that sets a length in pixels from a constant (a popover's widest width, the sidebar's width): it multiplies the constant,
 * so the box grows with the type inside it instead of squeezing it.
 */
export function currentUiScale(): number {
  const raw = Number.parseFloat(document.documentElement.style.getPropertyValue("--ui-scale"));
  return Number.isFinite(raw) && raw > 0 ? raw : 1;
}

/** Applies the remembered size. Call once at startup, before the first paint. */
export function applyStoredUiSize(): void { paint(readUiSize()); }

/** Sets, remembers and applies a size; returns the size actually used. */
export function setUiSize(percent: number): number {
  const size = clampUiSize(percent);
  writeLocal(KEY, String(size));
  paint(size);
  window.dispatchEvent(new Event(UI_SIZE_EVENT));
  return size;
}

/**
 * A CSS length held in a custom property (`--bm-x`), in CSS pixels. The property holds whatever the stylesheet says (`0.75rem`),
 * so it is resolved by the browser rather than parsed: a probe element takes the length as its width.
 */
export function cssPx(el: Element, name: string, fallback: number): number {
  const probe = document.createElement("span");
  probe.style.cssText = `position:absolute;visibility:hidden;pointer-events:none;width:var(${name}, ${fallback}px);height:0`;
  el.append(probe);
  // The resolved width, not the rect: a rect includes any transform on the way up (a sidebar that is still scaling open
  // would measure 12 px as 11.8), and a length in a custom property is a layout length.
  const px = Number.parseFloat(getComputedStyle(probe).width);
  probe.remove();
  return Number.isFinite(px) && px > 0 ? px : fallback;
}
