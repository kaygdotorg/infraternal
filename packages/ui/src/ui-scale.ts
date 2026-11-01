/**
 * UI size (#283): every length in the stylesheets is in rem and the root font size is the one number that scales the whole
 * interface (`:root { font-size: calc(16px * var(--ui-scale, 1)) }` in styles.css). Never CSS `zoom`: it blurs hairlines,
 * scales hit areas unevenly and breaks measuring code.
 *
 * This module holds what code needs to live with rem lengths. A CSS length held in a custom property (`--bm-x`) is whatever
 * the stylesheet says (`0.75rem`), so code that needs it in pixels asks the browser (`cssPx`), never `parseFloat`.
 */

/**
 * A CSS length held in a custom property, in CSS pixels: a probe element takes the length as its width and the browser
 * resolves it. The resolved width, not a rect: a rect includes any transform on the way up (a sidebar that is still scaling
 * open would measure 12 px as 11.8), and a length in a custom property is a layout length.
 */
export function cssPx(el: Element, name: string, fallback: number): number {
  const probe = document.createElement("span");
  probe.style.cssText = `position:absolute;visibility:hidden;pointer-events:none;width:var(${name}, ${fallback}px);height:0`;
  el.append(probe);
  const px = Number.parseFloat(getComputedStyle(probe).width);
  probe.remove();
  return Number.isFinite(px) && px > 0 ? px : fallback;
}
