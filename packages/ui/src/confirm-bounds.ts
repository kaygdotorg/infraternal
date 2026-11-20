// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Where a confirmation card may sit (D385, #486): a plain function from the window the card is about, the viewport and the
 * card's own height to the box the card must stay inside.
 *
 * - The box is the window's rectangle intersected with the viewport, inset by 9 px on every side, so a window that is
 *   partly panned off screen never puts the card off screen, and the card keeps the same inset as the window's own overlays.
 * - When that box is too small for the card (a short window, a window mostly off screen: narrower than 10 rem, or less
 *   tall than the card), the card falls back to the viewport, inset the same, so it is never cut off.
 * - With no window (a card about a sidebar row) the box is the viewport, inset 12 px as before.
 *
 * Pure so a unit test can pin the edge cases without a browser (`confirm-bounds.test.ts`).
 */

/** A rectangle by its four edges, in viewport pixels. */
export interface Box { left: number; top: number; right: number; bottom: number }

/** The inset kept between a card and its window's edge. */
export const CONFIRM_INSET = 9;
/** The inset kept from the viewport when the card is about nothing inside a window. */
const VIEWPORT_INSET = 12;
/** The narrowest a card may be made to fit a window, in pixels, before the viewport is used instead. */
const MIN_WIDTH = 160;

/** Shrinks a box by `by` on every side (never below zero size). */
function inset(box: Box, by: number): Box {
  const left = box.left + by, top = box.top + by;
  return { left, top, right: Math.max(left, box.right - by), bottom: Math.max(top, box.bottom - by) };
}

/** The box the card must stay inside. `win` is the window's rectangle, or nothing; `cardHeight` is the card's measured height (0 when not yet known). */
export function confirmBox(win: Box | undefined, view: { width: number; height: number }, cardHeight: number): Box {
  const viewport: Box = { left: 0, top: 0, right: view.width, bottom: view.height };
  if (!win) return inset(viewport, VIEWPORT_INSET);
  const shown: Box = { left: Math.max(win.left, 0), top: Math.max(win.top, 0), right: Math.min(win.right, view.width), bottom: Math.min(win.bottom, view.height) };
  const box = inset(shown, CONFIRM_INSET);
  const fits = box.right - box.left >= MIN_WIDTH && box.bottom - box.top >= cardHeight;
  return fits ? box : inset(viewport, CONFIRM_INSET);
}
