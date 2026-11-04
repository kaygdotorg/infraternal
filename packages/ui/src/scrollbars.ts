/**
 * Scroll bars only while scrolling (TASTE §4, "Every platform sees its own conventions"). macOS draws an
 * overlay bar only while a surface scrolls; Windows and Linux draw a classic bar all the time. This module
 * gives every scroll container the macOS behaviour on every platform, in two halves:
 *
 * - CSS (packages/ui/styles.css, the `:where(*…)` rules) keeps the bar thin and transparent at rest. The
 *   track keeps its width, so content never shifts when the thumb appears. A surface that sets its own
 *   scrollbar-width still wins, because the rule has zero specificity.
 * - This module sets `data-scrolling` on the surface being scrolled and clears it 800 ms after the last
 *   scroll event. While the attribute is set, the thumb takes the theme's token colour; clearing it fades
 *   the colour out over the CSS transition (none under reduced motion).
 *
 * One passive listener on the document serves every surface, rather than one per surface. Surfaces are
 * built in many modules (including the `?` panel, which this helper must not reach into), so per-surface
 * registration would have to touch all of them; a capture listener costs nothing until something scrolls.
 * It reads no layout and writes only an attribute and a timer. Terminal viewports keep their own behaviour
 * and are skipped here and in CSS.
 */

/** How long after the last scroll event the bar stays up before it fades. */
const HIDE_AFTER_MS = 800;

/** The pending "hide the bar" timer for each surface that is scrolling. */
const hideTimers = new WeakMap<Element, number>();
/** Whether {@link installAutoScrollbars} has already added its listener. */
let installed = false;

/** Shows the bar on the scrolled surface and restarts its hide timer. */
function onScroll(event: Event): void {
  const surface = event.target;
  // The document itself (page scroll) and terminal viewports are not surfaces this module styles.
  if (!(surface instanceof HTMLElement) || surface.closest(".terminal-host")) return;
  // Check before writing: setting an attribute that is already set still dirties the element.
  if (!surface.hasAttribute("data-scrolling")) surface.setAttribute("data-scrolling", "");
  window.clearTimeout(hideTimers.get(surface));
  hideTimers.set(surface, window.setTimeout(() => surface.removeAttribute("data-scrolling"), HIDE_AFTER_MS));
}

/** Installs the one document listener. Idempotent: every mount may call it. */
export function installAutoScrollbars(): void {
  if (installed) return;
  installed = true;
  // Scroll events do not bubble, so the listener must be in the capture phase to see every surface.
  document.addEventListener("scroll", onScroll, { capture: true, passive: true });
}
