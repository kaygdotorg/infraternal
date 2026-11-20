// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Whether the phone's on-screen keyboard is open, and a watcher that keeps that answer true.
 *
 * iOS Safari does not resize the layout viewport for the keyboard: it shrinks `visualViewport`, and it may send the
 * last `resize` before the keyboard has finished going away, or none at all when a system sheet (a password prompt, the
 * passkey sheet) was on top. A page that only reacts to `visualViewport` events then keeps its "keyboard open" layout
 * (a short window, the key tray floating mid-screen) until a reload. So the answer here is recomputed from the live
 * numbers and from focus, and {@link watchKeyboard} re-reads it a moment after every trigger, whatever the events said.
 */

/** A viewport this much shorter than the layout viewport (in CSS px) counts as "the keyboard is up". */
const KEYBOARD_MIN_PX = 120;
/** Re-reads after a trigger, in ms: the keyboard's close animation takes about 250 ms, and a sheet can add more. */
const SETTLE_MS = [120, 400, 1000] as const;

/** True when the focused element takes text, so a keyboard has a reason to be showing. */
function editableFocused(): boolean {
  const el = document.activeElement;
  if (!(el instanceof HTMLElement)) return false;
  return el.isContentEditable || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement || (el instanceof HTMLInputElement && !["button", "checkbox", "radio", "submit", "reset", "range", "file", "image"].includes(el.type));
}

/**
 * True while the keyboard is up: the visible area is clearly shorter than the layout viewport (after undoing a pinch zoom,
 * which also shrinks it) and a text field has focus. Without a focused field a short viewport is a leftover, not a keyboard.
 */
export function keyboardIsOpen(): boolean {
  const viewport = window.visualViewport;
  if (!viewport) return false;
  return viewport.height * viewport.scale < window.innerHeight - KEYBOARD_MIN_PX && editableFocused();
}

/**
 * Calls `onChange` with the current answer after every viewport, window, focus and page-visibility event, and again 120 ms,
 * 400 ms and 1 s later, so a dropped or early final event cannot leave the layout stuck. Returns the function that stops it.
 */
export function watchKeyboard(onChange: (open: boolean) => void): () => void {
  const timers = new Set<number>();
  const run = (): void => onChange(keyboardIsOpen());
  const trigger = (): void => {
    run();
    for (const timer of timers) window.clearTimeout(timer);
    timers.clear();
    for (const delay of SETTLE_MS) {
      const timer = window.setTimeout(() => { timers.delete(timer); run(); }, delay);
      timers.add(timer);
    }
  };
  const viewport = window.visualViewport;
  viewport?.addEventListener("resize", trigger);
  viewport?.addEventListener("scroll", trigger);
  window.addEventListener("resize", trigger);
  window.addEventListener("orientationchange", trigger);
  window.addEventListener("pageshow", trigger);
  document.addEventListener("focusin", trigger);
  document.addEventListener("focusout", trigger);
  document.addEventListener("visibilitychange", trigger);
  return () => {
    viewport?.removeEventListener("resize", trigger);
    viewport?.removeEventListener("scroll", trigger);
    window.removeEventListener("resize", trigger);
    window.removeEventListener("orientationchange", trigger);
    window.removeEventListener("pageshow", trigger);
    document.removeEventListener("focusin", trigger);
    document.removeEventListener("focusout", trigger);
    document.removeEventListener("visibilitychange", trigger);
    for (const timer of timers) window.clearTimeout(timer);
    timers.clear();
  };
}
