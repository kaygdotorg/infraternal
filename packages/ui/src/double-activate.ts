// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The gesture that starts an in-place rename (#259): a double click with a mouse, a double tap with a finger or pen. It is
 * its own small module because a tree has to listen for it from the first screen, while the field itself
 * (inline-rename.on-demand.ts) loads only when a rename starts.
 *
 * Touch needs its own detection: a double tap is not reliably a `dblclick` on every phone browser, and the browser's own
 * double-tap zoom must not run on the name (`touch-action: manipulation`).
 */

/** A second tap this soon after the first, and this close to it, is a double tap (a mouse gets the system's double-click time). */
const DOUBLE_TAP_MS = 320;
/** The same, for a mouse: a click pair this close in time counts. */
const DOUBLE_CLICK_MS = 500;
/** Pixels: a second press this close to the first is on the same spot even if the list moved a different row under it. */
const SAME_SPOT = 6;
/** Pixels: the most two taps on the same row may be apart; a press that moves more than half of it is a drag. */
const DOUBLE_TAP_SLOP = 24;

/** The last tap per element, kept outside the listeners: a list that is rebuilt after the first tap re-attaches them. */
const lastTaps = new WeakMap<HTMLElement, { x: number; y: number; at: number; key: unknown } | undefined>();

/**
 * Listens for a double click (mouse) or double tap (touch, pen) on `target` and calls
 * `handler(event, key)` with the key of the first press.
 *
 * Why it reads pointer events and not only `dblclick`: that event is skipped when the first
 * click rebuilt the list, so the second click lands on a new button (opening a session does this).
 * A press that moves more than 12 px is a drag or scroll and ends the sequence. The element is
 * set to `touch-action: manipulation` so the browser's double-tap zoom never swallows the second tap.
 *
 * @param target the element to listen on; one listener can serve every row of a list
 * @param handler called once per double activation
 * @param signal aborting it removes every listener this call added
 * @param keyOf identifies the row under the pointer (return `undefined` where nothing can be renamed);
 *   both presses must hit the same key. By default the key is the target itself.
 */
export function onDoubleActivate(target: HTMLElement, handler: (event: Event, key: unknown) => void, signal: AbortSignal, keyOf: (event: Event) => unknown = () => target): void {
  target.style.touchAction ||= "manipulation";
  target.addEventListener("dblclick", (event) => { if (keyOf(event) === undefined) return; event.preventDefault(); handler(event, keyOf(event)); }, { signal });
  let down: { x: number; y: number } | undefined;
  target.addEventListener("pointerdown", (event) => { down = event.button === 0 ? { x: event.clientX, y: event.clientY } : undefined; }, { signal });
  target.addEventListener("pointerup", (event) => {
    if (!down) return;
    const moved = Math.hypot(event.clientX - down.x, event.clientY - down.y) > DOUBLE_TAP_SLOP / 2;
    down = undefined;
    if (moved) { lastTaps.delete(target); return; }
    const now = event.timeStamp, key = keyOf(event), last = lastTaps.get(target);
    const apart = last ? Math.hypot(event.clientX - last.x, event.clientY - last.y) : Infinity;
    // The same thing twice, or (a list that was rebuilt and re-sorted under a pointer that did not move: opening a session moves it
    // to the top, and the release can land on the gap or on another row) anything at the same spot: the first one is the one
    // meant, and `handler` gets its key.
    if (last && now - last.at <= (event.pointerType === "mouse" ? DOUBLE_CLICK_MS : DOUBLE_TAP_MS) && (last.key === key ? apart <= DOUBLE_TAP_SLOP : apart <= SAME_SPOT)) {
      lastTaps.delete(target);
      handler(event, last.key);
    } else if (key === undefined) lastTaps.delete(target);
    else lastTaps.set(target, { x: event.clientX, y: event.clientY, at: now, key });
  }, { signal });
  target.addEventListener("pointercancel", () => { down = undefined; }, { signal });
}
