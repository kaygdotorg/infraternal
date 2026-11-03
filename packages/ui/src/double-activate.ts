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
const DOUBLE_CLICK_MS = 500;
/** A second press this close to the first is on the same spot even if the list moved a different row under it. */
const SAME_SPOT = 6;
const DOUBLE_TAP_SLOP = 24;

/**
 * Calls `handler` on a double click (mouse) or a double tap (touch, pen). A tap that moved is a drag or a scroll and
 * does not count. Both are found from the pointer events by `keyOf`'s key, not from the browser's `dblclick` alone: that
 * one is not sent when the first click rebuilt the list and the second landed on a new button (opening a session does). The element opts out of the browser's double-tap zoom, so the second tap is ours. `keyOf` names the
 * thing under the finger (a row of a list that one listener serves; `undefined`: nothing to rename here): both taps
 * must land on the same one.
 */
/** The last tap per element, kept outside the listeners: a list that is rebuilt after the first tap re-attaches them. */
const lastTaps = new WeakMap<HTMLElement, { x: number; y: number; at: number; key: unknown } | undefined>();

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
