/**
 * The modifier key that turns the mouse wheel into a canvas move (D374, A17).
 *
 * The canvas moves on purpose, never as an overflow of content that ran out of room to scroll. A trackpad or Magic Mouse
 * has sideways swipes for that; an ordinary mouse has only a vertical wheel, so holding this key while turning it moves the
 * canvas sideways from anywhere, content included.
 *
 * Which key is still the owner's to pick: it must be one that no browser takes for itself (zoom, history, text size) on
 * macOS, Windows and Linux. The research and the measured table are on issue #444. Changing the choice is this one constant.
 */

/** The `KeyboardEvent.key` names a wheel modifier can have, one per modifier flag on a `WheelEvent`. */
export type WheelModifier = "Alt" | "Shift" | "Control" | "Meta";

/** The chosen modifier. Provisional until the owner decides (D374 leaves it open). */
export const CANVAS_WHEEL_MODIFIER: WheelModifier = "Alt";

/** True when `e` was made with the canvas modifier held. */
export function canvasModifierHeld(e: WheelEvent): boolean {
  switch (CANVAS_WHEEL_MODIFIER) {
    case "Alt": return e.altKey;
    case "Shift": return e.shiftKey;
    case "Control": return e.ctrlKey;
    case "Meta": return e.metaKey;
  }
}

/**
 * The sideways and vertical amounts a wheel event asks of the canvas. With the modifier held an ordinary wheel's vertical
 * turn becomes a sideways move (as Shift does natively), so a mouse can reach every window in a row.
 */
export function canvasDeltas(e: WheelEvent): { dx: number; dy: number } {
  let dx = e.deltaX, dy = e.deltaY;
  if ((e.shiftKey || canvasModifierHeld(e)) && !dx) { dx = dy; dy = 0; }
  return { dx, dy };
}
