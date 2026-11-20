/**
 * The modifier key that turns the mouse wheel into a canvas move (D374, A17; chosen in D377).
 *
 * The canvas moves on purpose, never as an overflow of content that ran out of room to scroll. A trackpad or Magic Mouse
 * has sideways swipes for that; an ordinary mouse has only a vertical wheel, so holding this key while turning it moves the
 * canvas sideways from anywhere, content included.
 *
 * The owner chose Option/Alt on every OS (D377). Shift is not the modifier: Shift+wheel scrolls content sideways, as the
 * browser does. Alt is safe in every browser because the router cancels every wheel gesture the canvas owns: Firefox's own
 * action for Alt+wheel is history back/forward, and a measured run (Firefox 159, issue #444) showed `preventDefault` on the
 * wheel event stops it, so no Firefox-only fallback key is needed. Changing the choice is this one constant.
 */

/** The `KeyboardEvent.key` names a wheel modifier can have, one per modifier flag on a `WheelEvent`. */
export type WheelModifier = "Alt" | "Shift" | "Control" | "Meta";

/** The chosen modifier: Option/Alt (D377). */
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
 * The sideways and vertical amounts a wheel event asks of the canvas once the canvas has the gesture. With the modifier
 * held, or Shift over bare canvas, the move is sideways only: an ordinary wheel's vertical turn becomes the sideways amount,
 * so a mouse can reach every window in a row, and a trackpad's stray vertical drift is dropped.
 */
export function canvasDeltas(e: WheelEvent): { dx: number; dy: number } {
  if (e.shiftKey || canvasModifierHeld(e)) return { dx: e.deltaX || e.deltaY, dy: 0 };
  return { dx: e.deltaX, dy: e.deltaY };
}

/**
 * How the modifier gesture is written for people, as the keyboard help and tooltips show it: "⌥ + scroll" on a Mac and
 * "Alt + scroll" elsewhere. Derived from the constant, so the words follow a changed choice.
 */
export function canvasModifierKeys(): { mac: string; other: string } {
  const names: Record<WheelModifier, { mac: string; other: string }> = {
    Alt: { mac: "⌥", other: "Alt" },
    Shift: { mac: "⇧", other: "Shift" },
    Control: { mac: "⌃", other: "Ctrl" },
    Meta: { mac: "⌘", other: "Win" },
  };
  const n = names[CANVAS_WHEEL_MODIFIER];
  return { mac: `${n.mac} + scroll`, other: `${n.other} + scroll` };
}
