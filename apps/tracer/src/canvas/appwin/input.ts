/**
 * Turns browser input into the wire's `VideoInput` messages (contracts/wire.md §9) for an app window or a screen.
 *
 * - Keyboard layout text and held shortcuts use the shared protocol DesktopKeyboard adapter.
 * - Pointer positions are millionths of the stream's frame (0–1,000,000), measured on the picture itself. The
 *   picture sits letterboxed inside the window when its shape differs (an app that refuses a size, D208 A2), and
 *   CSS bands are rejected before input is sent; they do not name a remote edge. Clamped coordinates are retained
 *   for callers, while `inside` distinguishes a new input from a release of a previously held button.
 * - Scroll is sent in pixels, positive towards the content's top, which is the opposite sign of a browser wheel.
 * - Modifier bits follow the helper contract: 1 shift, 2 control, 4 option, 8 command.
 *
 * Pure functions, no DOM state: unit-tested in `input.test.ts`.
 */
export { modifierBits } from "../../../../../packages/protocol/src/desktop-input";

/** Where the picture sits inside its box: the largest rectangle of the frame's shape that fits (object-fit: contain). */
export function containedRect(box: { width: number; height: number }, frame: { width: number; height: number }): { x: number; y: number; width: number; height: number } {
  if (!frame.width || !frame.height || !box.width || !box.height) return { x: 0, y: 0, width: box.width, height: box.height };
  const k = Math.min(box.width / frame.width, box.height / frame.height);
  const width = frame.width * k, height = frame.height * k;
  return { x: (box.width - width) / 2, y: (box.height - height) / 2, width, height };
}

/** A 0–1 fraction as the wire's integer millionths, clamped to 0–1,000,000. */
const clampMillionths = (v: number): number => Math.min(1_000_000, Math.max(0, Math.round(v * 1_000_000)));

/**
 * A pointer position inside `box` as the wire's coordinates on the picture. `offsetX/offsetY` are relative to the box's
 * layout size (the camera's zoom is divided out by the caller), `picture` is where the frame sits inside it.
 */
export function framePoint(offsetX: number, offsetY: number, picture: { x: number; y: number; width: number; height: number }): { x: number; y: number; inside: boolean } {
  if (picture.width <= 0 || picture.height <= 0) return { x: 0, y: 0, inside: false };
  const inside = offsetX >= picture.x && offsetY >= picture.y && offsetX < picture.x + picture.width && offsetY < picture.y + picture.height;
  return { x: clampMillionths((offsetX - picture.x) / picture.width), y: clampMillionths((offsetY - picture.y) / picture.height), inside };
}

/** Wire mouse buttons: 0 left, 1 right, 2 middle. Other buttons (back, forward) have no wire code. */
export function wireButton(button: number): number | undefined {
  return button === 0 ? 0 : button === 2 ? 1 : button === 1 ? 2 : undefined;
}

/** A wheel event as pixels, positive towards the content's top. Lines and pages are turned into pixels first. */
export function scrollDelta(e: Pick<WheelEvent, "deltaX" | "deltaY" | "deltaMode">, lineHeight = 16, pageHeight = 600): { dx: number; dy: number } {
  const k = e.deltaMode === 1 ? lineHeight : e.deltaMode === 2 ? pageHeight : 1;
  const clamp = (v: number): number => Math.max(-2_000_000, Math.min(2_000_000, Math.round(v)));
  // `-0` would encode as zero anyway; the explicit `|| 0` keeps tests and logs free of negative zeros.
  return { dx: clamp(-e.deltaX * k) || 0, dy: clamp(-e.deltaY * k) || 0 };
}

/**
 * Whether the machine's pointer should hear about a move now. Moves are the only high-rate input; they are coalesced to
 * one per animation frame by the caller, and this keeps the position changes that matter: a move that lands on the
 * same millionth as the last sent one is dropped.
 */
export function movedEnough(prev: { x: number; y: number } | undefined, next: { x: number; y: number }): boolean {
  return !prev || prev.x !== next.x || prev.y !== next.y;
}
