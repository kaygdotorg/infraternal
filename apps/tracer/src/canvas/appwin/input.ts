/**
 * Turns browser input into the wire's `VideoInput` messages (contracts/wire.md §9) for an app window or a screen.
 *
 * - Keys are physical: the wire carries the machine's own virtual key codes (0–127), so the keyboard layout of the
 *   machine decides what a key types, exactly as if the person sat at it. `KeyboardEvent.code` names the physical
 *   key, which is why this table is keyed by `code` and never by `key`.
 * - Pointer positions are millionths of the stream's frame (0–1,000,000), measured on the picture itself. The
 *   picture sits letterboxed inside the window when its shape differs (an app that refuses a size, D208 A2), and
 *   positions in the bands are still sent: the machine answers that a band takes no clicks.
 * - Scroll is sent in pixels, positive towards the content's top, which is the opposite sign of a browser wheel.
 * - Modifier bits follow the helper contract: 1 shift, 2 control, 4 option, 8 command.
 *
 * Pure functions, no DOM state: unit-tested in `input.test.ts`.
 */
import type { VideoInput } from "../../../../../packages/protocol/src/desktop";

/** macOS virtual key codes by `KeyboardEvent.code`. */
export const MAC_KEYCODE: Readonly<Record<string, number>> = {
  KeyA: 0, KeyS: 1, KeyD: 2, KeyF: 3, KeyH: 4, KeyG: 5, KeyZ: 6, KeyX: 7, KeyC: 8, KeyV: 9, IntlBackslash: 10, KeyB: 11, KeyQ: 12, KeyW: 13, KeyE: 14, KeyR: 15,
  KeyY: 16, KeyT: 17, Digit1: 18, Digit2: 19, Digit3: 20, Digit4: 21, Digit6: 22, Digit5: 23, Equal: 24, Digit9: 25, Digit7: 26, Minus: 27, Digit8: 28, Digit0: 29,
  BracketRight: 30, KeyO: 31, KeyU: 32, BracketLeft: 33, KeyI: 34, KeyP: 35, Enter: 36, KeyL: 37, KeyJ: 38, Quote: 39, KeyK: 40, Semicolon: 41, Backslash: 42,
  Comma: 43, Slash: 44, KeyN: 45, KeyM: 46, Period: 47, Tab: 48, Space: 49, Backquote: 50, Backspace: 51, Escape: 53, MetaRight: 54, MetaLeft: 55, ShiftLeft: 56,
  CapsLock: 57, AltLeft: 58, ControlLeft: 59, ShiftRight: 60, AltRight: 61, ControlRight: 62, NumpadDecimal: 65, NumpadMultiply: 67, NumpadAdd: 69, NumLock: 71,
  NumpadDivide: 75, NumpadEnter: 76, NumpadSubtract: 78, NumpadEqual: 81, Numpad0: 82, Numpad1: 83, Numpad2: 84, Numpad3: 85, Numpad4: 86, Numpad5: 87, Numpad6: 88,
  Numpad7: 89, Numpad8: 91, Numpad9: 92, IntlYen: 93, IntlRo: 94, F5: 96, F6: 97, F7: 98, F3: 99, F8: 100, F9: 101, F11: 103, F13: 105, F16: 106, F14: 107,
  F10: 109, F12: 111, F15: 113, Help: 114, Insert: 114, Home: 115, PageUp: 116, Delete: 117, F4: 118, End: 119, F2: 120, PageDown: 121, F1: 122,
  ArrowLeft: 123, ArrowRight: 124, ArrowDown: 125, ArrowUp: 126,
};

export const MOD_SHIFT = 1, MOD_CONTROL = 2, MOD_OPTION = 4, MOD_COMMAND = 8;

export function modifierBits(e: Pick<KeyboardEvent, "shiftKey" | "ctrlKey" | "altKey" | "metaKey">): number {
  return (e.shiftKey ? MOD_SHIFT : 0) | (e.ctrlKey ? MOD_CONTROL : 0) | (e.altKey ? MOD_OPTION : 0) | (e.metaKey ? MOD_COMMAND : 0);
}

/** The key message for a physical key, or undefined for a key the machine has no code for. */
export function keyInput(e: Pick<KeyboardEvent, "code" | "shiftKey" | "ctrlKey" | "altKey" | "metaKey">, down: boolean): VideoInput | undefined {
  const keycode = MAC_KEYCODE[e.code];
  return keycode === undefined ? undefined : { kind: "key", keycode, down, modifiers: modifierBits(e) };
}

/** Where the picture sits inside its box: the largest rectangle of the frame's shape that fits (object-fit: contain). */
export function containedRect(box: { width: number; height: number }, frame: { width: number; height: number }): { x: number; y: number; width: number; height: number } {
  if (!frame.width || !frame.height || !box.width || !box.height) return { x: 0, y: 0, width: box.width, height: box.height };
  const k = Math.min(box.width / frame.width, box.height / frame.height);
  const width = frame.width * k, height = frame.height * k;
  return { x: (box.width - width) / 2, y: (box.height - height) / 2, width, height };
}

const clampMillionths = (v: number): number => Math.min(1_000_000, Math.max(0, Math.round(v * 1_000_000)));

/**
 * A pointer position inside `box` as the wire's coordinates on the picture. `offsetX/offsetY` are relative to the box's
 * layout size (the camera's zoom is divided out by the caller), `picture` is where the frame sits inside it.
 */
export function framePoint(offsetX: number, offsetY: number, picture: { x: number; y: number; width: number; height: number }): { x: number; y: number } {
  if (picture.width <= 0 || picture.height <= 0) return { x: 0, y: 0 };
  return { x: clampMillionths((offsetX - picture.x) / picture.width), y: clampMillionths((offsetY - picture.y) / picture.height) };
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
