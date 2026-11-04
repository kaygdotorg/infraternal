/**
 * Role: browser pointer, wheel and keyboard conversion for authenticated desktop viewers [D208].
 *
 * Turns DOM events into {@link VideoInput} values for the desktop wire protocol. Use
 * {@link bindDesktopInput} to wire a whole viewer surface, or the smaller helpers
 * ({@link keyboardInput}, {@link pointerCoordinates}, {@link scrollInput}) to build
 * the inputs yourself. The module only produces inputs; the caller sends them.
 */
import type { VideoInput } from "./desktop";

/** The modifier-key flags that `KeyboardEvent`, `PointerEvent` and `WheelEvent` all carry. */
export interface Modifiers { shiftKey: boolean; ctrlKey: boolean; altKey: boolean; metaKey: boolean }
/** Packs modifier flags into the wire bit set: shift 1, control 2, alt 4, meta 8. */
export function modifierBits(e: Modifiers): number {
  return Number(e.shiftKey) | Number(e.ctrlKey) << 1 | Number(e.altKey) << 2 | Number(e.metaKey) << 3;
}
/**
 * Maps a `KeyboardEvent.code` (physical key position) to the host keycode sent in a `key`
 * input. Physical ANSI/ISO positions; printable text follows KeyboardEvent.key instead of
 * this table. A code that is not listed has no host key and is not sent.
 */
export const MAC_KEYCODES: Readonly<Record<string, number>> = Object.freeze({
  KeyA: 0, KeyS: 1, KeyD: 2, KeyF: 3, KeyH: 4, KeyG: 5, KeyZ: 6, KeyX: 7, KeyC: 8, KeyV: 9,
  IntlBackslash: 10, KeyB: 11, KeyQ: 12, KeyW: 13, KeyE: 14, KeyR: 15, KeyY: 16, KeyT: 17,
  Digit1: 18, Digit2: 19, Digit3: 20, Digit4: 21, Digit6: 22, Digit5: 23, Equal: 24, Digit9: 25,
  Digit7: 26, Minus: 27, Digit8: 28, Digit0: 29, BracketRight: 30, KeyO: 31, KeyU: 32,
  BracketLeft: 33, KeyI: 34, KeyP: 35, Enter: 36, KeyL: 37, KeyJ: 38, Quote: 39, KeyK: 40,
  Semicolon: 41, Backslash: 42, Comma: 43, Slash: 44, KeyN: 45, KeyM: 46, Period: 47,
  Tab: 48, Space: 49, Backquote: 50, Backspace: 51, Escape: 53, MetaRight: 54, MetaLeft: 55,
  ShiftLeft: 56, CapsLock: 57, AltLeft: 58, ControlLeft: 59, ShiftRight: 60, AltRight: 61,
  ControlRight: 62, F17: 64, NumpadDecimal: 65, NumpadMultiply: 67, NumpadAdd: 69,
  NumLock: 71, NumpadDivide: 75, NumpadEnter: 76, NumpadSubtract: 78, F18: 79, F19: 80,
  NumpadEqual: 81, Numpad0: 82, Numpad1: 83, Numpad2: 84, Numpad3: 85, Numpad4: 86,
  Numpad5: 87, Numpad6: 88, Numpad7: 89, F20: 90, Numpad8: 91, Numpad9: 92,
  IntlYen: 93, IntlRo: 94, F5: 96, F6: 97, F7: 98, F3: 99, F8: 100, F9: 101,
  F11: 103, F13: 105, F16: 106, F14: 107, F10: 109, F12: 111, F15: 113, Help: 114,
  Home: 115, PageUp: 116, Delete: 117, F4: 118, End: 119, F2: 120, PageDown: 121,
  F1: 122, ArrowLeft: 123, ArrowRight: 124, ArrowDown: 125, ArrowUp: 126,
});
/**
 * Converts one keyboard event into a wire input, or `null` when nothing should be sent.
 * A single printable character typed without Ctrl or Meta becomes a `text` input on key
 * down (key up sends nothing), so the host receives the character the user's layout produced.
 * Anything else becomes a `key` input looked up by `e.code`; unmapped codes give `null`.
 * Composition waits for a committed text input; IME is outside this physical-key adapter.
 * Dead keys and `Unidentified` also give `null`.
 * @param down true for keydown, false for keyup
 */
export function keyboardInput(e: Modifiers & { code: string; key: string; isComposing: boolean }, down: boolean): VideoInput | null {
  if (e.isComposing || e.key === "Dead" || e.key === "Unidentified") return null;
  if (!e.ctrlKey && !e.metaKey && Array.from(e.key).length === 1) {
    const scalar = e.key.codePointAt(0)!;
    if (scalar >= 32 && !(scalar >= 127 && scalar <= 159) && !(scalar >= 0xd800 && scalar <= 0xdfff)) return down ? { kind: "text", scalar } : null;
  }
  const keycode = Object.hasOwn(MAC_KEYCODES, e.code) ? MAC_KEYCODES[e.code] : undefined;
  return keycode === undefined ? null : { kind: "key", keycode, down, modifiers: modifierBits(e) };
}
/**
 * Keyboard state for one viewer: it remembers which host keycode each pressed physical key
 * produced. A keyup releases the physical key chosen at keydown even after Ctrl/Meta is
 * released first.
 */
export class DesktopKeyboard {
  private readonly held = new Map<string, number>();
  /**
   * Converts a key event like {@link keyboardInput}, but a keyup of a key that went down as
   * a `key` input always sends the matching `key` release (same keycode), and a keyup for a
   * key that was never sent gives `null`.
   */
  input(e: Parameters<typeof keyboardInput>[0], down: boolean): VideoInput | null {
    if (!down) {
      const keycode = this.held.get(e.code);
      this.held.delete(e.code);
      return keycode === undefined ? null : { kind: "key", keycode, down: false, modifiers: modifierBits(e) };
    }
    const input = keyboardInput(e, true);
    if (input?.kind === "key") this.held.set(e.code, input.keycode);
    return input;
  }
  /** Forgets all held keys and returns the `release` input that tells the host to do the same. */
  release(): VideoInput { this.held.clear(); return { kind: "release" }; }
}

/**
 * Attach input to an existing viewer surface. The caller sends on its authenticated control stream.
 *
 * Handles pointer down/move/up (with pointer capture and focus on press), wheel, key down/up
 * and the context menu (suppressed). When the surface loses focus or the pointer capture, a
 * `release` input is sent so the host never keeps a stuck key or button. Handled events have
 * `preventDefault` called. The surface needs `tabindex` to receive key events.
 * @param surface the element showing the remote screen
 * @param send called with each input, in order
 * @returns a function that removes every listener and sends a final `release`
 */
export function bindDesktopInput(surface: HTMLElement, send: (input: VideoInput) => void): () => void {
  const keyboard = new DesktopKeyboard();
  const bindings = new AbortController();
  const signal = bindings.signal;
  const pointer = (e: PointerEvent): void => {
    const point = pointerCoordinates(e.clientX, e.clientY, surface.getBoundingClientRect());
    const button = e.type === "pointermove" ? (e.buttons & 1 ? 0 : e.buttons & 2 ? 1 : e.buttons & 4 ? 2 : 0) : pointerButton(e.button);
    if (!point || button === null) return;
    const state = e.type === "pointerdown" ? 1 : e.type === "pointerup" ? 2 : 0;
    if (state === 1) { surface.focus({ preventScroll: true }); surface.setPointerCapture(e.pointerId); }
    send({ kind: "mouse", ...point, button, state, modifiers: modifierBits(e) }); e.preventDefault();
  };
  for (const type of ["pointerdown", "pointermove", "pointerup"] as const) surface.addEventListener(type, pointer, { signal });
  surface.addEventListener("wheel", e => {
    const point = pointerCoordinates(e.clientX, e.clientY, surface.getBoundingClientRect());
    if (!point) return;
    const input = scrollInput(point, e.deltaX, e.deltaY, e.deltaMode, surface.clientHeight, modifierBits(e));
    if (input) { send(input); e.preventDefault(); }
  }, { passive: false, signal });
  for (const type of ["keydown", "keyup"] as const) surface.addEventListener(type, e => {
    const input = keyboard.input(e, type === "keydown");
    if (input) { send(input); e.preventDefault(); }
  }, { signal });
  const release = (): void => { send(keyboard.release()); };
  surface.addEventListener("blur", release, { signal });
  surface.addEventListener("pointercancel", release, { signal });
  surface.addEventListener("lostpointercapture", release, { signal });
  surface.addEventListener("contextmenu", e => e.preventDefault(), { signal });
  return () => { bindings.abort(); release(); };
}
/**
 * Convert CSS coordinates once to millionths; host point density is applied by the helper.
 * @param x client X of the pointer
 * @param y client Y of the pointer
 * @param rect the surface's bounding box
 * @returns the position as 0 to 1_000_000 on each axis, or `null` when the pointer is
 * outside the box, the box is empty, or any number is not finite
 */
export function pointerCoordinates(x: number, y: number, rect: { left: number; top: number; width: number; height: number }): { x: number; y: number } | null {
  if (![x, y, rect.left, rect.top, rect.width, rect.height].every(Number.isFinite) || rect.width <= 0 || rect.height <= 0 || x < rect.left || y < rect.top || x >= rect.left + rect.width || y >= rect.top + rect.height) return null;
  return { x: Math.round((x - rect.left) / rect.width * 1_000_000), y: Math.round((y - rect.top) / rect.height * 1_000_000) };
}
/**
 * Converts a DOM `PointerEvent.button` (0 left, 1 middle, 2 right) to the wire button
 * (0 left, 1 right, 2 middle); `null` for any other button such as back or forward.
 */
export function pointerButton(button: number): number | null { return [0, 2, 1][button] ?? null; }
/**
 * Converts a wheel event into a `scroll` input, or `null` for non-finite deltas, a
 * non-positive `pageHeight` or an unknown `mode`.
 * Native pixel scroll signs are opposite browser wheel signs. Line/page units are explicit.
 * @param point position from {@link pointerCoordinates}
 * @param mode `WheelEvent.deltaMode`: 0 pixels, 1 lines (16 px each), 2 pages (`pageHeight` px)
 * @param pageHeight height of the surface in CSS pixels, used for page-mode deltas
 */
export function scrollInput(point: { x: number; y: number }, dx: number, dy: number, mode: number, pageHeight: number, modifiers: number): Extract<VideoInput, { kind: "scroll" }> | null {
  if (![dx, dy, pageHeight].every(Number.isFinite) || pageHeight <= 0 || ![0, 1, 2].includes(mode)) return null;
  const unit = mode === 1 ? 16 : mode === 2 ? pageHeight : 1;
  const delta = (n: number): number => -Math.round(Math.max(-2147483647, Math.min(2147483647, n * unit)));
  return { kind: "scroll", ...point, dx: delta(dx), dy: delta(dy), modifiers };
}
