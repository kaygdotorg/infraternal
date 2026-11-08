// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Where the last input came from: the keyboard or a pointer (mouse, pen or touch).
 *
 * Why it exists (#427, owner, 2026-11-08: "Keyboard opens instantly"). Anything opened or closed from a keyboard shortcut
 * appears and disappears with no animation, while the same thing opened with the pointer or a finger keeps its motion. The
 * source is a property of the event that flips the state, so it is tracked once, here, and every surface reads it instead of
 * carrying its own "was this a key?" flag.
 *
 * How it works. One pair of passive listeners on `window`, in the capture phase, so they run before any shortcut or click
 * handler of the same event:
 *
 * - `keydown` sets the source to `"keyboard"`, except a modifier key on its own (Shift, Control, Alt, Meta and the like): holding
 *   one down starts no action and must not cut short a pointer-opened surface's motion (Shift pressed 60 ms into a pointer
 *   open would otherwise end its fade). The last key of a chord is not a modifier, so it still sets the source before the
 *   shortcut's handler runs;
 * - `pointerdown` (which covers mouse, pen and touch) and `wheel` (a mouse wheel or a trackpad swipe, which press nothing) set it
 *   to `"pointer"`. Code reads the source to decide whether a camera flight springs, so a trackpad swipe through the windows
 *   must not be taken for a key press just because the person typed a moment before.
 *
 * Only events the person made count. A script that dispatches a key or pointer event (`isTrusted` false) says nothing about how
 * the person acted, so the tracker ignores it: a pointer click that happens to dispatch a synthetic shortcut still reads as a
 * pointer.
 *
 * The source stays what the last trusted key or pointer press made it, until the next one. That includes Space and Enter on a
 * focused button: the button clicks on keyup (Space) or keydown (Enter), and the click still finds the source "keyboard", so
 * the same button behaves the same way whichever key presses it. The source is only ever read at the moment something
 * changes, so how long ago the key was does not matter.
 *
 * Surfaces do not read the source from CSS by time. Whatever opens, closes or changes state calls {@link markMotion} on its
 * element at that moment, which writes the answer onto the element itself (`data-motion="instant"` or `"animate"`). It stays
 * there until that element's next change, and the surface's CSS keys off its own attribute, so no other easing is touched and
 * there is no window of frames after the key to get wrong. The root also carries `data-input="keyboard" | "pointer"`, for
 * inspection and tests; no style depends on it.
 *
 * Before any input has happened, and for changes that no key caused (a timer, a network event), the source is `"pointer"`,
 * so those keep their animation.
 */

/** The two kinds of input that can open or close a surface. */
export type InputSource = "keyboard" | "pointer";

/** `KeyboardEvent.key` values of keys that only modify other keys; pressing one is not a shortcut by itself. */
const MODIFIER_KEYS: ReadonlySet<string> = new Set(["Shift", "Control", "Alt", "AltGraph", "Meta", "OS", "Super", "Hyper", "Fn", "FnLock", "CapsLock", "NumLock", "ScrollLock"]);

/** The source of the most recent key or pointer press. */
let current: InputSource = "pointer";
/** The disposer of the installed tracker, or `undefined` when none is installed. */
let installed: (() => void) | undefined;

/** The source of the most recent key or pointer press (`"pointer"` before any input). */
export function inputSource(): InputSource {
  return current;
}

/**
 * True when the key that was pressed last is what is running the code now, so a surface that opens or closes should do it
 * with no animation at all. Call it at the moment the state changes, not earlier.
 * @example
 * if (triggeredByKeyboard()) spring.set(1, true); else spring.set(1);
 */
export function triggeredByKeyboard(): boolean {
  return current === "keyboard";
}

/**
 * Says, on each of `elements`, whether the change about to happen to it is keyboard-triggered: writes `data-motion="instant"`
 * when the last input was a key and `data-motion="animate"` otherwise. Call it right before the state flips (before `hidden`
 * changes, a class or attribute toggles), in the same task, so the style recalculation that applies the new state also sees the
 * attribute. The attribute stays until the element's next call. Returns true when the change is instant, so a caller that
 * animates with script can skip its animation too.
 * @example
 * const instant = markMotion(palette, scrim);
 * palette.hidden = false;
 */
export function markMotion(...elements: Array<Element | null | undefined>): boolean {
  const instant = triggeredByKeyboard();
  const value = instant ? "instant" : "animate";
  for (const element of elements) if (element && element.getAttribute("data-motion") !== value) element.setAttribute("data-motion", value);
  return instant;
}

/**
 * Installs the page-wide tracker once (a second call returns the first disposer) and returns its disposer. Marks the root
 * `data-input="pointer"` until the first key is pressed.
 */
export function installInputSource(root: HTMLElement = document.documentElement): () => void {
  if (installed) return installed;
  const set = (source: InputSource): void => {
    current = source;
    // One attribute write per change of source, never per event.
    if (root.dataset.input !== source) root.dataset.input = source;
  };
  const key = (event: Event): void => {
    if (!event.isTrusted || MODIFIER_KEYS.has((event as KeyboardEvent).key)) return;
    set("keyboard");
  };
  const pointer = (event: Event): void => { if (event.isTrusted) set("pointer"); };
  set("pointer");
  window.addEventListener("wheel", pointer, { capture: true, passive: true });
  window.addEventListener("keydown", key, { capture: true, passive: true });
  window.addEventListener("pointerdown", pointer, { capture: true, passive: true });
  installed = () => {
    window.removeEventListener("keydown", key, { capture: true });
    window.removeEventListener("pointerdown", pointer, { capture: true });
    window.removeEventListener("wheel", pointer, { capture: true });
    delete root.dataset.input;
    current = "pointer";
    installed = undefined;
  };
  return installed;
}
