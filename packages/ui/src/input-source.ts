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
 * The source is written to the root as `data-input="keyboard" | "pointer"`, in the same task as the event. CSS therefore
 * sees it in the same style recalculation that applies the surface's new state, so a rule such as
 * `:root[data-input="keyboard"] .palette { transition: none }` removes the transition for both an open and a close. Script
 * reads {@link triggeredByKeyboard} the same way. Because each new event overwrites the last one, a pointer close of a
 * keyboard-opened surface may animate and a keyboard close of a pointer-opened one is instant, with no extra bookkeeping.
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
  const key = (event: Event): void => { if (!MODIFIER_KEYS.has((event as KeyboardEvent).key)) set("keyboard"); };
  const pointer = (): void => set("pointer");
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
