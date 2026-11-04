/**
 * Keyboard Lock in fullscreen (D222). When the app enters fullscreen through its own fullscreen action and the browser
 * has the Keyboard Lock API (Chromium-based browsers and Safari 26.4 and later; not Firefox), the reserved keys reach the
 * page: ⌘W and Ctrl+Shift+W close the window too, and any reserved key that is not ours (Ctrl+W, Ctrl+T on PC) goes into
 * the focused terminal, as in a native terminal. Leaving fullscreen releases the keys. Automatic, with no setting.
 *
 * The lock needs a user gesture and a fullscreen element, so it is taken only in `enterAppFullscreen`, never on a timer
 * or on page load. Feature detection decides everything: where `navigator.keyboard.lock` is missing the functions do
 * nothing and the app keeps the default chords. Nothing here names a shortcut; the bindings that use the lock are in the
 * canvas (`isKeyboardLocked` gates the lock-only alternates).
 */

/** The part of `navigator.keyboard` the lock uses (the Keyboard Lock API, Chromium and Safari). */
export interface KeyboardLockApi {
  lock?(keyCodes?: readonly string[]): Promise<void>;
  unlock?(): void;
}

let locked = false;

/** Whether the reserved keys are held right now (true only between a successful lock and the release). */
export const isKeyboardLocked = (): boolean => locked;

/** Whether this browser has the Keyboard Lock API at all. */
export const keyboardLockSupported = (keyboard: KeyboardLockApi | undefined = navigatorKeyboard()): boolean => typeof keyboard?.lock === "function";

/**
 * Takes every key for the page (no key codes means all keys; the browser still keeps its own escape, a long press of Esc,
 * and the OS keys). Resolves to whether the lock is now held. A refused lock (no fullscreen, no gesture) leaves the
 * app on the default chords rather than failing.
 */
export async function lockReservedKeys(keyboard: KeyboardLockApi | undefined = navigatorKeyboard()): Promise<boolean> {
  if (!keyboard?.lock) return (locked = false);
  try {
    await keyboard.lock();
    locked = true;
  } catch {
    locked = false;
  }
  return locked;
}

/** Gives the reserved keys back to the browser. Safe to call when nothing is held. */
export function releaseReservedKeys(keyboard: KeyboardLockApi | undefined = navigatorKeyboard()): void {
  locked = false;
  keyboard?.unlock?.();
}

/**
 * Enters fullscreen on `element` (a user gesture is required, so call this from the action itself) and takes the reserved
 * keys once the element is full. Leaving fullscreen by any route (Esc, the browser's own control) releases them.
 */
export async function enterAppFullscreen(element: HTMLElement): Promise<void> {
  if (typeof document === "undefined") return;
  await element.requestFullscreen();
  if (document.fullscreenElement === element) await lockReservedKeys();
}

if (typeof document !== "undefined") {
  document.addEventListener("fullscreenchange", () => {
    if (!document.fullscreenElement) releaseReservedKeys();
  });
}

/** `navigator.keyboard` when it exists; `undefined` on the server and in browsers without the API. */
function navigatorKeyboard(): KeyboardLockApi | undefined {
  return typeof navigator === "undefined" ? undefined : (navigator as Navigator & { keyboard?: KeyboardLockApi }).keyboard;
}
