/**
 * Platform facts the shortcut UI needs. `isMacPlatform()` decides which modifier a shortcut is
 * shown and matched with (⌘ on macOS and iPadOS keyboards, Ctrl elsewhere). Read once per
 * call, never cached, so a test can emulate either platform before the page loads.
 */
/** True on macOS, iPhone and iPad, judged from the browser's platform hint (falling back to the user agent). */
export function isMacPlatform(): boolean {
  const hint = navigator.platform || (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData?.platform || navigator.userAgent;
  return /mac|iphone|ipad/i.test(hint);
}

/**
 * Whether a hardware keyboard is likely, so shortcut hints (key caps and "· ⌘1" tails) are worth showing. One rule for every
 * surface: a phone reports a coarse pointer with no hover and has no keys to hint at, while a desktop, and an iPad with a
 * keyboard and trackpad that reports a fine pointer or hover, keep them. Read on each call, so it follows a changed device.
 */
export function keyboardLikely(): boolean {
  return typeof matchMedia !== "function" || !matchMedia("(hover: none) and (pointer: coarse)").matches;
}

/** A shortcut written once for each platform; `shortcutLabel` picks the one that works here. */
export interface PlatformKeys { mac: string; other: string }

/**
 * Modifier words that a written key label ("Ctrl+Shift+L") turns into Apple glyphs on a Mac keyboard.
 * A written label names physical keys, so Ctrl is the Control key on every platform; only its
 * rendering changes. Glyphs are never shown elsewhere (Windows and Linux read the words).
 */
const MAC_GLYPHS: Record<string, string> = { Ctrl: "⌃", Control: "⌃", Alt: "⌥", Option: "⌥", Shift: "⇧", Cmd: "⌘", Command: "⌘", Meta: "⌘" };

/** A written key label as this platform shows it: "Ctrl+Shift+L" → "⌃⇧L" on a Mac, unchanged elsewhere. */
export function keysLabel(keys: string): string {
  if (keys.length < 2 || !keys.includes("+") || !isMacPlatform()) return keys;
  // A label can end in the plus key itself ("Ctrl++", "⌘+"). Splitting on "+" would drop it (it left a lone "⌘"), so the
  // trailing plus is taken as the key first and the rest is split into modifiers.
  const plusKey = keys.endsWith("+");
  let head = plusKey ? keys.slice(0, -1) : keys;
  if (plusKey && head.endsWith("+")) head = head.slice(0, -1);
  const parts = head ? head.split("+") : [];
  const key = plusKey ? "+" : parts.pop() ?? "";
  return parts.map((part) => MAC_GLYPHS[part] ?? part).join("") + key;
}

/** The label of a shortcut for this platform: a written label goes through {@link keysLabel}, a {@link PlatformKeys} pair picks `mac` or `other`. */
export const shortcutLabel = (keys: PlatformKeys | string): string => typeof keys === "string" ? keysLabel(keys) : isMacPlatform() ? keys.mac : keys.other;
