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
  const parts = keys.split("+");
  const key = parts.pop() ?? "";
  return parts.map((part) => MAC_GLYPHS[part] ?? part).join("") + key;
}

export const shortcutLabel = (keys: PlatformKeys | string): string => typeof keys === "string" ? keysLabel(keys) : isMacPlatform() ? keys.mac : keys.other;
