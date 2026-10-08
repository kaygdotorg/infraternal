/**
 * Platform facts the shortcut UI needs. `isMacPlatform()` decides which modifier a shortcut is
 * shown and matched with (⌘ on macOS and iPadOS keyboards, Ctrl elsewhere). Read once per
 * call, never cached, so a test can emulate either platform before the page loads.
 */
export function isMacPlatform(): boolean {
  const hint = navigator.platform || (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData?.platform || navigator.userAgent;
  return /mac|iphone|ipad/i.test(hint);
}

/** A shortcut written once for each platform; `shortcutLabel` picks the one that works here. */
export interface PlatformKeys { mac: string; other: string }
export const shortcutLabel = (keys: PlatformKeys | string): string => typeof keys === "string" ? keys : isMacPlatform() ? keys.mac : keys.other;
