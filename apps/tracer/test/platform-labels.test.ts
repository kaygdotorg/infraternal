/**
 * Key labels follow the platform (TASTE: "Every platform sees its own conventions"). A Windows or Linux
 * browser must never show the Apple modifier glyphs; a Mac or iPad keyboard must. The helpers read the
 * platform on every call, so each test swaps `navigator` and restores it afterwards.
 */
import { afterEach, expect, test } from "bun:test";
import { isMacPlatform, keysLabel, shortcutLabel } from "../../../packages/ui/src/platform";
import { comboLabel, keyCaps, PALETTE_KEYS, type Combo } from "../../../packages/ui/src/shortcuts";

const realNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
const APPLE_GLYPHS = /[⌘⌥⌃⇧]/;

function emulate(platform: string, userAgent: string): void {
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { platform, userAgent } });
}

afterEach(() => {
  if (realNavigator) Object.defineProperty(globalThis, "navigator", realNavigator);
  else delete (globalThis as { navigator?: unknown }).navigator;
});

const WINDOWS = { platform: "Win32", userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36" };
const LINUX = { platform: "Linux x86_64", userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36" };
const MAC = { platform: "MacIntel", userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15" };
const IPAD = { platform: "iPad", userAgent: "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15" };

const COMBOS: Combo[] = [
  { code: "KeyK", mod: true },
  { code: "KeyG", mod: true, shift: true },
  { code: "KeyR", ctrl: true, alt: true },
  { code: "KeyD", ctrl: true, alt: true, shift: true },
  { code: "Digit1", mod: true },
  { code: "Escape" },
];

test("Windows and Linux: combo labels and written keys never show an Apple glyph", () => {
  for (const env of [WINDOWS, LINUX]) {
    emulate(env.platform, env.userAgent);
    expect(isMacPlatform()).toBe(false);
    for (const combo of COMBOS) expect(comboLabel(combo)).not.toMatch(APPLE_GLYPHS);
    expect(shortcutLabel(PALETTE_KEYS)).toBe("Ctrl+Shift+K");
    expect(keysLabel("Ctrl+Shift+L")).toBe("Ctrl+Shift+L");
    expect(keysLabel("Shift+Scroll")).toBe("Shift+Scroll");
    expect(keyCaps(PALETTE_KEYS)).toEqual(["Ctrl", "Shift", "K"]);
    expect(comboLabel({ code: "KeyG", mod: true, shift: true })).toBe("Ctrl+Shift+G");
  }
});

test("Mac and iPad keyboards: the same labels are written with Apple glyphs", () => {
  for (const env of [MAC, IPAD]) {
    emulate(env.platform, env.userAgent);
    expect(isMacPlatform()).toBe(true);
    for (const combo of COMBOS.filter((c) => c.mod || c.ctrl || c.alt || c.shift)) expect(comboLabel(combo)).toMatch(APPLE_GLYPHS);
    expect(shortcutLabel(PALETTE_KEYS)).toBe("⌘K");
    expect(keysLabel("Ctrl+Shift+L")).toBe("⌃⇧L");
    expect(keysLabel("Shift+F6")).toBe("⇧F6");
    expect(keysLabel("Esc")).toBe("Esc");
    expect(keyCaps(PALETTE_KEYS)).toEqual(["⌘", "K"]);
    expect(comboLabel({ code: "KeyG", mod: true, shift: true })).toBe("⌘⇧G");
    expect(comboLabel({ code: "KeyR", ctrl: true, alt: true })).toBe("⌃⌥R");
  }
});

test("a platform read from userAgentData counts the same as navigator.platform", () => {
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { platform: "", userAgent: WINDOWS.userAgent, userAgentData: { platform: "Windows" } } });
  expect(isMacPlatform()).toBe(false);
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { platform: "", userAgent: MAC.userAgent, userAgentData: { platform: "macOS" } } });
  expect(isMacPlatform()).toBe(true);
});
