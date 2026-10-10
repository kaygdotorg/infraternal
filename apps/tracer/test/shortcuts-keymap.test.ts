/**
 * The D222 keymap rules (packages/ui/src/shortcuts.ts): a printable shortcut matches the character the layout types,
 * Option chords on a Mac match the physical key (Option rewrites the character), AltGr never triggers, and labels
 * show the Ctrl+Shift family on PC and the Command family on a Mac. Platforms are emulated through navigator.
 */
import { beforeEach, expect, test } from "bun:test";
import { comboLabel, keyCaps, matchesCombo, platformCombo, type Combo } from "../../../packages/ui/src/shortcuts";

const setPlatform = (platform: string): void => {
  Object.defineProperty(globalThis, "navigator", { value: { platform, userAgent: "", userAgentData: undefined }, configurable: true });
};

interface Keys { key: string; code: string; ctrl?: boolean; meta?: boolean; alt?: boolean; shift?: boolean; altGraph?: boolean }
/** A keystroke as the browser reports it; only the fields the matcher reads are filled in. */
const press = (keys: Keys): KeyboardEvent => ({
  key: keys.key, code: keys.code, ctrlKey: !!keys.ctrl, metaKey: !!keys.meta, altKey: !!keys.alt, shiftKey: !!keys.shift,
  getModifierState: (name: string) => name === "AltGraph" && !!keys.altGraph,
}) as unknown as KeyboardEvent;

beforeEach(() => setPlatform("Win32"));

test("PC: Ctrl+Shift+K matches the palette chord, plain Ctrl+K does not (it is the terminal's)", () => {
  const palette: Combo = { code: "KeyK", key: "k", mod: true, shift: true };
  expect(matchesCombo(press({ key: "K", code: "KeyK", ctrl: true, shift: true }), palette)).toBe(true);
  expect(matchesCombo(press({ key: "k", code: "KeyK", ctrl: true }), palette)).toBe(false);
});

test("a key-named combo follows the character, so a German layout's ? is the same shortcut as a US ?", () => {
  const panel: Combo = { code: "Minus", key: "?", shift: true };
  // German: ? is Shift+ß (physical Minus). US: ? is Shift+/ (physical Slash). Both type "?".
  expect(matchesCombo(press({ key: "?", code: "Minus", shift: true }), panel)).toBe(true);
  expect(matchesCombo(press({ key: "?", code: "Slash", shift: true }), panel)).toBe(true);
  expect(matchesCombo(press({ key: "_", code: "Slash", shift: true }), panel)).toBe(false);
});

test("Ctrl+Shift+/ matches on a US keyboard, where Shift turns / into ?, and on layouts that type / with Shift", () => {
  const panel: Combo = { code: "Slash", key: "/", mod: true, shift: true };
  expect(matchesCombo(press({ key: "?", code: "Slash", ctrl: true, shift: true }), panel)).toBe(true);
  expect(matchesCombo(press({ key: "/", code: "Digit7", ctrl: true, shift: true }), panel)).toBe(true);
  expect(matchesCombo(press({ key: "/", code: "Slash", ctrl: true }), panel)).toBe(false);
});

test("Ctrl+Shift+] and [ match on US keys that Shift turns into } and {", () => {
  const next: Combo = { code: "BracketRight", key: "]", mod: true, shift: true };
  expect(matchesCombo(press({ key: "}", code: "BracketRight", ctrl: true, shift: true }), next)).toBe(true);
  expect(matchesCombo(press({ key: "]", code: "BracketRight", ctrl: true }), next)).toBe(false);
});

test("Ctrl++ accepts both the plus and the equals key, with or without Shift (Shift is not compared)", () => {
  const up: Combo = { code: "Equal", key: "+", mod: true };
  expect(matchesCombo(press({ key: "+", code: "Equal", ctrl: true, shift: true }), up)).toBe(true);
  expect(matchesCombo(press({ key: "=", code: "Equal", ctrl: true }), up)).toBe(false);
  const alternate: Combo = { code: "Equal", key: "=", mod: true };
  expect(matchesCombo(press({ key: "=", code: "Equal", ctrl: true }), alternate)).toBe(true);
});

test("AltGr never triggers a shortcut, even one that would otherwise match (D206, D222)", () => {
  const close: Combo = { code: "KeyX", key: "x", mod: true, shift: true };
  expect(matchesCombo(press({ key: "x", code: "KeyX", ctrl: true, alt: true, shift: true, altGraph: true }), close)).toBe(false);
  expect(matchesCombo(press({ key: "x", code: "KeyX", ctrl: true, shift: true }), close)).toBe(true);
});

test("Mac: Option chords match the physical key, since Option rewrites the character", () => {
  setPlatform("MacIntel");
  const close = platformCombo({ code: "KeyW", mod: true, alt: true }, { code: "KeyX", key: "x", mod: true, shift: true });
  // Command+Option+W types "∑" on a US Mac: the character is not "w", but the physical key is still W.
  expect(matchesCombo(press({ key: "∑", code: "KeyW", meta: true, alt: true }), close)).toBe(true);
  expect(matchesCombo(press({ key: "w", code: "KeyW", meta: true }), close)).toBe(false);
});

test("labels: PC reads Ctrl and Shift, a Mac reads the glyphs; the panel's ? is shown without a Shift", () => {
  expect(comboLabel({ code: "Slash", key: "/", mod: true, shift: true })).toBe("Ctrl+Shift+/");
  expect(comboLabel({ code: "Minus", key: "?", shift: true })).toBe("?");
  expect(comboLabel({ code: "KeyD", key: "d", mod: true, shift: true })).toBe("Ctrl+Shift+D");
  expect(comboLabel({ code: "Enter", key: "Enter", mod: true, shift: true, alt: true })).toBe("Ctrl+Shift+Alt+Enter");
  expect(comboLabel({ code: "Equal", key: "+", mod: true })).toBe("Ctrl++");
  setPlatform("MacIntel");
  expect(comboLabel({ code: "KeyP", key: "p", mod: true, shift: true })).toBe("⌘⇧P");
  expect(comboLabel({ code: "Enter", key: "Enter", mod: true })).toBe("⌘↩");
  expect(comboLabel({ code: "KeyW", mod: true, alt: true })).toBe("⌥⌘W");
  expect(comboLabel({ code: "Slash", key: "?", shift: true })).toBe("?");
});

test("key caps split the plus key correctly", () => {
  expect(keyCaps("Ctrl++")).toEqual(["Ctrl", "+"]);
  expect(keyCaps("⌘+")).toEqual(["⌘", "+"]);
  expect(keyCaps("Ctrl+Shift+]")).toEqual(["Ctrl", "Shift", "]"]);
});

test("a Mac chord without Shift does not fire with Shift held: ⌘D is not ⌘⇧D (the Mac defaults pin shift:false)", () => {
  setPlatform("MacIntel");
  const splitRight = platformCombo({ code: "KeyD", key: "d", mod: true, shift: false }, { code: "KeyD", key: "d", mod: true, shift: true });
  expect(matchesCombo(press({ key: "d", code: "KeyD", meta: true }), splitRight)).toBe(true);
  expect(matchesCombo(press({ key: "D", code: "KeyD", meta: true, shift: true }), splitRight)).toBe(false);
  const newRight = platformCombo({ code: "Enter", key: "Enter", mod: true, shift: false }, { code: "Enter", key: "Enter", mod: true, shift: true });
  expect(matchesCombo(press({ key: "Enter", code: "Enter", meta: true, shift: true }), newRight)).toBe(false);
});
