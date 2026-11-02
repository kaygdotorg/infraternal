/** Role: checks browser input mapping independently of browser presentation [D208]. */
import { expect, test } from "bun:test";
import { keyboardInput, modifierBits, pointerCoordinates, pointerButton, scrollInput, MAC_KEYCODES, DesktopKeyboard } from "./desktop-input";
import { decodeDesktop, measureDesktop, writeDesktop } from "./desktop";

test("coordinates reject bands/outside edges and retain subpixel density", () => {
  const rect = { left: -50, top: 10, width: 480, height: 300 };
  expect(pointerCoordinates(190, 160, rect)).toEqual({ x: 500_000, y: 500_000 });
  expect(pointerCoordinates(-50, 10, rect)).toEqual({ x: 0, y: 0 });
  expect(pointerCoordinates(430, 10, rect)).toBe(null);
  expect(pointerCoordinates(10, 310, rect)).toBe(null);
  expect(pointerCoordinates(NaN, 10, rect)).toBe(null);
  expect(pointerCoordinates(10, 10, { ...rect, width: 0 })).toBe(null);
  expect(pointerButton(0)).toBe(0); expect(pointerButton(1)).toBe(2); expect(pointerButton(2)).toBe(1);
  expect(pointerButton(3)).toBe(null);
});
test("physical keys, modifiers and committed layout text have distinct encodings", () => {
  for (let bits = 0; bits < 16; bits++) expect(modifierBits({ shiftKey: !!(bits & 1), ctrlKey: !!(bits & 2), altKey: !!(bits & 4), metaKey: !!(bits & 8) })).toBe(bits);
  expect(new Set(Object.values(MAC_KEYCODES)).size).toBe(Object.keys(MAC_KEYCODES).length);
  const e = { code: "KeyY", key: "z", shiftKey: false, ctrlKey: false, altKey: false, metaKey: false, isComposing: false };
  expect(keyboardInput(e, true)).toEqual({ kind: "text", scalar: 122 });
  expect(keyboardInput(e, false)).toBe(null);
  expect(keyboardInput({ ...e, key: "😀" }, true)).toEqual({ kind: "text", scalar: 0x1f600 });
  expect(keyboardInput({ ...e, key: "Dead" }, true)).toBe(null);
  expect(keyboardInput({ ...e, isComposing: true }, true)).toBe(null);
  expect(keyboardInput({ ...e, ctrlKey: true }, true)).toEqual({ kind: "key", keycode: 16, down: true, modifiers: 2 });
  expect(keyboardInput({ ...e, code: "ArrowLeft", key: "ArrowLeft" }, true)).toEqual({ kind: "key", keycode: 123, down: true, modifiers: 0 });
  expect(keyboardInput({ ...e, code: "Unknown", key: "Unknown" }, true)).toBe(null);
  expect(keyboardInput({ ...e, code: "toString", key: "Unknown" }, true)).toBe(null);
});
test("wheel units become bounded signed native pixel deltas", () => {
  expect(scrollInput({ x: 500_000, y: 500_000 }, 1.5, -3, 0, 800, 0)).toEqual({ kind: "scroll", x: 500_000, y: 500_000, dx: -2, dy: 3, modifiers: 0 });
  expect(scrollInput({ x: 0, y: 0 }, 1, 1, 1, 800, 15)?.dy).toBe(-16);
  expect(scrollInput({ x: 0, y: 0 }, 0, 1, 2, 800, 0)?.dy).toBe(-800);
  expect(scrollInput({ x: 0, y: 0 }, Infinity, 0, 0, 800, 0)).toBe(null);
});
test("Unicode scalar extension roundtrips and rejects surrogate/out-of-range text", () => {
  for (const scalar of [32, 0xe9, 0x1f600, 0x10ffff]) {
    const m = { kind: "input", input: { kind: "text", scalar } } as const;
    const { tag, length } = measureDesktop(m); const b = new Uint8Array(length);
    writeDesktop(m, b, 0); expect(decodeDesktop(tag, b)).toEqual(m);
    expect(() => decodeDesktop(tag, b.subarray(0, length - 1))).toThrow();
  }
  for (const scalar of [0, 31, 127, 0xd800, 0xdfff, 0x110000, -1, NaN]) expect(() => measureDesktop({ kind: "input", input: { kind: "text", scalar } })).toThrow();
});
test("server control state is a bounded boolean envelope", () => {
  for (const active of [false, true]) {
    const m = { kind: "input", input: { kind: "control", active } } as const;
    const { tag, length } = measureDesktop(m); const bytes = new Uint8Array(length);
    writeDesktop(m, bytes, 0); expect(decodeDesktop(tag, bytes)).toEqual(m);
  }
  expect(() => decodeDesktop(0x43, Uint8Array.of(5, 2))).toThrow();
  expect(() => decodeDesktop(0x43, Uint8Array.of(5, 1, 0))).toThrow();
});
test("shortcut release follows its press after modifiers change", () => {
  const keyboard = new DesktopKeyboard();
  const e = { code: "KeyY", key: "z", shiftKey: false, ctrlKey: true, altKey: false, metaKey: false, isComposing: false };
  expect(keyboard.input(e, true)).toEqual({ kind: "key", keycode: 16, down: true, modifiers: 2 });
  expect(keyboard.input({ ...e, ctrlKey: false }, false)).toEqual({ kind: "key", keycode: 16, down: false, modifiers: 0 });
  expect(keyboard.input({ ...e, ctrlKey: false }, true)).toEqual({ kind: "text", scalar: 122 });
  expect(keyboard.input(e, false)).toBe(null);
  expect(keyboard.release()).toEqual({ kind: "release" });
});
