// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Guards the vendored ghostty-web KeyEncoder binding against libghostty-vt WASM ABI drift (#607).
 *
 * Loads the checked-in `ghostty-vt.wasm` and exercises `KeyEncoder.setOption` and `KeyEncoder.encode`
 * for the keys that bypass InputHandler's JavaScript fast path: Ctrl+letter chords, Alt+letter chords,
 * and arrow keys in both normal and DECCKM application cursor mode. Also verifies that every
 * `exports.ghostty_*` symbol referenced by `ghostty-web.js` is exported by `ghostty-vt.wasm`.
 */
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Ghostty, Key, KeyAction, KeyEncoderOption, Mods } from "../vendor/ghostty-web";

const VENDOR_DIR = resolve(import.meta.dir, "../vendor/ghostty-web/dist");
const WASM_PATH = resolve(VENDOR_DIR, "ghostty-vt.wasm");
const JS_PATH = resolve(VENDOR_DIR, "ghostty-web.js");
const decoder = new TextDecoder();

/** Loads the vendored Ghostty WASM engine once for this file. */
const enginePromise = Ghostty.load(WASM_PATH);

describe("ghostty-web KeyEncoder ABI (#607)", () => {
  test("every ghostty_* WASM export called by ghostty-web.js exists in ghostty-vt.wasm", async () => {
    const wasmBytes = readFileSync(WASM_PATH);
    const mod = await WebAssembly.compile(wasmBytes);
    const exportNames = new Set(WebAssembly.Module.exports(mod).map((e) => e.name));

    const js = readFileSync(JS_PATH, "utf8");
    const called = [...new Set(Array.from(js.matchAll(/exports\.(ghostty_[a-zA-Z0-9_]+)/g), (m) => m[1]!))];
    expect(called.length).toBeGreaterThan(30);

    const missing = called.filter((name) => !exportNames.has(name));
    expect(missing).toEqual([]);
  });

  test("encodes Ctrl+key combinations to C0 control bytes", async () => {
    const ghostty = await enginePromise;
    const encoder = ghostty.createKeyEncoder();
    try {
      const cases: Array<[string, Key, string, string]> = [
        ["Ctrl+A", Key.A, "a", "\x01"],
        ["Ctrl+C", Key.C, "c", "\x03"],
        ["Ctrl+D", Key.D, "d", "\x04"],
        ["Ctrl+R", Key.R, "r", "\x12"],
      ];
      for (const [label, key, utf8, expected] of cases) {
        encoder.setOption(KeyEncoderOption.CURSOR_KEY_APPLICATION, false);
        const bytes = encoder.encode({
          action: KeyAction.PRESS,
          key,
          mods: Mods.CTRL,
          utf8,
        });
        expect(decoder.decode(bytes), label).toBe(expected);
      }
    } finally {
      encoder.dispose();
    }
  });

  test("encodes arrow keys in both normal CSI and DECCKM application SS3 modes", async () => {
    const ghostty = await enginePromise;
    const encoder = ghostty.createKeyEncoder();
    try {
      const arrows: Array<[string, Key, string, string]> = [
        ["ArrowUp", Key.UP, "\x1b[A", "\x1bOA"],
        ["ArrowDown", Key.DOWN, "\x1b[B", "\x1bOB"],
        ["ArrowRight", Key.RIGHT, "\x1b[C", "\x1bOC"],
        ["ArrowLeft", Key.LEFT, "\x1b[D", "\x1bOD"],
      ];
      for (const [label, key, normalSeq, appSeq] of arrows) {
        encoder.setOption(KeyEncoderOption.CURSOR_KEY_APPLICATION, false);
        expect(decoder.decode(encoder.encode({ action: KeyAction.PRESS, key, mods: Mods.NONE })), `${label} normal`).toBe(normalSeq);

        encoder.setOption(KeyEncoderOption.CURSOR_KEY_APPLICATION, true);
        expect(decoder.decode(encoder.encode({ action: KeyAction.PRESS, key, mods: Mods.NONE })), `${label} app`).toBe(appSeq);
      }
    } finally {
      encoder.dispose();
    }
  });

  test("encodes modified arrows and Alt+letter with UTF-8 GhosttyString", async () => {
    const ghostty = await enginePromise;
    const encoder = ghostty.createKeyEncoder();
    try {
      encoder.setOption(KeyEncoderOption.CURSOR_KEY_APPLICATION, false);
      encoder.setOption(KeyEncoderOption.ALT_ESC_PREFIX, true);

      const ctrlLeft = encoder.encode({ action: KeyAction.PRESS, key: Key.LEFT, mods: Mods.CTRL });
      expect(decoder.decode(ctrlLeft)).toBe("\x1b[1;5D");

      const altB = encoder.encode({ action: KeyAction.PRESS, key: Key.B, mods: Mods.ALT, utf8: "b" });
      expect(decoder.decode(altB)).toBe("\x1bb");
    } finally {
      encoder.dispose();
    }
  });
});
