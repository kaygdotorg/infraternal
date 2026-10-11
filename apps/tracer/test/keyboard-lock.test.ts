/** Keyboard Lock (packages/ui/src/keyboard-lock.ts, D222): feature detection, the lock taken and refused, and the release. */
import { expect, test } from "bun:test";
import { isKeyboardLocked, keyboardLockSupported, lockReservedKeys, releaseReservedKeys } from "../../../packages/ui/src/keyboard-lock";

test("no Keyboard Lock API means no lock and no error: the default chords stay in force", async () => {
  expect(keyboardLockSupported(undefined)).toBe(false);
  expect(keyboardLockSupported({})).toBe(false);
  expect(await lockReservedKeys(undefined)).toBe(false);
  expect(isKeyboardLocked()).toBe(false);
});

test("a granted lock is held until it is released, and the release unlocks the keys", async () => {
  let locks = 0, unlocks = 0;
  const keyboard = { lock: async () => { locks++; }, unlock: () => { unlocks++; } };
  expect(keyboardLockSupported(keyboard)).toBe(true);
  expect(await lockReservedKeys(keyboard)).toBe(true);
  expect(isKeyboardLocked()).toBe(true);
  releaseReservedKeys(keyboard);
  expect(isKeyboardLocked()).toBe(false);
  expect({ locks, unlocks }).toEqual({ locks: 1, unlocks: 1 });
});

test("a refused lock (no gesture, not full screen) leaves the keys with the browser and does not throw", async () => {
  const keyboard = { lock: async () => { throw new Error("NotAllowedError"); }, unlock: () => undefined };
  expect(await lockReservedKeys(keyboard)).toBe(false);
  expect(isKeyboardLocked()).toBe(false);
});
