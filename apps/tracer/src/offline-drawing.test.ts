/** Offline identity is display data only, account-scoped and erased by sign-out (D245, #243). */
import { expect, test } from "bun:test";
import { cachedDrawingIdentity } from "./offline-drawing";
import { canvasKey, clearAccountStorage, drawingIdentityKey, lastAccountKey } from "./account-storage";
test("cached identity needs a matching layout and sign-out removes it", async () => {
  const values = new Map<string, string>();
  const original = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  const originalSession = Object.getOwnPropertyDescriptor(globalThis, "sessionStorage");
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: { getItem: (k: string) => values.get(k) ?? null, setItem: (k: string, v: string) => values.set(k, v), removeItem: (k: string) => values.delete(k), key: (i: number) => [...values.keys()][i] ?? null, get length() { return values.size; } } });
  Object.defineProperty(globalThis, "sessionStorage", { configurable: true, value: localStorage });
  const id = "12345678-1234-4234-8234-123456789abc";
  try {
    // Write the exact public subset directly: no worker registration is needed in this unit check.
    localStorage.setItem(lastAccountKey, id);
    localStorage.setItem(drawingIdentityKey(id), JSON.stringify({ user_id: id, hostname: "host", username: "person", fresh: 999, cookie: "untrusted" }));
    expect(await cachedDrawingIdentity()).toBeUndefined();
    localStorage.setItem(canvasKey(id), JSON.stringify({ format: "infraternal.canvas", version: 1, revision: 1, views: [] }));
    expect(await cachedDrawingIdentity()).toEqual({ user_id: id, hostname: "host", username: "person" });
    clearAccountStorage(id); expect(await cachedDrawingIdentity()).toBeUndefined(); expect(values.size).toBe(0);
  } finally { if (original) Object.defineProperty(globalThis, "localStorage", original); else Reflect.deleteProperty(globalThis, "localStorage"); if (originalSession) Object.defineProperty(globalThis, "sessionStorage", originalSession); else Reflect.deleteProperty(globalThis, "sessionStorage"); }
});
