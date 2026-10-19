/** Offline identity is display data only, account-scoped and erased by sign-out (D245, #243). */
import { expect, test } from "bun:test";
import { cachedDrawingIdentity } from "./offline-drawing";
import { cacheDrawingIdentity } from "./offline-cache";
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
    const document = { format: "infraternal.canvas", version: 1, revision: 1, views: [] };
    localStorage.setItem(canvasKey(id), JSON.stringify({ cacheVersion: 2, canonical: document, document, pending: [] }));
    expect(await cachedDrawingIdentity()).toEqual({ user_id: id, hostname: "host", username: "person" });
    localStorage.setItem(canvasKey(id), JSON.stringify({ cacheVersion: 2, canonical: {}, document, pending: [] }));
    expect(await cachedDrawingIdentity()).toBeUndefined();
    clearAccountStorage(id); expect(await cachedDrawingIdentity()).toBeUndefined(); expect(values.size).toBe(0);
  } finally { if (original) Object.defineProperty(globalThis, "localStorage", original); else Reflect.deleteProperty(globalThis, "localStorage"); if (originalSession) Object.defineProperty(globalThis, "sessionStorage", originalSession); else Reflect.deleteProperty(globalThis, "sessionStorage"); }
});

test("sign-in caches only public drawing labels", () => {
  const values = new Map<string, string>();
  const original = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: { getItem: (k: string) => values.get(k) ?? null, setItem: (k: string, v: string) => values.set(k, v), removeItem: (k: string) => values.delete(k), key: (i: number) => [...values.keys()][i] ?? null, get length() { return values.size; } } });
  const id = "12345678-1234-4234-8234-123456789abc";
  try {
    cacheDrawingIdentity({ user_id: id, hostname: "host", username: "person", display_name: "Person", recovery_pending: { ready_at: 10 } });
    expect(values.get(lastAccountKey)).toBe(id);
    expect(JSON.parse(values.get(drawingIdentityKey(id))!)).toEqual({ user_id: id, hostname: "host", username: "person", display_name: "Person" });
  } finally { if (original) Object.defineProperty(globalThis, "localStorage", original); else Reflect.deleteProperty(globalThis, "localStorage"); }
});
