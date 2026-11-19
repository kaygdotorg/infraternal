/** Icons are fetched once per content hash, checked, and kept by hash (#146, D349). */
import { expect, test } from "bun:test";
import { AppIcons, checkedIcon, isIconHash } from "./app-icons";

/** A tiny real PNG (1 × 1); the browser-side check is signature, size and hash, not dimensions. */
const PNG = Uint8Array.from(atob("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/0xAAAAAASUVORK5CYII="), (c) => c.charCodeAt(0));
/** Base64 of `bytes`, as the server sends icons. */
const base64 = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes));
/** The lowercase hex SHA-256 of `bytes`: an icon's name. */
const hashOf = async (bytes: Uint8Array<ArrayBuffer>): Promise<string> =>
  Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (b) => b.toString(16).padStart(2, "0")).join("");

test("an icon must be a PNG of at most 16 KiB whose SHA-256 is the name asked for", async () => {
  const hash = await hashOf(PNG);
  expect(isIconHash(hash)).toBe(true);
  expect(await checkedIcon({ png: base64(PNG) }, hash)).toEqual(PNG);
  expect(await checkedIcon({ png: base64(PNG) }, "0".repeat(64))).toBeUndefined();
  const gif = new TextEncoder().encode("GIF89a-not-a-png");
  expect(await checkedIcon({ png: base64(gif) }, await hashOf(gif))).toBeUndefined();
  const big = new Uint8Array(16 * 1024 + 1); big.set(PNG);
  expect(await checkedIcon({ png: base64(big) }, await hashOf(big))).toBeUndefined();
  expect(await checkedIcon({ png: "%%%" }, hash)).toBeUndefined();
});

test("one hash is fetched once, shared by concurrent loads, and a bad answer is not asked again", async () => {
  const hash = await hashOf(PNG);
  const calls: Array<Record<string, unknown>> = [];
  let changes = 0;
  const icons = new AppIcons(async (action, input) => {
    expect(action).toBe("desktop.icon");
    calls.push(input);
    return { png: base64(PNG) };
  });
  icons.onChange(() => { changes++; });
  const [a, b] = await Promise.all([icons.load("mac", hash), icons.load("mac", hash)]);
  expect(a).toBeDefined();
  expect(a).toBe(b);
  expect(icons.url(hash)).toBe(a);
  expect(await icons.load("other-mac", hash)).toBe(a);
  expect(calls).toEqual([{ host_id: "mac", sha256: hash }]);
  expect(changes).toBe(1);
  // The host answers the wrong bytes for this name: refused once, never asked again.
  const wrong = "1".repeat(64);
  expect(await icons.load("mac", wrong)).toBeUndefined();
  expect(await icons.load("mac", wrong)).toBeUndefined();
  expect(calls.length).toBe(2);
  expect(await icons.load("mac", "not-a-hash")).toBeUndefined();
  expect(calls.length).toBe(2);
  icons.dispose();
});
