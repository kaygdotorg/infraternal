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

/** A held transfer keeps other icon calls off the socket, including after disposal. */
test("icon transfers run one at a time and disposal skips queued work", async () => {
  const first = await hashOf(PNG);
  const second = "1".repeat(64);
  const third = "2".repeat(64);
  const calls: unknown[] = [];
  let releaseFirst!: (reply: Record<string, unknown>) => void;
  const firstReply = new Promise<Record<string, unknown>>((resolve) => { releaseFirst = resolve; });
  let enterSecond!: () => void;
  const enteredSecond = new Promise<void>((resolve) => { enterSecond = resolve; });
  const icons = new AppIcons(async (_, input) => {
    calls.push(input.sha256);
    if (input.sha256 === first) return firstReply;
    enterSecond();
    return { png: "" };
  });
  const a = icons.load("mac", first);
  const b = icons.load("mac", second);
  const c = icons.load("mac", third);
  await Promise.resolve();
  expect(calls).toEqual([first]);
  releaseFirst({ png: base64(PNG) });
  expect(await a).toBeDefined();
  await enteredSecond;
  expect(calls).toEqual([first, second]);
  icons.dispose();
  expect(await b).toBeUndefined();
  expect(await c).toBeUndefined();
  expect(calls).toEqual([first, second]);
});

/** A blocked icon reply leaves space for at most 64 distinct pending hashes. */
test("a busy picker bounds pending icon loads and shares a queued request", async () => {
  let finish!: (reply: Record<string, unknown>) => void;
  const reply = new Promise<Record<string, unknown>>((resolve) => { finish = resolve; });
  let calls = 0;
  const icons = new AppIcons(() => {
    calls++;
    return reply;
  });
  const hashes = Array.from({ length: 65 }, (_, index) => index.toString(16).padStart(64, "0"));
  const queued = hashes.slice(0, 64).map((hash) => icons.load("mac", hash));

  expect(icons.load("mac", hashes[63]!)).toBe(queued[63]!);
  const overflow = icons.load("mac", hashes[64]!);
  expect(await Promise.race([overflow, Promise.resolve("queued")])).toBeUndefined();
  expect(calls).toBe(1);
  icons.dispose();
  finish({ png: "" });

  expect(await Promise.all(queued)).toEqual(Array(64).fill(undefined));
  expect(calls).toBe(1);
});
