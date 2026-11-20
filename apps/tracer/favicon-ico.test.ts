/** Checks the `.ico` wrapper against the real icon file and rejects input that is not a PNG. */
import { test, expect } from "bun:test";
import { readFile } from "node:fs/promises";
import { pngToIco } from "./favicon-ico";

test("the 32px icon becomes a one-image .ico that carries the PNG untouched", async () => {
  const png = new Uint8Array(await readFile("icons/dark-32.png"));
  const ico = pngToIco(png);
  const view = new DataView(ico.buffer);
  expect([view.getUint16(0, true), view.getUint16(2, true), view.getUint16(4, true)]).toEqual([0, 1, 1]);
  expect([ico[6], ico[7]]).toEqual([32, 32]);
  expect(view.getUint32(14, true)).toBe(png.length);
  expect(view.getUint32(18, true)).toBe(22);
  expect(ico.slice(22)).toEqual(png);
  expect(pngToIco(png)).toEqual(ico);
});

test("anything that is not a PNG is refused", () => {
  expect(() => pngToIco(new Uint8Array(40))).toThrow("not a PNG");
});
