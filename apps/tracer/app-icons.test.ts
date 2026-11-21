// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The home-screen icon (#560). iOS draws its own rounded mask over the icon and paints any transparent pixel black, so an icon
 * that is pre-rounded or inset leaves a black ring and black corner slivers on the home screen. The apple-touch-icon must be a
 * full-bleed opaque square of exactly 180 x 180: a PNG colour type without an alpha channel (grey 0, RGB 2, palette 3 with no
 * `tRNS` chunk) is the cheapest proof, and it is what these tests check without decoding pixels.
 */
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

/** Reads the PNG header fields and the chunk names of a file in `icons/`. */
function inspect(name: string): { width: number; height: number; colourType: number; chunks: string[] } {
  const bytes = readFileSync(new URL(`./icons/${name}`, import.meta.url));
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const chunks: string[] = [];
  for (let at = 8; at < bytes.length; ) {
    chunks.push(bytes.toString("latin1", at + 4, at + 8));
    at += 12 + view.getUint32(at);
  }
  return { width: view.getUint32(16), height: view.getUint32(20), colourType: bytes[25]!, chunks };
}

describe("apple-touch-icon", () => {
  const icon = inspect("apple-touch-icon.png");

  test("is 180 x 180", () => {
    expect([icon.width, icon.height]).toEqual([180, 180]);
  });

  test("has no alpha channel, so no pixel can turn black on the home screen", () => {
    expect([4, 6]).not.toContain(icon.colourType);
    expect(icon.chunks).not.toContain("tRNS");
  });
});
