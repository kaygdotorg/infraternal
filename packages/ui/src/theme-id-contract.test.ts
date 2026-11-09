// SPDX-License-Identifier: AGPL-3.0-only
/** Keeps the browser's selectable theme, font and background ids aligned with the canvas server's accepted account-look ids. */
import { readFileSync } from "node:fs";
import { expect, test } from "bun:test";
import { CUSTOM_ID, GRADIENT_IDS, SOLID_CUSTOM_ID, SOLID_IDS } from "../../../apps/tracer/src/canvas/themes/backgrounds";
import { FONTS } from "./fonts";
import { THEMES } from "./themes";

/** Reads one fixed string allowlist from the Rust canvas model so a client addition cannot silently become unsavable. */
function serverIds(name: "SCHEME_IDS" | "FONT_IDS" | "BACKGROUND_IDS"): string[] {
  const source = readFileSync(new URL("../../../crates/plugins/canvas/src/model.rs", import.meta.url), "utf8");
  const block = source.match(new RegExp(`const ${name}: &\\[&str\\] = &\\[([\\s\\S]*?)\\];`));
  if (!block) throw new Error(`the canvas model no longer declares ${name}`);
  return [...block[1]!.matchAll(/"([^"]+)"/g)].map((match) => match[1]!);
}

/** Requires every selectable theme and font to be accepted by the server's bounded account-look schema. */
test("theme and font ids stay identical in the browser and canvas server", () => {
  const schemes = serverIds("SCHEME_IDS");
  const fonts = serverIds("FONT_IDS");
  expect(new Set(schemes).size, "the server scheme list has no duplicate ids").toBe(schemes.length);
  expect(new Set(fonts).size, "the server font list has no duplicate ids").toBe(fonts.length);
  expect(schemes.sort(), "every client theme is accepted and no unknown scheme is stored").toEqual(Object.keys(THEMES).sort());
  expect(fonts.sort(), "every client font is accepted and no unknown font is stored").toEqual(FONTS.map(({ id }) => id).sort());
});

/** Requires every background the editor can choose (gradients, scheme solids, and the two custom ids) to be accepted by the server. */
test("background ids stay identical in the browser and canvas server", () => {
  const server = serverIds("BACKGROUND_IDS");
  expect(new Set(server).size, "the server background list has no duplicate ids").toBe(server.length);
  expect(server.sort(), "every client background is accepted and no unknown background is stored").toEqual([CUSTOM_ID, SOLID_CUSTOM_ID, ...SOLID_IDS, ...GRADIENT_IDS].sort());
});
