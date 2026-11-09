// SPDX-License-Identifier: AGPL-3.0-only
/** Keeps the browser's selectable theme and font ids aligned with the canvas server's accepted account-look ids. */
import { readFileSync } from "node:fs";
import { expect, test } from "bun:test";
import { FONTS } from "./fonts";
import { THEMES } from "./themes";

/** Reads one fixed string allowlist from the Rust canvas model so a client addition cannot silently become unsavable. */
function serverIds(name: "SCHEME_IDS" | "FONT_IDS"): string[] {
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
