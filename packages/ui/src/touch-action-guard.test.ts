// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The pinch guard (#560): iOS Safari zooms the whole page on a pinch unless `touch-action` leaves out `pinch-zoom`, and an element
 * inside a scroll container does not inherit that from the root. The shared stylesheet therefore gives every element
 * `touch-action: pan-x pan-y` through a `:where()` rule (zero specificity, so every class that sets its own value still wins).
 * These tests read the stylesheet's text, so they run without a browser; the real behaviour was measured on an iPhone Simulator
 * (see the issue) with a reference page that has a scroll container, a `manipulation` child and this one rule.
 */
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("../styles.css", import.meta.url), "utf8");

describe("pinch guard", () => {
  test("every element starts from pan-x pan-y", () => {
    expect(css).toMatch(/:where\(\*\)\s*\{\s*touch-action:\s*pan-x pan-y;\s*\}/);
  });

  test("the guard has zero specificity, so a class can still choose another value", () => {
    // `:where(*)` is the only selector allowed to carry the blanket value; a plain `*` would override `touch-action: none` on the canvas.
    expect(css).not.toMatch(/(^|\n)\*\s*\{[^}]*touch-action/);
  });

  test("no rule hands the pinch back with `auto` or `pinch-zoom`", () => {
    const risky = css.split("\n").filter((line) => /touch-action:\s*(auto|pinch-zoom|manipulation pinch-zoom)\b/.test(line));
    expect(risky).toEqual([]);
  });
});
