// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Tests of the pure part of the adaptive glass: reading a terminal's cells into a backdrop range (D365, #448).
 *
 * The range must follow what the screen really shows under the card: plain text leaves it near the page colour, while a
 * bright band at the card's edge (two inverse rows, a status line and a prompt) must reach nearly its own colour even at
 * the widest blur. The solved glass for each range is then checked on the same numbers by `glass-contrast.test.ts`; the
 * pixel check of the whole path is `apps/tracer/test/glass-terminal.spec.ts`.
 */
import { describe, expect, test } from "bun:test";
import { luminanceOf, type Rgb } from "./glass-contrast";
import { blurCells, rangeOfGrid } from "./glass-adapt.on-demand";
import type { GlassGridRead } from "./glass-under";
import { THEMES, glassFor } from "./themes";

/** A grid of `cols` by `rows` cells of one colour, cells 8 by 17 px (a terminal's), with the given rows painted `paint`. */
function screen(cols: number, rows: number, bg: Rgb, paint: Array<{ row: number; colour: Rgb }> = []): GlassGridRead {
  const rgb = new Uint8Array(cols * rows * 3);
  for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
    const colour = paint.find((p) => p.row === r)?.colour ?? bg;
    rgb.set(colour, (r * cols + c) * 3);
  }
  return { x: 0, y: 0, cellW: 8, cellH: 17, cols, rows, rgb };
}

/** The Ink theme's page colour, which a default-background cell stands for. */
const INK_BG: Rgb = [13, 14, 16];
/** Pure white: the lightest a bright row can be. */
const WHITE: Rgb = [255, 255, 255];

describe("the backdrop range of a terminal screen", () => {
  test("a plain screen stays at the page colour", () => {
    const range = rangeOfGrid(screen(36, 25, INK_BG), 32);
    expect(luminanceOf(range.light)).toBeLessThan(0.01);
  });

  test("two bright rows at the top edge of the card stay bright after the widest blur", () => {
    const rows = [{ row: 0, colour: WHITE }, { row: 1, colour: WHITE }];
    const range = rangeOfGrid(screen(36, 25, INK_BG, rows), 32);
    // A flat blur of the whole card would leave about a fifth of the band's colour (luminance about 0.03); the card's own blur leaves most of it.
    expect(luminanceOf(range.light)).toBeGreaterThan(0.2);
  });

  test("one bright row in the middle is much dimmer than two at the edge", () => {
    const edge = rangeOfGrid(screen(36, 25, INK_BG, [{ row: 0, colour: WHITE }, { row: 1, colour: WHITE }]), 32);
    const middle = rangeOfGrid(screen(36, 25, INK_BG, [{ row: 12, colour: WHITE }]), 32);
    expect(luminanceOf(middle.light)).toBeLessThan(luminanceOf(edge.light));
  });

  test("a card with no blur sees every cell as it is", () => {
    const range = rangeOfGrid(screen(36, 25, INK_BG, [{ row: 5, colour: WHITE }]), 0);
    expect(luminanceOf(range.light)).toBeGreaterThan(0.9);
  });

  test("the blur keeps the mean colour of the screen", () => {
    const read = screen(36, 25, INK_BG, [{ row: 3, colour: WHITE }]);
    const before = read.rgb.reduce((a, b) => a + b, 0), blurred = blurCells(read, 12);
    const after = blurred.reduce((a, b) => a + b, 0);
    expect(Math.abs(after - before) / before).toBeLessThan(0.05);
  });

  test("what the content needs: bright rows at the edge raise Ink Frosted, plain text does not", () => {
    const ink = THEMES.ink!;
    const plain = glassFor(ink, 4, rangeOfGrid(screen(36, 25, INK_BG), 32));
    const bars = glassFor(ink, 4, rangeOfGrid(screen(36, 25, INK_BG, [{ row: 0, colour: WHITE }, { row: 1, colour: WHITE }]), 32));
    expect(plain.alpha).toBeCloseTo(0.2, 2);
    expect(bars.alpha).toBeGreaterThan(plain.alpha);
    expect(bars.ok).toBe(true);
  });
});
