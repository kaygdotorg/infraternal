// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Reads the cells of a terminal screen for the glass (D365): what colour each cell shows under a glass card, so the card can
 * be given exactly the opacity and text colours that content needs (`glass-adapt.on-demand.ts`).
 *
 * An on-demand chunk (D188). The terminal registers its screen with `registerGlassGrid` as it opens, and loads this module in
 * the background; a card that opens over the screen reads through it. Nothing here is on the critical path or runs on the
 * write or input path.
 */
import type { Terminal } from "../vendor/ghostty-web";
import type { GlassGridRead } from "../../../packages/ui/src/glass-under.on-demand";

/** The part of the terminal's renderer the glass reads: its canvas, and the theme background it treats as the default cell. */
export interface GlassRenderer {
  /** The canvas the screen is drawn on; its box maps client positions to cells. */
  getCanvas(): HTMLCanvasElement;
  /** The theme's background as channels; a cell with this background stands for what the window shows there. */
  themeBackgroundRgb?: number[];
}

/**
 * The cells of the visible screen under `rect`, as the colour each shows to the glass. A cell shows its background (its
 * foreground when inverted); a default-background cell stands for `base`, which is what the window shows there. A cell
 * holding a character mixes in a fifth of its text colour, the share of a cell that glyph strokes cover once blurred.
 * Reads the buffer, never the canvas, so there is no pixel readback.
 */
export function readGlassCells(terminal: Terminal, renderer: GlassRenderer | undefined, rect: DOMRect, base: readonly [number, number, number]): GlassGridRead | null {
  const canvas = renderer?.getCanvas();
  const { cols, rows } = terminal;
  if (!canvas || !cols || !rows) return null;
  const box = canvas.getBoundingClientRect();
  if (box.width <= 0 || box.height <= 0) return null;
  const cellW = box.width / cols, cellH = box.height / rows;
  const c0 = Math.min(cols - 1, Math.max(0, Math.floor((rect.left - box.left) / cellW)));
  const c1 = Math.min(cols - 1, Math.max(c0, Math.ceil((rect.right - box.left) / cellW) - 1));
  const r0 = Math.min(rows - 1, Math.max(0, Math.floor((rect.top - box.top) / cellH)));
  const r1 = Math.min(rows - 1, Math.max(r0, Math.ceil((rect.bottom - box.top) / cellH) - 1));
  const buffer = terminal.buffer.active;
  const first = buffer.length - rows - buffer.viewportY;
  const theme = renderer?.themeBackgroundRgb;
  const defaultBg = theme ? (theme[0]! << 16) | (theme[1]! << 8) | theme[2]! : -1;
  const out = new Uint8Array((r1 - r0 + 1) * (c1 - c0 + 1) * 3);
  let at = 0;
  for (let r = r0; r <= r1; r++) {
    const line = buffer.getLine(first + r);
    for (let c = c0; c <= c1; c++) {
      const cell = line?.getCell(c);
      let bg = base[0] << 16 | base[1] << 8 | base[2], fg = bg, ink = false;
      if (cell) {
        const inverse = cell.isInverse() !== 0;
        const back = inverse ? cell.getFgColor() : cell.getBgColor(), front = inverse ? cell.getBgColor() : cell.getFgColor();
        if (back !== defaultBg) bg = back;
        fg = front === defaultBg ? bg : front;
        ink = cell.getCodepoint() > 32 && cell.isInvisible() === 0;
      }
      for (let shift = 16; shift >= 0; shift -= 8) {
        const b = (bg >> shift) & 255;
        out[at++] = ink ? Math.round(b * 0.8 + ((fg >> shift) & 255) * 0.2) : b;
      }
    }
  }
  return { x: box.left + c0 * cellW, y: box.top + r0 * cellH, cellW, cellH, cols: c1 - c0 + 1, rows: r1 - r0 + 1, rgb: out };
}
