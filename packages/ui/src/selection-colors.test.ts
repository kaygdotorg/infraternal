/**
 * The terminal's selection colours (#426, D365): on every theme the highlight must stand out from the cell background
 * (3:1, a non-text indicator) and the selected text must stay readable on it (4.5:1). On ink the renderer's own default
 * (dark text on a dim translucent fill) failed both.
 */
import { expect, test } from "bun:test";
import { contrastRatio } from "./color";
import { selectionColors, terminalTheme, THEMES } from "./themes";

for (const [id, theme] of Object.entries(THEMES)) {
  test(`selection on ${id}: highlight 3:1 against the cell, text 4.5:1 on the highlight`, () => {
    const { background, foreground } = selectionColors(theme);
    expect(contrastRatio(background, theme.bg), "highlight against the background").toBeGreaterThanOrEqual(3);
    expect(contrastRatio(foreground, background), "selected text on the highlight").toBeGreaterThanOrEqual(4.5);
  });

  test(`the terminal theme for ${id} carries those colours`, () => {
    const colors = selectionColors(theme);
    const t = terminalTheme(theme, false);
    expect(t.selectionBackground).toBe(colors.background);
    expect(t.selectionForeground).toBe(colors.foreground);
  });
}
