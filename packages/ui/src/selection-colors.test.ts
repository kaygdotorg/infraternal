/**
 * The terminal's selection colours (#426, D365): on every theme the selected text must stay readable on the highlight (4.5:1),
 * and on dark themes the highlight must also stand out from the cell background (3:1, a non-text indicator). On ink the
 * renderer's own default (dark text on a dim translucent fill) failed both; light themes keep their soft highlight and, since D380,
 * switch to dark text when their own cannot reach 4.5:1 on it. Every theme × selection pair is checked below, and the interface's
 * `::selection` takes the same pair.
 */
import { expect, test } from "bun:test";
import { contrastRatio } from "./color";
import { selectionColors, terminalTheme, THEMES } from "./themes";

for (const [id, theme] of Object.entries(THEMES)) {
  test(`selection on ${id}: text 4.5:1 on the highlight${theme.dark ? ", highlight 3:1 against the cell" : ""}`, () => {
    const { background, foreground } = selectionColors(theme);
    if (theme.dark) expect(contrastRatio(background, theme.bg), "highlight against the background").toBeGreaterThanOrEqual(3);
    expect(contrastRatio(foreground, background), "selected text on the highlight").toBeGreaterThanOrEqual(4.5);
  });

  // D380: a light theme's selected text stays dark whichever way it adapts, so it never flips to a pale colour on a pale highlight.
  if (!theme.dark) {
    test(`selection on light ${id}: the selected text is dark`, () => {
      const { background, foreground } = selectionColors(theme);
      expect(contrastRatio(foreground, "#ffffff"), "selected text against white").toBeGreaterThanOrEqual(4.5);
      expect(contrastRatio(foreground, background), "selected text on the highlight").toBeGreaterThanOrEqual(4.5);
    });
  }

  test(`the terminal theme for ${id} carries those colours`, () => {
    const colors = selectionColors(theme);
    const t = terminalTheme(theme, false);
    expect(t.selectionBackground).toBe(colors.background);
    expect(t.selectionForeground).toBe(colors.foreground);
  });
}
