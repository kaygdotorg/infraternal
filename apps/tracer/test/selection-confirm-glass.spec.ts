/**
 * D380 on the production build: selected text adapts in every curated theme (#426), and confirmation cards are the shared
 * floating-card glass (#391).
 *
 * Selection: for every theme, text selected in the terminal and text selected in the interface (a sample line on the overlay
 * material, taking the page's `::selection`) use the colour pair `selectionColors` gives, and the pair reads at 4.5:1. The
 * shots are saved per theme, then composed into one contact sheet under `selection/` in the evidence directory.
 *
 * Confirmation: the card started from the palette over a dense terminal and over an empty one, on desktop and at 393 px, in
 * an ink (dark) and a paper (light) theme. It has no glass bed, and on the phone it keeps an inset from both screen edges.
 */
import { readFile } from "node:fs/promises";
import { expect, test, type Page } from "playwright/test";
import { contrastRatio } from "../../../packages/ui/src/color";
import { selectionColors, THEMES } from "../../../packages/ui/src/themes";
import { tracerEvidencePath } from "./evidence-path";
import { openDenseConsole, startRemovalFromPalette } from "./removal-fixture";

/** `#rrggbb` as the `rgb(r, g, b)` text a computed style reports. */
const asRgb = (hex: string): string => `rgb(${[1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)).join(", ")})`;

/** Drags across the third row from the bottom of the terminal's text, the way a person selects with the mouse. */
async function selectTerminalRow(page: Page): Promise<{ x: number; y: number }> {
  const metrics = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
  const box = await page.locator("#terminal-host canvas").boundingBox();
  if (!metrics || !box) throw new Error("terminal selection geometry is unavailable");
  const y = box.y + (metrics.rows - 3) * metrics.cellHeight + metrics.cellHeight / 2;
  await page.mouse.move(box.x + metrics.cellWidth / 2, y);
  await page.mouse.down();
  await page.mouse.move(box.x + metrics.cellWidth * 12.5, y);
  await page.mouse.up();
  return { x: box.x, y: y - metrics.cellHeight / 2 };
}

test("selected text adapts in every curated theme, in the terminal and in the interface", async ({ page }) => {
  test.setTimeout(600_000);
  await page.setViewportSize({ width: 1440, height: 900 });
  const tiles: { id: string; name: string; terminal: string; ui: string }[] = [];
  for (const [id, theme] of Object.entries(THEMES)) {
    await page.goto(`/?mock=1&theme=${id}&bg=none`);
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
    await expect(page.locator("#terminal-screen")).toHaveAttribute("data-theme", id);
    const pair = selectionColors(theme);
    expect(contrastRatio(pair.foreground, pair.background), `${id}: selected text on its highlight`).toBeGreaterThanOrEqual(4.5);

    // The interface: a sample line on the overlay material, selected as a whole.
    await page.evaluate(() => {
      const card = document.createElement("div");
      card.className = "ui-overlay-surface";
      card.id = "d380-sample";
      Object.assign(card.style, { position: "fixed", left: "24px", top: "24px", zIndex: "999", padding: "10px 14px", font: "500 14px var(--font-ui, monospace)" });
      card.innerHTML = '<span id="d380-text">Selected text in the interface</span>';
      document.body.append(card);
      const range = document.createRange();
      range.selectNodeContents(document.getElementById("d380-text")!);
      const selection = getSelection()!;
      selection.removeAllRanges();
      selection.addRange(range);
    });
    const computed = await page.evaluate(() => {
      const style = getComputedStyle(document.getElementById("d380-text")!, "::selection");
      return { background: style.backgroundColor, color: style.color };
    });
    expect(computed.background, `${id}: interface selection fill`).toBe(asRgb(pair.background));
    expect(computed.color, `${id}: interface selection text`).toBe(asRgb(pair.foreground));
    const uiShot = tracerEvidencePath("selection", `${id}-ui.png`);
    await page.locator("#d380-sample").screenshot({ path: uiShot });
    await page.evaluate(() => { getSelection()?.removeAllRanges(); document.getElementById("d380-sample")?.remove(); });

    // The terminal: a mouse drag over a row of text.
    const origin = await selectTerminalRow(page);
    const terminalShot = tracerEvidencePath("selection", `${id}-terminal.png`);
    await page.screenshot({ path: terminalShot, clip: { x: origin.x, y: Math.max(0, origin.y - 10), width: 340, height: 40 }, animations: "disabled" });
    tiles.push({ id, name: theme.name, terminal: terminalShot, ui: uiShot });
  }

  // The contact sheet: one row per theme, the terminal selection beside the interface selection.
  const cells = await Promise.all(tiles.map(async (tile) => {
    const [terminal, ui] = await Promise.all([readFile(tile.terminal), readFile(tile.ui)]);
    return `<figure><figcaption>${tile.name} (${tile.id})</figcaption><img src="data:image/png;base64,${terminal.toString("base64")}"><img src="data:image/png;base64,${ui.toString("base64")}"></figure>`;
  }));
  const sheet = await page.context().newPage();
  await sheet.setViewportSize({ width: 1500, height: 900 });
  await sheet.setContent(`<style>body{margin:12px;background:#777;font:12px monospace;color:#fff;display:grid;grid-template-columns:repeat(2,1fr);gap:8px 16px}figure{margin:0}figcaption{margin-bottom:2px}img{display:block;margin-bottom:2px}</style>${cells.join("")}`);
  await sheet.screenshot({ path: tracerEvidencePath("selection", "contact-sheet.png"), fullPage: true });
  await sheet.close();
});

/** Empties the terminal and the previews, so nothing behind a card is text: the plain background. */
async function clearTerminals(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const hook = window.__tracerTestDouble as unknown as { writeText(text: string): Promise<void> };
    await hook.writeText("\x1b[2J\x1b[H");
    for (const pre of document.querySelectorAll<HTMLElement>(".cl-preview")) pre.textContent = "";
  });
}

for (const size of [{ id: "desktop", width: 1440, height: 900, touch: false }, { id: "phone-393", width: 393, height: 852, touch: true }] as const) {
  for (const theme of ["ink", "paper"] as const) {
    for (const background of ["busy", "plain"] as const) {
      test(`confirmation card ${size.id} ${theme} over a ${background} background is shared glass, inset on a phone`, async ({ browser }) => {
        const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, hasTouch: size.touch, isMobile: size.touch });
        const page = await context.newPage();
        try {
          await openDenseConsole(page, theme, "tinted");
          if (background === "plain") await clearTerminals(page);
          await startRemovalFromPalette(page);
          const tip = page.locator(".ui-confirm-tip[data-open='true']");
          await expect(tip).toBeVisible();
          // sleep: the open animation (scale 0.96 to 1, under 300 ms) must finish before the card is measured and shot
          await page.waitForTimeout(400);
          await expect(page.locator(".ui-glass-bed"), "no glass bed under the card").toHaveCount(0);
          const box = (await tip.boundingBox())!;
          const filled = await tip.evaluate((el) => getComputedStyle(el).backgroundColor);
          expect(filled, "the card's fill is translucent, not opaque").toMatch(/rgba\(.*,\s*0?\.\d+\)|oklab|color\(/);
          if (size.touch) {
            expect(box.x, "inset from the left screen edge").toBeGreaterThanOrEqual(8);
            expect(size.width - (box.x + box.width), "inset from the right screen edge").toBeGreaterThanOrEqual(8);
          }
          await page.screenshot({ path: tracerEvidencePath("confirm-glass", `${size.id}-${theme}-${background}.png`), animations: "disabled" });
        } finally { await context.close(); }
      });
    }
  }
}
