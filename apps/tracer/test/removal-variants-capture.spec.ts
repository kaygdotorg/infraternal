// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Screenshots of the three ways to offer "Remove host" in the machine details card, for the owner's pick (#486).
 * Run on demand against a production build: `J475B_CAPTURE=1 bun x playwright test test/removal-variants-capture.spec.ts`.
 *
 * It is a capture, not a gate: it asserts only that each state is on screen. For each variant (`foot`, `menu`, `inline`),
 * viewport (1440×900 and 393×852 at DPR 3) and theme (ink, dark; paper, light) it saves the whole window at rest and then
 * the state after the person presses the action: the glass confirmation card, or the question in the panel. Files land in
 * the evidence directory under `removal-variants/<variant>-<size>-<theme>-<state>.png`.
 */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const sizes = [{ id: "desktop", width: 1440, height: 900, scale: 1, touch: false }, { id: "phone", width: 393, height: 852, scale: 3, touch: true }] as const;
const themes = ["ink", "paper"] as const;
const variants = ["foot", "menu", "inline"] as const;

/** Opens the details card of the first window on the windows test double, with the removal adapter on. */
async function openCard(page: Page, variant: string, theme: string): Promise<void> {
  await page.context().request.post("/__mock/reset").catch(() => undefined);
  await page.goto(`/?mock=1&proto=windows&bg=none&fixture=none&removal=1&removalui=${variant}&theme=${theme}`);
  await expect.poll(() => page.evaluate(() => (window as unknown as { __tracerCanvas?: { windows(): string[] } }).__tracerCanvas?.windows().length ?? 0), { timeout: 30_000 }).toBeGreaterThan(2);
  await page.locator(".ui-window").first().locator(".ui-window-pill").click();
  await expect(page.locator(".canvas-popover")).toBeVisible();
  if (variant !== "foot") await expect(page.locator(variant === "menu" ? ".canvas-popover-more" : ".canvas-popover-action")).toBeVisible();
  // sleep: the open animation (200 ms) and the scroll fade settle
  await page.waitForTimeout(500);
}

/** The window the card sits in, so the capture shows the card in its real surroundings. */
const shot = (page: Page, name: string) => page.locator(".ui-window").first().screenshot({ path: tracerEvidencePath("removal-variants", `${name}.png`) });

test.skip(process.env.J475B_CAPTURE !== "1", "set J475B_CAPTURE=1 to capture");

for (const variant of variants) for (const size of sizes) for (const theme of themes) {
  test(`removal ${variant} ${size.id} ${theme}`, async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.scale, hasTouch: size.touch, isMobile: size.touch, colorScheme: theme === "ink" ? "dark" : "light" });
    const page = await context.newPage();
    try {
      await openCard(page, variant, theme);
      const base = `${variant}-${size.id}-${theme}`;
      await shot(page, `${base}-1-rest`);
      if (variant === "foot") {
        await page.locator(".canvas-popover-action .ui-sp-row").click();
        await expect(page.locator(".ui-confirm-tip[data-open='true']")).toBeVisible();
      } else if (variant === "menu") {
        await page.locator(".canvas-popover-more").click();
        await expect(page.locator(".ui-window-menu")).toBeVisible();
        await page.waitForTimeout(350);
        await shot(page, `${base}-2-menu`);
        await page.locator(".ui-window-menu-item").click();
        await expect(page.locator(".ui-confirm-tip[data-open='true']")).toBeVisible();
      } else {
        await page.locator(".canvas-popover-action .ui-sp-row").click();
        await expect(page.locator(".canvas-popover-ask")).toBeVisible();
      }
      // sleep: the card's or the question's entrance (under 300 ms)
      await page.waitForTimeout(450);
      await shot(page, `${base}-${variant === "inline" ? "2-question" : "3-confirm"}`);
    } finally { await context.close(); }
  });
}
