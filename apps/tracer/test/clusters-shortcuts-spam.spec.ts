/**
 * Pressing `?` over and over ends either with the shortcuts panel fully open and showing its content, or with no
 * panel at all, never with an empty shell left on screen (#141). Opening while the close is still playing used to
 * mount a second panel and leave the first one behind, half clipped and faded out.
 */
import { expect, test, type Page } from "playwright/test";

async function boot(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=mocha&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  // A press outside any field, on the canvas background.
  await page.mouse.click(720, 880);
  await page.waitForTimeout(300);
}

/** Every shortcuts panel in the document, with what is visible of it. */
const panels = (page: Page) => page.evaluate(() => [...document.querySelectorAll<HTMLElement>(".ui-shortcuts")].map((p) => {
  const head = p.querySelector<HTMLElement>(".ui-shortcuts-head");
  return { clip: p.style.clipPath, opacity: getComputedStyle(p).opacity, headOpacity: head ? getComputedStyle(head).opacity : null, rows: p.querySelectorAll(".ui-shortcuts-row").length, anim: p.getAnimations().length };
}));

for (const gap of [30, 120]) {
  for (const presses of [20, 21]) {
    test(`${presses} presses of ? every ${gap} ms end ${presses % 2 ? "open with content" : "closed"}, never an empty shell`, async ({ page }) => {
      await boot(page);
      let most = 0;
      for (let i = 0; i < presses; i++) {
        await page.keyboard.press("?");
        most = Math.max(most, (await panels(page)).length);
        await page.waitForTimeout(gap);
      }
      await page.waitForTimeout(1500);
      const end = await panels(page);
      console.log(`gap ${gap} presses ${presses}: most panels at once ${most}, end`, JSON.stringify(end));
      expect(most, "at most one panel is ever mounted").toBeLessThanOrEqual(1);
      if (presses % 2) {
        expect(end).toHaveLength(1);
        expect(end[0]!.rows).toBeGreaterThan(5);
        expect(end[0]!.clip, "settled open: no clip left").toBe("");
        expect(end[0]!.headOpacity).toBe("1");
        expect(end[0]!.opacity).toBe("1");
      } else {
        expect(end).toHaveLength(0);
      }
      // And one more press brings it to the opposite state, whatever came before.
      await page.keyboard.press("?");
      await page.waitForTimeout(1000);
      expect((await panels(page)).length).toBe(presses % 2 ? 0 : 1);
    });
  }
}
