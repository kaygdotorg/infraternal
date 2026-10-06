/** Production-browser geometry checks for the unauthenticated setup screen. */
import { expect, test, type Page, type TestInfo } from "playwright/test";

const viewports = [
  { id: "iphone-15", width: 393, height: 852 },
  { id: "desktop", width: 1440, height: 900 },
] as const;

test("setup primary button reaches the card content edge on phone and desktop", async ({ page }, testInfo) => {
  await page.context().request.post("/__mock/reset");
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "no-preference" });
  await page.goto("/?mock=1");
  await expect(page.locator("#setup-next")).toBeVisible();
  await expect(page.locator("#faulty-field")).toHaveAttribute("data-ready", "true");

  const screenshots: string[] = [];
  for (const viewport of viewports) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    const path = testInfo.outputPath(`step-1-button-${viewport.id}.png`);
    await page.screenshot({ path, fullPage: true, animations: "disabled" });
    await testInfo.attach(`step-1-button-${viewport.id}`, { path, contentType: "image/png" });
    screenshots.push(path);

    const inset = await primaryRightInset(page);
    console.log(`STEP1_PRIMARY_RIGHT_INSET ${viewport.id}: ${inset.toFixed(3)} px`);
    expect(inset, `primary button should align on ${viewport.id}`).toBeLessThanOrEqual(1);
  }
  console.log(`SETUP_BUTTON_SCREENSHOTS ${screenshots.join(" ")}`);
});

/** Measures the primary button against the card's padding-box content edge. */
async function primaryRightInset(page: Page): Promise<number> {
  return page.locator("#setup-next").evaluate((button) => {
    const card = button.closest<HTMLElement>(".auth-card");
    if (!card) throw new Error("setup card is missing");
    const buttonRect = button.getBoundingClientRect();
    const cardRect = card.getBoundingClientRect();
    const cardStyle = getComputedStyle(card);
    const contentRight = cardRect.right
      - Number.parseFloat(cardStyle.borderRightWidth)
      - Number.parseFloat(cardStyle.paddingRight);
    return Math.abs(contentRight - buttonRect.right);
  });
}
