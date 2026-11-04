/**
 * Choosing a font (Settings, Appearance, or the command palette) changes everything that shows text: the interface
 * (pills, labels), a window's body (the mock terminal windows are DOM text), and the live terminal's canvas. Each
 * must compute to the chosen family and the face must actually be loaded (`document.fonts.check`).
 */
import { expect, test, type Page } from "playwright/test";

const FONTS = [
  { id: "geist-mono", label: "Geist Mono", family: "Geist Mono" },
  { id: "jetbrains-mono", label: "JetBrains Mono", family: "JetBrains Mono" },
  { id: "commit-mono", label: "Commit Mono", family: "Commit Mono" },
];

async function families(page: Page): Promise<Record<string, string>> {
  return page.evaluate(() => {
    const first = (sel: string): string => { const n = document.querySelector(sel); return n ? getComputedStyle(n).fontFamily : "(missing)"; };
    const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas");
    return {
      interface: first(".cl-label-name"),
      pill: first("#capsule"),
      windowTitle: first(".ui-window-host"),
      windowBody: first(".cl-preview"),
      terminal: canvas?.getContext("2d")?.font ?? "(no canvas)",
    };
  });
}

async function expectFont(page: Page, font: { id: string; label: string; family: string }, via: string): Promise<void> {
  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.font), { timeout: 15_000 }).toBe(font.id);
  await page.waitForTimeout(1500);
  const seen = await families(page);
  for (const [where, family] of Object.entries(seen)) expect(family, `${font.label} via ${via}: ${where}`).toContain(font.family);
  expect(await page.evaluate((f) => document.fonts.check(`500 14px "${f}"`), font.family), `${font.label} face is loaded`).toBe(true);
}

test("a font chosen in Settings, Appearance reaches the interface, a window body and the live terminal", async ({ page }) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1000);
  await page.keyboard.press("Control+Shift+K");
  await page.keyboard.type("Appearance › Font");
  await page.keyboard.press("Enter");
  await page.waitForTimeout(1500);
  for (const font of FONTS) {
    await page.locator(`.ui-sp section[data-kind="font"] .ui-sp-row[data-id="${font.id}"]`).first().evaluate((n) => (n as HTMLElement).click());
    await expectFont(page, font, "Settings");
  }
});

test("a font choice reaches the interface, a window body and the live terminal", async ({ page }) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1500);
  for (const font of FONTS) {
    await page.keyboard.press("Control+Shift+K");
    await page.keyboard.type(font.label);
    await page.keyboard.press("Enter");
    await expect.poll(() => page.evaluate(() => document.documentElement.dataset.font), { timeout: 15_000 }).toBe(font.id);
    await page.waitForTimeout(1500);
    const seen = await families(page);
    for (const [where, family] of Object.entries(seen)) expect(family, `${font.label}: ${where}`).toContain(font.family);
    const loaded = await page.evaluate((f) => document.fonts.check(`500 14px "${f}"`), font.family);
    expect(loaded, `${font.label} face is loaded`).toBe(true);
  }
});

test("the chosen font survives a reload", async ({ page }) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.keyboard.press("Control+Shift+K");
  await page.keyboard.type("JetBrains Mono");
  await page.keyboard.press("Enter");
  await expectFont(page, FONTS[1]!, "palette");
  await page.reload();
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1500);
  await expectFont(page, FONTS[1]!, "reload");
});
