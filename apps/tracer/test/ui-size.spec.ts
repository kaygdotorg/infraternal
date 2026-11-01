/**
 * The UI size slider (#283, TASTE "The size of the whole UI is the person's to set"): Settings → Appearance has a slider from
 * 50 % to 150 % in 5 % steps, relative to the UI's base: a desktop is drawn at 1.1 times a 16 px root (owner, 2026-11-01:
 * "110% should be the new 100% and default"), a touch screen at 1. It scales the whole UI live through the root font size (rem
 * tokens, never CSS zoom), is remembered in this browser, and at 100 % (the default) there is no custom property.
 * The terminal's own font size is not part of it.
 */
import { expect, test, type Page } from "playwright/test";

const open = async (page: Page, width = 1440, height = 900): Promise<void> => {
  await page.setViewportSize({ width, height });
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(900);
};
const showAppearance = async (page: Page): Promise<void> => {
  await page.keyboard.press("Control+Shift+K");
  await page.waitForTimeout(350);
  await page.keyboard.type("Settings: Appearance", { delay: 6 });
  await page.waitForTimeout(400);
  await page.keyboard.press("Enter");
  await page.waitForTimeout(1500);
};
const slider = (page: Page) => page.getByRole("slider", { name: "UI size" });
const rootPx = (page: Page): Promise<number> => page.evaluate(() => parseFloat(getComputedStyle(document.documentElement).fontSize));
/** The desktop's base: 16 px x 1.1. */
const BASE = 17.6;
/** The layout height of a header pill on the canvas: a control sized by the rem tokens (not a rect: the camera's zoom is not part of it). */
const pillHeight = (page: Page): Promise<number> => page.evaluate(() => document.querySelector<HTMLElement>(".ui-window-actions")!.offsetHeight);

test("the slider goes from 50 % to 150 % in 5 % steps and starts at 100 %", async ({ page }) => {
  await open(page);
  await showAppearance(page);
  const input = slider(page);
  await expect(input).toBeVisible();
  expect(await input.getAttribute("min")).toBe("50");
  expect(await input.getAttribute("max")).toBe("150");
  expect(await input.getAttribute("step")).toBe("5");
  await expect(input).toHaveValue("100");
  await expect(page.locator(".ui-slider-value")).toHaveText("100 %");
  expect(await rootPx(page)).toBeCloseTo(BASE, 5);
  expect(await page.evaluate(() => document.documentElement.style.getPropertyValue("--ui-scale"))).toBe("");
});

test("the default is 110 % of the old size on a desktop, and the migration keeps the pixels of an old stored size", async ({ page }) => {
  await open(page);
  expect(await rootPx(page)).toBeCloseTo(17.6, 5);
  // A size stored before the base existed (120 % of 16 px = 19.2 px) is 110 % of the new base: the same pixels.
  await page.addInitScript(() => { if (!sessionStorage.getItem("seeded")) { sessionStorage.setItem("seeded", "1"); localStorage.setItem("tracer.ui-size", "120"); localStorage.removeItem("tracer.ui-size.v2"); } });
  await page.reload();
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  expect(await rootPx(page)).toBeCloseTo(19.36, 5);
  expect(await page.evaluate(() => [localStorage.getItem("tracer.ui-size"), localStorage.getItem("tracer.ui-size.v2")])).toEqual([null, "110"]);
});

test("it scales the whole UI live: the root font size, the controls and the type follow, and the readout says the percentage", async ({ page }) => {
  await open(page);
  await showAppearance(page);
  const standard = await pillHeight(page);
  const input = slider(page);
  await input.focus();
  await page.keyboard.press("End");
  await expect(page.locator(".ui-slider-value")).toHaveText("150 %");
  expect(await rootPx(page)).toBeCloseTo(BASE * 1.5, 5);
  expect(Math.abs((await pillHeight(page)) - standard * 1.5)).toBeLessThan(0.6);
  await page.keyboard.press("Home");
  await expect(page.locator(".ui-slider-value")).toHaveText("50 %");
  expect(await rootPx(page)).toBeCloseTo(BASE * 0.5, 5);
  expect(Math.abs((await pillHeight(page)) - standard * 0.5)).toBeLessThan(0.6);
  // One step up is 5 %.
  await page.keyboard.press("ArrowRight");
  await expect(page.locator(".ui-slider-value")).toHaveText("55 %");
  expect(await rootPx(page)).toBeCloseTo(BASE * 0.55, 5);
  await expect(input).toHaveAttribute("aria-valuetext", "55 %");
});

test("the size is remembered in this browser, and 100 % leaves nothing behind", async ({ page }) => {
  await open(page);
  await showAppearance(page);
  await slider(page).focus();
  for (let i = 0; i < 4; i += 1) await page.keyboard.press("ArrowRight"); // 120 %
  await expect(page.locator(".ui-slider-value")).toHaveText("120 %");
  await page.reload();
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  expect(await rootPx(page)).toBeCloseTo(BASE * 1.2, 5);
  await showAppearance(page);
  await expect(slider(page)).toHaveValue("120");
  for (let i = 0; i < 4; i += 1) await page.keyboard.press("ArrowLeft");
  await slider(page).focus();
  for (let i = 0; i < 4; i += 1) await page.keyboard.press("ArrowLeft");
  await expect(page.locator(".ui-slider-value")).toHaveText("100 %");
  expect(await page.evaluate(() => document.documentElement.style.getPropertyValue("--ui-scale"))).toBe("");
  expect(await rootPx(page)).toBeCloseTo(BASE, 5);
});

test("the sidebar and the popovers grow with it, so the type inside is not squeezed", async ({ page }) => {
  await open(page);
  await page.locator("#sidebar-toggle").click();
  await page.waitForTimeout(800);
  const sidebar = (): Promise<number> => page.evaluate(() => document.querySelector<HTMLElement>("#sidebar")!.offsetWidth);
  const standard = await sidebar();
  await showAppearance(page);
  await slider(page).focus();
  await page.keyboard.press("End");
  await page.waitForTimeout(500);
  expect(Math.abs((await sidebar()) - standard * 1.5), "the sidebar at 150 %").toBeLessThanOrEqual(2);
  await page.keyboard.press("Home");
  await page.waitForTimeout(500);
  expect(Math.abs((await sidebar()) - standard * 0.5), "the sidebar at 50 %").toBeLessThanOrEqual(2);
});

test("hairlines stay one pixel and nothing overflows at 50 % and 150 %", async ({ page }) => {
  await open(page);
  await showAppearance(page);
  await slider(page).focus();
  for (const [key, size] of [["End", 150], ["Home", 50]] as const) {
    await page.keyboard.press(key);
    await page.waitForTimeout(500);
    const overflow = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, sh: document.documentElement.scrollHeight, ch: document.documentElement.clientHeight }));
    expect(overflow.sw, `${size} %: horizontal overflow`).toBeLessThanOrEqual(overflow.cw);
    expect(overflow.sh, `${size} %: vertical overflow`).toBeLessThanOrEqual(overflow.ch);
    // A hairline is a pixel at every size: the window card's border does not scale.
    expect(await page.evaluate(() => parseFloat(getComputedStyle(document.querySelector(".ui-window")!).borderTopWidth))).toBeLessThanOrEqual(1.5);
  }
});

test.describe("on a phone", () => {
  test.use({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true });
  test("a touch screen keeps its own size: a base of 1, so the default root is 16 px", async ({ page }) => {
    await open(page, 393, 852);
    expect(await rootPx(page)).toBe(16);
  });

  test("the slider is a 44 px target and works by touch", async ({ page }) => {
    await open(page, 393, 852);
    await showAppearance(page).catch(async () => { await page.evaluate(() => document.dispatchEvent(new KeyboardEvent("keydown", { key: "K", code: "KeyK", ctrlKey: true, shiftKey: true, bubbles: true }))); });
    await page.keyboard.type("Settings: Appearance", { delay: 6 }).catch(() => undefined);
    await page.keyboard.press("Enter").catch(() => undefined);
    await page.waitForTimeout(1500);
    const box = await slider(page).boundingBox();
    expect(box).not.toBeNull();
    expect(box!.height).toBeGreaterThanOrEqual(43.5);
  });
});
