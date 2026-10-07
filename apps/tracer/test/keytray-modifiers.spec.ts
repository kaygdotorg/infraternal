/** Verifies touch-safe keybar focus, modifier states, terminal bytes, and screenshots. */
import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { devices, expect, test, type Browser, type BrowserContext, type Locator, type Page, type TestInfo } from "playwright/test";

const baseURL = `http://localhost:${Number(process.env.TRACER_TEST_PORT ?? "4173")}`;

async function mobilePage(browser: Browser): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ ...devices["iPhone 15"], baseURL });
  await context.request.post("/__mock/open-terminal");
  const page = await context.newPage();
  await page.goto("/?mock=1&theme=ink&bg=none");
  await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
  await focusTerminal(page);
  return { context, page };
}

async function focusTerminal(page: Page): Promise<void> {
  await page.locator("#terminal-host").evaluate((host) => {
    const input = host.querySelector<HTMLElement>("textarea, input, [contenteditable='true']") ?? host;
    input.focus({ preventScroll: true });
  });
  await expect.poll(() => page.evaluate(() => {
    const host = document.querySelector<HTMLElement>("#terminal-host");
    return Boolean(host && (document.activeElement === host || host.contains(document.activeElement)));
  })).toBe(true);
}

async function inputBytes(context: BrowserContext): Promise<number[]> {
  const response = await context.request.get("/__mock/state?input_bytes=1");
  const state = await response.json() as { input_bytes: number[] };
  return state.input_bytes;
}

async function expectInputBytes(context: BrowserContext, expected: number[]): Promise<void> {
  await expect.poll(() => inputBytes(context)).toEqual(expected);
}

async function doubleTap(button: Locator): Promise<void> {
  // Locator.tap waits for Chromium's touch click delay; dispatch the two touch
  // pointer pairs at once so this test covers the real 300 ms pointer window.
  await button.evaluate((element) => {
    const rect = element.getBoundingClientRect();
    const point = { clientX: rect.left + rect.width / 2, clientY: rect.top + rect.height / 2 };
    for (const pointerId of [41, 42]) {
      element.dispatchEvent(new PointerEvent("pointerdown", {
        bubbles: true, cancelable: true, pointerId, pointerType: "touch", isPrimary: true, button: 0, buttons: 1, ...point,
      }));
      element.dispatchEvent(new PointerEvent("pointerup", {
        bubbles: true, cancelable: true, pointerId, pointerType: "touch", isPrimary: true, button: 0, buttons: 0, ...point,
      }));
      element.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, detail: 1 }));
    }
  });
}

async function saveState(page: Page, testInfo: TestInfo, state: "off" | "armed" | "locked"): Promise<void> {
  const path = testInfo.outputPath(`keytray-${state}.png`);
  await mkdir(dirname(path), { recursive: true });
  await page.screenshot({ path, animations: "disabled" });
  await testInfo.attach(`keytray-${state}`, { path, contentType: "image/png" });
}

test("iPhone 15 tray modifiers send one-shot, locked, combined, and xterm arrow bytes", async ({ browser }, testInfo) => {
  test.setTimeout(60_000);
  const { context, page } = await mobilePage(browser);
  try {
    const control = page.getByRole("button", { name: "Control" });
    const option = page.getByRole("button", { name: "Option" });
    const up = page.getByRole("button", { name: "Up" });

    await expect(control).toHaveAttribute("aria-pressed", "false");
    await saveState(page, testInfo, "off");
    await control.tap();
    await expect(control).toHaveAttribute("aria-pressed", "true");
    await expect(control).toHaveAttribute("aria-label", "Control, armed");
    await saveState(page, testInfo, "armed");

    // A fresh page resets the tap interval so screenshot work cannot make the double tap late.
    await page.reload();
    await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
    await focusTerminal(page);
    const lockedControl = page.getByRole("button", { name: "Control" });
    await doubleTap(lockedControl);
    await expect(lockedControl).toHaveAttribute("aria-pressed", "mixed");
    await expect(lockedControl).toHaveAttribute("aria-label", "Control, locked");
    await saveState(page, testInfo, "locked");
    await lockedControl.tap();
    await expect(lockedControl).toHaveAttribute("aria-pressed", "false");

    await lockedControl.tap();
    await page.keyboard.press("c");
    await page.keyboard.press("c");
    await expectInputBytes(context, [0x03, 0x63]);

    await doubleTap(lockedControl);
    await page.keyboard.press("c");
    await page.keyboard.press("c");
    await page.keyboard.press("c");
    await expectInputBytes(context, [0x03, 0x63, 0x03, 0x03, 0x03]);
    await lockedControl.tap();
    await expect(lockedControl).toHaveAttribute("aria-pressed", "false");
    await page.keyboard.press("c");
    await expectInputBytes(context, [0x03, 0x63, 0x03, 0x03, 0x03, 0x63]);

    await option.tap();
    await page.keyboard.press("c");
    await page.keyboard.press("c");
    await expectInputBytes(context, [0x03, 0x63, 0x03, 0x03, 0x03, 0x63, 0x1b, 0x63, 0x63]);

    await doubleTap(option);
    await expect(option).toHaveAttribute("aria-pressed", "mixed");
    await page.keyboard.press("c");
    await page.keyboard.press("c");
    await expectInputBytes(context, [0x03, 0x63, 0x03, 0x03, 0x03, 0x63, 0x1b, 0x63, 0x63, 0x1b, 0x63, 0x1b, 0x63]);
    await option.tap();

    await lockedControl.tap();
    await up.tap();
    await expectInputBytes(context, [
      0x03, 0x63, 0x03, 0x03, 0x03, 0x63, 0x1b, 0x63, 0x63, 0x1b, 0x63, 0x1b, 0x63,
      0x1b, 0x5b, 0x31, 0x3b, 0x35, 0x41,
    ]);

    await lockedControl.tap();
    await option.tap();
    await up.tap();
    await expectInputBytes(context, [
      0x03, 0x63, 0x03, 0x03, 0x03, 0x63, 0x1b, 0x63, 0x63, 0x1b, 0x63, 0x1b, 0x63,
      0x1b, 0x5b, 0x31, 0x3b, 0x35, 0x41, 0x1b, 0x5b, 0x31, 0x3b, 0x37, 0x41,
    ]);
  } finally {
    await context.close();
  }
});

test("every visible iPhone 15 key tray button keeps focus in the terminal input", async ({ browser }) => {
  const { context, page } = await mobilePage(browser);
  try {
    const keys = page.locator("#keybar .keytray > button:not([hidden])");
    const count = await keys.count();
    expect(count).toBeGreaterThan(0);
    for (let index = 0; index < count; index += 1) {
      await keys.nth(index).tap();
      await expect.poll(() => page.evaluate(() => {
        const host = document.querySelector<HTMLElement>("#terminal-host");
        return Boolean(host && (document.activeElement === host || host.contains(document.activeElement)));
      }), { message: `keybar button ${index + 1} moved focus away from the terminal` }).toBe(true);
    }
    expect(await keys.evaluateAll((buttons) => buttons.every((button) => (button as HTMLButtonElement).tabIndex === -1))).toBe(true);

    const beforeKeyboardTray = await inputBytes(context);
    await page.keyboard.press("F6");
    await expect.poll(() => page.evaluate(() => document.activeElement?.id)).toBe("keytray");
    await page.keyboard.press("ArrowRight");
    await expect(page.locator("#keytray")).toHaveAttribute("aria-activedescendant", "key-tab");
    await page.keyboard.press("Enter");
    await expect.poll(() => page.evaluate(() => {
      const host = document.querySelector<HTMLElement>("#terminal-host");
      return Boolean(host && (document.activeElement === host || host.contains(document.activeElement)));
    })).toBe(true);
    await expectInputBytes(context, [...beforeKeyboardTray, 0x09]);
  } finally {
    await context.close();
  }
});
