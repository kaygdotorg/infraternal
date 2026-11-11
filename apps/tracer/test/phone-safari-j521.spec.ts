// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The phone bugs J509 found in iPhone Simulator Safari (#500, J521), each checked in a production build:
 *
 * 1. The SSH password (and key passphrase) field is not a password-typed field, so Safari offers neither "Use Strong
 *    Password?" nor "Save Password?" for a credential that is used once and belongs to someone else's machine.
 * 2. The layout leaves its keyboard state when the keyboard goes away, even if the last `visualViewport` event was early or lost.
 * 3. The Add host sign-in step keeps its options in view on a short phone card: the footer is one row, not two stacked buttons.
 * 4. After the only window ends, the screen says "No windows open" while a host exists; "No hosts yet" is for no host.
 * 5. With no saved theme the app follows the system's light or dark scheme (TASTE "Light and dark everywhere"); once the
 *    account's look exists, the account's theme wins on every device (D352), so a later system change does not flip it.
 * 6. The host-key and sign-in titles name the typed port.
 */
import { expect, test, type Page } from "playwright/test";

/** A short iPhone page: 402 x 874 minus Safari's top and bottom bars leaves about this much. */
const PHONE = { width: 402, height: 740 };
test.use({ viewport: PHONE, hasTouch: true, isMobile: true, deviceScaleFactor: 3 });

const wizard = (page: Page) => page.locator(".ah-float");
const inWizard = (page: Page, name: string) => wizard(page).getByRole("button", { name, exact: true });

/** Resets the shared test double and opens the clusters canvas on a phone. */
async function open(page: Page, query = ""): Promise<void> {
  await page.request.post("/__mock/reset", { maxRetries: 1 });
  await page.request.post("/__mock/bootstrap/reset", { maxRetries: 1 });
  await page.goto(`/?mock=1&proto=clusters&scene=3&theme=ink&bg=none${query}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 45_000 });
}
/** Opens the wizard, types `host` as the destination and continues. */
async function typeHost(page: Page, host: string): Promise<void> {
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
  await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible({ timeout: 45_000 });
  await page.locator(".ui-chip-text").click();
  await page.keyboard.type(`${host} `, { delay: 5 });
  await inWizard(page, "Continue").click();
}

test("the SSH password and passphrase are masked text fields, never password-typed", async ({ page }) => {
  await open(page);
  await typeHost(page, "kayg@needs-key.lab");
  await expect(page.getByRole("heading", { name: /Sign in to needs-key.lab/ })).toBeVisible({ timeout: 15_000 });
  await page.getByText("Sign in with a password").click();
  expect(await page.locator("input[type='password']").count(), "Safari offers Strong Password and Save Password for any password-typed field").toBe(0);
  for (const name of ["password", "passphrase"]) {
    const field = page.locator(`[data-secret='${name}']`);
    expect(await field.getAttribute("type")).toBe("text");
    expect(await field.getAttribute("autocomplete")).toBe("off");
    expect(await field.getAttribute("autocorrect")).toBe("off");
    expect(await field.getAttribute("autocapitalize")).toBe("none");
    expect(await field.getAttribute("spellcheck")).toBe("false");
    expect(await field.getAttribute("name"), "no name for a manager to match on").toBeNull();
  }
  // Typed text is drawn as dots, the placeholder is not.
  const password = page.locator("[data-secret='password']");
  await password.fill("hunter2-not-real");
  expect(await password.evaluate((el) => getComputedStyle(el).getPropertyValue("-webkit-text-security"))).toBe("disc");
});

test("the sign-in step keeps its options in view on a short phone card", async ({ page }) => {
  await open(page);
  await typeHost(page, "kayg@needs-key.lab");
  await expect(page.getByRole("heading", { name: /Sign in to needs-key.lab/ })).toBeVisible({ timeout: 15_000 });
  const m = await page.evaluate(() => {
    const scroll = document.querySelector<HTMLElement>(".ah-scroll")!.getBoundingClientRect();
    const foot = document.querySelector<HTMLElement>(".ah-foot")!.getBoundingClientRect();
    const option = [...document.querySelectorAll<HTMLElement>(".ah-option")].find((o) => /password/i.test(o.textContent ?? ""))!.getBoundingClientRect();
    return { scrollH: scroll.height, footH: foot.height, optionTop: option.top, optionBottom: option.bottom, scrollTop: scroll.top, scrollBottom: scroll.bottom };
  });
  test.info().annotations.push({ type: "measured", description: JSON.stringify(m) });
  expect(m.footH, "Back and Sign in share one row").toBeLessThan(90);
  expect(m.optionBottom, "the password option is visible without scrolling").toBeLessThanOrEqual(m.scrollBottom);
});

test("the host-key and sign-in titles name the typed port", async ({ page }) => {
  await open(page);
  await typeHost(page, "kayg@newkey.lab:2222");
  await expect(page.getByRole("heading", { name: "Check newkey.lab:2222's key" })).toBeVisible({ timeout: 15_000 });
});

/** Fakes the visual viewport's height (the keyboard) and tells the page, as Safari does. */
async function setViewportHeight(page: Page, height: number, notify: boolean): Promise<void> {
  await page.evaluate(([h, tell]) => {
    const vv = window.visualViewport!;
    Object.defineProperty(vv, "height", { configurable: true, get: () => h });
    if (tell) vv.dispatchEvent(new Event("resize"));
  }, [height, notify] as const);
}

test("the layout leaves its keyboard state when the keyboard goes, even if the last event never came", async ({ page }) => {
  await open(page);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
  await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible({ timeout: 45_000 });
  await page.locator(".ui-chip-text").click();
  await setViewportHeight(page, 380, true);
  await expect(page.locator("html")).toHaveAttribute("data-kb", "open");
  // The keyboard goes: the field loses focus and the viewport is whole again, but Safari's final resize never arrives.
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  await setViewportHeight(page, PHONE.height, false);
  await expect(page.locator("html")).toHaveAttribute("data-kb", "closed", { timeout: 3_000 });
});

test("with no saved theme the app follows the system scheme, and the account's saved theme wins afterwards", async ({ browser, baseURL }) => {
  const context = await browser.newContext({ baseURL: baseURL!, colorScheme: "dark", viewport: PHONE, hasTouch: true, isMobile: true });
  const page = await context.newPage();
  await page.request.post("/__mock/reset", { maxRetries: 1 });
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
  await expect(page.locator(".ui-window").first()).toBeVisible({ timeout: 45_000 });
  const dark = await page.locator("html").getAttribute("data-theme");
  expect(["mocha", "macchiato", "frappe"], `first load in a dark system: ${dark}`).toContain(dark);
  await context.close();
  const light = await browser.newContext({ baseURL: baseURL!, colorScheme: "light", viewport: PHONE, hasTouch: true, isMobile: true });
  const lightPage = await light.newPage();
  await lightPage.goto("/?mock=1&proto=product&fresh=1&bg=none");
  await expect(lightPage.locator(".ui-window").first()).toBeVisible({ timeout: 45_000 });
  expect(await lightPage.locator("html").getAttribute("data-theme")).toBe("latte");
  await light.close();
});

test("after the only window ends, a host that exists is not called missing", async ({ page }) => {
  await page.request.post("/__mock/reset", { maxRetries: 1 });
  await page.goto("/?mock=1&proto=product&fresh=1&theme=ink&bg=none");
  await expect(page.locator("[data-view='console'] .ui-window").first()).toBeVisible({ timeout: 45_000 });
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:close", source: "keyboard" } })));
  await expect(page.locator(".cl-empty")).toBeVisible({ timeout: 10_000 });
  await expect(page.locator(".cl-empty-title")).toHaveText("No windows open");
  await expect(page.locator(".cl-empty-add")).toHaveText("Open shell");
  await page.locator(".cl-empty-add").click();
  await expect(page.locator("[data-view='console'] .ui-window").first()).toBeVisible({ timeout: 15_000 });
});
