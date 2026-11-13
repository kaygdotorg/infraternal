// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The phone bugs J509 found in iPhone Simulator Safari (#500, J521), each checked in a production build:
 *
 * 1. The SSH password (and key passphrase) field stays a secure password field (dots to VoiceOver, no copy) and says it is an
 *    existing password, so Safari does not offer a generated one for a credential that is used once and belongs to another machine.
 * 2. The layout leaves its keyboard state when the keyboard goes away, even if the last `visualViewport` event was early or lost.
 * 3. The Add host sign-in step keeps its options in view on a short phone card: the footer is one row, not two stacked buttons.
 * 4. After the only window ends, the screen says "No windows open" while a host exists; "No hosts yet" is for no host.
 * 5. D390 (amends D352): an account that never picked a theme follows the system's light or dark scheme on every device, live
 *    (TASTE "Light and dark everywhere"), and its first load saves no theme. Once the person picks a theme, the account's theme
 *    wins on every device, so a later system change does not flip it.
 * 6. The host-key and sign-in titles name the typed port.
 */
import { expect, test, type Page } from "playwright/test";

/** A short iPhone page: 402 x 874 minus Safari's top and bottom bars leaves about this much. */
const PHONE = { width: 402, height: 740 };
test.use({ viewport: PHONE, hasTouch: true, isMobile: true, deviceScaleFactor: 3 });

/** The add-host card. */
const wizard = (page: Page) => page.locator(".ah-float");
/** A button of the add-host card, by its exact name. */
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

test("the SSH password and passphrase stay secure fields that tell Safari they are existing passwords", async ({ page }) => {
  await open(page);
  await typeHost(page, "kayg@needs-key.lab");
  await expect(page.getByRole("heading", { name: /Sign in to needs-key.lab/ })).toBeVisible({ timeout: 15_000 });
  await page.getByText("Sign in with a password").click();
  for (const name of ["password", "passphrase"]) {
    const field = page.locator(`[data-secret='${name}']`);
    // A real password field: iOS exposes dots (never the text) to VoiceOver and blocks copy. A text field drawn as dots did neither.
    expect(await field.getAttribute("type")).toBe("password");
    // "current-password" is the token that keeps Safari from offering a generated password; "off" is ignored on password fields.
    expect(await field.getAttribute("autocomplete")).toBe("current-password");
    expect(await field.getAttribute("autocorrect")).toBe("off");
    expect(await field.getAttribute("autocapitalize")).toBe("none");
    expect(await field.getAttribute("spellcheck")).toBe("false");
    expect(await field.getAttribute("name"), "no name for a manager to match on").toBeNull();
  }
});

test("the SSH password is paired with its account in one form, so Safari's Save Password names it (#510)", async ({ page }) => {
  await open(page);
  await typeHost(page, "kayg@needs-key.lab");
  await expect(page.getByRole("heading", { name: /Sign in to needs-key.lab/ })).toBeVisible({ timeout: 15_000 });
  await page.getByText("Sign in with a password").click();
  const form = page.locator("form[data-ah-method-form]");
  const account = form.locator("input[autocomplete='username']");
  // Without a username field Safari's sheet shows an empty "User Name". The account is the SSH user at the host.
  await expect(account).toHaveValue("kayg@needs-key.lab");
  expect(await account.getAttribute("readonly")).not.toBeNull();
  expect(await account.getAttribute("tabindex"), "the hidden account never takes a Tab stop").toBe("-1");
  expect(await page.evaluate(() => { const a = document.querySelector("input[autocomplete=username]"); const p = document.querySelector("[data-secret=password]"); return !!a?.closest("form") && a.closest("form") === p?.closest("form"); })).toBe(true);
  // Enter in the password field signs in (the form's submit), and the page does not navigate.
  const url = page.url();
  await page.locator("[data-secret='password']").fill("correct horse battery staple");
  await page.keyboard.press("Enter");
  await expect(page.locator(".ah-stage-row[data-stage='detect'] .ah-stage-detail")).toHaveText("Signed in with your password", { timeout: 15_000 });
  expect(page.url()).toBe(url);
});

test("the sign-in step keeps its options in view on a short phone card", async ({ page }) => {
  await open(page);
  await typeHost(page, "kayg@needs-key.lab");
  await expect(page.getByRole("heading", { name: /Sign in to needs-key.lab/ })).toBeVisible({ timeout: 15_000 });
  const geometry = () => page.evaluate(() => {
    const scroll = document.querySelector<HTMLElement>(".ah-scroll")!.getBoundingClientRect();
    const foot = document.querySelector<HTMLElement>(".ah-foot")!.getBoundingClientRect();
    const field = document.querySelector<HTMLElement>("[data-secret='password']")!.getBoundingClientRect();
    return { scrollH: scroll.height, footH: foot.height, fieldTop: field.top, fieldBottom: field.bottom, scrollTop: scroll.top, scrollBottom: scroll.bottom };
  });
  const before = await geometry();
  test.info().annotations.push({ type: "measured", description: JSON.stringify(before) });
  expect(before.footH, "Back and Sign in share one row, not two stacked buttons").toBeLessThan(90);
  expect(before.scrollH, "the scroll body has room for the title and the options").toBeGreaterThanOrEqual(300);
  // Choosing the password option shows its field inside the scroll body without any scrolling by the person.
  await page.getByText("Sign in with a password").click();
  await expect.poll(async () => { const g = await geometry(); return g.fieldTop >= g.scrollTop && g.fieldBottom <= g.scrollBottom; }, { timeout: 3_000 }).toBe(true);
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

/** The `themeChosen` flag of every cached look on this page (the cache is the look the first paint reads). */
const chosenFlags = (page: Page): Promise<unknown[]> => page.evaluate(() => Object.entries(localStorage)
  .filter(([key]) => key === "tracer.look" || key.startsWith("tracer.look.account."))
  .map(([, value]) => { try { return (JSON.parse(value) as { themeChosen?: unknown }).themeChosen; } catch { return "unreadable"; } }));

test("a never-chosen theme follows the system, live and on every device; a picked theme does not (D390)", async ({ browser, baseURL }) => {
  const context = await browser.newContext({ baseURL: baseURL!, colorScheme: "dark", viewport: PHONE, hasTouch: true, isMobile: true });
  const page = await context.newPage();
  await page.request.post("/__mock/reset", { maxRetries: 1 });
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
  await expect(page.locator(".ui-window").first()).toBeVisible({ timeout: 45_000 });
  const dark = await page.locator("html").getAttribute("data-theme");
  expect(["mocha", "macchiato", "frappe"], `first load in a dark system: ${dark}`).toContain(dark);
  // The first load saved no theme: the cache holds none that counts as chosen, so a light device is not forced dark.
  expect(await chosenFlags(page)).not.toContain(true);
  // Nothing was picked, so the system's own change is followed while the page stays open.
  await page.emulateMedia({ colorScheme: "light" });
  await expect(page.locator("html")).toHaveAttribute("data-theme", "latte", { timeout: 5_000 });
  await page.emulateMedia({ colorScheme: "dark" });
  await expect(page.locator("html")).toHaveAttribute("data-theme", /^(mocha|macchiato|frappe)$/, { timeout: 5_000 });
  // Picking a theme in the palette is the person's choice: it is saved as chosen, and a later system change no longer moves it.
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("Theme: Frosted");
  await page.getByRole("option").filter({ hasText: "Theme: Frosted" }).first().click();
  await expect.poll(() => chosenFlags(page), { timeout: 5_000 }).toContain(true);
  const picked = await page.locator("html").getAttribute("data-theme");
  await page.emulateMedia({ colorScheme: "light" });
  // sleep: a negative check; give a wrongly followed system change time to land before asserting the theme stayed.
  await page.waitForTimeout(500);
  expect(await page.locator("html").getAttribute("data-theme")).toBe(picked);
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
