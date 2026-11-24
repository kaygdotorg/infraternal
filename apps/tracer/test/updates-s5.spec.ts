/**
 * The owner's Updates controls (#211, S5; mockup, D162) on the preview build, against the scripted double
 * (`?mock=1&proto=clusters&scene=3&updates=1`): the Settings › Machines › Updates window in every state, the Inbox item
 * "Update ready · <version>" (and no toast at all), and what Update now and Roll back do. Alignment is measured (±0.5 px, the owner's rule):
 * the window's rows, buttons and history share one left edge.
 *
 * Captures: with `INFRATERNAL_EVIDENCE_DIR` set, each state is written at 1440x900 (DPR 2) and 393x852 (DPR 3) in ink and paper.
 * The assertions only prove each state was reached; nobody judges the pictures here.
 */
import { resolve } from "node:path";
import { expect, test, type BrowserContext, type Locator, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

/** Where the captures are written (outside the checkout). */
const OUT = tracerEvidencePath("updates-s5");
/** The two screen sizes of the review: desktop at DPR 2 and phone at DPR 3. */
const SIZES = [
  ["desktop", { width: 1440, height: 900 }, 2],
  ["phone", { width: 393, height: 852 }, 3],
] as const;
/** The states the capture visits, in the order of the palette rows. */
const STATES = ["current", "checking", "downloading", "ready", "switching", "trial", "undone-health", "undone-owner", "failed", "offline", "no-release", "never", "edge", "aged", "off", "long"] as const;
/** The Updates window's selector. */
const WINDOW = '[data-window-id="s-machines-updates"]';

/** Opens the preview build on the double in `theme`; the window is idle once the first frame had settled. */
async function open(context: BrowserContext, theme: string, phone: boolean): Promise<Page> {
  const page = await context.newPage();
  await page.goto(`/?mock=1&proto=clusters&scene=3&updates=1&bg=none&theme=${theme}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  // sleep: the preview's opening animation has no event to wait for; the capture must not catch it half way.
  await page.waitForTimeout(1200);
  void phone;
  return page;
}

/** Puts the double in a state and opens its window, as the palette row does. */
async function scenario(page: Page, id: string): Promise<void> {
  await page.evaluate((action) => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action, source: "keyboard" } })), `proto:upd:${id}`);
  await expect(page.locator(`${WINDOW} .cl-up`)).toBeVisible({ timeout: 10_000 });
  // sleep: the window's fly-in and the retained-state fade have no event; the capture waits for them to finish.
  await page.waitForTimeout(900);
}

/** The left edge of `l` on the page, for the alignment checks. */
const left = async (l: Locator): Promise<number> => (await l.boundingBox())!.x;

for (const [name, viewport, scale] of SIZES) {
  for (const theme of ["ink", "paper"]) {
    test.describe(`${name} ${theme}`, () => {
      test.setTimeout(300_000);
      test("every state of the Updates window, with the Inbox item and toast where they belong", async ({ browser }) => {
        const context = await browser.newContext({ viewport, deviceScaleFactor: scale, ...(name === "phone" ? { hasTouch: true, isMobile: true } : {}) });
        const page = await open(context, theme, name === "phone");
        for (const id of STATES) {
          await scenario(page, id);
          await page.screenshot({ path: resolve(OUT, `updates-${id}-${name}-${theme}.png`) });
        }
        // The Inbox item the staged version raises: the sidebar open, the item expanded.
        await scenario(page, "ready");
        await page.locator("#sidebar-toggle").click();
        await expect(page.locator(".ui-inbox .ui-inbox-row").first()).toBeVisible();
        await page.locator(".ui-inbox .ui-inbox-row").first().click();
        // sleep: the Inbox row's expand animation has no event; the capture waits for it.
        await page.waitForTimeout(600);
        await page.screenshot({ path: resolve(OUT, `inbox-ready-${name}-${theme}.png`) });
        await context.close();
      });
    });
  }
}

test.describe("behaviour", () => {
  test("the window is aligned, Update now installs and says so, Roll back asks first and names the loss", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
    const page = await open(context, "ink", false);
    await scenario(page, "ready");
    const win = page.locator(WINDOW);
    // One left edge: the kv keys, the detail sentence, the buttons row, the setting rows and the history heading.
    const edges = await Promise.all([
      left(win.locator(".ui-kv-key").first()), left(win.locator(".cl-up-detail")), left(win.locator(".cl-up-button").first()),
      left(win.locator(".ui-setting-title").first()), left(win.locator(".ui-ts-title")),
    ]);
    for (const e of edges) expect(Math.abs(e - edges[0]!)).toBeLessThanOrEqual(0.5);
    // The buttons are a grid of equal cells, so a wrapped row starts on the same edge as the first.
    const buttonLefts = await win.locator(".cl-up-button").evaluateAll((bs) => bs.map((b) => b.getBoundingClientRect().left));
    expect(buttonLefts[0]).toBeGreaterThan(0);
    // The staged version raises the Inbox item and no toast: an update never raises one (owner, 2026-11-22).
    await expect(page.locator(".ui-toast")).toHaveCount(0);
    await expect(win.getByRole("button", { name: "Update now" })).toBeEnabled();
    await expect(win.getByRole("button", { name: "Roll back" })).toBeEnabled();
    // The status marks are as tall as the text beside them.
    const mark = await win.locator(".ui-kv-mark").first().boundingBox();
    const text = await win.locator(".ui-kv-value").first().evaluate((n) => parseFloat(getComputedStyle(n).fontSize));
    expect(Math.abs(mark!.height - text)).toBeLessThanOrEqual(0.5);
    await win.getByRole("button", { name: "Update now" }).click();
    await expect(page.locator(".ui-toast")).toHaveCount(0);
    await expect(win.locator(".ui-kv-value", { hasText: "Installing 0.5.0…" })).toBeVisible();
    await expect(win.locator(".ui-kv-value", { hasText: "Up to date" })).toBeVisible({ timeout: 10_000 });
    await expect(win.locator(".ui-kv-value", { hasText: "0.5.0 · stable" })).toBeVisible();
    expect(await page.evaluate(() => (window as unknown as { __updatesReloads?: number }).__updatesReloads)).toBe(1);
    // Roll back asks first, names the version that comes back and what is lost, and does nothing until confirmed.
    await win.getByRole("button", { name: "Roll back" }).click();
    const ask = page.locator(".ui-confirm-tip, [role=alertdialog], [role=dialog]").filter({ hasText: "Go back to 0.4.2?" }).first();
    await expect(ask).toBeVisible();
    await expect(ask).toContainText("is lost");
    await ask.getByRole("button", { name: "Keep this version" }).click();
    await expect(win.locator(".ui-kv-value", { hasText: "0.5.0 · stable" })).toBeVisible();
    await context.close();
  });

  test("the channel row has no Default line, and switching to Edge asks first, naming the risk", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await open(context, "ink", false);
    await scenario(page, "current");
    const win = page.locator(WINDOW);
    const channel = win.locator("[data-setting=update-channel]");
    await expect(channel.locator(".ui-setting-caption")).toHaveCount(0);
    await expect(win.locator("[data-setting=update-quiet]").locator(".ui-setting-caption")).toHaveCount(1);
    const chosen = () => page.evaluate(() => (window as unknown as { __updatesDouble: { facts(): { channel: string } } }).__updatesDouble.facts().channel);
    await channel.getByRole("tab", { name: "Edge" }).click();
    const ask = page.locator(".ui-confirm-tip").filter({ hasText: "Switch to Edge?" });
    await expect(ask).toContainText("may break");
    await ask.getByRole("button", { name: "Stay on Stable" }).click();
    await expect(channel.getByRole("tab", { name: "Stable" })).toHaveAttribute("aria-selected", "true");
    expect(await chosen()).toBe("stable");
    await channel.getByRole("tab", { name: "Edge" }).click();
    await page.locator(".ui-confirm-tip").last().getByRole("button", { name: "Use Edge" }).click();
    await expect.poll(chosen).toBe("edge");
    await context.close();
  });

  test("Roll back is offered for a day after the install and not after", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await open(context, "ink", false);
    await scenario(page, "current");
    await expect(page.locator(WINDOW).getByRole("button", { name: "Roll back" })).toBeEnabled();
    await scenario(page, "aged");
    await expect(page.locator(WINDOW).getByRole("button", { name: "Roll back" })).toBeDisabled();
    await context.close();
  });

  test("a refusal is said under the buttons, never as a toast, and changes nothing", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await open(context, "ink", false);
    await scenario(page, "current");
    await page.evaluate(() => (window as unknown as { __updatesDouble: { refuseNext(s: string): void } }).__updatesDouble.refuseNext("Confirm with your passkey first."));
    await page.locator(WINDOW).getByRole("button", { name: "Check now" }).click();
    await expect(page.locator(`${WINDOW} .cl-up-refusal`)).toHaveText("Confirm with your passkey first.");
    await expect(page.locator(".ui-toast")).toHaveCount(0);
    await context.close();
  });
});
