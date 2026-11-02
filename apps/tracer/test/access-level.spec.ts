/**
 * The "Access level" row of a machine's details and the privileged-access consent under it (#215, D286): the row says
 * Limited with a quiet cross and opens the consent; the consent walks consent → password → progress → done; the machine
 * decides which secret is asked; a wrong password says so in place and empties the field; an unreachable machine says nothing
 * changed; Escape closes the pane before the popover. `?privilege=<scenario>` gives the test double a privilege service; without
 * it the row does not exist (the product has none yet).
 *
 * Alignment (TASTE): the three icon buttons share a centre line and end at the pane's padding; the row's mark and its value
 * share a centre line. Desktop 1440×900 and phone 393×852.
 */
import { expect, test, type Page } from "playwright/test";

const base = "/?mock=1&proto=clusters&scene=1&theme=ink&bg=none";

async function open(page: Page, scenario: string | undefined, width = 1440, height = 900): Promise<void> {
  await page.setViewportSize({ width, height });
  await page.goto(`${base}${scenario ? `&privilege=${scenario}` : ""}`);
  await page.waitForFunction(() => (window as unknown as { __tracerClusters?: unknown }).__tracerClusters, null, { timeout: 30_000 });
  await page.waitForTimeout(700);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(v: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(900);
  await page.locator(".ui-window-pill").first().click();
  await expect(page.locator(".canvas-popover")).toBeVisible();
  await page.waitForTimeout(400);
}
const row = (page: Page) => page.locator(".canvas-popover .ui-kv-row", { hasText: "Access level" });
const pane = (page: Page) => page.locator(".cl-pv[data-open]");
const press = async (page: Page): Promise<void> => { await row(page).locator(".ui-kv-press, .ui-kv-cell").last().click(); await expect(pane(page)).toBeVisible(); };

test("without a privilege service the row does not exist", async ({ page }) => {
  await open(page, undefined);
  await expect(page.locator(".canvas-popover .ui-kv-row").first()).toBeVisible();
  await expect(row(page)).toHaveCount(0);
});

test("sudo: the sentence, three icons, the sudo password, progress, then Full access with a tick", async ({ page }) => {
  await open(page, "sudo");
  await expect(row(page)).toContainText("Limited");
  expect(await row(page).locator(".ui-mark").getAttribute("data-mark")).toBe("off");
  await press(page);
  await expect(pane(page)).toContainText("Allow full access?");
  await expect(pane(page)).toContainText("runs without special privileges");
  expect(await pane(page).locator(".ui-confirm-bar button").evaluateAll((b) => b.map((x) => x.getAttribute("aria-label")))).toEqual(["What changes? Read the docs", "Not now", "Continue"]);
  // Alignment: the icon buttons share a centre line, and the last one ends at the pane's right padding.
  const geometry = await pane(page).evaluate((root) => {
    const bar = root.querySelector(".ui-confirm-bar")!;
    const centres = [...bar.querySelectorAll("button")].map((b) => { const r = b.getBoundingClientRect(); return r.top + r.height / 2; });
    const card = root.querySelector(".cl-pv-card")!.getBoundingClientRect(), pad = parseFloat(getComputedStyle(root.querySelector(".cl-pv-pane")!).paddingRight);
    const last = bar.lastElementChild!.getBoundingClientRect();
    const title = root.querySelector(".ui-confirm-tip-message")!.getBoundingClientRect(), padLeft = parseFloat(getComputedStyle(root.querySelector(".cl-pv-pane")!).paddingLeft);
    return { spread: Math.max(...centres) - Math.min(...centres), rightGap: card.right - pad - last.right, leftGap: title.left - (card.left + padLeft) };
  });
  expect(geometry.spread, "icon buttons on one centre line").toBeLessThanOrEqual(0.5);
  expect(Math.abs(geometry.rightGap), "last button at the pane's right padding").toBeLessThanOrEqual(0.5);
  expect(Math.abs(geometry.leftGap), "text at the pane's left padding").toBeLessThanOrEqual(0.5);
  await pane(page).locator(".ui-confirm-yes").click();
  await expect(pane(page)).toContainText("Your sudo password for kayg");
  await expect(pane(page)).toContainText("Never stored or logged");
  const field = page.locator(".cl-pv-field");
  await field.fill("pw");
  await page.keyboard.press("Enter");
  await expect(field).toHaveCount(0); // the secret left the page with the send
  await expect(row(page)).toContainText("Full access", { timeout: 8000 });
  expect(await row(page).locator(".ui-mark").getAttribute("data-mark")).toBe("ok");
});

test("the row's mark and its value share a centre line", async ({ page }) => {
  await open(page, "sudo");
  const spread = await row(page).evaluate((r) => {
    const mark = r.querySelector(".ui-mark")!.getBoundingClientRect(), text = r.querySelector(".ui-kv-value .ui-kv-text, .ui-kv-value")!;
    const range = document.createRange();
    range.selectNodeContents(text);
    const line = [...range.getClientRects()].find((q) => q.width > 0.5)!;
    return Math.abs(mark.top + mark.height / 2 - (line.top + line.height / 2));
  });
  expect(spread).toBeLessThanOrEqual(0.5);
});

test("doas, root and sudo-not-allowed show which password the machine asks for", async ({ page }) => {
  for (const [scenario, words] of [["doas", "Your doas password for kayg"], ["root", "The root password for build-01"], ["denied", "isn't allowed to use sudo"]] as const) {
    await open(page, scenario);
    await press(page);
    await pane(page).locator(".ui-confirm-yes").click();
    await expect(pane(page)).toContainText(words);
    await expect(page.locator(".cl-pv-field")).toBeVisible();
  }
});

test("a wrong password says so in place, empties the field and lets the next one through", async ({ page }) => {
  await open(page, "wrong");
  await press(page);
  await pane(page).locator(".ui-confirm-yes").click();
  await page.locator(".cl-pv-field").fill("nope");
  await page.keyboard.press("Enter");
  await expect(page.locator(".cl-pv-error")).toContainText("didn't work", { timeout: 6000 });
  await expect(page.locator(".cl-pv-field")).toHaveValue("");
  await page.locator(".cl-pv-field").fill("right");
  await page.keyboard.press("Enter");
  await expect(row(page)).toContainText("Full access", { timeout: 8000 });
});

test("an unreachable machine says nothing changed; Escape closes the pane before the popover", async ({ page }) => {
  await open(page, "offline");
  await press(page);
  await expect(pane(page)).toContainText("can't be reached right now");
  await expect(pane(page)).toContainText("nothing was changed");
  await page.keyboard.press("Escape");
  await expect(page.locator(".cl-pv[data-open]")).toHaveCount(0);
  await expect(page.locator(".canvas-popover")).toHaveCount(1);
  await page.keyboard.press("Escape");
  await expect(page.locator(".canvas-popover")).toHaveCount(0);
});

test("several selected: one consent and one password for the machines that allow sudo", async ({ page }) => {
  await open(page, "bulk");
  await press(page);
  await expect(pane(page)).toContainText("Allow full access on 2 computers?");
  await expect(pane(page)).toContainText("edge-arm doesn't allow sudo");
  expect(await pane(page).locator(".ui-confirm-yes").getAttribute("aria-label")).toBe("Apply to all 2 hosts that allow sudo");
  await pane(page).locator(".ui-confirm-yes").click();
  await page.locator(".cl-pv-field").fill("pw");
  await page.keyboard.press("Enter");
  await expect(page.locator(".cl-pv-run-name")).toHaveCount(2);
  await expect(row(page)).toContainText("Full access", { timeout: 9000 });
});

test("the buttons' tooltips open below them and never cover the password field", async ({ page }) => {
  await open(page, "root");
  await press(page);
  await pane(page).locator(".ui-confirm-yes").click();
  const field = (await page.locator(".cl-pv-field").boundingBox())!;
  for (const label of ["Cancel", "Give full access"]) {
    const button = page.locator(`.cl-pv .ui-confirm-bar [aria-label="${label}"]`);
    await button.hover();
    const tip = page.locator(".tip-pos .tip");
    await expect(tip).toHaveText(label);
    const t = (await tip.boundingBox())!;
    expect(t.x < field.x + field.width && t.x + t.width > field.x && t.y < field.y + field.height && t.y + t.height > field.y, `${label}: the tip stays clear of the field`).toBe(false);
  }
});

test("the palette finds Allow full access on a host and opens its consent", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${base}&privilege=sudo`);
  await page.waitForFunction(() => (window as unknown as { __tracerClusters?: unknown }).__tracerClusters, null, { timeout: 30_000 });
  await page.waitForTimeout(900);
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette-input")).toBeFocused();
  expect(await page.locator("#palette-results .result", { hasText: "Allow full access" }).count(), "query-only: not in the empty list").toBe(0);
  await page.keyboard.type("full access on build-01");
  await page.waitForTimeout(400);
  await expect(page.locator("#palette-results .result").first()).toContainText("Allow full access on build-01");
  await page.keyboard.press("Enter");
  await expect(pane(page)).toContainText("Allow full access?", { timeout: 6000 });
});

test.describe("phone 393×852", () => {
  test.use({ hasTouch: true, isMobile: true, deviceScaleFactor: 3 });
  test("the consent fits the popover and its buttons are 44 px targets", async ({ page }) => {
    await open(page, "sudo", 393, 852);
    await row(page).locator(".ui-kv-press, .ui-kv-cell").last().tap();
    await expect(pane(page)).toBeVisible();
    const m = await pane(page).evaluate((root) => {
      const card = root.querySelector(".cl-pv-card")!.getBoundingClientRect(), pop = document.querySelector(".canvas-popover")!.getBoundingClientRect();
      const heights = [...root.querySelectorAll(".ui-confirm-bar button")].map((b) => { const r = b.getBoundingClientRect(); return Math.min(r.width, r.height); });
      return { inside: card.left >= pop.left && card.right <= pop.right, minTarget: Math.min(...heights) };
    });
    expect(m.inside).toBe(true);
    await page.waitForTimeout(500);
    // The pane opened below the fold of the popover and was scrolled into view: its whole box is inside the popover's.
    const seen = await pane(page).evaluate((root) => { const card = root.querySelector(".cl-pv-card")!.getBoundingClientRect(), pop = document.querySelector(".canvas-popover")!.getBoundingClientRect(); return card.top >= pop.top && card.bottom <= pop.bottom + 0.5; });
    expect(seen, "the consent is fully in view").toBe(true);
    expect(m.minTarget).toBeGreaterThanOrEqual(43.5);
  });
});
