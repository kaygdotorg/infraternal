/**
 * The version pill and its panel (#216) on the production build, against the scripted source of the test double
 * (`?mock=1&proto=clusters&scene=3&version=1`). The same pill and panel mount in the product with the build's own facts.
 *
 * What is checked, in the owner's words (2026-11-01):
 * - a copy answers in place: the text fades out and a clipboard icon with "Copied" replaces it, no tooltip;
 * - the default action is contextual: the Updates value checks (never copies), the heading and plain lines copy;
 * - one Updates key, no second "Hosts" key; lag shows by itself; a press checks every host together and the value
 *   morphs to a spinner and then to "N updates available — proceed?" or "Up to date".
 * Screenshots and short videos for the issue go to the external evidence directory (see the last test).
 */
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type BrowserContext, type Locator, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const CAPTURES = tracerEvidencePath("version-pill");
mkdirSync(CAPTURES, { recursive: true });

const url = (theme = "ink"): string => `/?mock=1&proto=clusters&scene=3&bg=none&theme=${theme}&version=1`;
const pill = (page: Page) => page.locator(".ui-version-pill");
const panel = (page: Page) => page.locator(".cl-vp:not([hidden])");
const updatesValue = (page: Page) => panel(page).locator(".ui-kv-row", { has: page.locator(".ui-kv-key", { hasText: "Updates" }) }).locator(".ui-kv-value");

async function load(page: Page, theme = "ink"): Promise<void> {
  await page.goto(url(theme));
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator("#sidebar")).toBeVisible();
  await expect(pill(page)).toBeVisible({ timeout: 10_000 });
}

/** Chooses a scripted state of the double from the palette, as a person would. */
async function scenario(page: Page, label: string): Promise<void> {
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill(`Mockup: version – ${label}`);
  await page.keyboard.press("Enter");
  await expect(panel(page)).toBeVisible();
  await page.waitForTimeout(400);
}

/** Touch pointer pairs dispatched together, so the test covers the real double-tap window (Locator.tap waits for the click delay). */
async function taps(target: Locator, times: number): Promise<void> {
  await target.evaluate((element, count) => {
    const rect = element.getBoundingClientRect();
    const point = { clientX: rect.left + rect.width / 2, clientY: rect.top + rect.height / 2 };
    for (let i = 0; i < count; i++) {
      const pointerId = 60 + i;
      element.dispatchEvent(new PointerEvent("pointerdown", { bubbles: true, cancelable: true, pointerId, pointerType: "touch", isPrimary: true, button: 0, buttons: 1, ...point }));
      element.dispatchEvent(new PointerEvent("pointerup", { bubbles: true, cancelable: true, pointerId, pointerType: "touch", isPrimary: true, button: 0, buttons: 0, ...point }));
      element.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, detail: 1 }));
    }
  }, times);
}

const clipboard = (page: Page): Promise<string> => page.evaluate(() => navigator.clipboard.readText());

test.describe("desktop", () => {
  test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, permissions: ["clipboard-read", "clipboard-write"] });

  test("the pill sits on the footer's line, as tall as its neighbours, and opens the panel inside the sidebar", async ({ page }) => {
    await load(page);
    const [user, version, gear] = await Promise.all(["#sidebar .ui-sidebar-user", ".ui-version-pill", "#sidebar .ui-sidebar-settings"].map((s) => page.locator(s).boundingBox()));
    expect(Math.abs(version!.height - user!.height)).toBeLessThan(0.5);
    expect(Math.abs(version!.height - gear!.height)).toBeLessThan(0.5);
    expect(version!.x).toBeGreaterThan(user!.x + user!.width - 1);
    expect(version!.x + version!.width).toBeLessThan(gear!.x + 1);
    await expect(pill(page)).toHaveAttribute("aria-expanded", "false");
    await expect(pill(page)).toHaveAttribute("aria-label", /^Version 0\.4\.2\. Up to date\. Community edition\./);
    await pill(page).click();
    await expect(pill(page)).toHaveAttribute("aria-expanded", "true");
    await expect(panel(page)).toBeVisible();
    await page.waitForTimeout(450); // the card grows out of the pill for 200 ms; measure it at rest
    await expect(panel(page).locator(".cl-vp-heading")).toHaveText("infraternal 0.4.2");
    // The panel is a card in the sidebar, above the footer, and the pill closes it again.
    const card = (await panel(page).boundingBox())!, foot = (await page.locator("#sidebar .ui-sidebar-foot").boundingBox())!;
    expect(card.y + card.height).toBeLessThanOrEqual(foot.y + 1);
    await pill(page).click();
    await expect(panel(page)).toHaveCount(0);
  });

  test("opening the panel and pressing Updates cost almost no script, and no long task runs", async ({ page }) => {
    await load(page);
    await page.evaluate(() => {
      const tasks: number[] = [];
      new PerformanceObserver((list) => { for (const entry of list.getEntries()) tasks.push(entry.duration); }).observe({ type: "longtask", buffered: false });
      (window as unknown as { __long: number[] }).__long = tasks;
    });
    // The synchronous work of the first open (the panel is built then) and of a warm open, in the page's own clock.
    const first = await page.evaluate(() => { const t = performance.now(); document.querySelector<HTMLElement>(".ui-version-pill")!.click(); return performance.now() - t; });
    await expect(panel(page)).toBeVisible();
    // Escape closes it from anywhere on the page, not only from the pill or the card (Safari does not focus a clicked button).
    await page.keyboard.press("Escape");
    await expect(panel(page)).toHaveCount(0);
    const warm = await page.evaluate(() => { const t = performance.now(); document.querySelector<HTMLElement>(".ui-version-pill")!.click(); return performance.now() - t; });
    await expect(panel(page)).toBeVisible();
    const press = await page.evaluate(() => {
      const value = [...document.querySelectorAll<HTMLElement>(".cl-vp .ui-kv-row")].find((row) => row.querySelector(".ui-kv-key")?.textContent === "Updates")!.querySelector<HTMLElement>(".ui-kv-value")!;
      const t = performance.now(); value.click(); return performance.now() - t;
    });
    await page.waitForTimeout(1500);
    const long = await page.evaluate(() => (window as unknown as { __long: number[] }).__long);
    console.log(`VERSION_COST first-open=${first.toFixed(1)}ms warm-open=${warm.toFixed(1)}ms press=${press.toFixed(1)}ms long-tasks=${JSON.stringify(long)}`);
    expect(first).toBeLessThan(40);
    expect(warm).toBeLessThan(20);
    expect(press).toBeLessThan(20);
    expect(long.filter((ms) => ms >= 50)).toEqual([]);
  });

  test("one Updates row, no second key for the same thing", async ({ page }) => {
    await load(page);
    await scenario(page, "two hosts behind");
    const keys = await panel(page).locator(".ui-kv-key").allTextContents();
    expect(keys.filter((k) => /updates/i.test(k))).toEqual(["Updates"]);
    expect(keys).not.toContain("Hosts");
    // The lag shows by itself: no press was needed.
    await expect(updatesValue(page)).toHaveText("2 updates available — proceed?");
    await expect(updatesValue(page).locator(".ui-mark")).toHaveAttribute("data-mark", "warn");
    await expect(pill(page).locator(".ui-version-mark")).toHaveAttribute("data-mark", "warn");
  });

  test("a press checks every host together: spinner, then one update, then proceed, then up to date", async ({ page }) => {
    await load(page);
    await scenario(page, "a check finds one update");
    await expect(updatesValue(page)).toHaveText("Up to date");
    const started = Date.now();
    await updatesValue(page).click();
    // The value morphs to the turning arc and the words of the work.
    await expect(updatesValue(page)).toHaveText("Checking for updates…");
    await expect(updatesValue(page).locator(".ui-mark")).toHaveAttribute("data-mark", "busy");
    await expect(updatesValue(page)).toHaveText("1 update available — proceed?", { timeout: 8000 });
    // Five probes of 500 ms each, asked together, plus the spinner's minimum, finish well inside the sum of the probes.
    expect(Date.now() - started).toBeLessThan(2300);
    // A press never copied: the clipboard holds nothing of the row.
    expect(await clipboard(page)).not.toMatch(/update|Up to date|Checking/);
    await expect(updatesValue(page).locator(".ui-mark")).toHaveAttribute("data-mark", "warn");
    await expect(pill(page).locator(".ui-version-mark")).toHaveAttribute("data-mark", "warn");
    await updatesValue(page).click();
    await expect(updatesValue(page)).toHaveText("Updating 1…");
    await expect(updatesValue(page)).toHaveText("Up to date", { timeout: 10_000 });
    await expect(pill(page).locator(".ui-version-mark")).toHaveAttribute("data-mark", "ok");
    await expect(panel(page).locator(".cl-vp-heading")).toHaveText("infraternal 0.5.0");
  });

  test("a check that finds nothing goes back to Up to date; one that cannot finish says so and tries again on a press", async ({ page }) => {
    await load(page);
    await scenario(page, "never checked");
    await expect(updatesValue(page)).toHaveText("Check for updates");
    await expect(pill(page).locator(".ui-version-mark")).toBeHidden();
    await updatesValue(page).click();
    await expect(updatesValue(page)).toHaveText("Checking for updates…");
    await expect(updatesValue(page)).toHaveText("Up to date", { timeout: 8000 });
    await scenario(page, "cannot check");
    await expect(updatesValue(page)).toHaveText("Couldn't check — try again", { timeout: 10_000 });
    await expect(updatesValue(page).locator(".ui-mark")).toHaveAttribute("data-mark", "off");
    await updatesValue(page).click();
    await expect(updatesValue(page)).toHaveText("Checking for updates…");
    await expect(updatesValue(page)).toHaveText("Couldn't check — try again", { timeout: 8000 });
  });

  test("a value with an action does it; everything else copies, and a copy answers in place with no tooltip", async ({ page }) => {
    await load(page);
    await pill(page).click();
    await expect(panel(page)).toBeVisible();
    // The heading has no action, so it copies the whole build id.
    const heading = panel(page).locator(".cl-vp-heading");
    await heading.click();
    expect(await clipboard(page)).toBe("0.4.2-3f9c2ab");
    await expect(heading).toHaveAttribute("data-copied", "");
    await expect(heading.locator(".ui-copied")).toHaveText("Copied");
    await expect(heading.locator(".ui-copied svg")).toHaveCount(1);
    await expect(heading.locator(".ui-kv-text")).toHaveCSS("opacity", "0");
    expect((await page.locator(".tip").allInnerTexts()).join(" ")).not.toContain("Copied");
    // It fades back on its own.
    await expect(heading).not.toHaveAttribute("data-copied", "", { timeout: 3000 });
    await expect(heading.locator(".ui-kv-text")).toHaveCSS("opacity", "1");
    // A plain line with no action copies its own text.
    const line = panel(page).locator(".ui-kv-wide .ui-kv-value", { hasText: "Every feature" });
    await line.click();
    expect(await clipboard(page)).toBe("Every feature, unlimited hosts, one person");
    await expect(line.locator(".ui-copied")).toHaveText("Copied");
    // A key always copies its own word.
    await panel(page).locator(".ui-kv-key", { hasText: "Updates" }).click();
    expect(await clipboard(page)).toBe("Updates");
    // The Updates value did not copy: it ran its action, so the clipboard still holds the key.
    await updatesValue(page).click();
    await expect(updatesValue(page)).toHaveText("Checking for updates…");
    expect(await clipboard(page)).toBe("Updates");
    await expect(updatesValue(page)).not.toHaveAttribute("data-copied", "");
  });

  test("a keyboard copy shows the result with no fade", async ({ page }) => {
    await load(page);
    await pill(page).click();
    const heading = panel(page).locator(".cl-vp-heading");
    await heading.focus();
    await page.keyboard.press("Enter");
    await expect(heading).toHaveAttribute("data-instant", "");
    await expect(heading.locator(".ui-copied")).toHaveText("Copied");
  });

  test("Escape closes the panel first and keeps the sidebar; the palette reaches the same panel", async ({ page }) => {
    await load(page);
    await pill(page).click();
    await expect(panel(page)).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(panel(page)).toHaveCount(0);
    await expect(page.locator("#sidebar")).toBeVisible();
    await page.keyboard.press("Control+Shift+K");
    await page.locator("#palette-input").fill("check for updates");
    await page.keyboard.press("Enter");
    await expect(panel(page)).toBeVisible();
    await expect(updatesValue(page)).toHaveText("Checking for updates…");
  });
});

test.describe("reduced motion", () => {
  test.use({ viewport: { width: 1440, height: 900 }, permissions: ["clipboard-read", "clipboard-write"] });

  test("the copy keeps its crossfade, the icon does not scale, and the spinner does not turn", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await load(page);
    await pill(page).click();
    const heading = panel(page).locator(".cl-vp-heading");
    await heading.click();
    await expect(heading.locator(".ui-copied")).toHaveText("Copied");
    await expect(heading.locator(".ui-copied-icon")).toHaveCSS("transform", "none");
    await updatesValue(page).click();
    await expect(updatesValue(page).locator(".ui-mark[data-mark='busy']")).toHaveCSS("animation-name", "none");
  });
});

test.describe("phone", () => {
  test.use({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true, permissions: ["clipboard-read", "clipboard-write"] });

  test("touch targets are 44 px; a single tap answers the Updates value, a double tap copies a plain line", async ({ page }) => {
    await load(page);
    expect((await pill(page).boundingBox())!.height).toBeGreaterThanOrEqual(43.5);
    await pill(page).tap();
    await expect(panel(page)).toBeVisible();
    // One tap on the pressable value starts the check.
    await updatesValue(page).tap();
    await expect(updatesValue(page)).toHaveText("Checking for updates…");
    // One tap on a plain line is free for scrolling and selection; two copy it.
    const line = panel(page).locator(".ui-kv-wide .ui-kv-value", { hasText: "Every feature" });
    await taps(line, 1);
    await page.waitForTimeout(150);
    await expect(line).not.toHaveAttribute("data-copied", "");
    await taps(line, 2);
    await expect(line).toHaveAttribute("data-copied", "");
    await expect(line.locator(".ui-copied")).toHaveText("Copied");
  });

  test("the panel and the footer fit the narrow sidebar without overflow", async ({ page }) => {
    await load(page);
    await scenario(page, "worst case");
    await page.waitForTimeout(450); // measured at rest, after the card has grown out of the pill
    const box = (await panel(page).boundingBox())!, sidebar = (await page.locator("#sidebar").boundingBox())!;
    expect(box.x).toBeGreaterThanOrEqual(sidebar.x - 0.5);
    expect(box.x + box.width).toBeLessThanOrEqual(sidebar.x + sidebar.width + 0.5);
    const report = await panel(page).evaluate((node) => {
      const right = node.getBoundingClientRect().right;
      const wide = [...node.querySelectorAll<HTMLElement>("*")].filter((e) => e.getBoundingClientRect().right > right + 0.5).map((e) => `${e.tagName}.${e.className}:${(e.getBoundingClientRect().right - right).toFixed(1)}`);
      const scrolling = [node, ...node.querySelectorAll<HTMLElement>("*")].filter((e) => e.scrollWidth - e.clientWidth > 0.5).map((e) => `${e.tagName}.${e.className}:${e.scrollWidth}/${e.clientWidth}`);
      return { overflow: node.scrollWidth - node.clientWidth, wide: wide.slice(0, 8), scrolling: scrolling.slice(0, 8) };
    });
    console.log(`PANEL_OVERFLOW ${JSON.stringify(report)}`);
    // Nothing is drawn beyond the card's right edge. (The card's scroll width is a couple of pixels wider than its box by design:
    // a value's highlight run and the close button have negative margins that the card's padding absorbs.)
    expect(report.wide).toEqual([]);
  });
});

/** Review captures and short videos for the issue (not assertions about taste). */
async function capture(context: BrowserContext, page: Page, size: string, theme: string): Promise<void> {
  await load(page, theme);
  const shot = async (name: string): Promise<void> => { await page.waitForTimeout(450); await page.screenshot({ path: resolve(CAPTURES, `${name}-${size}-${theme}.png`) }); };
  await shot("pill-closed");
  await pill(page).click();
  await shot("panel-up-to-date");
  await scenario(page, "two hosts behind");
  await shot("lag-shows-by-itself");
  await scenario(page, "a check finds one update");
  await updatesValue(page).click();
  await page.waitForTimeout(250);
  await page.screenshot({ path: resolve(CAPTURES, `checking-${size}-${theme}.png`) });
  await expect(updatesValue(page)).toHaveText("1 update available — proceed?", { timeout: 8000 });
  await shot("proceed");
  await updatesValue(page).click();
  await page.waitForTimeout(250);
  await page.screenshot({ path: resolve(CAPTURES, `updating-${size}-${theme}.png`) });
  await expect(updatesValue(page)).toHaveText("Up to date", { timeout: 10_000 });
  await shot("up-to-date-after");
  await scenario(page, "cannot check");
  await shot("cannot-check");
  await scenario(page, "Team licence, seats nearly full");
  await shot("team-licence");
  await panel(page).locator(".cl-vp-heading").click();
  await page.waitForTimeout(220);
  await page.screenshot({ path: resolve(CAPTURES, `copied-in-place-${size}-${theme}.png`) });
  await context.close();
}

for (const [size, viewport, scale, touch] of [["1440x900", { width: 1440, height: 900 }, 2, false], ["393x852", { width: 393, height: 852 }, 3, true]] as const) {
  for (const theme of ["ink", "paper"]) {
    test(`captures and a video, ${size} ${theme}`, async ({ browser }) => {
      test.skip(!process.env.J56_CAPTURE, "review captures run on request (J56_CAPTURE=1)");
      const context = await browser.newContext({
        viewport, deviceScaleFactor: scale, permissions: ["clipboard-read", "clipboard-write"], ...(touch ? { hasTouch: true, isMobile: true } : {}),
        recordVideo: { dir: resolve(CAPTURES, "video"), size: viewport },
      });
      await capture(context, await context.newPage(), size, theme);
    });
  }
}
