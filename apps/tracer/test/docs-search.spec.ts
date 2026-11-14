// SPDX-License-Identifier: AGPL-3.0-only
/**
 * ⌘K matches the text of the docs (#339, D388), on a production build, in the app's palette and on a standalone docs page.
 *
 * The app: a word that is only in the body of a page ("check value", in the recovery words) lists that section under "Page text",
 * after the title and heading rows, with the match highlighted, and Enter opens the page at the heading. The text index
 * (`/docs/search.json`) is not fetched until the palette opens. The standalone page: the ⌘K button and the key open a palette of the same
 * results; a result is a link to the heading's anchor. Both at 1440×900 and on phones (393×852, 375×667), in dark and light; every row's
 * icon, title and snippet share a left edge (±0.5 px) and nothing scrolls sideways. Captures go to the external evidence directory.
 *
 * The test double adds the docs only with `?docs=1`; its web root holds the docs tree the build writes, so `/docs/reference/keys/` is a
 * standalone page of the instance's own docs.
 */
import { mkdirSync } from "node:fs";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

/** Where this spec writes its screenshots (the evidence folder). */
const OUT = tracerEvidencePath("docs-search");
/** The window sizes the spec runs at: a desktop, a phone, and the smallest phone. */
const SIZES = [
  { name: "desktop", width: 1440, height: 900, scale: 2, touch: false },
  { name: "phone", width: 393, height: 852, scale: 3, touch: true },
  { name: "small", width: 375, height: 667, scale: 3, touch: true },
] as const;

for (const size of SIZES) for (const scheme of ["dark", "light"] as const) {
  test(`${size.name} ${scheme}: the app's palette finds body text and the standalone page does too`, async ({ browser }) => {
    mkdirSync(OUT, { recursive: true });
    const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.scale, hasTouch: size.touch, isMobile: size.touch, colorScheme: scheme });
    const page = await context.newPage();
    const failures: string[] = [];
    const requests: string[] = [];
    page.on("pageerror", (error) => failures.push(error.message));
    page.on("request", (request) => requests.push(new URL(request.url()).pathname));
    const shot = (name: string) => page.screenshot({ path: `${OUT}/${name}.${size.name}.${scheme}.png` });
    try {
      // ---- the app -------------------------------------------------------------------------------------------------------
      await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${scheme === "dark" ? "ink" : "paper"}&bg=plain&docs=1`);
      await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
      await expect.poll(() => requests.includes("/docs/index.json"), { timeout: 15_000 }).toBe(true);
      // The text index waits for a search: the page has been open a while and it has not been asked for.
      // sleep: proves a negative, that nothing asks for the text index while the page idles; there is no event to wait for.
      await page.waitForTimeout(1200);
      expect(requests, "the text index is not fetched before the palette opens").not.toContain("/docs/search.json");
      await page.keyboard.press("Control+Shift+K");
      await expect(page.locator("#palette-input")).toBeFocused();
      await expect.poll(() => requests.includes("/docs/search.json"), { timeout: 10_000 }).toBe(true);
      await page.locator("#palette-input").fill("check value");
      const hit = page.locator('.palette .result[data-action="canvas:docs:reference/keys#recovery-words"]');
      await expect(hit).toBeVisible();
      await expect(hit.locator(".result-label")).toHaveText("Recovery words");
      await expect(hit.locator(".result-hint")).toHaveText("Keys and how long they last");
      await expect(hit.locator(".result-snippet mark").first()).toHaveText("check");
      await expect(page.locator(".palette .group-label", { hasText: "Page text" })).toBeVisible();
      // A word in a title lists the title row before any text match: "keys" finds the page under "Docs" and then the text rows.
      await page.locator("#palette-input").fill("keys");
      await expect(page.locator(".palette .result").first()).toBeVisible();
      const groups = await page.locator(".palette .group-label").allTextContents();
      if (groups.includes("Page text")) expect(groups.indexOf("Docs"), "title and heading rows are listed before text rows").toBeLessThan(groups.indexOf("Page text"));
      await page.locator("#palette-input").fill("check value");
      await expect(hit).toBeVisible();
      // Alignment: the row's icon, title and snippet share the left edges of the rows around them, and nothing scrolls sideways.
      const metrics = await page.evaluate(() => {
        const box = (element: Element | null) => element!.getBoundingClientRect();
        const row = document.querySelector<HTMLElement>('.palette .result[data-action="canvas:docs:reference/keys#recovery-words"]')!;
        const results = document.querySelector<HTMLElement>(".palette-results")!;
        return {
          label: box(row.querySelector(".result-label")).left, snippet: box(row.querySelector(".result-snippet")).left,
          iconMid: box(row.querySelector(".result-icon")).top + box(row.querySelector(".result-icon")).height / 2,
          labelMid: box(row.querySelector(".result-label")).top + box(row.querySelector(".result-label")).height / 2,
          overflow: results.scrollWidth - results.clientWidth,
        };
      });
      expect(Math.abs(metrics.label - metrics.snippet), "title and snippet share a left edge").toBeLessThanOrEqual(0.5);
      expect(Math.abs(metrics.iconMid - metrics.labelMid), "icon and title share a centre line").toBeLessThanOrEqual(0.5);
      expect(metrics.overflow, "the list does not scroll sideways").toBeLessThanOrEqual(0);
      // A name is never truncated (TASTE): the page's name ("Keys and how long they last") shows whole, wrapping under the heading on a phone.
      const hintBox = await page.evaluate(() => {
        const row = document.querySelector<HTMLElement>('.palette .result[data-action="canvas:docs:reference/keys#recovery-words"]')!;
        const hint = row.querySelector<HTMLElement>(".result-hint")!;
        const label = row.querySelector<HTMLElement>(".result-label")!;
        const range = document.createRange();
        range.selectNodeContents(hint);
        const text = range.getBoundingClientRect();
        const rowBox = row.getBoundingClientRect();
        return { clipped: hint.scrollWidth - hint.clientWidth, textRight: text.right, rowRight: rowBox.right, hintLeft: hint.getBoundingClientRect().left, labelLeft: label.getBoundingClientRect().left, ellipsis: getComputedStyle(hint).textOverflow };
      });
      expect(hintBox.clipped, "the page name is not clipped").toBeLessThanOrEqual(0);
      expect(hintBox.ellipsis, "the page name has no ellipsis").not.toBe("ellipsis");
      expect(hintBox.textRight, "the page name stays inside its row").toBeLessThanOrEqual(hintBox.rowRight + 0.5);
      // sleep: the screenshot waits for the list's fonts and layout to settle; no event marks the end.
      await page.waitForTimeout(300);
      await shot("app-palette-body");
      // Enter opens the page at the heading, in the Docs view.
      await hit.click();
      await expect(page.locator('.ui-window[data-window-id="d-reference/keys"] .dr-page h1')).toHaveText("Keys and how long they last", { timeout: 10_000 });

      // ---- the standalone page --------------------------------------------------------------------------------------------
      await page.goto("/docs/reference/keys/");
      await expect(page.locator("h1")).toHaveText("Keys and how long they last");
      // sleep: the page has been loaded a moment, so any early fetch of the text index would already have shown in `requests`.
      await page.waitForTimeout(600);
      const before = requests.filter((path) => path === "/docs/search.json").length;
      const opener = page.locator("button.bar-kbd");
      await opener.click();
      const input = page.locator("dialog.search input");
      await expect(input).toBeFocused();
      expect(requests.filter((path) => path === "/docs/search.json").length, "opening fetches the index").toBeGreaterThan(before);
      await input.fill("check value");
      const row = page.locator('dialog.search a.search-row[href="/docs/reference/keys/#recovery-words"]');
      await expect(row).toBeVisible();
      await expect(row.locator(".search-title")).toHaveText("Recovery words");
      await expect(row.locator(".search-snippet mark").first()).toHaveText("check");
      const edges = await page.evaluate(() => {
        const r = document.querySelector<HTMLElement>("dialog.search a.search-row")!;
        const box = (element: Element) => element.getBoundingClientRect();
        const list = document.querySelector<HTMLElement>(".search-results")!;
        return { title: box(r.querySelector(".search-title")!).left, snippet: box(r.querySelector(".search-snippet")!).left, overflow: list.scrollWidth - list.clientWidth, page: document.documentElement.scrollWidth - document.documentElement.clientWidth };
      });
      expect(Math.abs(edges.title - edges.snippet), "title and snippet share a left edge").toBeLessThanOrEqual(0.5);
      expect(edges.overflow, "the list does not scroll sideways").toBeLessThanOrEqual(0);
      expect(edges.page, "the page does not scroll sideways").toBeLessThanOrEqual(0);
      // sleep: the screenshot waits for the list's fonts and layout to settle; no event marks the end.
      await page.waitForTimeout(300);
      await shot("docs-palette-body");
      // A title match ranks first and arrows move the choice; Enter goes to the anchor; Escape closes and gives focus back.
      await input.fill("keys and how");
      await expect(page.locator("dialog.search .search-row").first().locator(".search-title")).toHaveText("Keys and how long they last");
      await page.keyboard.press("Escape");
      await expect(page.locator("dialog.search")).toBeHidden();
      await page.keyboard.press("Control+K");
      await expect(input).toBeFocused();
      await input.fill("check value");
      await page.keyboard.press("Enter");
      await expect(page).toHaveURL(/\/docs\/reference\/keys\/#recovery-words$/);
      // The result is on this very page, so the address only changes its hash: the dialog must still close, and focus must not stay in it.
      await expect(page.locator("dialog.search")).toBeHidden();
      expect(await page.evaluate(() => document.activeElement?.closest("dialog.search") ?? null), "focus left the dialog").toBeNull();
      await expect(page.locator("#recovery-words")).toBeInViewport();
      // Opened with the button and closed with Enter: following the hash moves the browser's focus starting point to the heading, so the
      // next Tab lands after the heading in the page, not on the (now hidden) dialog or back on the top bar.
      await opener.click();
      await expect(input).toBeFocused();
      await input.fill("check value");
      await page.keyboard.press("Enter");
      await expect(page.locator("dialog.search")).toBeHidden();
      await page.keyboard.press("Tab");
      expect(await page.evaluate(() => {
        const heading = document.getElementById("recovery-words")!;
        const now = document.activeElement!;
        return !now.closest("dialog.search") && now !== document.body && Boolean(heading.compareDocumentPosition(now) & Node.DOCUMENT_POSITION_FOLLOWING);
      }), "Tab continues from the heading the result led to").toBe(true);
      // A key press that confirms an IME composition is not Enter: the dialog stays and the page does not move.
      await opener.click();
      await input.fill("passkey");
      const urlBefore = page.url();
      await input.evaluate((element) => element.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", isComposing: true, bubbles: true, cancelable: true })));
      await expect(page.locator("dialog.search")).toBeVisible();
      expect(page.url()).toBe(urlBefore);
      expect(failures).toEqual([]);
    } finally { await context.close(); }
  });
}

test("a search that failed to load is asked for again on the next keystroke", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  try {
    let calls = 0;
    // The first answer is a server error; the next ones are the real file.
    await page.route("**/docs/search.json", (route) => (++calls === 1 ? route.fulfill({ status: 503, body: "busy" }) : route.continue()));
    await page.goto("/docs/reference/keys/");
    await page.locator("button.bar-kbd").click();
    const input = page.locator("dialog.search input");
    await input.fill("check value");
    await expect(page.locator("dialog.search .search-note")).toBeVisible();
    await input.fill("value check");
    await expect(page.locator('dialog.search a.search-row[href="/docs/reference/keys/#recovery-words"]')).toBeVisible();
    expect(calls).toBeGreaterThanOrEqual(2);
  } finally { await context.close(); }
});
