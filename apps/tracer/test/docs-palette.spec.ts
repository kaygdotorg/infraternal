// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The docs in the command palette, on a production build (#302): typing "keys" or "multiplexer" lists the page, Enter opens it
 * in a canvas window (no new tab), a heading result opens the page at that heading, and the index is fetched only once the
 * palette first opens. Alignment is measured (TASTE: one left edge, ±0.5 px) for the palette rows and for the page inside
 * its window, at 1440×900 DPR 2 and on a phone at 393×852 DPR 3. Captures go to the external evidence directory.
 */
import { mkdirSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const OUT = tracerEvidencePath("docs-palette");
const SIZES = [
  { name: "desktop", width: 1440, height: 900, scale: 2, touch: false },
  { name: "phone", width: 393, height: 852, scale: 3, touch: true },
] as const;

const row = (page: Page, text: string) => page.locator(".palette .result", { hasText: text }).first();

async function openPalette(page: Page): Promise<void> {
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette-input")).toBeFocused();
}

for (const size of SIZES) {
  test(`${size.name}: docs are searched in the palette and open in a canvas window`, async ({ browser }) => {
    mkdirSync(OUT, { recursive: true });
    const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.scale, hasTouch: size.touch, isMobile: size.touch, colorScheme: "dark" });
    const page = await context.newPage();
    const failures: string[] = [];
    const requests: string[] = [];
    page.on("pageerror", (error) => failures.push(error.message));
    page.on("request", (request) => requests.push(new URL(request.url()).pathname));
    try {
      await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=plain");
      await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
      await page.waitForTimeout(1200);

      // On demand: nothing of the docs is fetched until the palette opens, and the reader's code and styles wait for a page.
      expect(requests.filter((path) => path.startsWith("/docs/") || path.includes("docs-reader"))).toEqual([]);
      await openPalette(page);
      await page.keyboard.type("keys");
      await expect(row(page, "Keys and how long they last")).toBeVisible();
      expect(requests).toContain("/docs/index.json");
      expect(requests.filter((path) => path.includes("docs-reader") || path.endsWith("fragment.html"))).toEqual([]);
      await page.screenshot({ path: `${OUT}/${size.name}-search-keys.png` });

      // "multiplexer" finds the other page; the group heading reads "Docs".
      await page.locator("#palette-input").fill("multiplexer");
      await expect(row(page, "The Infraternal Multiplexer")).toBeVisible();
      await expect(page.locator(".palette .group-label", { hasText: "Docs" })).toBeVisible();

      // Alignment: a docs row's icon and label line up with the rows around it, and icon and text share a centre line (±0.5 px).
      await page.locator("#palette-input").fill("");
      await expect(row(page, "Keys and how long they last")).toBeVisible();
      const metrics = await page.evaluate(() => {
        const box = (element: Element | null) => element!.getBoundingClientRect();
        const rows = [...document.querySelectorAll<HTMLElement>(".palette .result")];
        const docs = rows.find((entry) => entry.textContent?.includes("Keys and how long they last"))!;
        const other = rows.find((entry) => !entry.textContent?.includes("Keys and how long they last"))!;
        return {
          docsIcon: box(docs.querySelector(".result-icon")).left, otherIcon: box(other.querySelector(".result-icon")).left,
          docsLabel: box(docs.querySelector(".result-label")).left, otherLabel: box(other.querySelector(".result-label")).left,
          iconMid: box(docs.querySelector(".result-icon")).top + box(docs.querySelector(".result-icon")).height / 2,
          labelMid: box(docs.querySelector(".result-label")).top + box(docs.querySelector(".result-label")).height / 2,
          headingsAtRest: rows.filter((entry) => entry.dataset.action?.includes("#")).length,
        };
      });
      expect(Math.abs(metrics.docsIcon - metrics.otherIcon), "icon left edge").toBeLessThanOrEqual(0.5);
      expect(Math.abs(metrics.docsLabel - metrics.otherLabel), "label left edge").toBeLessThanOrEqual(0.5);
      expect(Math.abs(metrics.iconMid - metrics.labelMid), "icon and label centre line").toBeLessThanOrEqual(0.5);
      expect(metrics.headingsAtRest, "headings appear only when something is typed").toBe(0);

      // Enter opens the page in a window of the canvas: same tab, a window with the page's title in its pill.
      await page.locator("#palette-input").fill("keys");
      await expect(row(page, "Keys and how long they last")).toHaveAttribute("aria-selected", "true");
      await page.keyboard.press("Enter");
      const article = page.locator(".dr-page");
      await expect(article.locator("h1")).toHaveText("Keys and how long they last", { timeout: 10_000 });
      expect(context.pages().length, "no new tab").toBe(1);
      expect(await page.locator(".ui-window", { has: article }).count()).toBe(1);
      expect(requests).toContain("/docs/keys/fragment.html");
      await page.evaluate(() => document.fonts.ready);
      await page.waitForTimeout(900);
      await page.screenshot({ path: `${OUT}/${size.name}-keys-window.png` });

      // One left edge for the title, a paragraph, a section heading, the table and the window's own text (±0.5 px).
      const edges = await page.evaluate(() => {
        const left = (selector: string) => document.querySelector(selector)!.getBoundingClientRect().left;
        return { title: left(".dr-page h1"), paragraph: left(".dr-page p"), heading: left(".dr-page h2"), table: left(".dr-page .table") };
      });
      for (const [name, x] of Object.entries(edges)) expect(Math.abs(x - edges.title), `${name} shares the title's left edge`).toBeLessThanOrEqual(0.5);
      // The table is read down the page in a window this narrow: its cells line up with the title and nothing scrolls sideways.
      expect(await page.evaluate(() => { const t = document.querySelector<HTMLElement>(".dr-page .table")!; return t.scrollWidth - t.clientWidth; })).toBeLessThanOrEqual(0);
      expect(Math.abs(await page.evaluate(() => document.querySelector(".dr-page td:first-child")!.getBoundingClientRect().left) - edges.title), "table cell shares the title's left edge").toBeLessThanOrEqual(0.5);
      // The page is fully inside its window: nothing runs sideways, and the type is the product's scale (13 px, 16 px on touch).
      expect(await page.evaluate(() => { const s = document.querySelector<HTMLElement>(".dr-scroll")!; return s.scrollWidth - s.clientWidth; })).toBeLessThanOrEqual(0);
      expect(await page.evaluate(() => parseFloat(getComputedStyle(document.querySelector(".dr-page p")!).fontSize) / (parseFloat(getComputedStyle(document.documentElement).fontSize) / 16))).toBe(size.touch ? 16 : 13);

      // Opening the same page again focuses its window instead of making a second one.
      await openPalette(page);
      await page.keyboard.type("keys");
      await page.keyboard.press("Enter");
      await page.waitForTimeout(400);
      expect(await page.locator(".dr-page").count()).toBe(1);

      // A heading result opens the page at that heading, scrolled inside the window and not by the canvas.
      await openPalette(page);
      await page.keyboard.type("host certificate");
      await expect(row(page, "Host certificate")).toBeVisible();
      await page.keyboard.press("Enter");
      await page.waitForTimeout(500);
      const offset = await page.evaluate(() => {
        const scroller = document.querySelector<HTMLElement>(".dr-scroll")!;
        const heading = document.querySelector<HTMLElement>(".dr-page #host-certificate")!;
        return { scrolled: scroller.scrollTop, gap: heading.getBoundingClientRect().top - scroller.getBoundingClientRect().top, scale: scroller.getBoundingClientRect().height / scroller.clientHeight };
      });
      expect(offset.scrolled).toBeGreaterThan(0);
      expect(Math.abs(offset.gap / offset.scale - 12), "the heading sits 12 px under the top of the window").toBeLessThanOrEqual(1);
      await page.screenshot({ path: `${OUT}/${size.name}-keys-heading.png` });

      expect(failures).toEqual([]);
    } finally {
      await context.close();
    }
  });
}
