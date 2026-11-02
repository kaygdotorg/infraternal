// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The docs on the canvas, on a production build (#302): a Docs view, a separate cluster with one window for each page of `docs/user/`,
 * in the views list and in ⌘K. Typing "keys" or "multiplexer" lists the page, Enter flies to its window in the Docs view (no new tab,
 * no second window), a heading result opens the page at that heading, and nothing of the reader is fetched until a docs window comes
 * near the screen. Measured (TASTE: ±0.5 px) for the palette rows and for the page inside its window, with the text column at most 70
 * characters wide, in ink and paper, at 1440×900 DPR 2 and on a phone at 393×852 DPR 3. Captures go to the external evidence directory.
 *
 * The test double adds the docs only with `?docs=1`, so the scenes of the other specs keep the views they are about.
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

for (const size of SIZES) for (const theme of ["ink", "paper"] as const) {
  test(`${size.name} ${theme}: the Docs view holds the pages, ⌘K finds them, and they read well in their windows`, async ({ browser }) => {
    mkdirSync(OUT, { recursive: true });
    const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.scale, hasTouch: size.touch, isMobile: size.touch, colorScheme: theme === "ink" ? "dark" : "light" });
    const page = await context.newPage();
    const failures: string[] = [];
    const requests: string[] = [];
    page.on("pageerror", (error) => failures.push(error.message));
    page.on("request", (request) => requests.push(new URL(request.url()).pathname));
    const shot = (name: string) => page.screenshot({ path: `${OUT}/${size.name}-${theme}-${name}.png` });
    try {
      await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&bg=plain&docs=1`);
      await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
      await page.waitForTimeout(1200);

      // ---- the view: one window per page of the folder, found through the index, nothing written in the app -----------
      await expect.poll(() => requests.includes("/docs/index.json"), { timeout: 15_000 }).toBe(true);
      const slugs = (await (await page.request.get("/docs/index.json")).json() as { pages: { slug: string; title: string }[] }).pages;
      expect(slugs.map((entry) => entry.slug).sort()).toEqual(["index", "keys", "multiplexer"]);
      await expect(page.locator('section.cl[data-view="docs"]')).toBeAttached({ timeout: 10_000 });
      expect(await page.locator('section.cl[data-view="docs"] .ui-window').evaluateAll((windows) => windows.map((w) => (w as HTMLElement).dataset.windowId).sort())).toEqual(slugs.map((entry) => `d-${entry.slug}`).sort());

      // The views list has it, after Settings, with its page count and a book icon; ⌘K has "Go to Docs".
      await page.locator("#capsule").click();
      const listRow = page.locator('.cl-viewrow[data-view="docs"]');
      await expect(listRow).toBeVisible();
      await expect(listRow.locator(".cl-viewrow-name")).toHaveText("Docs");
      await expect(listRow.locator(".cl-viewrow-meta")).toHaveText("3 pages");
      const order = await page.locator(".cl-viewlist .cl-viewrow[data-view]").evaluateAll((rows) => rows.map((r) => (r as HTMLElement).dataset.view));
      expect(order.indexOf("docs")).toBe(order.indexOf("settings") + 1);
      const listed = await page.evaluate(() => { const r = (s: string) => document.querySelector(`.cl-viewlist [data-view="${s}"]`)!; const box = (e: Element | null) => e!.getBoundingClientRect(); const docs = r("docs"), other = r("settings"); return { icon: [box(docs.querySelector(".cl-viewrow-icon")).left, box(other.querySelector(".cl-viewrow-icon")).left], name: [box(docs.querySelector(".cl-viewrow-name")).left, box(other.querySelector(".cl-viewrow-name")).left], mid: [box(docs.querySelector(".cl-viewrow-icon")).top + box(docs.querySelector(".cl-viewrow-icon")).height / 2, box(docs.querySelector(".cl-viewrow-name")).top + box(docs.querySelector(".cl-viewrow-name")).height / 2] }; });
      expect(Math.abs(listed.icon[0]! - listed.icon[1]!), "views list: icon left edge").toBeLessThanOrEqual(0.5);
      expect(Math.abs(listed.name[0]! - listed.name[1]!), "views list: name left edge").toBeLessThanOrEqual(0.5);
      expect(Math.abs(listed.mid[0]! - listed.mid[1]!), "views list: icon and name centre line").toBeLessThanOrEqual(0.5);
      await page.waitForTimeout(600);
      await shot("views-list");
      await page.keyboard.press("Escape");

      // On demand: nothing of the reader (its styles, a page's text) is fetched until a docs window comes near the screen.
      expect(requests.filter((path) => path.endsWith("fragment.html") || path.includes("docs-reader") || path.endsWith("/doc.css"))).toEqual([]);

      // ---- ⌘K: pages by title, headings by what is typed -------------------------------------------------------------
      await openPalette(page);
      await page.keyboard.type("keys");
      await expect(row(page, "Keys and how long they last")).toBeVisible();
      await shot("search-keys");
      await page.locator("#palette-input").fill("multiplexer");
      await expect(row(page, "The Infraternal Multiplexer")).toBeVisible();
      await expect(page.locator(".palette .group-label", { hasText: "Docs" })).toBeVisible();
      await page.locator("#palette-input").fill("go to docs");
      await expect(row(page, "Go to Docs")).toBeVisible();

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

      // ---- Enter flies to the page's window in the Docs view ---------------------------------------------------------
      await page.locator("#palette-input").fill("keys");
      await expect(row(page, "Keys and how long they last")).toHaveAttribute("aria-selected", "true");
      await page.keyboard.press("Enter");
      const article = page.locator('.ui-window[data-window-id="d-keys"] .dr-page');
      await expect(article.locator("h1")).toHaveText("Keys and how long they last", { timeout: 10_000 });
      expect(context.pages().length, "no new tab").toBe(1);
      expect(await page.locator('section.cl[data-view="docs"] .ui-window[data-window-id="d-keys"]').count()).toBe(1);
      await expect(page.locator("#capsule-host")).toHaveText("Docs");
      expect(requests).toContain("/docs/keys/fragment.html");
      expect(requests).toContain("/docs/doc.css");
      await page.evaluate(() => document.fonts.ready);
      await page.waitForTimeout(900);
      // The window is the active one and has no close button: like Settings, the cluster is not the person's to rearrange.
      await expect(page.locator('.ui-window[data-window-id="d-keys"]')).toHaveAttribute("data-active", "");
      expect(await page.locator('.ui-window[data-window-id="d-keys"] button[aria-label="Close"]').count()).toBe(0);
      await shot("keys-window");

      // One left edge for the title, the summary, a section heading, a sub-heading, text, the table and the window's own text (±0.5 px).
      const edges = await page.evaluate(() => {
        const left = (selector: string) => document.querySelector(`.ui-window[data-window-id="d-keys"] ${selector}`)!.getBoundingClientRect().left;
        return { title: left(".dr-page h1"), lede: left(".lede"), heading: left(".doc-body h2"), subheading: left(".doc-body h3"), paragraph: left(".doc-body > p"), table: left(".doc-body .table"), notes: left("footer.notes"), contents: left(".toc-fold summary") };
      });
      for (const [name, x] of Object.entries(edges)) expect(Math.abs(x - edges.title), `${name} shares the title's left edge`).toBeLessThanOrEqual(0.5);
      // The table is read down the page in a window this narrow: its cells line up with the title and nothing scrolls sideways.
      expect(await page.evaluate(() => { const t = document.querySelector<HTMLElement>('.ui-window[data-window-id="d-keys"] .dr-page .table')!; return t.scrollWidth - t.clientWidth; })).toBeLessThanOrEqual(0);
      // A stacked row is a small card whose box starts at the title's edge; its text is inset by its 1 px border and one 0.75rem of padding.
      expect(Math.abs(await page.evaluate(() => document.querySelector('.ui-window[data-window-id="d-keys"] .dr-page td:first-child')!.getBoundingClientRect().left) - edges.title - 13), "table cell text is inset 13 px in its card").toBeLessThanOrEqual(0.5);
      // The page is fully inside its window: nothing runs sideways, and the type is the product's scale (13 px, 16 px on touch).
      expect(await page.evaluate(() => { const s = document.querySelector<HTMLElement>('.ui-window[data-window-id="d-keys"] .dr-scroll')!; return s.scrollWidth - s.clientWidth; })).toBeLessThanOrEqual(0);
      expect(await page.evaluate(() => parseFloat(getComputedStyle(document.querySelector('.ui-window[data-window-id="d-keys"] .doc-body p')!).fontSize) / (parseFloat(getComputedStyle(document.documentElement).fontSize) / 16))).toBe(size.touch ? 16 : 13);
      // The measure: at most 70 characters, however wide the window.
      expect(await page.evaluate(() => {
        const body = document.querySelector<HTMLElement>('.ui-window[data-window-id="d-keys"] .doc-body')!;
        const probe = document.createElement("span");
        probe.style.cssText = "position:absolute;visibility:hidden;width:70ch";
        body.append(probe);
        const seventy = probe.offsetWidth;
        probe.remove();
        return body.offsetWidth - seventy;
      }), "the text column is at most 70ch").toBeLessThanOrEqual(0.5);

      // The contents: folded in a window one column wide, closed until opened; an entry scrolls the window, not the canvas.
      const fold = page.locator('.ui-window[data-window-id="d-keys"] .toc-fold');
      await expect(fold).toBeVisible();
      await expect(page.locator('.ui-window[data-window-id="d-keys"] .toc-side')).toBeHidden();
      expect(await fold.getAttribute("open")).toBeNull();
      await fold.locator("summary").click();
      await expect(fold.locator("a").first()).toBeVisible();
      await page.waitForTimeout(400);
      await shot("keys-contents");
      const camera = await page.evaluate(() => document.querySelector<HTMLElement>(".cl-world")?.style.transform ?? "");
      await fold.locator('a[href="#passkey"]').click();
      await page.waitForTimeout(400);
      const jumped = await page.evaluate(() => {
        const scroller = document.querySelector<HTMLElement>('.ui-window[data-window-id="d-keys"] .dr-scroll')!;
        const heading = document.querySelector<HTMLElement>('.ui-window[data-window-id="d-keys"] #passkey')!;
        return { scrolled: scroller.scrollTop, gap: heading.getBoundingClientRect().top - scroller.getBoundingClientRect().top, scale: scroller.getBoundingClientRect().height / scroller.clientHeight, world: document.querySelector<HTMLElement>(".cl-world")?.style.transform ?? "" };
      });
      expect(jumped.scrolled).toBeGreaterThan(0);
      expect(Math.abs(jumped.gap / jumped.scale - 12), "the heading sits 12 px under the top of the window").toBeLessThanOrEqual(1);
      expect(jumped.world, "the canvas did not move").toBe(camera);

      // Opening the same page again focuses its window instead of making a second one.
      await openPalette(page);
      await page.keyboard.type("keys");
      await page.keyboard.press("Enter");
      await page.waitForTimeout(500);
      expect(await page.locator('.ui-window[data-window-id="d-keys"] .dr-page').count()).toBe(1);

      // A heading result opens the page at that heading, scrolled inside the window and not by the canvas.
      await openPalette(page);
      await page.keyboard.type("host certificate");
      await expect(row(page, "Host certificate")).toBeVisible();
      await page.keyboard.press("Enter");
      await page.waitForTimeout(700);
      const offset = await page.evaluate(() => {
        const scroller = document.querySelector<HTMLElement>('.ui-window[data-window-id="d-keys"] .dr-scroll')!;
        const heading = document.querySelector<HTMLElement>('.ui-window[data-window-id="d-keys"] #host-certificate')!;
        return { scrolled: scroller.scrollTop, gap: heading.getBoundingClientRect().top - scroller.getBoundingClientRect().top, scale: scroller.getBoundingClientRect().height / scroller.clientHeight };
      });
      expect(offset.scrolled).toBeGreaterThan(0);
      expect(Math.abs(offset.gap / offset.scale - 12), "the heading sits 12 px under the top of the window").toBeLessThanOrEqual(1);
      await shot("keys-heading");

      // Another page: its window is the one in view, and the first page's window stays where it was.
      await openPalette(page);
      await page.keyboard.type("multiplexer");
      await page.keyboard.press("Enter");
      await expect(page.locator('.ui-window[data-window-id="d-multiplexer"] .dr-page h1')).toHaveText("The Infraternal Multiplexer", { timeout: 10_000 });
      await page.waitForTimeout(900);
      await expect(page.locator('.ui-window[data-window-id="d-multiplexer"]')).toHaveAttribute("data-active", "");
      await shot("multiplexer-window");
      // A link to another page stays in the canvas: the multiplexer page names no other page, so the front page's list is the check.
      await openPalette(page);
      await page.keyboard.type("documentation");
      await page.keyboard.press("Enter");
      await expect(page.locator('.ui-window[data-window-id="d-index"] .pages a').first()).toBeVisible({ timeout: 10_000 });
      await page.waitForTimeout(700);
      await page.locator('.ui-window[data-window-id="d-index"] .pages a[href="/docs/multiplexer/"]').click();
      await expect(page.locator('.ui-window[data-window-id="d-multiplexer"]')).toHaveAttribute("data-active", "");
      expect(context.pages().length, "a link to another page opens no tab").toBe(1);

      expect(failures).toEqual([]);
    } finally {
      await context.close();
    }
  });
}
