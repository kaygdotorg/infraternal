// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The docs pages (docs-build.ts, #298, #302) in a production build: `/docs/` lists the pages that are in `docs/user/` (no list in
 * the build), each page is written for a person (a summary under the title, a real heading hierarchy, a table of contents made from
 * the headings, a footer for the decisions), in ink and paper by the system scheme, and the app's ? opens the instance's own page.
 *
 * Measured, not eyeballed (TASTE): one left edge for the header, title, summary, headings, text, code, table and footer (±0.5 px); the
 * text column is 70 characters wide; the contents are sticky beside the page on a wide screen and folded on a phone; the page never
 * scrolls sideways and ships no script. Captures (1440×900 at 2×, 393×852 at 3×) go to the external evidence directory.
 */
import { existsSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const OUT = tracerEvidencePath("docs");
const SIZES = [
  { name: "desktop", width: 1440, height: 900, scale: 2, touch: false },
  { name: "phone", width: 393, height: 852, scale: 3, touch: true },
] as const;

/**
 * Headless Chromium reports a fine pointer even with touch emulation, so on a phone size the page's own `pointer: coarse`
 * rule is read from its served stylesheet and applied unconditionally, as a phone would. The rule must exist: it is the real
 * one that is measured and captured.
 */
async function asPhone(page: Page): Promise<void> {
  const source = await (await page.request.get("/docs/docs.css")).text();
  const css = /@media \(pointer: coarse\)\s*\{\s*(:root\s*\{[^}]*\})\s*\}/.exec(source)?.[1] ?? "";
  expect(css, "docs.css has a pointer: coarse rule").toContain("--text-body: 16px");
  await page.addStyleTag({ content: css });
}

for (const size of SIZES) for (const scheme of ["dark", "light"] as const) {
  test(`${size.name} ${scheme}: the index and the pages render, read well and line up`, async ({ browser }) => {
    mkdirSync(OUT, { recursive: true });
    const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.scale, hasTouch: size.touch, isMobile: size.touch, colorScheme: scheme });
    const page = await context.newPage();
    const failures: string[] = [];
    page.on("pageerror", (error) => failures.push(error.message));
    page.on("response", (response) => { if (response.status() >= 400) failures.push(`${response.status()} ${response.url()}`); });
    try {
      // ---- the front page: its own text, then every page that is in the folder -------------------------------------
      await page.goto("/docs/");
      if (size.touch) await asPhone(page);
      await expect(page.getByRole("heading", { level: 1, name: "Documentation" })).toBeVisible();
      await expect(page.locator(".doc .lede")).toHaveText("Guides for using Infraternal, written for the people who use it.");
      const listed = await page.locator(".pages a strong").allTextContents();
      expect(listed.sort()).toEqual(["Keys and how long they last", "The Infraternal Multiplexer"]);
      for (const name of ["Keys and how long they last", "The Infraternal Multiplexer"]) await expect(page.locator(".pages a", { hasText: name }).locator("span")).not.toHaveText("");
      await page.screenshot({ path: `${OUT}/${size.name}-${scheme}-index.png` });

      // ---- a page --------------------------------------------------------------------------------------------------
      await page.getByRole("link", { name: /The Infraternal Multiplexer/ }).click();
      await expect(page).toHaveURL(/\/docs\/multiplexer\/$/);
      if (size.touch) await asPhone(page);
      await expect(page.getByRole("heading", { level: 1, name: "The Infraternal Multiplexer" })).toBeVisible();
      await page.evaluate(() => document.fonts.ready);
      await page.screenshot({ path: `${OUT}/${size.name}-${scheme}-multiplexer.png` });
      await page.screenshot({ path: `${OUT}/${size.name}-${scheme}-multiplexer-full.png`, fullPage: true });

      // No script, no comments from the source file, and the page's own scheme colours.
      expect(await page.locator("script").count()).toBe(0);
      expect(await page.content()).not.toContain("SPDX");
      const background = await page.evaluate(() => getComputedStyle(document.body.parentElement!).backgroundColor);
      expect(background).toBe(scheme === "dark" ? "rgb(16, 17, 19)" : "rgb(246, 246, 244)");

      // The structure a reader relies on: one title, a one-sentence summary right under it, a hierarchy without skipped levels.
      expect(await page.locator("h1").count()).toBe(1);
      const levels = await page.evaluate(() => [...document.querySelectorAll("main h1, main h2, main h3, main h4, main h5, main h6")].map((h) => Number(h.tagName[1])));
      expect(levels[0]).toBe(1);
      for (let i = 1; i < levels.length; i += 1) expect(levels[i]! - levels[i - 1]!, "no heading skips a level").toBeLessThanOrEqual(1);
      expect(await page.evaluate(() => document.querySelector(".doc-head h1")!.nextElementSibling!.className)).toBe("lede");
      // No decision or issue number in the text; they live in the footer.
      const text = await page.evaluate(() => [...document.querySelectorAll(".doc-head, .doc-body > :not(footer)")].map((node) => node.textContent).join(" "));
      expect(text).not.toMatch(/\bD\d{1,3}\b|#\d{2,4}\b/);
      await expect(page.locator("footer.notes")).toContainText("Behind this page");

      // One left edge for the header link, the title, the summary, a section heading, a sub-heading, text, the code block, the table and the footer (±0.5 px).
      const edges = await page.evaluate(() => {
        const left = (selector: string) => document.querySelector(selector)!.getBoundingClientRect().left;
        return { header: left("header a"), title: left("main h1"), lede: left("main .lede"), heading: left("main h2"), subheading: left("main h3"), text: left(".doc-body > p"), code: left("main pre"), table: left("main .table"), notes: left("footer.notes") };
      });
      for (const [name, x] of Object.entries(edges)) expect(Math.abs(x - edges.header), `${name} shares the header's left edge`).toBeLessThanOrEqual(0.5);

      // The measure: the text column is 70 characters of the page font, or the screen when the screen is narrower.
      const measure = await page.evaluate(() => {
        const body = document.querySelector<HTMLElement>(".doc-body")!;
        const probe = Object.assign(document.createElement("span"), {});
        probe.style.cssText = "position:absolute;visibility:hidden;width:70ch";
        body.append(probe);
        const seventy = probe.getBoundingClientRect().width;
        probe.remove();
        return { seventy, column: body.getBoundingClientRect().width, head: document.querySelector(".doc-head")!.getBoundingClientRect().width };
      });
      expect(measure.column, "the text is at most 70ch wide").toBeLessThanOrEqual(measure.seventy + 0.5);
      expect(measure.head, "the title block has the same measure").toBeLessThanOrEqual(measure.seventy + 0.5);
      if (!size.touch) expect(Math.abs(measure.column - measure.seventy), "on a desktop the column is 70ch").toBeLessThanOrEqual(0.5);

      // The contents: made from the headings, so each entry points at a heading that is there, in the order of the page.
      const headings = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>(".doc-body h2, .doc-body h3")].map((h) => h.id));
      const contents = await page.evaluate(() => [...document.querySelectorAll<HTMLAnchorElement>(".toc-fold a")].map((a) => a.getAttribute("href")!.slice(1)));
      expect(contents).toEqual(headings);
      expect(contents.length).toBeGreaterThan(5);
      if (!size.touch) {
        // Wide: a column beside the text that stays in view while the page scrolls; the folded form is not shown.
        await expect(page.locator(".toc-side")).toBeVisible();
        await expect(page.locator(".toc-fold")).toBeHidden();
        expect(await page.evaluate(() => getComputedStyle(document.querySelector(".toc")!).position)).toBe("sticky");
        const beside = await page.evaluate(() => ({ toc: document.querySelector(".toc")!.getBoundingClientRect(), body: document.querySelector(".doc-body")!.getBoundingClientRect() }));
        expect(beside.toc.left, "contents sit to the right of the text").toBeGreaterThan(beside.body.right);
        const before = await page.evaluate(() => document.querySelector(".toc")!.getBoundingClientRect().top);
        await page.mouse.wheel(0, 900);
        await page.waitForTimeout(250);
        const after = await page.evaluate(() => ({ top: document.querySelector(".toc")!.getBoundingClientRect().top, scrolled: window.scrollY }));
        expect(after.scrolled, "the page scrolled").toBeGreaterThan(400);
        expect(Math.abs(after.top - 24), "the contents stay 1.5rem under the top").toBeLessThanOrEqual(1);
        expect(before).toBeGreaterThan(after.top - 1);
        // An entry jumps to its heading, which stops a little under the top.
        await page.locator('.toc-side a[href="#undoing-a-switch"]').click();
        await page.waitForTimeout(250);
        expect(await page.evaluate(() => Math.abs(document.getElementById("undoing-a-switch")!.getBoundingClientRect().top - 16)), "the heading is 16 px under the top").toBeLessThanOrEqual(1);
        await page.screenshot({ path: `${OUT}/${size.name}-${scheme}-multiplexer-scrolled.png` });
      } else {
        // Narrow: one folded row under the summary, closed until it is tapped; it is a 44 px target and starts at the text's left edge.
        await expect(page.locator(".toc-side")).toBeHidden();
        await expect(page.locator(".toc-fold")).toBeVisible();
        expect(await page.locator(".toc-fold").getAttribute("open")).toBeNull();
        const row = await page.evaluate(() => { const r = document.querySelector(".toc-fold summary")!.getBoundingClientRect(); return { left: r.left, height: r.height, top: r.top }; });
        expect(row.height).toBeGreaterThanOrEqual(44);
        expect(Math.abs(row.left - edges.title), "the folded row shares the title's left edge").toBeLessThanOrEqual(0.5);
        expect(row.top, "the folded row is under the summary").toBeGreaterThan(await page.evaluate(() => document.querySelector(".lede")!.getBoundingClientRect().bottom) - 1);
        await page.locator(".toc-fold summary").click();
        await expect(page.locator(".toc-fold a").first()).toBeVisible();
        await page.waitForTimeout(400);
        await page.screenshot({ path: `${OUT}/${size.name}-${scheme}-multiplexer-contents.png` });
        for (const link of await page.locator(".toc-fold a").all()) expect((await link.boundingBox())!.height, "contents entries are 44 px targets").toBeGreaterThanOrEqual(43.5);
        await page.locator('.toc-fold a[href="#undoing-a-switch"]').click();
        await page.waitForTimeout(250);
        expect(await page.evaluate(() => Math.abs(document.getElementById("undoing-a-switch")!.getBoundingClientRect().top - 16))).toBeLessThanOrEqual(1);
      }

      // Nothing scrolls sideways (wide tables and code scroll inside their own box), and the text meets the type scale.
      expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBe(0);
      expect(await page.evaluate(() => parseFloat(getComputedStyle(document.querySelector(".doc-body p")!).fontSize))).toBe(size.touch ? 16 : 13);
      if (size.touch) expect(await page.evaluate(() => document.querySelector("header a")!.getBoundingClientRect().height)).toBeGreaterThanOrEqual(44);

      // The keys page: a long page with sub-headings under three groups.
      await page.goto("/docs/keys/");
      if (size.touch) await asPhone(page);
      await expect(page.getByRole("heading", { level: 1, name: "Keys and how long they last" })).toBeVisible();
      expect(await page.evaluate(() => [...document.querySelectorAll(".doc-body h2")].map((h) => h.textContent))).toEqual(["The short version", "Signing in", "Adding and trusting hosts", "Between machines"]);
      await page.screenshot({ path: `${OUT}/${size.name}-${scheme}-keys.png` });

      // The web root serves the encodings precompress writes next to every text file, so the pages need them too.
      for (const file of ["multiplexer/index.html", "multiplexer/fragment.html", "index/fragment.html", "index.html", "docs.css", "doc.css", "index.json"]) {
        for (const ext of ["br", "gz"]) expect(existsSync(resolve(process.env.TRACER_DIST ?? "dist", "docs", `${file}.${ext}`)), `${file}.${ext}`).toBe(true);
      }
      expect(failures).toEqual([]);
    } finally {
      await context.close();
    }
  });
}
