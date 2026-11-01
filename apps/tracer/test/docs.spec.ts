// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The docs pages (docs-build.ts, #298) in a production build: `/docs/` lists the published pages, `/docs/multiplexer/`
 * renders `docs/multiplexer.md`, ink and paper by the system scheme, and the app's ? opens the instance's own page.
 * Alignment is measured (TASTE: one left edge, ±0.5 px), the page never scrolls sideways, and it ships no script.
 * Captures (1440×900 at 2×, 393×852 at 3×) go to the external evidence directory.
 */
import { existsSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { chromium, expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const OUT = tracerEvidencePath("docs");
const SIZES = [
  { name: "desktop", width: 1440, height: 900, scale: 2, touch: false },
  { name: "phone", width: 393, height: 852, scale: 3, touch: true },
] as const;

for (const size of SIZES) for (const scheme of ["dark", "light"] as const) {
  test(`${size.name} ${scheme}: the index and the multiplexer page render and line up`, async ({ browser: shared }) => {
    mkdirSync(OUT, { recursive: true });
    // Headless Chromium reports a fine pointer even with touch emulation; a phone's coarse pointer is switched on at launch,
    // because the type scale and the 44 px targets follow `pointer: coarse`.
    const browser = size.touch ? await chromium.launch({ args: ["--blink-settings=primaryPointerType=4,availablePointerTypes=4,primaryHoverType=1,availableHoverTypes=1"] }) : shared;
    const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.scale, hasTouch: size.touch, isMobile: size.touch, colorScheme: scheme });
    const page = await context.newPage();
    const failures: string[] = [];
    page.on("pageerror", (error) => failures.push(error.message));
    page.on("response", (response) => { if (response.status() >= 400) failures.push(`${response.status()} ${response.url()}`); });
    try {
      await page.goto("/docs/");
      await expect(page.getByRole("heading", { level: 1, name: "Documentation" })).toBeVisible();
      await page.screenshot({ path: `${OUT}/${size.name}-${scheme}-index.png` });
      await page.getByRole("link", { name: /The Infraternal Multiplexer/ }).click();
      await expect(page).toHaveURL(/\/docs\/multiplexer\/$/);
      await expect(page.getByRole("heading", { level: 1, name: "The Infraternal Multiplexer" })).toBeVisible();
      await page.evaluate(() => document.fonts.ready);
      await page.screenshot({ path: `${OUT}/${size.name}-${scheme}-multiplexer.png` });
      await page.screenshot({ path: `${OUT}/${size.name}-${scheme}-multiplexer-full.png`, fullPage: true });

      // No script, no comments from the source file, and the page's own scheme colours.
      expect(await page.locator("script").count()).toBe(0);
      expect(await page.content()).not.toContain("SPDX");
      const background = await page.evaluate(() => getComputedStyle(document.body.parentElement!).backgroundColor);
      expect(background).toBe(scheme === "dark" ? "rgb(16, 17, 19)" : "rgb(246, 246, 244)");

      // One left edge for the header link, the title, a paragraph, a section heading, the code block and the table (±0.5 px).
      const edges = await page.evaluate(() => {
        const left = (selector: string) => document.querySelector(selector)!.getBoundingClientRect().left;
        return { header: left("header a"), title: left("main h1"), lede: left("main p"), heading: left("main h2"), code: left("main pre"), table: left("main .table") };
      });
      for (const [name, x] of Object.entries(edges)) expect(Math.abs(x - edges.header), `${name} shares the header's left edge`).toBeLessThanOrEqual(0.5);

      // Nothing scrolls sideways (wide tables and code scroll inside their own box), and the text meets the type scale.
      expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBe(0);
      const bodySize = await page.evaluate(() => parseFloat(getComputedStyle(document.querySelector("main p")!).fontSize));
      expect(bodySize).toBe(size.touch ? 16 : 13);
      if (size.touch) expect(await page.evaluate(() => document.querySelector("header a")!.getBoundingClientRect().height)).toBeGreaterThanOrEqual(44);

      // The web root serves the encodings precompress writes next to every text file, so the pages need them too.
      for (const file of ["multiplexer/index.html", "index.html", "docs.css"]) {
        for (const ext of ["br", "gz"]) expect(existsSync(resolve(process.env.TRACER_DIST ?? "dist", "docs", `${file}.${ext}`)), `${file}.${ext}`).toBe(true);
      }
      expect(failures).toEqual([]);
    } finally {
      await context.close();
      if (browser !== shared) await browser.close();
    }
  });
}
