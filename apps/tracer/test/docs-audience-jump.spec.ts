// SPDX-License-Identifier: AGPL-3.0-only
/**
 * On a phone, a contents tap on an audience's docs page (the pages with a side column, `.docs-col`, #482) lands the heading 1 rem from
 * the top. The top bar is not sticky on a phone, so no room is kept for it: the margin that docs.css reserves for the sticky bar
 * applies from 40 rem up only.
 *
 * The production build serves the flat docs only, so this spec builds the whole site into a scratch folder with the real
 * `site-build.ts` (bun, since Playwright runs under node) and answers `/docs/user/` from it; styles, fonts and scripts still come from the production build. Captures at 393 and 375
 * px, light and dark, go to the external evidence directory.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

/** Where this spec writes its screenshots. */
const OUT = tracerEvidencePath("docs-audience-jump");

for (const width of [393, 375]) for (const scheme of ["light", "dark"] as const) {
  test(`${width} ${scheme}: a contents tap on an audience page lands the heading 1 rem from the top`, async ({ browser }) => {
    mkdirSync(OUT, { recursive: true });
    const tree = mkdtempSync(join(tmpdir(), "docs-audience-"));
    try {
      execFileSync("bun", ["run", "site-build.ts", tree], { cwd: join(import.meta.dirname, ".."), stdio: "pipe" });
      const context = await browser.newContext({ viewport: { width, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true, colorScheme: scheme });
      const page = await context.newPage();
      await page.route("**/docs/user/**", async (route) => {
        const path = decodeURIComponent(new URL(route.request().url()).pathname).replace(/^\/docs\/user\//, "");
        const file = join(tree, "docs", "user", path.endsWith("/") ? `${path}index.html` : path);
        if (!existsSync(file)) return route.fallback();
        return route.fulfill({ body: readFileSync(file), contentType: file.endsWith(".html") ? "text/html" : file.endsWith(".css") ? "text/css" : "application/octet-stream" });
      });
      await page.goto("/docs/user/reference/keys/");
      expect(await page.locator(".docs-col").count(), "this is a page with a side column").toBe(1);
      await expect(page.locator(".toc-fold")).toBeVisible();
      await page.locator(".toc-fold summary").click();
      const link = page.locator('.toc-fold a[href="#browser-sign-in"]');
      await expect(link).toBeVisible();
      await link.click();
      // sleep: the jump to the anchor is instant; give the scroll one frame to settle before measuring.
      await page.waitForTimeout(250);
      const top = await page.evaluate(() => document.getElementById("browser-sign-in")!.getBoundingClientRect().top);
      expect(Math.abs(top - 16), `the heading is 1 rem (16 px) under the top, was ${top}`).toBeLessThanOrEqual(1);
      await page.screenshot({ path: `${OUT}/${width}-${scheme}-jump.png` });
      await context.close();
    } finally { rmSync(tree, { recursive: true, force: true }); }
  });
}
