/**
 * UI consistency audit (#345, J195): captures and a computed-style census of the main screens, taken from a production build.
 *
 * What it is for. The stylesheets say what a rule asks for; only the browser says what a person sees. For each of the six main
 * screens (canvas, sidebar, palette, Settings, sign-in, a window's info popover) at the three review sizes (1440x900, 393x852,
 * 375x667) in the ink and paper themes, this writes:
 *   - `<label>/<size>-<theme>-<screen>.png`: the screenshot, so a before and an after can sit side by side;
 *   - `<label>/census-<size>-<theme>.json`: every distinct computed font size, weight, line height, letter spacing, corner radius,
 *     transition duration and easing on that screen, with how many elements use it and three example selectors, plus a `probes`
 *     entry: shared components (`.check`, `.swap`) built inside the screen's root and their computed transition. A rule that reads a
 *     custom property the page does not define at that point is dropped by the browser at computed-value time, so the component
 *     would show `0s` here although its stylesheet asks for 140 ms.
 *
 * How to run it. It is off unless `UI_AUDIT=1`. `UI_AUDIT_LABEL` names the output folder ("before", "after"; default "run"), so
 * run it once on the base commit and once on the branch and compare the folders. Images and JSON go to the external evidence
 * directory (evidence-path.ts), never into the checkout.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

test.skip(!process.env.UI_AUDIT, "the consistency audit is run on request");

const LABEL = process.env.UI_AUDIT_LABEL ?? "run";
const OUT = tracerEvidencePath("ui-audit", LABEL);
const SIZES = [
  { name: "1440x900", width: 1440, height: 900, touch: false },
  { name: "393x852", width: 393, height: 852, touch: true },
  { name: "375x667", width: 375, height: 667, touch: true },
] as const;
const THEMES = ["ink", "paper"] as const;

type Census = Record<string, Record<string, { count: number; examples: string[] }>>;
interface Page_ { census: Census; probes: Record<string, string> }

/** Counts the computed values of the properties the audit compares, for everything visible under `root`. */
async function census(page: Page, rootSelector: string): Promise<Page_> {
  return page.evaluate((selector) => {
    const root = document.querySelector(selector) ?? document.body;
    const out: Record<string, Record<string, { count: number; examples: string[] }>> = {};
    const note = (family: string, value: string, el: Element): void => {
      const bucket = (out[family] ??= {});
      const entry = (bucket[value] ??= { count: 0, examples: [] });
      entry.count += 1;
      if (entry.examples.length < 3) entry.examples.push(`${el.tagName.toLowerCase()}${el.className && typeof el.className === "string" ? "." + el.className.trim().split(/\s+/).slice(0, 2).join(".") : ""}`);
    };
    for (const el of [root, ...Array.from(root.querySelectorAll("*"))]) {
      const box = el.getBoundingClientRect();
      if (box.width === 0 || box.height === 0) continue;
      const cs = getComputedStyle(el);
      if (cs.visibility === "hidden" || cs.display === "none") continue;
      // Only elements that carry their own text: a container's font size is whatever its children inherit.
      const hasText = Array.from(el.childNodes).some((n) => n.nodeType === 3 && (n.textContent ?? "").trim().length > 0);
      if (hasText) {
        note("font-size", cs.fontSize, el);
        note("font-weight", cs.fontWeight, el);
        note("line-height", cs.lineHeight === "normal" ? "normal" : `${(parseFloat(cs.lineHeight) / parseFloat(cs.fontSize)).toFixed(2)}`, el);
        note("letter-spacing", cs.letterSpacing === "normal" ? "normal" : `${(parseFloat(cs.letterSpacing) / parseFloat(cs.fontSize)).toFixed(3)}em`, el);
      }
      if (cs.borderTopLeftRadius !== "0px") note("radius", cs.borderTopLeftRadius, el);
      if (cs.transitionDuration !== "0s" && cs.transitionProperty !== "none") {
        note("transition-duration", cs.transitionDuration.split(",")[0]!.trim(), el);
        note("transition-easing", cs.transitionTimingFunction.split(/,(?![^(]*\))/)[0]!.trim(), el);
      }
      if (cs.zIndex !== "auto") note("z-index", cs.zIndex, el);
    }
    // Shared components built in place, as a feature would: what transition does each get in this screen's scope?
    const probes: Record<string, string> = {};
    const host = document.querySelector(".terminal-screen") ?? document.querySelector(".auth-screen") ?? document.body;
    const specs: Array<[string, string, string]> = [
      ["check", '<label class="check"><input class="visually-hidden" type="checkbox"><span class="tick"></span></label>', ".check"],
      ["swap svg", '<span class="swap"><svg viewBox="0 0 16 16"></svg></span>', ".swap svg"],
    ];
    for (const [name, html, pick] of specs) {
      const wrap = document.createElement("div");
      wrap.innerHTML = html;
      host.appendChild(wrap);
      const cs = getComputedStyle(wrap.querySelector(pick)!);
      probes[name] = `${cs.transitionDuration} | ${cs.transitionTimingFunction}`;
      wrap.remove();
    }
    return { census: out, probes };
  }, rootSelector);
}

async function openCanvas(page: Page, theme: string, scene = 1): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=${scene}&theme=${theme}&bg=none`);
  await page.waitForFunction(() => (window as unknown as { __tracerClusters?: unknown }).__tracerClusters, null, { timeout: 30_000 });
  await page.waitForTimeout(700);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(v: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(900);
}

for (const size of SIZES) {
  for (const theme of THEMES) {
    test.describe(`${size.name} ${theme}`, () => {
      test.use({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.touch ? 3 : 2, ...(size.touch ? { hasTouch: true, isMobile: true } : {}) });
      const results: Record<string, Page_ | { skipped: string }> = {};
      const stem = `${size.name}-${theme}`;

      /** Runs one screen's capture; a screen that cannot be reached is recorded as skipped, not as a failure of the rest. */
      const screen = (name: string, body: (page: Page) => Promise<string>): void => {
        test(name, async ({ page }) => {
          try {
            const selector = await body(page);
            await page.waitForTimeout(500);
            mkdirSync(OUT, { recursive: true });
            await page.screenshot({ path: resolve(OUT, `${stem}-${name}.png`) });
            results[name] = await census(page, selector);
          } catch (error) {
            results[name] = { skipped: String(error).slice(0, 200) };
          }
          writeFileSync(resolve(OUT, `census-${stem}.json`), JSON.stringify(results, null, 1));
        });
      };

      screen("canvas", async (page) => { await openCanvas(page, theme); return ".terminal-screen"; });
      screen("sidebar", async (page) => {
        await openCanvas(page, theme);
        await page.locator("#sidebar-toggle").click();
        await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1);
        await page.waitForTimeout(900);
        return "#sidebar";
      });
      screen("palette", async (page) => {
        await openCanvas(page, theme);
        await page.keyboard.press("Meta+k");
        if (!(await page.locator("#palette").isVisible())) await page.keyboard.press("Control+Shift+K");
        await expect(page.locator("#palette")).toBeVisible();
        await page.waitForTimeout(400);
        return "#palette";
      });
      screen("settings", async (page) => {
        await openCanvas(page, theme, 3);
        await page.keyboard.press("Control+Shift+K");
        await expect(page.locator("#palette")).toBeVisible();
        await page.keyboard.type("Settings: Appearance");
        await page.waitForTimeout(200);
        await page.keyboard.press("Enter");
        await expect(page.locator(".ui-sp").first()).toBeVisible({ timeout: 8000 });
        await page.waitForTimeout(900);
        return ".ui-sp";
      });
      screen("popover", async (page) => {
        await openCanvas(page, theme);
        await page.locator(".ui-window-pill").first().click();
        await expect(page.locator(".canvas-popover")).toBeVisible();
        await page.waitForTimeout(500);
        return ".canvas-popover";
      });
      screen("sign-in", async (page) => {
        await page.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: false } }));
        await page.route("**/auth/session", (route) => route.fulfill({ status: 401, json: {} }));
        await page.emulateMedia({ colorScheme: theme === "ink" ? "dark" : "light" });
        await page.goto("/");
        await expect(page.locator("#login-passkey")).toBeVisible();
        await page.waitForTimeout(900);
        return ".auth-screen";
      });
    });
  }
}
