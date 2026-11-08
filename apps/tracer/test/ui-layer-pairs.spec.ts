/**
 * Overlay pairs (#345, J383, D372): captures and a hit test of every pair of layers that can be open at once, from a
 * production build.
 *
 * Why it exists. The z-index layer scale (--z-content, -chrome, -sidebar, -overlay, -toast, -tooltip) replaced bare numbers.
 * The map is monotone, so no pair should change order; this spec is the proof. For each pair (a lower layer, then an upper
 * layer opened on top of it) it writes a screenshot, `<label>/<size>-<theme>-<pair>.png`, and checks that the element at the
 * centre of the upper layer really belongs to the upper layer (`document.elementFromPoint`): a layer that fell behind would
 * fail here even where the screenshot looks fine. `<label>/pairs-<size>-<theme>.json` records each pair's computed z-index
 * and the verdict, so a before and an after run can be compared.
 *
 * How to run it. Off unless `UI_AUDIT=1`; `UI_AUDIT_LABEL` names the output folder, as in ui-consistency-audit.spec.ts.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

test.skip(!process.env.UI_AUDIT, "the overlay-pair captures are run on request");

/** Names this run's evidence folder (for example `before` or `after`). */
const LABEL = process.env.UI_AUDIT_LABEL ?? "run";
/** Where this run writes its screenshots and verdicts. */
const OUT = tracerEvidencePath("ui-audit", LABEL);
/** The three review sizes from CLAUDE.md, phones first. */
const SIZES = [
  { name: "393x852", width: 393, height: 852, touch: true },
  { name: "375x667", width: 375, height: 667, touch: true },
  { name: "1440x900", width: 1440, height: 900, touch: false },
] as const;
/** Both colour modes. */
const THEMES = ["ink", "paper"] as const;

/** One verdict: the computed z-index of both layers and whether the upper one is what a pointer would hit at its centre. */
interface Verdict { lower: string; upper: string; lowerZ: string; upperZ: string; upperOnTop: boolean }

/** Opens the mock canvas on the console view, as the consistency audit does. */
async function openCanvas(page: Page, theme: string, scene = 1): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=${scene}&theme=${theme}&bg=none`);
  await page.waitForFunction(() => (window as unknown as { __tracerClusters?: unknown }).__tracerClusters, null, { timeout: 30_000 });
  // sleep: a capture is taken after the layer has finished its entrance animation, there is no event to wait on
  await page.waitForTimeout(700);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(v: string): void } }).__tracerClusters.flyView("console"));
  // sleep: a capture is taken after the layer has finished its entrance animation, there is no event to wait on
  await page.waitForTimeout(900);
}

/** Opens the palette with whichever shortcut this platform answers to. */
async function openPalette(page: Page): Promise<void> {
  await page.keyboard.press("Meta+k");
  if (!(await page.locator("#palette").isVisible())) await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible();
  // sleep: a capture is taken after the layer has finished its entrance animation, there is no event to wait on
  await page.waitForTimeout(400);
}

/** Opens Settings on its appearance page through the palette. */
async function openSettings(page: Page): Promise<void> {
  await openPalette(page);
  await page.keyboard.type("Settings: Appearance");
  // sleep: a capture is taken after the layer has finished its entrance animation, there is no event to wait on
  await page.waitForTimeout(200);
  await page.keyboard.press("Enter");
  await expect(page.locator(".ui-sp").first()).toBeVisible({ timeout: 8000 });
  // sleep: a capture is taken after the layer has finished its entrance animation, there is no event to wait on
  await page.waitForTimeout(900);
}

/** Shows a toast through the page's own controller, which the canvas exposes as `__toast`. */
async function showToast(page: Page): Promise<void> {
  await page.waitForFunction(() => Boolean(Reflect.get(window, "__toast")), null, { timeout: 8000 });
  await page.evaluate(() => {
    const toast = Reflect.get(window, "__toast") as { show(value: Record<string, unknown>): void };
    toast.show({ message: "Layer check", duration: 0 });
  });
  await expect(page.locator('.ui-toast[data-open="true"]').first()).toBeVisible();
  // sleep: a capture is taken after the layer has finished its entrance animation, there is no event to wait on
  await page.waitForTimeout(500);
}

/** Reads both layers' computed z-index and whether the point at the upper layer's centre hits the upper layer. */
async function verdict(page: Page, lower: string, upper: string): Promise<Verdict> {
  return page.evaluate(([lo, up]) => {
    const lowEl = document.querySelector(lo!) as HTMLElement;
    const upEl = document.querySelector(up!) as HTMLElement;
    const box = upEl.getBoundingClientRect();
    const hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
    return {
      lower: lo!, upper: up!,
      lowerZ: getComputedStyle(lowEl).zIndex, upperZ: getComputedStyle(upEl).zIndex,
      upperOnTop: Boolean(hit && hit.closest(up!)),
    };
  }, [lower, upper] as [string, string]);
}

for (const size of SIZES) {
  for (const theme of THEMES) {
    test.describe(`${size.name} ${theme}`, () => {
      test.use({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.touch ? 3 : 2, ...(size.touch ? { hasTouch: true, isMobile: true } : {}) });
      const stem = `${size.name}-${theme}`;

      /**
       * Runs one pair: `open` builds the lower layer then the upper one; the selectors name them for the hit test. The verdict
       * goes to its own file (`pair-<size>-<theme>-<name>.json`): a failed test restarts the worker, so a shared object would
       * lose the earlier verdicts. `touchSkip` names a pair a phone cannot make (Settings and hover tooltips).
       */
      const pair = (name: string, lower: string, upper: string, open: (page: Page) => Promise<void>, touchSkip = false): void => {
        test(name, async ({ page }) => {
          test.skip(touchSkip && size.touch, "not reachable on a touch screen in the mock canvas");
          const file = resolve(OUT, `pair-${stem}-${name}.json`);
          try {
            await open(page);
            // sleep: a capture is taken after the layer has finished its entrance animation, there is no event to wait on
            await page.waitForTimeout(400);
            mkdirSync(OUT, { recursive: true });
            await page.screenshot({ path: resolve(OUT, `${stem}-${name}.png`) });
            const found = await verdict(page, lower, upper);
            writeFileSync(file, JSON.stringify(found, null, 1));
            expect(found.upperOnTop, `${name}: ${upper} is on top of ${lower}`).toBe(true);
          } catch (error) {
            mkdirSync(OUT, { recursive: true });
            writeFileSync(file, JSON.stringify({ skipped: String(error).slice(0, 400) }, null, 1));
            throw error;
          }
        });
      };

      pair("palette-over-popover", ".canvas-popover", "#palette", async (page) => {
        await openCanvas(page, theme);
        await page.locator(".ui-window-pill").first().click();
        await expect(page.locator(".canvas-popover")).toBeVisible();
        // sleep: a capture is taken after the layer has finished its entrance animation, there is no event to wait on
        await page.waitForTimeout(400);
        await openPalette(page);
      });
      pair("palette-over-sidebar", "#sidebar", "#palette", async (page) => {
        await openCanvas(page, theme);
        await page.locator("#sidebar-toggle").click();
        await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1);
        // sleep: a capture is taken after the layer has finished its entrance animation, there is no event to wait on
        await page.waitForTimeout(700);
        await openPalette(page);
      });
      pair("palette-over-settings", ".ui-sp", "#palette", async (page) => {
        await openCanvas(page, theme, 3);
        await openSettings(page);
        await page.keyboard.press("Control+Shift+K");
        await expect(page.locator("#palette")).toBeVisible();
        // sleep: a capture is taken after the layer has finished its entrance animation, there is no event to wait on
        await page.waitForTimeout(400);
      }, true);
      pair("toast-over-settings", ".ui-sp", '.ui-toast[data-open="true"]', async (page) => {
        await openCanvas(page, theme, 3);
        await openSettings(page);
        await showToast(page);
      }, true);
      pair("toast-over-palette", "#palette", '.ui-toast[data-open="true"]', async (page) => {
        await openCanvas(page, theme);
        await openPalette(page);
        await showToast(page);
      });
      pair("tooltip-over-sidebar", "#sidebar", ".tip-pos", async (page) => {
        await openCanvas(page, theme);
        await page.locator("#sidebar-toggle").click();
        await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1);
        // sleep: a capture is taken after the layer has finished its entrance animation, there is no event to wait on
        await page.waitForTimeout(700);
        await page.locator('#sidebar button[aria-label="Settings"]').first().hover();
        await expect(page.locator(".tip-pos")).toBeVisible({ timeout: 4000 });
      }, true);
      pair("popover-over-sidebar", "#sidebar", ".canvas-popover", async (page) => {
        await openCanvas(page, theme);
        await page.locator("#sidebar-toggle").click();
        await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1);
        // sleep: a capture is taken after the layer has finished its entrance animation, there is no event to wait on
        await page.waitForTimeout(700);
        // Clicked from script: with the sidebar open the pill can sit under it, and a forced pointer click misses.
        await page.evaluate(() => document.querySelector<HTMLElement>(".ui-window-pill")!.click());
        await expect(page.locator(".canvas-popover")).toBeVisible();
      });
    });
  }
}
