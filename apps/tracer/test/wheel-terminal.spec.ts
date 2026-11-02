// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The wheel over a terminal (D275, #308), on a production build against the terminal test double, without the input lock: with
 * scrollback and the window active, a vertical wheel scrolls the terminal's scrollback and the canvas does not move; a burst
 * past its top or bottom is swallowed; with the window not active the same wheel is the canvas's and the scrollback stays; and a
 * terminal with nothing to scroll leaves the wheel to the canvas. The real-PTY version of the stacked-column cases is
 * `real/wheel-routing.spec.ts`. Captures at 1440×900, DPR 2, go to the external evidence directory.
 */
import { mkdirSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const OUT = tracerEvidencePath("wheel-terminal");
const WINDOW = '.ui-window[data-window-id="w-build-01"]';

const canvasState = (page: Page): Promise<string> =>
  page.evaluate(() => `${document.querySelector<HTMLElement>(".cl-world")?.style.transform ?? ""}|${[...document.querySelectorAll<HTMLElement>(".cl-col")].map((c) => `${c.scrollTop}/${c.scrollLeft}`).join(",")}`);
/** The terminal sets `data-scrolled` on its first scroll; before that the attribute is absent, which means not scrolled. */
const scrolled = async (page: Page): Promise<string> => (await page.locator(`${WINDOW} .terminal-host`).getAttribute("data-scrolled")) ?? "false";
const burst = async (page: Page, dy: number, count: number): Promise<void> => { for (let i = 0; i < count; i++) { await page.mouse.wheel(0, dy); await page.waitForTimeout(8); } };

test("desktop: the active terminal scrolls its own scrollback without the input lock; an inactive one belongs to the canvas", async ({ browser }) => {
  test.setTimeout(240_000);
  mkdirSync(OUT, { recursive: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: "dark" });
  const page = await context.newPage();
  try {
    await context.request.post("/__mock/reset");
    await context.request.post("/__mock/open-terminal");
    await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&bg=none");
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
    await page.waitForTimeout(1200);
    console.log("STEP connected");
    // The scene opens on the overview; fly into Console so the window is live and the canvas is snapped to its windows.
    await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
    await page.waitForTimeout(1500);

    // 300 lines of output: a scrollback of about 270 rows.
    const text = Array.from({ length: 300 }, (_, i) => `line ${String(i + 1).padStart(3, "0")} of the scrollback`).join("\r\n") + "\r\n";
    expect((await context.request.post("/__mock/text-output", { data: { text } })).ok()).toBe(true);
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.scrollbackRows ?? 0), { timeout: 15_000 }).toBeGreaterThan(150);
    console.log("STEP scrollback ready");
    expect(await page.locator(".cl-viewport[data-input-lock]").count(), "the input lock is off").toBe(0);

    // Focus the window by clicking it, then wheel up over the terminal.
    const host = page.locator(`${WINDOW} .terminal-host`);
    await host.click({ position: { x: 80, y: 60 }, timeout: 15_000 });
    console.log("STEP clicked");
    await expect(page.locator(WINDOW)).toHaveAttribute("data-active", "");
    await page.waitForTimeout(900);
    const box = (await host.boundingBox())!;
    const at = { x: box.x + box.width / 2, y: Math.max(box.y, 80) + Math.min(box.height, 700) / 2 };
    const before = await canvasState(page);
    expect(await scrolled(page)).toBe("false");
    await page.mouse.move(at.x, at.y);
    await page.mouse.wheel(0, -400);
    console.log("STEP wheeled");
    await expect.poll(() => scrolled(page), "the scrollback moved").toBe("true");
    expect(await canvasState(page), "the canvas did not move").toBe(before);
    await page.screenshot({ path: `${OUT}/terminal-scrolled-back.png` });

    // The terminal's own smooth scroll chases the last event, so a long way is one big wheel, then a burst past the end:
    // swallowed, never chained into the canvas.
    const viewportY = (): Promise<number> => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.viewportY ?? 0);
    const rows = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.scrollbackRows ?? 0);
    await page.mouse.wheel(0, -20_000);
    await expect.poll(viewportY, { timeout: 10_000 }).toBeGreaterThanOrEqual(rows - 0.5);
    await burst(page, -200, 30);
    await page.waitForTimeout(500);
    expect(await canvasState(page), "momentum past the top did not reach the canvas").toBe(before);
    await page.mouse.wheel(0, 20_000);
    await expect.poll(() => scrolled(page), { timeout: 10_000 }).toBe("false");
    await burst(page, 200, 30);
    await page.waitForTimeout(600);
    expect(await scrolled(page)).toBe("false");
    expect(await canvasState(page), "momentum past the bottom did not reach the canvas").toBe(before);

    // Not the active window any more: a click on bare canvas clears it, and the same wheel is the canvas's.
    await page.waitForTimeout(500);
    await page.mouse.wheel(0, -400);
    await expect.poll(() => scrolled(page)).toBe("true");
    await page.mouse.wheel(0, 20_000);
    await expect.poll(() => scrolled(page), { timeout: 10_000 }).toBe("false");
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
    const gap = await page.evaluate(() => {
      for (let y = 60; y < 880; y += 12) for (let x = 12; x < 1428; x += 12) {
        const hit = document.elementFromPoint(x, y);
        if (hit && hit.closest(".cl-viewport") && !hit.closest(".ui-window, button, .cl-label, .cl-chip, [role=toolbar], #capsule")) return { x, y };
      }
      return undefined;
    });
    expect(gap, "a point of bare canvas exists").toBeDefined();
    await page.mouse.click(gap!.x, gap!.y);
    await expect(page.locator(WINDOW)).not.toHaveAttribute("data-active", "");
    await page.waitForTimeout(600);
    await page.mouse.move(at.x, at.y);
    await page.mouse.wheel(0, -400);
    await page.waitForTimeout(600);
    expect(await scrolled(page), "an inactive terminal's scrollback stays where it was").toBe("false");
  } finally {
    await context.close();
  }
});
