/**
 * The Settings switch "Programs can copy to your clipboard" (D373, #440). It sits in Terminal > Hosts, is ON by default,
 * and is stored on this device. When it is off, a program's copy in the terminal in use is only offered behind a Copy
 * action and the page writes nothing by itself; turned back on, the next copy lands at once. Runs on the production
 * tracer build at a desktop and a phone viewport.
 */
import { expect, test } from "playwright/test";
import { mkdirSync } from "node:fs";
import { tracerEvidencePath } from "./evidence-path";

/** The two sizes the gate names: a desktop window and an iPhone. */
const VIEWPORTS = [
  { name: "desktop", width: 1440, height: 900, dpr: 2, touch: false },
  { name: "phone", width: 393, height: 852, dpr: 3, touch: true },
] as const;
/** Where the screenshots go (outside the checkout). */
const OUT = tracerEvidencePath("osc52");
/** The label the owner chose (D373). */
const LABEL = "Programs can copy to your clipboard";
/** The bytes a program prints to copy `text`. */
const copy = (text: string): string => `\u001b]52;c;${Buffer.from(text, "utf8").toString("base64")}\u0007`;

for (const viewport of VIEWPORTS) {
  test.describe(`${viewport.name} ${viewport.width}x${viewport.height}`, () => {
    test.use({ viewport: { width: viewport.width, height: viewport.height }, deviceScaleFactor: viewport.dpr, hasTouch: viewport.touch, isMobile: viewport.touch });

    test("the switch is in Terminal > Hosts, on by default, and turning it off is remembered", async ({ page }) => {
      mkdirSync(OUT, { recursive: true });
      await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft");
      await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
      await page.evaluate(() => (window as unknown as { __tracerClusters: { openSettings(section: string): void } }).__tracerClusters.openSettings("terminal.hosts"));
      const input = page.getByRole("switch", { name: LABEL });
      await expect(input).toHaveCount(1, { timeout: 15_000 });
      await expect(page.locator('.ui-window[data-window-id="s-terminal-hosts"]')).toContainText("Clipboard");
      await expect(input).toBeChecked();
      expect(await page.evaluate(() => localStorage.getItem("tracer.program-copy"))).toBeNull();
      await page.screenshot({ path: `${OUT}/${viewport.name}-setting-on.png` });
      await input.click();
      await expect(input).not.toBeChecked();
      expect(await page.evaluate(() => localStorage.getItem("tracer.program-copy"))).toBe("0");
      await page.screenshot({ path: `${OUT}/${viewport.name}-setting-off.png` });
      // Remembered across a reload.
      await page.reload();
      await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
      await page.evaluate(() => (window as unknown as { __tracerClusters: { openSettings(section: string): void } }).__tracerClusters.openSettings("terminal.hosts"));
      await expect(page.getByRole("switch", { name: LABEL })).not.toBeChecked({ timeout: 15_000 });
    });

    test("off: the focused terminal's copy is only offered and nothing is written; on again: it lands at once", async ({ context }) => {
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      const page = await context.newPage();
      await context.request.post("/__mock/reset");
      await context.request.post("/__mock/open-terminal");
      await page.goto("/?mock=1&proto=product&bg=none&fixture=none&theme=ink");
      await expect.poll(() => page.evaluate(() => window.__tracerProductTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
      const host = page.locator("#terminal-host");
      if (viewport.touch) await host.tap({ position: { x: 40, y: 120 } }); else await host.click({ position: { x: 40, y: 120 } });
      await expect.poll(() => page.evaluate(() => document.querySelector("#terminal-host")?.contains(document.activeElement))).toBe(true);
      await page.evaluate(() => {
        const real = navigator.clipboard.writeText.bind(navigator.clipboard);
        const counted = window as unknown as { __writes: number };
        counted.__writes = 0;
        navigator.clipboard.writeText = async (text: string) => { counted.__writes += 1; await real(text); };
      });
      const writes = (): Promise<number> => page.evaluate(() => (window as unknown as { __writes: number }).__writes);
      const send = async (text: string): Promise<void> => { expect((await context.request.post("/__mock/live-query-output", { data: { text } })).ok()).toBe(true); };

      await page.evaluate(() => { localStorage.setItem("tracer.program-copy", "0"); navigator.clipboard.writeText("before"); });
      const base = await writes();
      await send(`\u001b[2J\u001b[H$ ${copy("kept off the clipboard")}`);
      const offer = page.locator(".ui-toast").filter({ hasText: /^From / });
      await expect(offer.locator(".ui-toast-action", { hasText: "Copy" })).toBeVisible({ timeout: 10_000 });
      await page.screenshot({ path: `${OUT}/${viewport.name}-off-offer.png` });
      // sleep: give a wrongly eager write time to land before asserting that none did
      await page.waitForTimeout(1500);
      expect(await writes(), "nothing written by itself").toBe(base);
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("before");

      await page.evaluate(() => localStorage.setItem("tracer.program-copy", "1"));
      await send(copy("lands at once"));
      await expect.poll(() => page.evaluate(() => navigator.clipboard.readText()), { timeout: 10_000 }).toBe("lands at once");
    });
  });
}
