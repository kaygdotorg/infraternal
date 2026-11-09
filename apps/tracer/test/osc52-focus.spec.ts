/**
 * Only the focused terminal may copy for a program on its own (#440). With the focus in the terminal, an OSC 52 copy goes to
 * the clipboard at once. With the focus anywhere else (another window or any other control), the same copy only offers a
 * "Copy" action that names the window, and the page never writes the clipboard by itself.
 *
 * The test double serves one terminal per page, so "another window" is modelled by what the product checks: the focus
 * sits outside the terminal's own host. Runs on the production tracer build at a desktop and a phone viewport.
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
/** The bytes a program prints to copy `text`. */
const copy = (text: string): string => `\u001b]52;c;${Buffer.from(text, "utf8").toString("base64")}\u0007`;

for (const viewport of VIEWPORTS) {
  test.describe(`${viewport.name} ${viewport.width}x${viewport.height}`, () => {
    test.use({ viewport: { width: viewport.width, height: viewport.height }, deviceScaleFactor: viewport.dpr, hasTouch: viewport.touch, isMobile: viewport.touch });

    test("the focused terminal copies by itself; with the focus elsewhere the copy is only offered, by name", async ({ context }) => {
      mkdirSync(OUT, { recursive: true });
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      const page = await context.newPage();
      await context.request.post("/__mock/reset");
      await context.request.post("/__mock/open-terminal");
      await page.goto("/?mock=1&proto=product&bg=none&fixture=none&theme=ink");
      await expect.poll(() => page.evaluate(() => window.__tracerProductTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
      // Count every clipboard write the page makes, whoever asks.
      await page.evaluate(() => {
        const real = navigator.clipboard.writeText.bind(navigator.clipboard);
        const counted = window as unknown as { __writes: number };
        counted.__writes = 0;
        navigator.clipboard.writeText = async (text: string) => { counted.__writes += 1; await real(text); };
      });
      const writes = (): Promise<number> => page.evaluate(() => (window as unknown as { __writes: number }).__writes);
      const send = async (text: string): Promise<void> => { expect((await context.request.post("/__mock/live-query-output", { data: { text } })).ok()).toBe(true); };

      // Focus elsewhere first: the menu button of the page, outside the terminal.
      await page.evaluate(() => (document.querySelector("button") as HTMLElement).focus());
      expect(await page.evaluate(() => document.querySelector("#terminal-host")?.contains(document.activeElement))).toBe(false);
      await page.evaluate(() => navigator.clipboard.writeText("before"));
      const base = await writes();
      await send(`\u001b[2J\u001b[Hremote\r\n${copy("from the unfocused window")}`);
      const offer = page.locator(".ui-toast").filter({ hasText: /^From / });
      await expect(offer).toBeVisible({ timeout: 10_000 });
      await expect(offer.locator(".ui-toast-action", { hasText: "Copy" })).toBeVisible();
      expect(await offer.locator(".ui-toast-message").evaluate((el) => Math.round(el.getBoundingClientRect().height / parseFloat(getComputedStyle(el).lineHeight))), "the name is on one line").toBe(1);
      const box = (await offer.boundingBox())!;
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(viewport.width);
      await page.screenshot({ path: `${OUT}/${viewport.name}-unfocused-offer.png` });
      // sleep: give a wrongly eager write time to land before asserting that none did
      await page.waitForTimeout(1500);
      expect(await writes(), "the page wrote nothing by itself").toBe(base);
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("before");

      // The offered text copies on a tap (the notice is the window's single one, so this is done before the next copy replaces it).
      await offer.locator(".ui-toast-action", { hasText: "Copy" }).evaluate((el: HTMLElement) => el.click());
      await expect.poll(() => page.evaluate(() => navigator.clipboard.readText()), { timeout: 10_000 }).toBe("from the unfocused window");

      // Back in the terminal, the next copy goes through at once.
      if (viewport.touch) await page.locator("#terminal-host").tap({ position: { x: 40, y: 120 } }); else await page.locator("#terminal-host").click({ position: { x: 40, y: 120 } });
      await expect.poll(() => page.evaluate(() => document.querySelector("#terminal-host")?.contains(document.activeElement))).toBe(true);
      await send(copy("from the focused window"));
      await expect.poll(() => page.evaluate(() => navigator.clipboard.readText()), { timeout: 10_000 }).toBe("from the focused window");
    });
  });
}
