/**
 * Two terminal windows, one OSC 52 copy each (#440). Only the focused window may write the clipboard by itself; a copy
 * from the other window waits behind a "Copy" action that names it, and never writes unprompted. Runs on the production
 * tracer build at a desktop and a phone viewport.
 */
import { expect, test, type Page } from "playwright/test";
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

/** One attached session as the test double reports it: its id and how many input bytes it has accepted. */
interface Attached { id: string; accepted_input_bytes: number }

for (const viewport of VIEWPORTS) {
  test.describe(`${viewport.name} ${viewport.width}x${viewport.height}`, () => {
    test.use({ viewport: { width: viewport.width, height: viewport.height }, deviceScaleFactor: viewport.dpr, hasTouch: viewport.touch, isMobile: viewport.touch });

    const attached = async (page: Page): Promise<Attached[]> =>
      ((await (await page.context().request.get("/__mock/state")).json()) as { attached_sessions: Attached[] }).attached_sessions;

    test("the focused window copies by itself; the other one only offers, by name, and never writes", async ({ context }) => {
      mkdirSync(OUT, { recursive: true });
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      const page = await context.newPage();
      await context.request.post("/__mock/reset");
      await context.request.post("/__mock/open-terminal");
      await page.goto("/?mock=1&proto=product&bg=none&fixture=none&theme=ink");
      await expect.poll(() => page.evaluate(() => window.__tracerProductTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
      // A second window: it opens its own session and takes the focus.
      await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:new:right", source: "pointer" } })));
      await expect.poll(async () => (await attached(page)).length, { timeout: 30_000 }).toBe(2);
      // Find out which session has the focus: type a letter and see whose input grew.
      const before = await attached(page);
      await page.keyboard.type("x");
      await expect.poll(async () => (await attached(page)).some((s, i) => s.accepted_input_bytes > before[i]!.accepted_input_bytes)).toBe(true);
      const after = await attached(page);
      const focusedIndex = after.findIndex((s, i) => s.accepted_input_bytes > before[i]!.accepted_input_bytes);
      const focused = after[focusedIndex]!.id;
      const other = after[1 - focusedIndex]!.id;
      const send = async (id: string, text: string): Promise<void> => {
        expect((await context.request.post("/__mock/live-query-output", { data: { text, session_id: id } })).ok()).toBe(true);
      };

      await page.evaluate(() => navigator.clipboard.writeText("before"));
      await send(other, copy("from the other window"));
      const offer = page.locator(".ui-toast").filter({ hasText: /text to copy/i });
      await expect(offer).toBeVisible({ timeout: 10_000 });
      await expect(offer.locator(".ui-toast-action", { hasText: "Copy" })).toBeVisible();
      // Named: the message says where the text came from, on one line, inside the viewport.
      const message = (await offer.locator(".ui-toast-message").textContent())!;
      expect(message).toMatch(/from \S+/);
      expect(await offer.locator(".ui-toast-message").evaluate((el) => Math.round(el.getBoundingClientRect().height / parseFloat(getComputedStyle(el).lineHeight)))).toBe(1);
      const box = (await offer.boundingBox())!;
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(viewport.width);
      await page.screenshot({ path: `${OUT}/${viewport.name}-other-window-offer.png` });
      // It waited: even after a pause the clipboard is untouched.
      await page.waitForTimeout(1500); // sleep: give a wrongly eager write time to land before asserting that none did
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("before");

      await send(focused, copy("from the focused window"));
      await expect.poll(() => page.evaluate(() => navigator.clipboard.readText()), { timeout: 10_000 }).toBe("from the focused window");

      // The offered text still copies on a tap, and says so.
      await offer.locator(".ui-toast-action", { hasText: "Copy" }).evaluate((el: HTMLElement) => el.click());
      await expect.poll(() => page.evaluate(() => navigator.clipboard.readText()), { timeout: 10_000 }).toBe("from the other window");
    });
  });
}
