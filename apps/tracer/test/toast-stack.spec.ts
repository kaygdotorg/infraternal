// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Toasts stack (D336, #335): newest in front, older ones compressed behind and fanned out on hover or focus, a cap of
 * three drawn, an error never removed or hidden by a later notice, one clock per toast held while the pointer rests
 * on the stack, and a touch swipe down to dismiss. Runs against the production-built preview at 1440x900 and 393x852;
 * the review screenshots (a stack of three with one error, dark and light) land in the external evidence directory.
 */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

type Probe = { dismiss(...id: [string?]): void; show(value: Record<string, unknown>): string };
declare global { interface Window { __toast?: Probe } }

const VIEWPORTS = [
  { name: "desktop", viewport: { width: 1440, height: 900 }, touch: false },
  { name: "phone", viewport: { width: 393, height: 852 }, touch: true },
] as const;
const ROOTLESS = "This server runs without root, so it can only open shells as its own user. Add a host to work elsewhere.";

async function open(page: Page, theme = "dark"): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForFunction(() => Boolean(window.__toast));
  // Start from an empty stack: the mock raises its own welcome notices.
  await page.evaluate(() => window.__toast!.dismiss());
  await expect(page.locator(".ui-toast")).toHaveCount(0);
}

const show = (page: Page, value: Record<string, unknown>): Promise<string> => page.evaluate((v) => window.__toast!.show(v), value);
const cards = (page: Page) => page.locator(".ui-toast");
const drawn = (page: Page) => page.locator('.ui-toast[data-hidden="false"]');
const box = async (page: Page, index: number) => (await cards(page).nth(index).boundingBox())!;

for (const { name, viewport, touch } of VIEWPORTS) {
  test.describe(`${name} ${viewport.width}x${viewport.height}`, () => {
    test.use({ viewport, hasTouch: touch, isMobile: touch });

    test("newest in front, older compressed behind, at most three drawn", async ({ page }) => {
      await open(page);
      for (const n of [1, 2, 3, 4]) await show(page, { message: `Notice ${n}`, duration: 0 });
      await expect(drawn(page)).toHaveCount(3);
      const front = page.locator('.ui-toast[data-front="true"]');
      await expect(front).toContainText("Notice 4");
      // Order in the DOM is creation order: the oldest (hidden) first, then the two behind, then the front.
      await expect(cards(page).nth(0)).toHaveAttribute("data-hidden", "true");
      const [mid, behind, f] = [await box(page, 2), await box(page, 1), await box(page, 3)];
      // Behind means smaller and higher, centred on the same line.
      expect(behind.width).toBeLessThan(mid.width);
      expect(mid.width).toBeLessThan(f.width);
      expect(behind.y).toBeLessThan(mid.y);
      expect(mid.y).toBeLessThan(f.y);
      expect(Math.abs(behind.x + behind.width / 2 - (f.x + f.width / 2))).toBeLessThan(0.75);
    });

    test("an error is never removed or hidden by later notices", async ({ page }) => {
      await open(page);
      const error = await show(page, { message: "Could not open a shell.", tone: "error", duration: 0 });
      for (const n of [1, 2, 3, 4, 5]) await show(page, { message: `Notice ${n}`, duration: 0 });
      const errorCard = page.locator('.ui-toast[data-tone="error"]');
      await expect(errorCard).toHaveAttribute("data-hidden", "false");
      await expect(drawn(page)).toHaveCount(3);
      // Clearing notices leaves it; only its own id removes it.
      await page.evaluate(() => window.__toast!.dismiss());
      await expect(cards(page)).toHaveCount(1);
      await expect(errorCard).toBeVisible();
      await page.evaluate((id) => window.__toast!.dismiss(id), error);
      await expect(cards(page)).toHaveCount(0);
    });

    test("an error stays beside a notice that arrives after it (the rootless first load)", async ({ page }) => {
      await open(page);
      await show(page, { message: ROOTLESS, tone: "error", duration: 0 });
      await show(page, { message: "Unlock host connections", duration: 0, action: { label: "Unlock" } });
      await expect(cards(page)).toHaveCount(2);
      await expect(page.locator('.ui-toast[data-tone="error"]')).toContainText("runs without root");
      await expect(page.locator('.ui-toast[data-tone="error"]')).toHaveAttribute("data-hidden", "false");
    });

    test("the rootless refusal fits about three lines", async ({ page }) => {
      await open(page);
      await show(page, { message: ROOTLESS, tone: "error", duration: 0 });
      const lines = await page.locator(".ui-toast-message").evaluate((node) => Math.round(node.getBoundingClientRect().height / Number.parseFloat(getComputedStyle(node).lineHeight)));
      expect(lines).toBeLessThanOrEqual(name === "phone" ? 3 : 2);
    });

    test("repeats update one toast with a count", async ({ page }) => {
      await open(page);
      for (let n = 0; n < 12; n++) await show(page, { message: "Message sent", duration: 0, key: "sent" });
      await expect(cards(page)).toHaveCount(1);
      await expect(page.locator(".ui-toast-message")).toHaveText("Message sent ×12");
      // Another tone is another toast.
      await show(page, { message: "Message sent", tone: "error", duration: 0 });
      await expect(cards(page)).toHaveCount(2);
    });

    test("each toast has its own clock and expires alone", async ({ page }) => {
      await open(page);
      await show(page, { message: "Quick", duration: 600 });
      await show(page, { message: "Kept", duration: 0 });
      await expect(cards(page)).toHaveCount(1);
      await expect(page.locator(".ui-toast-message")).toHaveText("Kept");
    });

    test("icons and text share a centre line in a one-line toast", async ({ page }) => {
      await open(page);
      await show(page, { message: "Short notice", duration: 0 });
      const [marker, message] = await page.evaluate(() => [".ui-toast-marker", ".ui-toast-message"].map((selector) => {
        const r = document.querySelector(selector)!.getBoundingClientRect();
        return r.top + r.height / 2;
      }));
      expect(Math.abs(marker! - message!)).toBeLessThanOrEqual(0.5);
    });

    test("reduced motion keeps only a short opacity change", async ({ page }) => {
      await page.emulateMedia({ reducedMotion: "reduce" });
      await open(page);
      await show(page, { message: "Calm", duration: 0 });
      const t = await cards(page).first().evaluate((node) => { const s = getComputedStyle(node); return { property: s.transitionProperty, duration: s.transitionDuration }; });
      expect(t.property).toBe("opacity");
      expect(Number.parseFloat(t.duration)).toBeLessThanOrEqual(0.12);
    });

    if (!touch) {
      test("hover fans the stack out and stops every clock; leaving collapses it", async ({ page }) => {
        await open(page);
        await show(page, { message: "Notice 1", duration: 1500 });
        await show(page, { message: "Notice 2", duration: 1500 });
        await show(page, { message: "Notice 3", duration: 1500 });
        const stack = page.locator(".ui-toast-stack");
        await expect(stack).toHaveAttribute("data-expanded", "false");
        await cards(page).nth(2).hover();
        await expect(stack).toHaveAttribute("data-expanded", "true");
        // Fanned out: no card overlaps the one in front of it.
        await expect.poll(async () => {
          const [a, b, c] = [await box(page, 0), await box(page, 1), await box(page, 2)];
          return Math.min(b.y - (a.y + a.height), c.y - (b.y + b.height));
        }).toBeGreaterThanOrEqual(0);
        // Held: still all there well after the clocks would have run out.
        await page.waitForTimeout(2200);
        await expect(cards(page)).toHaveCount(3);
        await page.mouse.move(5, 5);
        await expect(stack).toHaveAttribute("data-expanded", "false");
        await expect(cards(page)).toHaveCount(0, { timeout: 5000 });
      });

      test("keyboard focus fans the stack out", async ({ page }) => {
        await open(page);
        await show(page, { message: "Notice 1", duration: 0, dismissible: true });
        await show(page, { message: "Notice 2", duration: 0, dismissible: true });
        await page.keyboard.press("Tab");
        for (let i = 0; i < 40 && (await page.locator(".ui-toast-stack").getAttribute("data-expanded")) !== "true"; i++) await page.keyboard.press("Tab");
        await expect(page.locator(".ui-toast-stack")).toHaveAttribute("data-expanded", "true");
      });
    }

    if (touch) {
      test("a swipe down dismisses a toast; a short drag springs back", async ({ page }) => {
        await open(page);
        await show(page, { message: "Swipe me", duration: 0 });
        await show(page, { message: "Stay", duration: 0 });
        const front = cards(page).nth(1);
        await expect(front).toHaveAttribute("data-open", "true");
        const at = (await front.boundingBox())!;
        // A finger on the card's left padding: not on a button.
        const x = at.x + 8, y = at.y + at.height / 2;
        const cdp = await page.context().newCDPSession(page);
        const drag = async (dy: number): Promise<void> => {
          await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x, y }] });
          for (const step of [0.25, 0.5, 0.75, 1]) await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x, y: y + dy * step }] });
          await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
        };
        await drag(20);
        await expect(cards(page)).toHaveCount(2);
        await expect(front).toHaveAttribute("data-open", "true");
        await drag(90);
        await expect(cards(page)).toHaveCount(1);
        await expect(page.locator(".ui-toast-message")).toHaveText("Swipe me");
      });
    }

    for (const theme of ["dark", "light"] as const) {
      test(`screenshot: a stack of three with one error (${theme})`, async ({ page }) => {
        await open(page, theme);
        await show(page, { message: "Could not open a shell.", tone: "error", duration: 0 });
        await show(page, { message: "Unlock host connections", duration: 0, dismissible: true, action: { label: "Unlock" } });
        await show(page, { message: ROOTLESS, tone: "error", duration: 0 });
        await show(page, { message: "Layout saved", duration: 0 });
        await expect(drawn(page)).toHaveCount(3);
        await page.waitForTimeout(500);
        await page.screenshot({ path: tracerEvidencePath("toast-stack", `${name}-${theme}-collapsed.png`) });
        if (!touch) {
          await cards(page).last().hover();
          await expect(page.locator(".ui-toast-stack")).toHaveAttribute("data-expanded", "true");
          await page.waitForTimeout(500);
          await page.screenshot({ path: tracerEvidencePath("toast-stack", `${name}-${theme}-expanded.png`) });
        }
      });
    }
  });
}
