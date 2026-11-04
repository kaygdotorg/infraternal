/** Every access state of the auth cards keeps the sign-in card's rhythm, at three viewports.
 *
 * The first audit only captured the happy path, so a card with its action touching the line above it
 * shipped. This measures what a person sees: the lede-to-action gap, the failure's place above the
 * action, and equal ink above the mark and below the last control, on every state a person can reach
 * without a working server or passkey. */
import { expect, test, type Page } from "playwright/test";
import { uiFactor } from "./ui-factor";

const SIZES = [[1440, 900], [393, 852], [375, 667]] as const;

async function signedOut(page: Page): Promise<void> {
  await page.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/session", (route) => route.fulfill({ status: 401, json: {} }));
  await page.goto("/");
  await expect(page.locator("#login-passkey")).toBeVisible();
}

async function geometry(page: Page): Promise<{ gap: number; top: number; bottom: number; errorToAction: number | null; errorBelowAction: boolean }> {
  // A bounding box during the card entrance includes its temporary scale.
  await expect.poll(() => page.locator(".auth-card").evaluate(card =>
    card.getAnimations().every(animation => animation.playState !== "running"),
  )).toBe(true);
  const factor = await uiFactor(page);
  return page.locator(".auth-card").evaluate((card, factor) => {
    const rect = (selector: string): DOMRect | undefined => card.querySelector(selector)?.getBoundingClientRect();
    const lede = rect(".auth-lede")!;
    const action = card.querySelector<HTMLElement>(".auth-primary")!.getBoundingClientRect();
    const quiet = rect(".auth-text-button");
    const mark = rect(".auth-mark")!;
    const box = card.getBoundingClientRect();
    const error = card.querySelector(".auth-message:not(:empty)")?.getBoundingClientRect();
    // The card's last control: the quiet action (less its own empty inset) or the primary itself.
    const last = quiet ? { bottom: quiet.bottom - (quiet.height - 13 * factor) / 2 } : action;
    return {
      gap: (error ?? action).top - lede.bottom,
      top: mark.top - box.top,
      bottom: box.bottom - last.bottom,
      errorToAction: error ? action.top - error.bottom : null,
      errorBelowAction: error ? error.top > action.top : false,
    };
  }, factor);
}

for (const [width, height] of SIZES) {
  test.describe(`${width}x${height}`, () => {
    test.use({ viewport: { width, height } });

    test("sign-in, unreachable and loading share the lede-to-action gap and equal padding", async ({ page }) => {
      await signedOut(page);
      const factor = await uiFactor(page);
      const signIn = await geometry(page);
      await page.unroute("**/auth/status");
      await page.route("**/auth/status", (route) => route.abort());
      await page.goto("/");
      await expect(page.locator("#retry-status")).toBeVisible();
      await expect(page.locator(".auth-mark svg")).toBeVisible();
      const unreachable = await geometry(page);
      expect(unreachable.gap).toBeCloseTo(signIn.gap, 0);
      // Equal ink above the mark and below the button (the button is the last control).
      expect(Math.abs(unreachable.top - unreachable.bottom)).toBeLessThanOrEqual(1.5);
      // Full-width primary, the same height as "Continue with passkey".
      const buttons = await page.locator(".auth-primary").evaluate((button) => ({ width: button.getBoundingClientRect().width, card: button.closest(".auth-card")!.getBoundingClientRect().width, height: button.getBoundingClientRect().height }));
      expect(buttons.height).toBeCloseTo(48 * factor, 0); // (the card entrance is still settling its last 0.2 px)
      expect(buttons.width).toBeGreaterThan(buttons.card * 0.8);
      // Loading: the counter appears inside the button and nothing moves.
      await page.unroute("**/auth/status");
      await page.route("**/auth/status", () => { /* never answers */ });
      await page.locator("#retry-status").click();
      await expect(page.locator("#retry-status .busy-count")).toBeVisible();
      const loading = await geometry(page);
      expect(loading.gap).toBeCloseTo(unreachable.gap, 0);
    });

    for (const [name, arrange] of [
      ["cancelled passkey", async (page: Page) => {
        await page.addInitScript(() => { navigator.credentials.get = () => Promise.reject(new DOMException("cancelled", "NotAllowedError")); });
        await signedOut(page);
        await page.locator("#login-passkey").click();
      }],
      ["rate limited", async (page: Page) => {
        await signedOut(page);
        await page.route("**/auth/login-start", (route) => route.fulfill({ status: 429, json: {} }));
        await page.locator("#login-passkey").click();
      }],
      ["offline", async (page: Page) => {
        await signedOut(page);
        await page.context().setOffline(true);
        await page.locator("#login-passkey").click();
      }],
    ] as const) {
      test(`sign-in failure (${name}) sits centred above the action with the card's gap`, async ({ page }) => {
        await arrange(page);
        await expect(page.locator(".auth-message:not(:empty)")).toBeVisible();
        await expect.poll(() => page.locator(".auth-note").evaluateAll(notes =>
          notes.every(note => note.getAnimations().every(animation => animation.playState !== "running")),
        )).toBe(true);
        const factor = await uiFactor(page);
        const g = await geometry(page);
        expect(g.errorBelowAction).toBe(false);
        expect(g.gap).toBeCloseTo(28 * factor, 0);
        expect(g.errorToAction).toBeGreaterThanOrEqual(12 * factor - 0.5);
        // Equal ink above the mark and below the quiet action's text.
        expect(Math.abs(g.top - g.bottom)).toBeLessThanOrEqual(2);
      });
    }
  });
}
