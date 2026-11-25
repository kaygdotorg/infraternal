/**
 * Checks that the approval result cards (a request that cannot be shown, and the same card with the approved text)
 * hug their last line: the space under it equals the card's top padding, at desktop and phone sizes (TASTE:
 * "a card's bottom padding equals its top padding", owner 2026-11-25). The approved card is the error card's markup
 * with other words, so both share one measurement.
 */
import { expect, test } from "playwright/test";

const LINK = "/#join=AbCdEfGhIjKlMnOpQrStUvWxYz012345";

for (const profile of [
  { name: "desktop", viewport: { width: 1440, height: 900 } },
  { name: "phone", viewport: { width: 393, height: 852 } },
]) {
  test.describe(profile.name, () => {
    test.use({ viewport: profile.viewport });
    for (const variant of ["expired", "approved"]) {
      test(`${variant} card has equal top and bottom padding`, async ({ page }) => {
        await page.route("**/auth/status", route => route.fulfill({ json: { setup_required: false } }));
        await page.route("**/auth/session", route => route.fulfill({ json: {
          user_id: "11111111-1111-4111-8111-111111111111", username: "fixture_owner", display_name: "Fixture owner",
          device: "Browser", fresh: Math.floor(Date.now() / 1000),
        } }));
        await page.route("**/auth/device-inspect", route => route.fulfill({ status: 401, json: { error: "authorization failed" } }));
        await page.goto(LINK);
        await expect(page.getByRole("heading", { name: "Can't add this machine" })).toBeVisible();
        if (variant === "approved") {
          await page.evaluate(() => {
            document.querySelector("#device-approval-title")!.textContent = "Machine approved";
            document.querySelector(".auth-lede")!.textContent = "Return to the terminal. It will finish adding this machine.";
          });
        }
        const gaps = await page.evaluate(() => {
          const card = document.querySelector<HTMLElement>(".auth-card")!.getBoundingClientRect();
          const lede = document.querySelector<HTMLElement>(".auth-lede")!.getBoundingClientRect();
          const mark = document.querySelector<HTMLElement>(".auth-mark")!.getBoundingClientRect();
          return { top: mark.top - card.top, bottom: card.bottom - lede.bottom };
        });
        expect(Math.abs(gaps.top - gaps.bottom)).toBeLessThanOrEqual(2);
      });
    }
  });
}
