/** Pressing "Use recovery key" while the card's entrance is still running must still play the swap. */
import { expect, test } from "playwright/test";

test.skip(!["preview", "1"].includes(process.env.INFRATERNAL_RECOVERY_UI ?? "off"), "Recovery presentation requires an explicit build flag");

for (const delay of [0, 50, 150]) {
  test(`the card swap plays when recovery is pressed ${delay} ms after load`, async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "no-preference" });
    await page.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: false } }));
    await page.route("**/auth/session", (route) => route.fulfill({ status: 401, json: {} }));
    await page.goto("/?mock=1&proto=recovery");
    await page.locator("#use-recovery").waitFor({ state: "attached" });
    const seen = await page.evaluate(async (wait) => {
      await new Promise((resolve) => setTimeout(resolve, wait));
      document.querySelector<HTMLElement>("#use-recovery")!.click();
      let ghost = false, slid = false, interrupted = false;
      for (let frame = 0; frame < 20; frame++) {
        await new Promise((resolve) => requestAnimationFrame(resolve));
        ghost ||= document.querySelector(".auth-leaving .auth-card") !== null;
        const card = document.querySelector<HTMLElement>("#recovery-card");
        if (!card) continue;
        // The new card moves sideways (a swap), not just the entrance's 8 px rise.
        slid ||= Math.abs(new DOMMatrix(getComputedStyle(card).transform).m41) > 1;
        interrupted ||= wait < 240 && getComputedStyle(document.querySelector(".auth-leaving .auth-card") ?? card).opacity !== "1";
      }
      return { ghost, slid, interrupted };
    }, delay);
    expect(seen.ghost).toBe(true);
    expect(seen.slid).toBe(true);
    // The old card's entrance was still running when it was pressed: the ghost starts from that state.
    if (delay < 240) expect(seen.interrupted).toBe(true);
    await expect(page.locator(".auth-leaving")).toHaveCount(0);
  });
}
