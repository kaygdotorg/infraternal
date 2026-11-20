// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Alt+wheel never navigates history in Firefox, wherever the pointer is (D377, #444). Firefox's own action for Alt+wheel is
 * history back/forward (`mousewheel.with_alt.action = 2`, no platform guard). The canvas router cancels it inside the canvas
 * viewport; the top pill, the toolbars and the screen edge are outside it, so the page needs its own guard.
 *
 * Runs Firefox against the production build with a page behind it in the history, so "navigated back" is observable. If
 * Firefox cannot start here (missing system libraries) the spec fails loudly rather than skipping.
 */
import { expect, test } from "playwright/test";

test.use({ browserName: "firefox", viewport: { width: 1440, height: 900 } });

/** Where the pointer rests: the canvas centre, the top pill (outside the canvas viewport) and the right screen edge. */
const SPOTS = ["centre", "topPill", "rightEdge"] as const;

for (const spot of SPOTS) for (const [dx, dy] of [[0, 300], [300, 0]] as const) {
  test(`Firefox: Alt+wheel (${dx},${dy}) over the ${spot} does not go back in history`, async ({ browser, baseURL }) => {
    test.setTimeout(60_000);
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    await page.goto("data:text/html,<p>first</p>");
    await page.goto(`${baseURL}/?mock=1&proto=clusters&scene=3&theme=ink&bg=plain&docs=1`);
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 30_000 });
    // sleep: the mock canvas finishes its first layout; no event marks it
    await page.waitForTimeout(1500);
    const at = spot === "centre" ? { x: 720, y: 450 } : spot === "rightEdge" ? { x: 1437, y: 450 } : await page.locator("button.capsule").first().boundingBox().then((b) => ({ x: b!.x + b!.width / 2, y: b!.y + b!.height / 2 }));
    await page.mouse.move(at.x, at.y);
    await page.keyboard.down("Alt");
    await page.mouse.wheel(dx, dy);
    // sleep: a history navigation, if it happens, takes a moment to start; no event marks that nothing happened
    await page.waitForTimeout(900);
    await page.keyboard.up("Alt");
    expect(page.url().startsWith("data:"), "the page was not sent back to the page before it").toBe(false);
    await context.close();
  });
}
