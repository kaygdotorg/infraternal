/**
 * Dead-end messages in Settings (#568), run against the production build in the test double (`?mock=1`).
 *
 * A Settings read that fails says what happened and offers Try again; Try again draws the setting back in place. The double
 * refuses the first read of Keys Last when `settingread=fail` is in the URL (`canvas/mock/settings.ts`).
 *
 * The empty-window line (`emptyGroupNote`) is not checked here: the test double backs every setting and supplies data for
 * every other group, so no window of the double is empty. Its wording is pinned by `empty-note.test.ts`.
 *
 * `DEAD_END_SHOTS=<dir>` also writes the captures (1440x900 at DPR 2, 393x852 at DPR 3), before and after the
 * assertions, so the same spec makes the before/after evidence on origin/dev and on the branch.
 */
import { mkdirSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";

/** Where the captures go; the spec writes none unless this is set. */
const SHOTS = process.env.DEAD_END_SHOTS;
/** The page the tests open: the production tracer in the test double, with the clusters canvas and the mocha theme. */
const BASE = "/?mock=1&proto=clusters&docs=1&scene=3&theme=mocha&bg=none";
/** The Keys Last setting's title (definitions.on-demand.ts): the one setting of the Apps window. */
const KEYS_LAST = "Keys Last";
/** The message a failed read shows in the row's place. */
const READ_FAILED = "This could not be read just now.";

/** Opens the page with `query` (which names the Settings window) and waits until that window is up and has drawn. */
async function open(page: Page, query: string): Promise<void> {
  await page.goto(`${BASE}${query}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await expect(page.locator(".cl-crumbs:not([hidden])")).toBeVisible({ timeout: 20_000 });
  // sleep: the window draws its rows after its on-demand chunks load, and the double settles a frame later; no element marks that moment.
  await page.waitForTimeout(1800);
}

/** Writes a capture named `name` into `SHOTS` when that is set. */
async function shot(page: Page, name: string): Promise<void> {
  if (!SHOTS) return;
  mkdirSync(SHOTS, { recursive: true });
  await page.screenshot({ path: `${SHOTS}/${name}.png` });
}

/** The two viewports the spec runs at, the same as settings-rows-of-windows.spec.ts: a desktop at DPR 2 and a phone at DPR 3. */
const SIZES = {
  desktop: { viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, isMobile: false, hasTouch: false },
  phone: { viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true },
} as const;

for (const [size, use] of Object.entries(SIZES)) {
  test.describe(size, () => {
    test.use(use);

    test("a failed Settings read offers Try again, and Try again draws the setting back", async ({ page }) => {
      await open(page, "&at=you.apps&settingread=fail");
      await shot(page, `${size}-02-read-failed`);
      await expect(page.getByText(READ_FAILED, { exact: true })).toBeVisible({ timeout: 10_000 });
      const again = page.locator("button.ui-button", { hasText: "Try again" });
      await expect(again).toHaveCount(1);
      await again.click();
      await expect(page.getByText(READ_FAILED, { exact: true })).toHaveCount(0);
      await expect(page.getByText(KEYS_LAST, { exact: true })).toBeVisible({ timeout: 10_000 });
      await shot(page, `${size}-03-read-retried`);
    });
  });
}
