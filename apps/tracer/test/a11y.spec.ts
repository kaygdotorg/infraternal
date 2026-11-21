// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Accessibility regressions (#558): axe-core finds no ARIA misuse and no unreachable scroll regions on the main screens.
 *
 * Each rule here was a real finding of the audit (`a11y-audit.spec.ts`) and was fixed, so it must stay at zero: a role the
 * element may not carry, an ARIA state on an element that has no role, a name on a span with no role, and a scrolling log
 * that the keyboard cannot reach. The wider sweep (contrast, names, touch size) stays in the on-request audit, because some of
 * its findings are open and tracked on the issue.
 */
import { expect, test, type Page } from "playwright/test";
import { runAxe } from "./a11y-axe";

/** The rules that are held at zero. */
const HELD = { rules: ["aria-allowed-attr", "aria-prohibited-attr", "aria-allowed-role", "scrollable-region-focusable"] };

/** Asserts that axe reports nothing for the held rules on the current page. */
async function expectClean(page: Page, what: string): Promise<void> {
  const violations = await runAxe(page, HELD);
  expect(violations, `${what}: ${JSON.stringify(violations.map((v) => [v.rule, v.nodes[0]?.html]))}`).toEqual([]);
}

/** Opens the canvas at `scene` and flies into the Console view. */
async function openCanvas(page: Page, scene: number): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=${scene}&theme=ink&bg=none`);
  await page.waitForFunction(() => (window as unknown as { __tracerClusters?: unknown }).__tracerClusters, null, { timeout: 30_000 });
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(v: string): void } }).__tracerClusters.flyView("console"));
  await expect(page.locator(".ui-window").first()).toBeVisible();
}

test("the canvas and the sidebar use ARIA the way it is defined", async ({ page }) => {
  await openCanvas(page, 1);
  await expectClean(page, "canvas");
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1);
  await expectClean(page, "sidebar");
});

test("the add-hosts wizard names its source marks with a role", async ({ page }) => {
  await openCanvas(page, 3);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
  await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible({ timeout: 45_000 });
  await expect(page.locator(".ah-src").first()).toHaveAttribute("role", "img");
  await expectClean(page, "add hosts");
});

test("the phone key bar is a group, not a landmark with a group role", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 393, height: 852 }, hasTouch: true, isMobile: true });
  const page = await context.newPage();
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/open-terminal");
  await page.goto("/?mock=1&bg=none");
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-connected", "true", { timeout: 30_000 });
  await expectClean(page, "terminal on a phone");
  await context.close();
});

test("sign-in is clean", async ({ page }) => {
  await page.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/session", (route) => route.fulfill({ status: 401, json: {} }));
  await page.goto("/");
  await expect(page.locator("#login-passkey")).toBeVisible();
  await expectClean(page, "sign-in");
});
