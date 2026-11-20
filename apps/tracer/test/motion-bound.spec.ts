// SPDX-License-Identifier: AGPL-3.0-only
/**
 * `motionSettled` (test/motion.ts) waits for the page's own motion to end and enforces the owner's motion rule on the way:
 * nothing the product animates runs longer than 300 ms (#442). A fast transition passes; a slow one fails the spec naming
 * the rule, instead of being waited out. Runs on a plain page, so it needs no product build beyond the test server.
 */
import { expect, test, type Page } from "playwright/test";
import { motionSettled } from "./motion";

/** A page with one box whose opacity eases over `ms` once the test changes it. */
async function boxWithTransition(page: Page, ms: number): Promise<void> {
  await page.setContent(`<div id="box" style="width:40px;height:40px;background:#888;opacity:1;transition:opacity ${ms}ms ease-out"></div>`);
  await page.evaluate(() => { const box = document.getElementById("box")!; void box.offsetWidth; box.style.opacity = "0.2"; });
}

test("a 150 ms transition settles and passes", async ({ page }) => {
  await boxWithTransition(page, 150);
  await motionSettled(page);
  expect(await page.evaluate(() => document.getAnimations().filter((a) => a.playState === "running").length)).toBe(0);
});

test("a 600 ms transition fails the spec and names the 300 ms rule", async ({ page }) => {
  await boxWithTransition(page, 600);
  await expect(motionSettled(page)).rejects.toThrow(/300 ms/);
});

test("an endless animation is not motion to wait for, and is not held to the bound", async ({ page }) => {
  await page.setContent(`<style>@keyframes blink { to { opacity: 0.3 } } #caret { animation: blink 1s infinite }</style><div id="caret">|</div>`);
  await motionSettled(page);
});
