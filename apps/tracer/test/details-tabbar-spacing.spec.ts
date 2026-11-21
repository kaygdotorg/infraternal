// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The details popover's tab bar sits with equal space above it and below it (#127, owner 2026-11-21: "tab bar needs to be
 * equidistant from the card's top border and the inner card's top border"). Measured on the production build at 1440x900 and
 * 393x852, Ink and Paper; the run also writes a screenshot of the popover named by `TAB_SHOTS_LABEL` (before or after).
 */
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
for (const [name, vp, touch] of [["desktop", { width: 1440, height: 900 }, false], ["phone", { width: 393, height: 852 }, true]] as const)
for (const theme of ["ink", "paper"]) test(`${name} ${theme}`, async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: vp, deviceScaleFactor: touch ? 3 : 2, hasTouch: touch, isMobile: touch, colorScheme: theme === "ink" ? "dark" : "light" });
  const page = await ctx.newPage();
  await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&bg=none&sessions=0`);
  await page.waitForSelector(".cl-mockup"); await page.waitForTimeout(1500);
  await page.locator(`.ui-window .ui-window-pill`).first().click();
  await page.waitForSelector(".canvas-popover"); await page.waitForTimeout(800);
  const m = await page.evaluate(() => {
    const r = (s: string) => document.querySelector(s)!.getBoundingClientRect();
    const p = r(".canvas-popover"), t = r(".canvas-popover-tabs .ui-tabs"), s = r(".canvas-popover-scroll"), h = r(".canvas-popover-head");
    return { popTop: p.top, headTop: h.top, headBottom: h.bottom, tabsTop: t.top, tabsBottom: t.bottom, scrollTop: s.top, tabs: document.querySelectorAll(".canvas-popover .ui-tab").length };
  });
  const above = m.tabsTop - m.headBottom, below = m.scrollTop - m.tabsBottom;
  if ((process.env.TAB_SHOTS_LABEL ?? "after") !== "before") expect(Math.abs(above - below), `above ${above}px, below ${below}px: ${JSON.stringify(m)}`).toBeLessThanOrEqual(0.5);
  console.log(name, theme, `above ${above} below ${below}`);
  const b = (await page.locator(".canvas-popover").boundingBox())!;
  await page.screenshot({ path: tracerEvidencePath("tabbar", process.env.TAB_SHOTS_LABEL ?? "after", `${name}-${theme}.png`), clip: { x: Math.max(0, b.x - 12), y: Math.max(0, b.y - 12), width: Math.min(vp.width, b.width + 24), height: Math.min(vp.height, b.height + 24) } });
});
