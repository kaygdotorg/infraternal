/**
 * No stray tooltips (#141). A row's aria-label ("shell, open in another window") is for screen readers, not tooltip
 * text; tooltips appear only on real hover, long press or Tab focus, and go when their element is removed, is no
 * longer hovered, or the view changes.
 */
import { expect, test, type Page } from "playwright/test";

const tip = (page: Page): Promise<string | null> => page.evaluate(() => { const p = document.querySelector<HTMLElement>(".tip-pos"); return p && getComputedStyle(p).visibility === "visible" ? p.textContent : null; });

async function boot(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none&sessions=1");
  await expect(page.locator(".cl-sx-pop")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(800);
}

test("a session row never shows its aria-label as a tooltip", async ({ page }) => {
  await boot(page);
  const rows = page.locator(".cl-sx-pop .cl-sx-main");
  for (let i = 0; i < await rows.count(); i++) { await rows.nth(i).hover(); await page.waitForTimeout(650); expect(await tip(page), `row ${i}`).toBeNull(); }
});

test("a button with its own text is never a tooltip trigger, even while its text is not rendered", async ({ page }) => {
  await boot(page);
  await page.evaluate(() => {
    const b = document.createElement("button");
    b.setAttribute("aria-label", "shell, open in another window");
    b.id = "probe-row";
    b.style.cssText = "position:fixed;left:40px;top:300px;width:200px;height:40px;z-index:9999";
    b.innerHTML = '<span style="visibility:hidden">shell</span>';
    document.body.append(b);
  });
  await page.locator("#probe-row").hover();
  await page.waitForTimeout(700);
  expect(await tip(page)).toBeNull();
});

test("a hover tooltip goes when its element is removed or the view changes", async ({ page }) => {
  await boot(page);
  await page.evaluate(() => {
    const b = document.createElement("button");
    b.setAttribute("aria-label", "Probe tip");
    b.id = "probe-icon";
    b.style.cssText = "position:fixed;left:40px;top:300px;width:40px;height:40px;z-index:9999";
    b.innerHTML = '<svg viewBox="0 0 10 10" width="10" height="10"><circle cx="5" cy="5" r="4"/></svg>';
    document.body.append(b);
  });
  await page.locator("#probe-icon").hover();
  await expect.poll(() => tip(page)).toBe("Probe tip");
  await page.evaluate(() => document.getElementById("probe-icon")!.remove());
  await expect.poll(() => tip(page), { timeout: 1500 }).toBeNull();
  await page.evaluate(() => {
    const b = document.createElement("button");
    b.setAttribute("aria-label", "Probe tip two");
    b.id = "probe-icon2";
    b.style.cssText = "position:fixed;left:40px;top:300px;width:40px;height:40px;z-index:9999";
    b.innerHTML = '<svg viewBox="0 0 10 10" width="10" height="10"><circle cx="5" cy="5" r="4"/></svg>';
    document.body.append(b);
  });
  await page.mouse.move(60, 320);
  await page.locator("#probe-icon2").hover();
  await expect.poll(() => tip(page)).toBe("Probe tip two");
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("settings"));
  await expect.poll(() => tip(page), { timeout: 1500 }).toBeNull();
});
