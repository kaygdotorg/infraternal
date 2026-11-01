/**
 * The machine details card's destructive action is a row, not a button of centred prose (owner, 2026-11-01, #291 item 3).
 * On the windows prototype with `?removal=1` (the prototype has no host to remove, so the action does nothing) the row under
 * the facts must: be the shared settings row in its danger tone, put its label on the same left edge as the keys above it
 * and its hint on the label's edge, be at least the row height of the platform, and leave no `ui-button` in the card.
 * Alignment is measured to 0.5 px at the desktop and phone viewports.
 */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const sizes = [{ id: "desktop", width: 1440, height: 900, scale: 1, touch: false }, { id: "phone", width: 393, height: 852, scale: 3, touch: true }] as const;

async function openCard(page: Page, width: number, height: number): Promise<void> {
  await page.setViewportSize({ width, height });
  await page.context().request.post("/__mock/reset").catch(() => page.context().request.post("/__mock/reset"));
  await page.goto("/?mock=1&proto=windows&bg=none&fixture=none&removal=1");
  await expect.poll(() => page.evaluate(() => (window as unknown as { __tracerCanvas?: { windows(): string[] } }).__tracerCanvas?.windows().length ?? 0), { timeout: 30_000 }).toBeGreaterThan(2);
  await page.locator(".ui-window").first().locator(".ui-window-pill").click();
  await expect(page.locator(".canvas-popover")).toBeVisible();
}

for (const size of sizes) test(`details card ${size.id}: the destructive action is an aligned danger row`, async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.scale, hasTouch: size.touch, isMobile: size.touch });
  const page = await context.newPage();
  try {
    await openCard(page, size.width, size.height);
    await page.waitForTimeout(500); // the open animation
    const m = await page.evaluate(() => {
      const card = document.querySelector<HTMLElement>(".canvas-popover")!;
      const row = card.querySelector<HTMLElement>(".canvas-popover-action .ui-sp-row")!;
      const label = row.querySelector<HTMLElement>(".ui-sp-label")!, hint = row.querySelector<HTMLElement>(".ui-sp-hint")!;
      const key = card.querySelector<HTMLElement>(".ui-kv-key")!;
      const probe = document.createElement("span");
      probe.style.color = "var(--danger)";
      card.append(probe);
      const danger = getComputedStyle(probe).color;
      probe.remove();
      return {
        tone: row.dataset.tone, rowTag: row.tagName, rowHeight: row.getBoundingClientRect().height, buttons: card.querySelectorAll(".ui-button").length,
        keyLeft: key.getBoundingClientRect().left, labelLeft: label.getBoundingClientRect().left, hintLeft: hint.getBoundingClientRect().left,
        labelColor: getComputedStyle(label).color, danger, labelText: label.textContent, hintText: hint.textContent,
        hintBelow: hint.getBoundingClientRect().top >= label.getBoundingClientRect().bottom - 1,
        inside: card.getBoundingClientRect().bottom >= row.getBoundingClientRect().bottom && card.getBoundingClientRect().left <= row.getBoundingClientRect().left,
      };
    });
    expect(m.rowTag).toBe("BUTTON");
    expect(m.tone).toBe("danger");
    expect(m.buttons, "no centred button of prose remains").toBe(0);
    expect(m.labelText).toBe("Remove host");
    expect(m.hintText).toBe("Remove a host and uninstall its infraternal agent.");
    expect(m.labelColor, "the label wears the app's danger colour").toBe(m.danger);
    expect(Math.abs(m.labelLeft - m.keyLeft), "the label starts on the keys' left edge").toBeLessThanOrEqual(0.5);
    expect(Math.abs(m.hintLeft - m.labelLeft), "the hint starts on the label's left edge").toBeLessThanOrEqual(0.5);
    expect(m.hintBelow, "the hint sits under the label").toBe(true);
    expect(m.rowHeight, "the row is at least the platform's row height").toBeGreaterThanOrEqual(size.touch ? 44 : 28);
    expect(m.inside, "the row is inside the card").toBe(true);
    await page.locator(".canvas-popover").screenshot({ path: tracerEvidencePath("details-removal", `${size.id}.png`) });
  } finally { await context.close(); }
});
