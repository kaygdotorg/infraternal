/**
 * Remove host in the machine card (D385, #486): it sits at the end of the Connection tab only, never on the Machine tab, and
 * it is inline. On the windows prototype with `?removal=1` (the prototype has no host to remove, so confirming does nothing) the
 * block must: be the shared settings row in its danger tone with the label on the keys' left edge and the hint (one sentence,
 * never the label again) on the label's edge, be at least the platform's row height, leave no `ui-button` until it asks, and
 * then turn into the question inside the panel (no floating confirmation card) with Keep and a red Remove; Keep and Escape put the
 * row back. Alignment is measured to 0.5 px at the desktop and phone viewports.
 */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const sizes = [{ id: "desktop", width: 1440, height: 900, scale: 1, touch: false }, { id: "phone", width: 393, height: 852, scale: 3, touch: true }] as const;

/** Opens the first window's machine card on the windows prototype and switches to the Connection tab, where Remove host sits. */
async function openCard(page: Page, width: number, height: number): Promise<void> {
  await page.setViewportSize({ width, height });
  await page.context().request.post("/__mock/reset").catch(() => page.context().request.post("/__mock/reset"));
  await page.goto("/?mock=1&proto=windows&bg=none&fixture=none&removal=1");
  await expect.poll(() => page.evaluate(() => (window as unknown as { __tracerCanvas?: { windows(): string[] } }).__tracerCanvas?.windows().length ?? 0), { timeout: 30_000 }).toBeGreaterThan(2);
  await page.locator(".ui-window").first().locator(".ui-window-pill").click();
  await expect(page.locator(".canvas-popover")).toBeVisible();
  await expect(page.locator(".canvas-popover .ui-tab")).toHaveText(["Machine", "Connection"]);
  await expect(page.locator(".canvas-popover-action"), "nothing to remove on the Machine tab").toBeHidden();
  await page.locator(".canvas-popover .ui-tab", { hasText: "Connection" }).click();
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
      row.scrollIntoView({ block: "end" }); // it sits at the end of the scrolling list
      const label = row.querySelector<HTMLElement>(".ui-sp-label")!, hint = row.querySelector<HTMLElement>(".ui-sp-hint")!;
      const key = card.querySelector<HTMLElement>(".ui-kv-key")!;
      const probe = document.createElement("span");
      probe.style.color = "var(--danger)";
      card.append(probe);
      const danger = getComputedStyle(probe).color;
      probe.remove();
      return {
        tone: row.dataset.tone, rowTag: row.tagName, rowHeight: row.getBoundingClientRect().height, buttons: [...card.querySelectorAll<HTMLElement>(".ui-button")].filter((b) => b.offsetParent !== null).length, // the question's buttons exist but stay hidden until it asks
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
    expect(m.hintText).toBe("Revokes its access, then uninstalls the infraternal agent from it.");
    expect(m.hintText, "the hint is not the label again").not.toBe(m.labelText);
    expect(m.labelColor, "the label wears the app's danger colour").toBe(m.danger);
    expect(Math.abs(m.labelLeft - m.keyLeft), "the label starts on the keys' left edge").toBeLessThanOrEqual(0.5);
    expect(Math.abs(m.hintLeft - m.labelLeft), "the hint starts on the label's left edge").toBeLessThanOrEqual(0.5);
    expect(m.hintBelow, "the hint sits under the label").toBe(true);
    expect(m.rowHeight, "the row is at least the platform's row height").toBeGreaterThanOrEqual(size.touch ? 44 : 28);
    expect(m.inside, "the row is inside the card").toBe(true);
    await page.locator(".canvas-popover").screenshot({ path: tracerEvidencePath("details-removal", `${size.id}.png`) });
    // Pressing it asks inside the panel: no floating card, Keep and a red Remove, the same sentence; Keep and Escape restore the row.
    await page.locator(".canvas-popover-action .ui-sp-row").click();
    const ask = page.locator(".canvas-popover-ask");
    await expect(ask).toBeVisible();
    await expect(page.locator(".ui-confirm-tip")).toHaveCount(0);
    await expect(ask.locator("[data-keep]")).toHaveText("Keep");
    await expect(ask.locator("[data-yes]")).toHaveText("Remove");
    await expect(ask.locator(".canvas-popover-ask-effect")).toHaveText("Revokes its access, then uninstalls the infraternal agent from it.");
    await ask.locator("[data-keep]").click();
    await expect(page.locator(".canvas-popover-action .ui-sp-row")).toBeVisible();
    await page.locator(".canvas-popover-action .ui-sp-row").click();
    await page.keyboard.press("Escape");
    await expect(page.locator(".canvas-popover-action .ui-sp-row")).toBeVisible();
    await expect(page.locator(".canvas-popover")).toBeVisible();
  } finally { await context.close(); }
});
