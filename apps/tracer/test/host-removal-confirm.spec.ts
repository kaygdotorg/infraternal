/**
 * The host-removal confirmation belongs to what it acts on (TASTE: "A confirmation belongs to what it acts on"; owner,
 * 2026-11-06: "wtf?" and "it's just that the removal design is really bad!", #391).
 *
 * On the clusters prototype (scene 1) with `?removal=1`, another host's window is focused and "Remove host: <other>" is started
 * from the palette. The confirmation must: not sit on the focused window's pill (it is centred), word its two buttons
 * as short verbs side by side with a real cancel button, keep both inside the popover box at desktop and phone widths,
 * and use enough blur that no text behind it is readable. The probe works on the product's own wording through the
 * shared `confirmHostRemoval`, which the test double uses too.
 */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const sizes = [{ id: "desktop", width: 1440, height: 900 }, { id: "phone", width: 393, height: 852 }, { id: "small-phone", width: 375, height: 667 }] as const;
const themes = ["ink", "paper"] as const;

async function startRemovalFromPalette(page: Page, theme: string, dense: boolean): Promise<{ focusedPill: string; removed: string }> {
  await page.context().request.post("/__mock/reset").catch(() => undefined);
  await page.goto(`/?mock=1&proto=clusters&scene=1&bg=none&removal=1&theme=${theme}`);
  await expect(page.locator(".ui-window").nth(1)).toBeVisible({ timeout: 30_000 });
  // The dense variant first focuses a terminal window, so the question is read over a full screen of text.
  if (dense) {
    await page.keyboard.press("Control+Shift+K");
    await expect(page.locator("#palette-input")).toBeFocused();
    await page.locator("#palette-input").fill("Console");
    await page.locator('.palette .result[data-action^="canvas:view"]').first().click();
    // sleep: the camera flight into the Console view must land before the palette opens again
    await page.waitForTimeout(1500);
  }
  const focusedPill = (await page.locator(".ui-window").first().locator(".ui-window-pill").innerText()).toLowerCase();
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette-input")).toBeFocused();
  await page.locator("#palette-input").fill("Remove host");
  const rows = page.locator(".palette .result");
  await expect(rows.first()).toBeVisible();
  const labels = await rows.allInnerTexts();
  const other = labels.map((text) => /Remove host:\s*([^\s\n]+)/.exec(text)?.[1]).find((name) => name && !focusedPill.includes(name.toLowerCase()));
  expect(other, "a host other than the focused window's is offered").toBeTruthy();
  await page.locator("#palette-input").fill(`Remove host: ${other}`);
  await page.keyboard.press("Enter");
  return { focusedPill, removed: other! };
}

for (const dense of [false, true]) for (const size of sizes) for (const theme of themes) test(`removal from the palette ${size.id} ${theme}${dense ? " over a dense terminal" : ""}: centred, short buttons, opaque enough`, async ({ page }) => {
  await page.setViewportSize({ width: size.width, height: size.height });
  const { removed } = await startRemovalFromPalette(page, theme, dense);
  const tip = page.locator(".ui-confirm-tip");
  await expect(tip).toBeVisible();
  await expect(tip).toHaveAttribute("data-open", "true");
  // sleep: the open animation (scale 0.96 to 1) must finish before boxes are measured
  await page.waitForTimeout(400);
  const m = await page.evaluate(() => {
    const tip = document.querySelector<HTMLElement>(".ui-confirm-tip")!;
    const box = tip.getBoundingClientRect();
    const yes = tip.querySelector<HTMLElement>(".ui-confirm-yes")!, no = tip.querySelector<HTMLElement>(".ui-confirm-no")!;
    const yb = yes.getBoundingClientRect(), nb = no.getBoundingClientRect();
    const pill = document.querySelector<HTMLElement>(".ui-window .ui-window-pill")!.getBoundingClientRect();
    const blur = /blur\(([\d.]+)px\)/.exec(getComputedStyle(tip).backdropFilter)?.[1];
    const spans = [yes, no].map((button) => { const s = button.querySelector<HTMLElement>("span")!; return { text: s.textContent, scroll: s.scrollWidth, client: s.clientWidth }; });
    return {
      side: tip.dataset.side, box: { l: box.left, r: box.right, t: box.top, b: box.bottom, cx: box.left + box.width / 2, cy: box.top + box.height / 2 },
      yes: { l: yb.left, r: yb.right, t: yb.top, b: yb.bottom, text: yes.textContent }, no: { l: nb.left, r: nb.right, t: nb.top, b: nb.bottom, text: no.textContent },
      pill: { l: pill.left, r: pill.right, t: pill.top, b: pill.bottom }, blur: blur ? Number(blur) : 0, backdrop: getComputedStyle(tip).backdropFilter,
      spans, vw: innerWidth, vh: innerHeight, title: tip.querySelector(".ui-confirm-tip-message")!.textContent,
    };
  });
  expect(m.side, "started from the palette: centred, no tail").toBe("center");
  expect(Math.abs(m.box.cx - m.vw / 2), "centred horizontally").toBeLessThanOrEqual(1);
  expect(Math.abs(m.box.cy - m.vh / 2), "centred vertically").toBeLessThanOrEqual(1);
  const overlapsPill = m.box.l < m.pill.r && m.box.r > m.pill.l && m.box.t < m.pill.b && m.box.b > m.pill.t;
  const touchesPill = Math.abs((m.box.l + m.box.r) / 2 - (m.pill.l + m.pill.r) / 2) < 2 && Math.abs(m.box.t - m.pill.b) < 24;
  expect(touchesPill, "not hung on the focused window's pill").toBe(false);
  expect(overlapsPill && size.width >= 1000 ? "overlap" : "clear", "clear of the focused window's pill on desktop").toBe("clear");
  expect(m.title).toBe(`Remove ${removed}?`);
  expect(m.yes.text).toBe(`Remove ${removed}`);
  expect(m.yes.text!.length, "a verb, never a sentence").toBeLessThanOrEqual(28);
  expect(m.no.text).toBe("Keep");
  expect(m.no.r, "cancel sits beside confirm").toBeLessThanOrEqual(m.yes.l + 1);
  expect(Math.abs((m.no.t + m.no.b) / 2 - (m.yes.t + m.yes.b) / 2), "same centre line").toBeLessThanOrEqual(0.5);
  for (const b of [m.yes, m.no]) {
    expect(b.l, "button inside the popover, left").toBeGreaterThanOrEqual(m.box.l);
    expect(b.r, "button inside the popover, right").toBeLessThanOrEqual(m.box.r + 0.5);
    expect(b.b, "button inside the popover, bottom").toBeLessThanOrEqual(m.box.b);
  }
  for (const s of m.spans) expect(s.scroll, `${s.text} is not clipped`).toBeLessThanOrEqual(s.client + 1);
  expect(m.box.l, "inside the viewport").toBeGreaterThanOrEqual(0);
  expect(m.box.r).toBeLessThanOrEqual(m.vw);
  expect(m.blur, `blur hides text behind (backdrop-filter: ${m.backdrop})`).toBeGreaterThanOrEqual(28);
  await page.screenshot({ path: tracerEvidencePath("removal-confirm", `${size.id}-${theme}${dense ? "-dense" : ""}.png`) });
});
