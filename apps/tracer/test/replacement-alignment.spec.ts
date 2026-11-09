/**
 * Replacements start where what they replace starts (TASTE "An icon and its text share one centre line", the owner's
 * "the 'end session' should start from where the other rows also start from, please pay attention UI detail. like alignment
 * is the most basic thing here", 2026-11-01, #242): when something takes the place of a row's words, its first letter is on
 * the x of the label it replaced, on the same centre line and in the same size.
 *
 * - The in-row question ("End session? End · Cancel"): its left edge is the row label's, and the neighbouring rows' labels';
 *   the status dot keeps its column and sits on the question's centre line; the answers are not clipped by the row.
 * - The rename field: the text's left edge is the label's.
 * Measured at 1440 x 900 DPR 2 and 393 x 852 DPR 3, tolerance 0.5 px.
 */
import { expect, test, type Page } from "playwright/test";

const ROW = "s:build-01/journal";
const NEIGHBOURS = ["s:build-01/deploy", "s:build-01/release"];
const URL = "/?mock=1&proto=clusters&scene=3&theme=ink&bg=none";

/** The first line's rect of an element's text. Runs in the page. */
const lineOf = (el: Element): { left: number; cy: number; size: number } => {
  const range = document.createRange();
  range.selectNodeContents(el);
  const r = [...range.getClientRects()].find((q) => q.width > 0.5)!;
  return { left: r.left, cy: r.top + r.height / 2, size: parseFloat(getComputedStyle(el).fontSize) };
};

async function open(page: Page, width: number, height: number): Promise<void> {
  await page.setViewportSize({ width, height });
  await page.goto(URL);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1); // the row actions load with the sidebar
  await expect(page.locator(`#tree [data-id="${ROW}"]`)).toBeVisible();
  await page.waitForTimeout(800);
}

/** Opens the row's menu the way this device does (right-click, or the touch long press's contextmenu). */
async function menuOf(page: Page, touch: boolean, item: string): Promise<void> {
  const row = page.locator(`#tree [data-id="${ROW}"]`);
  if (touch) { const b = (await row.boundingBox())!; await row.dispatchEvent("contextmenu", { clientX: b.x + 40, clientY: b.y + b.height / 2 }); } else await row.click({ button: "right" });
  await page.waitForTimeout(500);
  await page.locator(".ui-window-menu-item", { hasText: item }).click();
  await page.waitForTimeout(600);
}

for (const [size, viewport, scale, touch] of [["desktop 1440×900 at DPR 2", { width: 1440, height: 900 }, 2, false], ["phone 393×852 at DPR 3", { width: 393, height: 852 }, 3, true]] as const) {
  test.describe(size, () => {
    test.use({ viewport, deviceScaleFactor: scale, isMobile: touch, hasTouch: touch });
    test.setTimeout(60_000);

    test("the in-row question starts at the row label's x, on its centre line and in its size, with its dot in place and no clipping", async ({ page }) => {
      await open(page, viewport.width, viewport.height);
      await menuOf(page, touch, "End session");
      const m = await page.evaluate(([row, neighbours, fn]) => {
        const line = eval(`(${fn})`) as (el: Element) => { left: number; cy: number; size: number };
        const leaf = (id: string) => document.querySelector(`#tree [data-id="${id}"]`) as HTMLElement;
        const label = (id: string) => leaf(id).querySelector(".bm-label")!;
        const dot = (id: string) => leaf(id).querySelector(".glyph")!.getBoundingClientRect();
        const ask = document.querySelector(".ui-row-ask")!;
        const q = ask.querySelector(".ui-row-ask-q")!;
        const rowBox = ask.parentElement!.getBoundingClientRect();
        const cancel = ask.querySelector(".ui-row-ask-no")!.getBoundingClientRect();
        const own = line(label(row as string)), asked = line(q);
        const dotBox = dot(row as string);
        return {
          text: q.textContent, own, asked,
          neighbours: (neighbours as string[]).map((id) => ({ label: line(label(id)), dotLeft: dot(id).left })),
          dotLeft: dotBox.left, dotCy: dotBox.top + dotBox.height / 2,
          dotShown: getComputedStyle(leaf(row as string).querySelector(".glyph")!).opacity,
          labelShown: getComputedStyle(label(row as string)).opacity,
          cancelRight: cancel.right, rowRight: rowBox.right,
        };
      }, [ROW, NEIGHBOURS, lineOf.toString()] as const);
      // The whole question, never cut down to a stub, starting on the label's x.
      // The whole question when the row has room (a phone's); "End?" when it has not (the desktop sidebar is 218 px wide): never cut.
      expect(touch ? ["End session?"] : ["End session?", "End?"]).toContain(m.text);
      expect(Math.abs(m.asked.left - m.own.left), "the question's left edge against its own row's label").toBeLessThanOrEqual(0.5);
      for (const n of m.neighbours) expect(Math.abs(m.asked.left - n.label.left), "against the other rows' labels").toBeLessThanOrEqual(0.5);
      expect(Math.abs(m.asked.cy - m.own.cy), "the same centre line").toBeLessThanOrEqual(0.5);
      expect(m.asked.size, "the same text size").toBe(m.own.size);
      // The dot keeps its column (the other rows' dots are on the same x) and the words fade, not the dot.
      for (const n of m.neighbours) expect(Math.abs(m.dotLeft - n.dotLeft), "the dot's column").toBeLessThanOrEqual(0.5);
      expect(m.dotShown).toBe("1");
      expect(m.labelShown).toBe("0");
      expect(Math.abs(m.dotCy - m.asked.cy), "the dot and the question on one centre line").toBeLessThanOrEqual(1);
      // The answers follow on the same line and the row does not clip them.
      expect(m.cancelRight, "Cancel inside the row").toBeLessThanOrEqual(m.rowRight + 0.5);
      await page.keyboard.press("Escape");
    });

    test("the rename field's text starts where the row's label starts", async ({ page }) => {
      await open(page, viewport.width, viewport.height);
      const before = await page.evaluate(([row, fn]) => { const line = eval(`(${fn})`) as (el: Element) => { left: number; size: number }; return line(document.querySelector(`#tree [data-id="${row}"] .bm-label`)!); }, [ROW, lineOf.toString()] as const);
      await menuOf(page, touch, "Rename");
      const field = await page.evaluate(() => { const i = document.querySelector(".ui-inline-rename") as HTMLInputElement; const r = i.getBoundingClientRect(), cs = getComputedStyle(i); return { textLeft: r.left + parseFloat(cs.paddingLeft) + parseFloat(cs.borderLeftWidth), size: parseFloat(cs.fontSize) }; });
      expect(Math.abs(field.textLeft - before.left), "rename text against the label").toBeLessThanOrEqual(0.5);
      // A touch field stays 16 px (iOS zooms into smaller ones, --text-input), above the 13 px label it replaces: on desktop the field matches the label exactly.
      expect(field.size).toBe(touch ? 16 : before.size);
      await page.keyboard.press("Escape");
    });
  });
}
