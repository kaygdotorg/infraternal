/** A desktop's saved wide column fits on a phone without rewriting the shared layout (#497). */
import { randomUUID } from "node:crypto";
import { expect, test, type Page } from "playwright/test";
import { cache, pair, request, settled, windows } from "./layout-devices";
import { tracerEvidencePath } from "../test/evidence-path";

/** Waits for the focused window's camera to rest, then measures its actual screen edges. */
async function frame(page: Page): Promise<{ left: number; right: number; width: number }> {
  let previous = "";
  await expect.poll(async () => {
    const box = await windows(page).first().boundingBox();
    const next = JSON.stringify(box);
    const stable = Boolean(box) && next === previous;
    previous = next;
    return stable;
  }).toBe(true);
  const box = (await windows(page).first().boundingBox())!;
  return { left: box.x, right: box.x + box.width, width: box.width };
}

test("393 px phone contains a desktop's wide window through reload and rotation", async ({ browser }) => {
  const f = await pair(browser);
  try {
    const base = (await cache(f.page)).canonical;
    const consoleView = base.views.find((view) => view.id === "console")!;
    if (consoleView.layout.type !== "tiled") throw Error("expected tiled Console");
    const column = consoleView.layout.columns[0]!;
    const applied = await request(f.server, f.desktop, "canvas.layout.apply", {
      op_id: randomUUID(), base_revision: base.revision,
      intent: { type: "weight", view_id: "console", column_id: column.id, weight: 3 },
    });
    expect(applied.ok).toBe(true);
    await expect.poll(async () => (await cache(f.mobile)).canonical.revision).toBe(base.revision + 1);
    await settled(f.mobile);
    const saved = (await cache(f.mobile)).canonical;
    for (const width of [393, 375, 430, 393]) {
      await f.mobile.setViewportSize({ width, height: 852 });
      const geometry = await frame(f.mobile);
      await f.mobile.screenshot({ path: tracerEvidencePath(`j506-phone-${width}.png`) });
      console.log(JSON.stringify({ viewport: width, geometry, revision: saved.revision }));
      expect(geometry.left).toBeGreaterThanOrEqual(-1);
      expect(geometry.right).toBeLessThanOrEqual(width + 1);
      expect(geometry.width).toBeLessThanOrEqual(width + 1);
      expect((await cache(f.mobile)).canonical).toEqual(saved);
    }
    await f.mobile.reload();
    await settled(f.mobile);
    const restored = await frame(f.mobile);
    expect(restored.right).toBeLessThanOrEqual(394);
    expect((await cache(f.mobile)).canonical).toEqual(saved);
    // Header neighbours keep their shared centre line after the narrower fit.
    const alignment = await windows(f.mobile).first().evaluate((window) => {
      const title = window.querySelector<HTMLElement>(".ui-window-pill")?.getBoundingClientRect();
      const close = window.querySelector<HTMLElement>('[data-action="close"]')?.getBoundingClientRect();
      return title && close ? Math.abs(title.top + title.height / 2 - close.top - close.height / 2) : null;
    });
    expect(alignment).not.toBeNull();
    expect(alignment!).toBeLessThanOrEqual(0.5);
  } finally { await f.dispose(); }
});
