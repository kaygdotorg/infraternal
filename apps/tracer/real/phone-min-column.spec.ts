/**
 * Phone minimum column width (D309, #243), against the real server: a desktop browser sets a four-column layout with
 * two columns at the weight floor, and a phone browser of the same account reads it from the server.
 *
 * - The phone draws every column at least at the readable minimum and pans to each of them.
 * - The server-held layout is the same document before the phone looked at it, after it rendered it and after it panned
 *   through it: same weights and same revision, so the phone wrote nothing.
 * - The desktop still draws the columns at their weights, with no floor.
 *
 * `PHONE_MIN_TAG` names the screenshots (before/after the change); they go to the evidence directory.
 */
import { expect, test, type Page } from "playwright/test";
import { randomUUID } from "node:crypto";
import { tracerEvidencePath } from "../test/evidence-path";
import { cache, pair, request, settled, windows } from "./layout-devices";

test.setTimeout(240_000);
const tag = process.env.PHONE_MIN_TAG ?? "after";
/** Two floor-weight columns, as the report: "the floor-weight columns are about 39 px wide on a phone". */
const FLOOR = 0.1;
const minAt = (width: number): number => Math.min(355, width - 44);

const widths = (page: Page): Promise<number[]> => page.evaluate(() => [...document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .cl-col')].map((c) => Math.round(c.querySelector(".ui-window")!.getBoundingClientRect().width)));
const weights = async (page: Page) => {
  const doc = (await cache(page)).canonical;
  const view = doc.views.find((v) => v.id === "console")!;
  if (view.layout.type !== "tiled") throw Error("tiled");
  return { revision: doc.revision, weights: view.layout.columns.map((c) => c.weight), /** Every view cell too: a phone that pushed views apart must not save it. */ cells: doc.views.map((v) => [v.id, v.cell.x, v.cell.y]) };
};

test("phone: floor-weight columns are drawn at the minimum, and the saved layout never changes", async ({ browser }) => {
  const f = await pair(browser);
  try {
    for (let n = 1; n < 4; n++) { await f.page.keyboard.press("Control+Shift+D"); await expect(windows(f.page)).toHaveCount(n + 1); await settled(f.page); }
    const base = (await cache(f.page)).canonical;
    const view = base.views.find((v) => v.id === "console")!;
    if (view.layout.type !== "tiled") throw Error("tiled");
    expect(view.layout.columns.length, "four columns").toBe(4);
    let revision = base.revision;
    for (const column of view.layout.columns.slice(1, 3)) {
      expect((await request(f.server, f.desktop, "canvas.layout.apply", { op_id: randomUUID(), base_revision: revision, intent: { type: "weight", view_id: view.id, column_id: column.id, weight: FLOOR } })).ok).toBe(true);
      revision += 1;
    }
    await expect.poll(async () => (await weights(f.mobile)).weights.filter((w) => w === FLOOR).length, { timeout: 15_000 }).toBe(2);
    await settled(f.mobile); await settled(f.page);
    await f.mobile.waitForTimeout(900);
    const set = await weights(f.page);
    expect((await weights(f.mobile)), "the phone reads what the desktop set").toEqual(set);

    // The phone's drawing.
    const phone = await widths(f.mobile);
    await f.mobile.screenshot({ path: tracerEvidencePath(`${tag}-phone-393x852-first.png`) });
    // The `before` capture records the behaviour without the floor, so it skips this one check.
    if (tag !== "before") for (const w of phone) expect(w, `phone column ${phone.join(",")}`).toBeGreaterThanOrEqual(minAt(393) - 1);
    expect(await f.mobile.evaluate(() => document.documentElement.scrollWidth), "the page itself never scrolls sideways").toBeLessThanOrEqual(393);

    // Pan to every column and back, the way a person does with the canvas row.
    for (let i = 1; i < 4; i++) {
      await f.mobile.locator("[data-cv='next']").tap(); await f.mobile.waitForTimeout(900);
      await f.mobile.screenshot({ path: tracerEvidencePath(`${tag}-phone-393x852-step${i + 1}.png`) });
      const framed = await f.mobile.evaluate(() => { const mid = innerWidth / 2; const rs = [...document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .ui-window')].map((n) => n.getBoundingClientRect()); const r = rs.reduce((a, b) => (Math.abs((b.left + b.right) / 2 - mid) < Math.abs((a.left + a.right) / 2 - mid) ? b : a)); return { left: Math.round(r.left), right: Math.round(r.right) }; });
      expect(framed.left, "the framed column is inside the left edge").toBeGreaterThanOrEqual(-1);
      expect(framed.right, "the framed column is inside the right edge").toBeLessThanOrEqual(394);
    }
    for (let i = 0; i < 3; i++) { await f.mobile.locator("[data-cv='previous']").tap(); await f.mobile.waitForTimeout(500); }
    await f.mobile.waitForTimeout(800);
    await settled(f.mobile);
    expect(await weights(f.mobile), "after panning, the phone's copy of the saved layout is unchanged").toEqual(set);
    // The server's own copy, read by a client that is neither device.
    const server = await request(f.server, f.desktop, "", {}, true);
    const text = JSON.stringify(server.value);
    expect(text, "the server-held layout still has the floor weights and the same revision").toContain(`"revision":${set.revision}`);
    expect((await weights(f.page)), "the desktop's copy is unchanged too").toEqual(set);

    // 375x667: the smallest phone keeps the minimum too.
    await f.mobile.setViewportSize({ width: 375, height: 667 }); await f.mobile.waitForTimeout(900);
    await f.mobile.screenshot({ path: tracerEvidencePath(`${tag}-phone-375x667-first.png`) });
    if (tag !== "before") for (const w of await widths(f.mobile)) expect(w).toBeGreaterThanOrEqual(minAt(375) - 1);
    expect(await weights(f.mobile)).toEqual(set);

    // Desktop: no floor, the columns are their weights.
    const desktop = await widths(f.page);
    await f.page.screenshot({ path: tracerEvidencePath(`${tag}-desktop-1440x900.png`) });
    expect(desktop[1]!, "a weight-floor column stays narrow on the desktop").toBeLessThan(100);
    expect(desktop[2]).toBe(desktop[1]);
    expect(desktop[0]!, "the other columns keep their larger weights").toBeGreaterThan(desktop[1]! * 3);
    console.log(JSON.stringify({ tag, set, phone, desktop }));
  } finally { await f.dispose(); }
});
