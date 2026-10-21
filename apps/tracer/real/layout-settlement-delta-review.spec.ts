/** Checks incoming settlement away from the current view and removal of every shared view (#243, D178, D248). */
import { devices, expect, test } from "playwright/test";
import { writeFile } from "node:fs/promises";
import { cache, enrol, request, settled } from "./layout-devices";
import { startRealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";

for (const profile of [
  { name: "desktop", options: { viewport: { width: 1440, height: 900 } } },
  { name: "phone", options: { ...devices["iPhone 15"], viewport: { width: 393, height: 852 } } },
]) test(`incoming Console and Mesh settle while this device is viewing Settings (${profile.name})`, async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4493) });
  const context = await browser.newContext({ ...profile.options, ignoreHTTPSErrors: true });
  const errors: string[] = [];
  try {
    const page = await context.newPage(); page.on("pageerror", (error) => errors.push(error.message)); await enrol(page, server);
    await expect.poll(async () => (await cache(page)).canonical.views.some((v) => v.id === "mesh")).toBe(true);
    await page.locator("#capsule").click();
    await page.locator('.cl-viewrow[data-view="settings"]').click();
    await expect(page.locator("#capsule-host")).toHaveText("Settings");
    for (const id of ["console", "mesh"]) {
      expect((await request(server, context, "canvas.layout.apply", {
        op_id: `move-${id}`, base_revision: (await cache(page)).canonical.revision,
        intent: { type: "view.update", view_id: id, cell: { x: 20, y: 20 } },
      })).ok).toBe(true);
      await expect.poll(async () => (await cache(page)).canonical.views.find((v) => v.id === id)?.cell).toEqual({ x: 20, y: 20 });
    }
    await settled(page);
    const measure = () => page.evaluate(async () => {
      await document.fonts.ready;
      for (let i = 0; i < 60; i++) await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      const rect = (id: string) => {
        const r = document.querySelector(`.cl[data-view="${id}"] ${id === "mesh" ? ".cl-content" : ".ui-window"}`)!.getBoundingClientRect();
        return { x: r.x, y: r.y, right: r.right, bottom: r.bottom, width: r.width, height: r.height };
      };
      const a = rect("console"), b = rect("mesh");
      return { a, b, overlap: a.x < b.right && b.x < a.right && a.y < b.bottom && b.y < a.bottom };
    });
    const geometry = await measure();
    await writeFile(tracerEvidencePath(`delta-disconnected-${profile.name}-geometry.json`), JSON.stringify(geometry, null, 2));
    // Save the current viewport and raw off-screen geometry before changing the camera.
    await page.screenshot({ path: tracerEvidencePath(`delta-disconnected-${profile.name}-viewport.png`) });
    expect((await cache(page)).canonical.views.filter((v) => ["console", "mesh"].includes(v.id)).map((v) => v.cell)).toEqual([{ x: 20, y: 20 }, { x: 20, y: 20 }]);
    expect(geometry.a.width).toBeGreaterThan(0);
    // Navigating after the incoming layout has settled exposes the same resting overlap on screen.
    await page.locator("#capsule").click();
    await page.locator('.cl-viewrow[data-view="console"]').click();
    await expect(page.locator("#capsule-host")).toHaveText("Console");
    await page.evaluate(async () => { for (let i = 0; i < 60; i++) await new Promise<void>((resolve) => requestAnimationFrame(() => resolve())); });
    await page.screenshot({ path: tracerEvidencePath(`delta-disconnected-${profile.name}-console.png`) });
    const visible = await measure();
    const again = await measure();
    await writeFile(tracerEvidencePath(`delta-disconnected-${profile.name}-geometry.json`), JSON.stringify({ before: geometry, visible, again, errors }, null, 2));
    expect(errors).toEqual([]);
    expect(again, "two resting geometry samples are identical").toEqual(visible);
    expect(visible.overlap, "incoming display settlement must visit overlaps beyond the current anchor's connected component").toBe(false);
  } finally { await context.close(); await server.dispose(); }
});

test("removing every shared view leaves generated Settings and allows a later shared view", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4493) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  const errors: string[] = [];
  try {
    const page = await context.newPage(); page.on("pageerror", (error) => errors.push(error.message));
    await enrol(page, server);
    // Enrollment can finish before the asynchronous Mesh offer has entered the shared layout.
    await expect.poll(async () => (await cache(page)).canonical.views.some((v) => v.id === "mesh")).toBe(true);
    await settled(page);
    for (const view of (await cache(page)).canonical.views) {
      expect((await request(server, context, "canvas.layout.apply", {
        op_id: `remove-${view.id}`, base_revision: (await cache(page)).canonical.revision,
        intent: { type: "view.remove", view_id: view.id },
      })).ok).toBe(true);
    }
    await expect.poll(async () => (await cache(page)).canonical.views.length).toBe(0);
    await expect(page.locator(".cl")).toHaveCount(1);
    await expect(page.locator('.cl[data-view="settings"]')).toHaveCount(1);
    await settled(page);
    expect((await request(server, context, "canvas.layout.apply", {
      op_id: "restore-console", base_revision: (await cache(page)).canonical.revision,
      intent: { type: "view.add", view: { id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } } },
    })).ok).toBe(true);
    await expect(page.locator('.cl[data-view="console"]')).toHaveCount(1);
    expect(errors).toEqual([]);
  } finally { await context.close(); await server.dispose(); }
});
