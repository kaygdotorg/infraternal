/** Checks incoming settlement away from the current view and removal of every shared view (#243, D178, D248). */
import { watchLayout } from "./layout-observer";
import { devices, expect, test } from "playwright/test";
import { writeFile } from "node:fs/promises";
import { cache, enrol, request, settled } from "./layout-devices";
import { startRealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";

for (const profile of [
  { name: "desktop", options: { viewport: { width: 1440, height: 900 } } },
  { name: "phone", options: { ...devices["iPhone 15"], viewport: { width: 393, height: 852 } } },
]) test(`incoming settlement preserves Settings and Console anchors (${profile.name})`, async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4493) });
  const context = await browser.newContext({ ...profile.options, ignoreHTTPSErrors: true });
  const errors: string[] = [];
  try {
    const page = watchLayout(await context.newPage()); page.on("pageerror", (error) => errors.push(error.message)); await enrol(page, server);
    await expect.poll(async () => (await cache(page)).canonical.views.some((v) => v.id === "mesh")).toBe(true);
    await settled(page);
    await page.locator("#capsule").click();
    await page.locator('.cl-viewrow[data-view="settings"]').click();
    await expect(page.locator("#capsule-host")).toHaveText("Settings");
    const waitForRest = () => page.evaluate(async () => {
      for (let i = 0; i < 60; i++) await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    });
    const anchorSnapshot = (id: string) => page.evaluate((viewId) => {
      const view = document.querySelector<HTMLElement>(`.cl[data-view="${CSS.escape(viewId)}"]`);
      const world = document.querySelector<HTMLElement>(".cl-world");
      if (!view || !world) throw new Error(`missing canvas anchor ${viewId}`);
      const position = /^translate\(([-\d.]+)px,\s*([-\d.]+)px\)$/.exec(view.style.transform);
      if (!position) throw new Error(`unexpected canvas position ${view.style.transform}`);
      const rect = view.getBoundingClientRect();
      return {
        local: { x: Number(position[1]), y: Number(position[2]) },
        displayed: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
        camera: world.style.transform,
      };
    }, id);
    const stableAnchorSnapshot = async (id: string) => {
      await waitForRest();
      let previous = await anchorSnapshot(id);
      for (let sample = 0; sample < 8; sample++) {
        await waitForRest();
        const next = await anchorSnapshot(id);
        if (JSON.stringify(next) === JSON.stringify(previous)) return next;
        previous = next;
      }
      throw new Error(`${id} did not reach a stable canvas position`);
    };
    // One-cell offsets overlap the active view from each side; every independent server update exercises settlement.
    const checkIncomingAnchor = async (currentId: string): Promise<void> => {
      for (const side of ["west", "east", "north", "south"] as const) {
        const before = await stableAnchorSnapshot(currentId);
        const x = Math.round(before.local.x / 120), y = Math.round(before.local.y / 120);
        const cell = side === "west" ? { x: x - 1, y }
          : side === "east" ? { x: x + 1, y }
            : side === "north" ? { x, y: y - 1 } : { x, y: y + 1 };
        const id = `anchor-${currentId}-${side}`;
        const state = await cache(page);
        const response = await request(server, context, "canvas.layout.apply", {
          op_id: `incoming-${currentId}-${side}`, base_revision: state.canonical.revision,
          intent: { type: "view.add", view: { id, kind: "console", name: `Anchor ${side}`, cell, layout: { type: "tiled", columns: [] } } },
        });
        expect(response.ok, JSON.stringify(response.value)).toBe(true);
        await expect.poll(async () => (await cache(page)).canonical.views.some((view) => view.id === id)).toBe(true);
        await settled(page);
        const after = await stableAnchorSnapshot(currentId);
        await writeFile(tracerEvidencePath(`delta-anchor-${currentId}-${side}.json`), JSON.stringify({ before, after, cell }, null, 2));
        if (JSON.stringify(after) !== JSON.stringify(before)) await page.screenshot({ path: tracerEvidencePath(`delta-anchor-${currentId}-${side}-moved.png`) });
        expect(after.local, `${currentId} keeps the same local position after the ${side} view arrives`).toEqual(before.local);
        expect(after.displayed, `${currentId} stays at the same displayed position after the ${side} view arrives`).toEqual(before.displayed);
        expect(after.camera, `${currentId} keeps the same camera after the ${side} view arrives`).toBe(before.camera);
      }
      await page.screenshot({ path: tracerEvidencePath(`delta-anchor-${currentId}.png`) });
    };
    if (profile.name === "desktop") {
      const origin = await stableAnchorSnapshot("settings");
      const cellX = Math.round(origin.local.x / 120), cellY = Math.round(origin.local.y / 120);
      const incoming = [
        { id: "console", dx: -3, dy: -2 },
        { id: "mesh", dx: 21, dy: 8 },
        { id: "anchor-settings-a", dx: -8, dy: -8 },
        { id: "anchor-settings-b", dx: -7, dy: -11 },
        { id: "anchor-settings-c", dx: 2, dy: -11 },
        { id: "anchor-settings-d", dx: -2, dy: 0 },
        { id: "anchor-settings-e", dx: 0, dy: 16 },
        { id: "anchor-settings-f", dx: 23, dy: 20 },
      ];
      for (const [index, view] of incoming.entries()) {
        const before = await stableAnchorSnapshot("settings");
        const cell = { x: cellX + view.dx, y: cellY + view.dy };
        const state = await cache(page);
        const intent = view.id === "console" || view.id === "mesh"
          ? { type: "view.update", view_id: view.id, cell }
          : { type: "view.add", view: { id: view.id, kind: "console", name: `Anchor cluster ${index}`, cell, layout: { type: "tiled" as const, columns: [] } } };
        const response = await request(server, context, "canvas.layout.apply", {
          op_id: `settings-cluster-${index}`, base_revision: state.canonical.revision, intent,
        });
        expect(response.ok, JSON.stringify(response.value)).toBe(true);
        await expect.poll(async () => (await cache(page)).canonical.views.find((candidate) => candidate.id === view.id)?.cell).toEqual(cell);
        await settled(page);
        const after = await stableAnchorSnapshot("settings");
        await writeFile(tracerEvidencePath(`delta-anchor-settings-cluster-${index}.json`), JSON.stringify({ id: view.id, cell, before, after }, null, 2));
        if (JSON.stringify(after) !== JSON.stringify(before)) await page.screenshot({ path: tracerEvidencePath(`delta-anchor-settings-cluster-${index}-moved.png`) });
        expect(after.local, `Settings keeps its local position after ${view.id} arrives`).toEqual(before.local);
        expect(after.displayed, `Settings keeps its displayed position after ${view.id} arrives`).toEqual(before.displayed);
        expect(after.camera, `Settings keeps its camera after ${view.id} arrives`).toBe(before.camera);
      }
      await page.screenshot({ path: tracerEvidencePath("delta-anchor-settings-cluster.png") });
    }
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
    if (profile.name === "desktop") await checkIncomingAnchor("console");
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
    const page = watchLayout(await context.newPage()); page.on("pageerror", (error) => errors.push(error.message));
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
