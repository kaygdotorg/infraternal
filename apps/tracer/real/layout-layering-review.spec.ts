/** Verifies settled cross-view geometry on a production-shaped recovered account (#243, D119, D248). */
import { watchLayout } from "./layout-observer";
import { devices, expect, test } from "playwright/test";
import { spawnSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { cache, enrol, request, settled, windows } from "./layout-devices";
import { startRealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";
import { isMacPlatform } from "../../../packages/ui/src/platform";

test.setTimeout(180_000);
for (const profile of [
  { name: "desktop", options: { viewport: { width: 1440, height: 900 } } },
  { name: "phone", options: { ...devices["iPhone 15"], viewport: { width: 393, height: 852 } } },
]) test(`settled Console has no Mesh or Settings content over its windows (${profile.name})`, async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4387) });
  const context = await browser.newContext({ ...profile.options, ignoreHTTPSErrors: true });
  try {
    const page = watchLayout(await context.newPage());
    await enrol(page, server);
    const doc = structuredClone((await cache(page)).canonical);
    const consoleView = doc.views.find((view) => view.id === "console")!;
    if (consoleView.layout.type !== "tiled") throw Error("missing Console layout");
    const target = consoleView.layout.columns[0]!.windows[0]!.target;
    if (target.type !== "session") throw Error("missing session reference");
    const targets = [target];
    for (let i = 1; i < 44; i++) {
      const result = await request(server, context, "ssh.session.open", {});
      expect(result.ok).toBe(true);
      targets.push({ ...target, id: String(result.value.session_id) });
    }
    let at = 0;
    consoleView.layout.columns = Array.from({ length: 29 }, (_, col) => ({ id: `column-${col}`, weight: 1,
      windows: Array.from({ length: col < 15 ? 2 : 1 }, (_, row) => ({ id: `window-${col}-${row}`, target: structuredClone(targets[at++]!), height: col < 15 ? 0.5 : 1 })),
    }));
    doc.revision = 2;
    doc.views = [consoleView,
      { id: "mesh", kind: "mesh", name: "Mesh", cell: { x: 2, y: 0 }, layout: { type: "graph", pinned: {} } },
      { id: "recovered-mesh", kind: "mesh", name: "Recovered: Mesh", cell: { x: 0, y: 0 }, layout: { type: "graph", pinned: {} } },
    ];
    await server.restart(async () => {
      const result = spawnSync("python3", ["-c", `import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db:
 db.execute("UPDATE canvas_heads SET revision=2,document=?,initialized=1",(sys.argv[2],))
 db.execute("DELETE FROM canvas_operations")
 db.execute("DELETE FROM canvas_snapshots")
`, `${server.dataDir}/infraternal.sqlite`, JSON.stringify(doc)], { encoding: "utf8" });
      expect(result.status).toBe(0);
    });
    await page.reload();
    await expect(windows(page)).toHaveCount(44);
    // Graph drawing is lazy when its view is off screen on a phone; its content footprint still participates in settlement.
    if (profile.name === "desktop") await expect(page.locator('.cl[data-view="mesh"] .cl-graph-arrows')).toHaveCount(1);
    await expect.poll(async () => (await cache(page)).canonical.revision).toBeGreaterThan(2);
    await settled(page);
    // A complete frame sequence and stable DOM distinguish resting overlap from a transition capture.
    const measure = () => page.evaluate(async () => {
      await document.fonts.ready;
      for (let i = 0; i < 120; i++) await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      const consoleWindows = [...document.querySelectorAll('.cl[data-view="console"] .ui-window')].map((el) => el.getBoundingClientRect());
      return [...document.querySelectorAll('.cl[data-view="mesh"] .cl-content, .cl[data-view="settings"] .ui-window')].map((el) => {
        const r = el.getBoundingClientRect();
        return { view: el.closest<HTMLElement>(".cl")?.dataset.view, x: r.x, y: r.y, width: r.width, height: r.height,
          intersections: consoleWindows.filter((c) => r.x < c.right && c.x < r.right && r.y < c.bottom && c.y < r.bottom).length };
      });
    });
    const first = await measure();
    const second = await measure();
    await page.screenshot({ path: tracerEvidencePath(`layering-${profile.name}-settled.png`) });
    await writeFile(tracerEvidencePath(`layering-${profile.name}-geometry.json`), JSON.stringify({ first, second }, null, 2));
    // Also prove the cached cold-load path still submits an edit after reconciliation.
    const revision = (await cache(page)).canonical.revision;
    await windows(page).first().dispatchEvent("pointerdown", { button: 0 });
    await page.keyboard.press(await page.evaluate(isMacPlatform) ? "Meta+d" : "Control+Shift+D");
    await expect.poll(async () => (await cache(page)).canonical.revision).toBeGreaterThan(revision);
    await settled(page);
    expect(second, "foreign-view geometry has stopped changing").toEqual(first);
    expect(second.filter((entry) => entry.intersections > 0), "foreign view content remains over Console after two complete resting frame sequences").toEqual([]);
  } finally { await context.close(); await server.dispose(); }
});

test("removing the current shared view still reconciles the surviving views", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4387) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  const errors: string[] = [];
  try {
    const page = watchLayout(await context.newPage());
    page.on("pageerror", (error) => errors.push(error.message));
    await enrol(page, server);
    await expect.poll(async () => (await cache(page)).canonical.views.some((view) => view.id === "mesh")).toBe(true);
    const result = await request(server, context, "canvas.layout.apply", {
      op_id: "remove-current-view", base_revision: (await cache(page)).canonical.revision,
      intent: { type: "view.remove", view_id: "console" },
    });
    expect(result.ok).toBe(true);
    await expect(page.locator('.cl[data-view="console"]')).toHaveCount(0);
    await expect(page.locator('.cl[data-view="settings"]')).toHaveCount(1);
    await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => resolve())));
    expect(errors).toEqual([]);
  } finally { await context.close(); await server.dispose(); }
});
