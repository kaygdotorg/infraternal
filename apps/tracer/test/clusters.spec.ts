/**
 * Clusters concept mockup (`?proto=clusters`, issue #89): walks the six scenes and checks the
 * behaviours the owner's open questions are about. Everything runs against the test double.
 */
import { expect, test, type Page } from "playwright/test";

type Probe = {
  scene(): number;
  camera(): { cx: number; cy: number; z: number; lod: string; zoomBand: string };
  views(): Array<{ id: string; x: number; y: number; w: number; h: number; windows: string[] }>;
  grants(): Array<{ id: string; from: string; to: string }>;
  reachFor(): string | undefined;
  reachCount(): number;
  float(): { cols: number; rows: number; width: number; height: number } | undefined;
};
const probe = <T>(page: Page, fn: (p: Probe) => T): Promise<T> =>
  page.evaluate((source) => (new Function("p", `return (${source})(p)`) as (p: unknown) => T)((window as unknown as { __tracerClusters: unknown }).__tracerClusters), fn.toString());

async function open(page: Page, scene: number, query = ""): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`/?mock=1&proto=clusters&scene=${scene}&theme=ink&bg=none${query}`);
  await expect(page.locator(".cl-stepper")).toBeVisible({ timeout: 20_000 });
  await expect.poll(() => probe(page, (p) => p.views().length)).toBeGreaterThan(0);
  // Let the camera come to rest before measuring.
  await page.waitForTimeout(500);
}

const overlap = (a: { x: number; y: number; w: number; h: number }, b: { x: number; y: number; w: number; h: number }): boolean =>
  a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

test("the stepper walks all six scenes without a page error", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await open(page, 1);
  await expect(page.locator(".cl-stepper-tag")).toHaveText(/mockup/i);
  for (let scene = 1; scene <= 6; scene++) {
    await expect.poll(() => probe(page, (p) => p.scene())).toBe(scene);
    await expect(page.locator(".cl-stepper-count")).toHaveText(`${scene}/6`);
    if (scene < 6) await page.locator('.cl-stepper-btn[data-dir="1"]').click();
    await page.waitForTimeout(250);
  }
  expect(errors).toEqual([]);
});

test("overview: three views, thumbnails, a hover summary, and the views listed in the sidebar and the palette", async ({ page }) => {
  await open(page, 1);
  expect((await probe(page, (p) => p.views())).map((v) => v.id)).toEqual(["console", "containers", "topology"]);
  const camera = await probe(page, (p) => p.camera());
  expect(camera.z).toBeLessThan(0.6);
  expect(camera.lod).toBe("thumb");
  await page.locator('.cl[data-view="console"] .cl-label').hover();
  await expect(page.locator(".cl-summary[data-open='true']")).toContainText("build-01");
  await page.mouse.move(700, 880);
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator("#tree .bm-sec")).toHaveCount(3);
  await page.locator("#sidebar-toggle").click();
  await page.keyboard.press("Control+k");
  await page.keyboard.type("go to");
  await expect(page.locator(".palette-result, [role='option']").filter({ hasText: "Go to Topology" }).first()).toBeVisible();
  await page.keyboard.press("Escape");
});

test("fly in: a view click springs the camera in and the windows go live above 60 percent", async ({ page }) => {
  await open(page, 1);
  await page.locator('.cl[data-view="console"] .cl-label').click();
  await expect.poll(async () => (await probe(page, (p) => p.camera())).lod, { timeout: 4000 }).toBe("live");
  await expect.poll(async () => (await probe(page, (p) => p.camera())).z, { timeout: 4000 }).toBeGreaterThan(0.9);
  // Control+2 is the same camera spring to the second view.
  await page.keyboard.press("Control+2");
  await expect.poll(async () => { const c = await probe(page, (p) => p.camera()); const v = (await probe(page, (p) => p.views())).find((x) => x.id === "containers")!; return Math.abs(c.cy - (v.y + v.h / 2)) < 300; }, { timeout: 4000 }).toBe(true);
});

test("arrows on demand: none by default, hover shows reach, a drag asks and then adds the grant to Topology", async ({ page }) => {
  await open(page, 3);
  expect(await probe(page, (p) => p.reachCount())).toBe(0);
  const pill = page.locator('.ui-window[data-window-id="w-build-01"] .ui-window-pill');
  await pill.hover();
  await expect.poll(() => probe(page, (p) => p.reachCount())).toBeGreaterThan(1);
  const before = (await probe(page, (p) => p.grants())).length;
  const port = (await page.locator('.ui-window[data-window-id="w-build-01"] .cl-port').boundingBox())!;
  const target = (await page.locator('.ui-window[data-window-id="w-studio-mac"] .ui-window-body').boundingBox())!;
  await page.mouse.move(port.x + 12, port.y + 12);
  await page.mouse.down();
  await page.mouse.move(target.x + 200, target.y + 200, { steps: 12 });
  await expect(page.locator('.ui-window[data-window-id="w-studio-mac"][data-drop]')).toHaveCount(1);
  await page.mouse.up();
  await expect(page.locator(".ui-confirm-tip")).toContainText("Let build-01 reach studio-mac?");
  await page.locator(".ui-confirm-yes").click();
  await expect.poll(async () => (await probe(page, (p) => p.grants())).length).toBe(before + 1);
  await expect(page.locator('.cl[data-view="topology"] .cl-arrow')).toHaveCount(before + 1);
});

test("a window kind decides its controls, and a terminal splits", async ({ page }) => {
  await open(page, 4);
  await expect(page.locator('.ui-window[data-window-id="w-containers"] [data-action="split"]')).toHaveCount(0);
  await expect(page.locator('.ui-window[data-window-id="w-logs"] [data-action="split"]')).toHaveCount(0);
  await page.locator('.cl-row[data-name="web-api"]').click();
  await expect(page.locator(".cl-float")).toBeVisible();
  await page.locator('.cl-float [data-action="close"]').click();
  await expect(page.locator(".cl-badge[data-open='true']")).toContainText("session in Console");
  await open(page, 3);
  const before = await page.locator('.cl[data-view="console"] .ui-window').count();
  await page.locator('.ui-window[data-window-id="w-studio-mac"] [data-action="split"]').click();
  await expect(page.locator('.cl[data-view="console"] .ui-window')).toHaveCount(before + 1);
});

test("container shell: the camera stays, the pill morphs into a floating terminal that resizes with its aspect locked and expands into Console", async ({ page }) => {
  await open(page, 4);
  const cam0 = await probe(page, (p) => p.camera());
  await page.locator('.cl-row[data-name="web-api"]').click();
  await expect(page.locator(".cl-float")).toBeVisible();
  await page.waitForTimeout(700);
  // The session already exists in Console.
  expect((await probe(page, (p) => p.views())).find((v) => v.id === "console")!.windows).toContain("w-shell-web-api");
  expect(await probe(page, (p) => p.camera())).toMatchObject({ cx: cam0.cx, cy: cam0.cy });
  const box0 = (await page.locator(".cl-float").boundingBox())!;
  const aspect0 = box0.width / box0.height;
  // Drag the east edge: the width changes by twice the travel and the aspect holds.
  await page.mouse.move(box0.x + box0.width - 2, box0.y + 120);
  await page.mouse.down();
  await page.mouse.move(box0.x + box0.width + 40, box0.y + 120, { steps: 6 });
  const mid = (await page.locator(".cl-float").boundingBox())!;
  expect(mid.width).toBeGreaterThan(box0.width + 60);
  expect(mid.width / mid.height).toBeCloseTo(aspect0, 1);
  // It stays centred on the pill.
  expect(Math.abs(mid.x + mid.width / 2 - 720)).toBeLessThan(2);
  await page.mouse.up();
  await expect.poll(async () => (await probe(page, (p) => p.float()))!.cols, { timeout: 4000 }).toBeGreaterThan(48);
  await page.locator('.cl-float [data-action="expand"]').click();
  await expect(page.locator(".cl-float")).toHaveCount(0, { timeout: 4000 });
  await expect.poll(async () => (await probe(page, (p) => p.camera())).z, { timeout: 4000 }).toBeCloseTo(1, 1);
  await expect(page.locator('.ui-window[data-window-id="w-shell-web-api"]')).toBeVisible();
});

test("the palette opens a shell by name from anywhere: in Console the camera flies to it", async ({ page }) => {
  await open(page, 2);
  await expect.poll(async () => (await probe(page, (p) => p.camera())).z, { timeout: 5000 }).toBeGreaterThan(0.9);
  await page.keyboard.press("Control+k");
  await page.keyboard.type("build");
  await expect(page.getByText("Open shell on build-01")).toBeVisible();
  await expect(page.getByText("arrives later").first()).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page.locator('.ui-window[data-window-id="w-build-01"]')).toBeVisible({ timeout: 4000 });
  expect((await probe(page, (p) => p.views())).find((v) => v.id === "console")!.windows).toContain("w-build-01");
});

test("the capsule lists the views with their shortcuts", async ({ page }) => {
  await open(page, 3);
  await page.locator("#capsule").click();
  await expect(page.locator(".cl-viewlist")).toContainText("Topology");
  await expect(page.locator(".cl-viewlist")).toContainText("Ctrl");
  await page.locator('.cl-viewrow[data-view="topology"]').click();
  await expect.poll(async () => (await probe(page, (p) => p.camera())).cx, { timeout: 4000 }).toBeGreaterThan(1500);
});

test("access by grants: a viewer sees only Console with two hosts; an operator sees all three views", async ({ page }) => {
  await open(page, 5);
  expect((await probe(page, (p) => p.views())).map((v) => v.id)).toEqual(["console"]);
  expect((await probe(page, (p) => p.views()))[0]!.windows).toHaveLength(2);
  await page.getByRole("tab", { name: "operator" }).click();
  await expect.poll(async () => (await probe(page, (p) => p.views())).length).toBe(3);
  await page.getByRole("tab", { name: "new user" }).click();
  await expect(page.locator(".cl-empty")).toContainText("No hosts yet");
});

test("structure: a dragged view snaps to the grid, pushes a neighbour aside and never overlaps", async ({ page }) => {
  await open(page, 6);
  const label = (await page.locator('.cl[data-view="containers"] .cl-label').boundingBox())!;
  await page.mouse.move(label.x + 40, label.y + 12);
  await page.mouse.down();
  await page.mouse.move(label.x + 60, label.y - 150, { steps: 6 });
  await page.mouse.move(label.x + 60, label.y - 330, { steps: 8 });
  await page.mouse.up();
  await page.waitForTimeout(1500);
  const views = await probe(page, (p) => p.views());
  for (const v of views) { expect(Math.abs(v.x / 120 - Math.round(v.x / 120))).toBeLessThan(0.02); expect(Math.abs(v.y / 120 - Math.round(v.y / 120))).toBeLessThan(0.02); }
  for (let i = 0; i < views.length; i++) for (let j = i + 1; j < views.length; j++) expect(overlap(views[i]!, views[j]!)).toBe(false);
});

test("structure: a window dragged by its pill lands in another column", async ({ page }) => {
  await open(page, 6);
  const pill = (await page.locator('.ui-window[data-window-id="w-edge-arm"] .ui-window-pill').boundingBox())!;
  const col1 = (await page.locator('.ui-window[data-window-id="w-build-01"]').boundingBox())!;
  await page.mouse.move(pill.x + 30, pill.y + 10);
  await page.mouse.down();
  await page.mouse.move(pill.x - 60, pill.y - 100, { steps: 6 });
  await page.mouse.move(col1.x + 150, col1.y + col1.height - 40, { steps: 8 });
  await expect(page.locator(".cl-slot")).toHaveCount(1);
  await page.mouse.up();
  await expect(page.locator(".cl-slot")).toHaveCount(0, { timeout: 4000 });
  const parent = await page.locator('.ui-window[data-window-id="w-edge-arm"]').evaluate((n) => n.parentElement?.querySelector('[data-window-id="w-build-01"]') !== null);
  expect(parent).toBe(true);
});
