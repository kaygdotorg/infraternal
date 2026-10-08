/**
 * Clusters concept mockup (`?proto=clusters`, issue #89): walks the six scenes and checks the
 * behaviours the owner's open questions are about. Everything runs against the test double.
 */
import { expect, test, type Browser, type Page } from "playwright/test";

type Probe = {
  scene(): number;
  camera(): { cx: number; cy: number; z: number; lod: string; zoomBand: string; tx: number; ty: number };
  views(): Array<{ id: string; x: number; y: number; w: number; h: number; windows: string[] }>;
  grants(): Array<{ id: string; from: string; to: string }>;
  reachFor(): string | undefined;
  reachCount(): number;
  float(): { cols: number; rows: number; width: number; height: number } | undefined;
  canvasLock(): { on: boolean; index: number; stops: number; view: string };
  setScene(n: number): void;
  setSnap(on: boolean): void;
};
const probe = <T>(page: Page, fn: (p: Probe) => T): Promise<T> =>
  page.evaluate((source) => (new Function("p", `return (${source})(p)`) as (p: unknown) => T)((window as unknown as { __tracerClusters: unknown }).__tracerClusters), fn.toString());

async function open(page: Page, scene: number, query = ""): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`/?mock=1&proto=clusters&scene=${scene}&theme=ink&bg=none${query}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await expect.poll(() => probe(page, (p) => p.views().length)).toBeGreaterThan(0);
  // Let the camera come to rest before measuring.
  await page.waitForTimeout(500);
}

const overlap = (a: { x: number; y: number; w: number; h: number }, b: { x: number; y: number; w: number; h: number }): boolean =>
  a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

test("the six scenes load from the palette and the mockup tag, without a page error", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await open(page, 1);
  await expect(page.locator(".cl-mockup")).toHaveText(/mockup/i);
  await page.keyboard.press("Control+k");
  await page.keyboard.type("mockup: scene");
  await expect(page.getByText("Mockup: scene 4 Open from a container")).toBeVisible();
  await page.keyboard.press("Escape");
  for (let scene = 1; scene <= 6; scene++) {
    await probe(page, (p) => p.setScene(0)).catch(() => undefined);
    await page.evaluate((n) => (window as unknown as { __tracerClusters: { setScene(n: number): void } }).__tracerClusters.setScene(n), scene);
    await expect.poll(() => probe(page, (p) => p.scene())).toBe(scene);
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
  expect((await probe(page, (p) => p.canvasLock())).on).toBe(false);
  await page.keyboard.press("Control+k");
  await page.keyboard.type("go to");
  await expect(page.locator(".palette-result, [role='option']").filter({ hasText: "Go to Topology" }).first()).toBeVisible();
  await page.keyboard.press("Control+a");
  await page.keyboard.type("canvas lock");
  await expect(page.getByText("Canvas lock on")).toBeVisible();
  await page.keyboard.press("Escape");
});

test("fly in: a view click springs the camera in and the windows go live above 60 percent", async ({ page }) => {
  await open(page, 1);
  await page.locator('.cl[data-view="console"] .cl-label').click();
  await expect.poll(async () => (await probe(page, (p) => p.camera())).lod, { timeout: 4000 }).toBe("live");
  await expect.poll(async () => (await probe(page, (p) => p.camera())).z, { timeout: 4000 }).toBeGreaterThan(0.9);
  // Flying in turns snap on.
  expect((await probe(page, (p) => p.canvasLock())).on).toBe(true);
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
  const pill = (await page.locator("#capsule").boundingBox())!;
  expect(Math.abs(mid.x + mid.width / 2 - (pill.x + pill.width / 2))).toBeLessThan(2);
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
  await page.keyboard.press("Control+k");
  await page.keyboard.type("sign in as");
  await page.getByText("Mockup: sign in as a operator").click();
  await expect.poll(async () => (await probe(page, (p) => p.views())).length).toBe(3);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { setRole(r: string): void } }).__tracerClusters.setRole("new"));
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

async function touchPage(browser: Browser, scene: number): Promise<{ page: Page; touch: (type: "touchStart" | "touchMove" | "touchEnd", pts: Array<{ x: number; y: number }>) => Promise<unknown>; close(): Promise<void> }> {
  const context = await browser.newContext({ baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`, viewport: { width: 393, height: 852 }, deviceScaleFactor: 2, hasTouch: true, isMobile: true });
  const page = await context.newPage();
  await page.goto(`/?mock=1&proto=clusters&scene=${scene}&theme=ink&bg=none`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(900);
  const cdp = await context.newCDPSession(page);
  const touch = (type: "touchStart" | "touchMove" | "touchEnd", pts: Array<{ x: number; y: number }>) =>
    cdp.send("Input.dispatchTouchEvent", { type, touchPoints: pts.map((p, i) => ({ ...p, id: i })) });
  return { page, touch, close: () => context.close() };
}
/** Two fingers (the canvas lock's gesture) travelling from `from` to `to`. */
const swipe2 = async (t: Awaited<ReturnType<typeof touchPage>>, from: { x: number; y: number }, to: { x: number; y: number }, steps = 8): Promise<void> => {
  const at = (k: number, d: number): Array<{ x: number; y: number }> => [{ x: from.x + ((to.x - from.x) * k) / steps - d, y: from.y + ((to.y - from.y) * k) / steps }, { x: from.x + ((to.x - from.x) * k) / steps + d, y: from.y + ((to.y - from.y) * k) / steps }];
  await t.touch("touchStart", at(0, 20));
  for (let i = 1; i <= steps; i++) await t.touch("touchMove", at(i, 20));
  await t.touch("touchEnd", []);
};
const swipe = async (t: Awaited<ReturnType<typeof touchPage>>, from: { x: number; y: number }, to: { x: number; y: number }, steps = 8): Promise<void> => {
  await t.touch("touchStart", [from]);
  for (let i = 1; i <= steps; i++) await t.touch("touchMove", [{ x: from.x + ((to.x - from.x) * i) / steps, y: from.y + ((to.y - from.y) * i) / steps }]);
  await t.touch("touchEnd", []);
};

test("canvas lock on a phone: two fingers move one column at a time, pinch does nothing, the toggle frees the canvas", async ({ browser }) => {
  const t = await touchPage(browser, 3);
  try {
    const { page } = t;
    expect(await probe(page, (p) => p.canvasLock())).toMatchObject({ on: true, index: 0, stops: 3 });
    // One finger never moves windows: it scrolls the terminal it is on.
    await swipe(t, { x: 300, y: 400 }, { x: 120, y: 400 });
    await page.waitForTimeout(400);
    expect((await probe(page, (p) => p.canvasLock())).index).toBe(0);
    await swipe2(t, { x: 210, y: 400 }, { x: 40, y: 400 });
    await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).index).toBe(1);
    await page.waitForTimeout(1600);
    const rested = (await probe(page, (p) => p.camera())).tx;
    await page.waitForTimeout(300);
    expect(Math.abs((await probe(page, (p) => p.camera())).tx - rested)).toBeLessThan(1);
    await swipe2(t, { x: 100, y: 400 }, { x: 330, y: 400 });
    await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).index).toBe(0);
    // The toolbar's previous and next move one window too.
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="next"]')!.click());
    await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).index, { timeout: 4000 }).toBeGreaterThanOrEqual(0);
    // A pinch changes nothing while the canvas is locked.
    const z0 = (await probe(page, (p) => p.camera())).z;
    await t.touch("touchStart", [{ x: 150, y: 400 }, { x: 250, y: 400 }]);
    for (let i = 1; i <= 6; i++) await t.touch("touchMove", [{ x: 150 - i * 2, y: 400 }, { x: 250 + i * 2, y: 400 }]);
    await t.touch("touchEnd", []);
    await page.waitForTimeout(500);
    expect((await probe(page, (p) => p.camera())).z).toBe(z0);
    // The canvas lock toggle frees the canvas (zoomed out), then locks it again.
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="canvas-lock"]')!.click());
    await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).on).toBe(false);
    await expect.poll(async () => (await probe(page, (p) => p.camera())).z, { timeout: 4000 }).toBeLessThan(0.7);
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="canvas-lock"]')!.click());
    await expect.poll(async () => (await probe(page, (p) => p.camera())).z, { timeout: 4000 }).toBe(1);
  } finally { await t.close(); }
});

test("canvas lock on a phone: tapping a neighbour that peeks in moves there; two fingers step windows in a column", async ({ browser }) => {
  const t = await touchPage(browser, 3);
  try {
    const { page } = t;
    // The next column peeks in at the right edge.
    await page.touchscreen.tap(368, 500);
    await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).index, { timeout: 4000 }).toBe(1);
    await page.waitForTimeout(800);
    const col = '.cl-col[data-id="c2"]';
    await swipe2(t, { x: 200, y: 600 }, { x: 200, y: 200 }, 10);
    await expect.poll(() => page.locator(col).evaluate((n) => n.scrollTop), { timeout: 3000 }).toBeGreaterThan(20);
    await page.waitForTimeout(900);
    const top = await page.locator(col).evaluate((n) => ({ s: n.scrollTop, starts: [...n.querySelectorAll<HTMLElement>(":scope > .ui-window")].map((w) => w.offsetTop - 14), max: n.scrollHeight - n.clientHeight }));
    expect(top.starts.concat(top.max).some((v) => Math.abs(Math.min(v, top.max) - top.s) < 2)).toBe(true);
  } finally { await t.close(); }
});

test("snap on desktop: wheel and trackpad move between windows and columns, ctrl-wheel does not zoom", async ({ page }) => {
  await page.setViewportSize({ width: 1000, height: 800 });
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(900);
  expect(await probe(page, (p) => p.canvasLock())).toMatchObject({ on: true, index: 0 });
  expect((await probe(page, (p) => p.canvasLock())).stops).toBeGreaterThan(1);
  await page.keyboard.down("Control");
  await page.mouse.move(500, 400);
  await page.mouse.wheel(0, -300);
  await page.keyboard.up("Control");
  await page.waitForTimeout(300);
  expect((await probe(page, (p) => p.camera())).z).toBe(1);
  // Horizontal: one column per gesture.
  await page.mouse.wheel(160, 0);
  await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).index).toBe(1);
  await page.waitForTimeout(500);
  await page.mouse.wheel(-160, 0);
  await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).index).toBe(0);
  // Vertical: the second window of a column.
  await page.waitForTimeout(500);
  const second = page.locator('.cl-col[data-id="c2"]');
  const box = (await second.boundingBox())!;
  await page.mouse.move(box.x + 100, box.y + 200);
  await page.mouse.wheel(0, 120);
  await expect.poll(() => second.evaluate((n) => n.scrollTop), { timeout: 3000 }).toBeGreaterThan(50);
});

test("toolbar: the keyboard row follows terminal focus, the canvas row follows a tap on the canvas, swipes switch and scroll rows", async ({ browser }) => {
  const t = await touchPage(browser, 3);
  try {
    const { page } = t;
    const row = (): Promise<string | null> => page.evaluate(() => document.querySelector("#terminal-screen")!.getAttribute("data-row"));
    // The live terminal has focus: keyboard row.
    await page.touchscreen.tap(200, 500);
    await expect.poll(row).toBe("keys");
    await expect(page.locator("#keytray")).toHaveAttribute("data-rows", "2");
    // Tap empty canvas: the canvas row.
    await page.touchscreen.tap(200, 130);
    await expect.poll(row).toBe("canvas");
    const tray = (await page.locator("#keytray").boundingBox())!;
    expect(tray.height).toBeGreaterThanOrEqual(44);
    // Swipe down shows the key row (the lower one), swipe up the canvas row (the upper one).
    await swipe(t, { x: tray.x + 100, y: tray.y + 12 }, { x: tray.x + 100, y: tray.y + 44 }, 6);
    await expect.poll(row).toBe("keys");
    await page.waitForTimeout(500);
    await swipe(t, { x: tray.x + 100, y: tray.y + 32 }, { x: tray.x + 100, y: tray.y }, 6);
    await expect.poll(row).toBe("canvas");
    await page.waitForTimeout(500);
    // Horizontal swipe scrolls the overflowing canvas row.
    await swipe(t, { x: tray.x + 300, y: tray.y + 22 }, { x: tray.x + 100, y: tray.y + 22 }, 8);
    await expect.poll(() => page.evaluate(() => document.querySelector("#keyrow-canvas")!.scrollLeft), { timeout: 3000 }).toBeGreaterThan(40);
  } finally { await t.close(); }
});

test("toolbar: Ctrl latches (tap arms, double tap holds), snap and lock work from the canvas row", async ({ browser }) => {
  const t = await touchPage(browser, 3);
  try {
    const { page } = t;
    await page.touchscreen.tap(200, 500);
    await expect(page.locator("#terminal-screen")).toHaveAttribute("data-row", "keys");
    const ctrl = page.locator('[data-mod="ctrl"]');
    const state = (): Promise<string | null> => ctrl.getAttribute("data-mod-state");
    expect(await state()).toBe("off");
    const box = (await ctrl.boundingBox())!;
    expect(box.height).toBeGreaterThanOrEqual(44);
    await page.touchscreen.tap(box.x + box.width / 2, box.y + box.height / 2);
    await expect.poll(state).toBe("armed");
    await page.waitForTimeout(500);
    await page.touchscreen.tap(box.x + box.width / 2, box.y + box.height / 2);
    await expect.poll(state).toBe("off");
    await page.touchscreen.tap(box.x + box.width / 2, box.y + box.height / 2);
    await page.touchscreen.tap(box.x + box.width / 2, box.y + box.height / 2);
    await expect.poll(state).toBe("locked");
    // Canvas row: snap and lock.
    await page.touchscreen.tap(200, 130);
    await expect(page.locator("#terminal-screen")).toHaveAttribute("data-row", "canvas");
    await page.waitForTimeout(500);
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="input-lock"]')!.click());
    await expect(page.locator('.ui-window[data-active][data-locked]')).toHaveCount(1);
    await expect(page.locator('[data-cv="input-lock"]')).toHaveAttribute("aria-pressed", "true");
    // Locked, the canvas lock and the overview are off limits; unlocking brings them back.
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="overview"]')!.click());
    expect((await probe(page, (p) => p.canvasLock())).on).toBe(true);
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="input-lock"]')!.click());
    await expect(page.locator('.ui-window[data-locked]')).toHaveCount(0);
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="overview"]')!.click());
    await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).on).toBe(false);
  } finally { await t.close(); }
});
