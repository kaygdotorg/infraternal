/**
 * What an app window's card tells the person, and what it must never do to the machine (#146, D208 A2/A3, D342, TASTE).
 *
 * Run with `TRACER_DOUBLE_APPWIN=1 bun x playwright test test/appwin-card.spec.ts` against a production build; without the
 * app-window double every test here is skipped. The double is a Mac that lists windows and streams H.264.
 *
 * What it proves, one test per owner-settled finding of the J171 review:
 * 1. control is an icon in the window's pill, never a badge over the picture (D342);
 * 2. resizing a card follows on the machine but never shows control (D208 A2 and A3);
 * 3. "Reconnecting" and "Paused" are the pill's dot and mark plus a dimmed picture, never a bordered text strip (TASTE);
 * 4. a dimmed picture keeps its contrast in light mode, so it reads as paused and not as a grey slab;
 * 5. the header's actions are the shared action pill, level with the title pill, on a desktop and on a phone;
 * 6. a narrow pill gives up the quiet part (machine, app) before the title, and the title comes first.
 */
import { expect, test, type Page } from "playwright/test";
import { requireFixtureH264 } from "./appwin/codec-support";

test.beforeAll(() => {
  test.skip(process.env.TRACER_DOUBLE_APPWIN !== "1", "needs TRACER_DOUBLE_APPWIN=1 (the app-window double)");
});

const paletteShortcut = process.platform === "darwin" ? "Meta+K" : "Control+Shift+K";
const config = (page: Page, data: Record<string, unknown>) => page.request.post("/__mock/appwin/config", { data });
const machineState = async (page: Page) => (await page.request.get("/__mock/appwin/state")).json() as Promise<{ sessions: Array<{ controller: boolean }>; sizes: Array<{ width: number; height: number }> }>;
const appWindow = (page: Page) => page.locator(".ui-window[data-kind='app']");
const stage = (page: Page) => appWindow(page).locator(".aw-stage");

async function openCanvas(page: Page, before: Record<string, unknown> = {}): Promise<void> {
  await page.request.post("/__mock/reset");
  await config(page, { reset: true, ...before });
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none&appwin=1");
  await expect(page.locator(".ui-window").first()).toBeVisible();
  await page.keyboard.press(paletteShortcut);
  await expect(page.getByRole("option", { name: /Open shell on build-01/ })).toBeVisible({ timeout: 25_000 });
  await page.keyboard.press("Escape");
}

async function openApp(page: Page, name: RegExp = /Editor, stream\.ts/): Promise<void> {
  await requireFixtureH264(page);
  await page.getByRole("button", { name: "New window", exact: true }).click();
  await page.getByRole("option", { name }).click();
  await expect(stage(page).first()).toHaveAttribute("data-picture", "live", { timeout: 20_000 });
}

/** Drags the card's east edge `by` pixels to the right (a resize by hand). */
async function dragEast(page: Page, by: number): Promise<void> {
  const handle = (await appWindow(page).locator('.ui-window-resize[data-edge="e"]').boundingBox())!;
  await page.mouse.move(handle.x + handle.width / 2, handle.y + handle.height / 2);
  await page.mouse.down();
  await page.mouse.move(handle.x + by, handle.y + handle.height / 2, { steps: 8 });
  await page.mouse.up();
}

/** Forces the window's stream into "paused" the way a hidden page does, then shows the canvas again so it can be looked at. */
async function pause(page: Page): Promise<void> {
  await page.evaluate(() => { Object.defineProperty(document, "hidden", { configurable: true, get: () => true }); document.dispatchEvent(new Event("visibilitychange")); });
  await expect(stage(page)).toHaveAttribute("data-picture", "dim");
  await page.evaluate(() => { document.querySelectorAll<HTMLElement>("*").forEach((e) => { if (e.style.visibility === "hidden") e.style.visibility = ""; }); });
}

test("control is an icon in the pill, and nothing about it is drawn over the picture (D342)", async ({ page }) => {
  await openCanvas(page);
  await openApp(page);
  await expect(page.locator(".aw-pillmark")).toHaveCount(0);
  const box = (await stage(page).boundingBox())!;
  await page.mouse.click(box.x + 120, box.y + 160);
  const mark = appWindow(page).locator(".ui-window-pill .aw-pillmark");
  await expect(mark).toHaveAttribute("data-tip", "Controlled from infraternal");
  // No badge and no strip over the picture, whatever the state.
  await expect(appWindow(page).locator(".aw .cl-sx-badge, .aw .cl-sx-strip, .aw-control")).toHaveCount(0);
  // The mark sits on the pill's centre line, level with the connection dot beside it (±0.5 px).
  const centres = await appWindow(page).evaluate((card) => {
    const pill = card.querySelector<HTMLElement>(".ui-window-pill")!.getBoundingClientRect();
    const centre = (selector: string): number => { const r = card.querySelector<HTMLElement>(selector)!.getBoundingClientRect(); return r.top + r.height / 2; };
    return { pill: pill.top + pill.height / 2, mark: centre(".aw-pillmark"), dot: centre(".ui-window-conn"), markInside: card.querySelector(".aw-pillmark")!.getBoundingClientRect().right <= pill.right };
  });
  expect(Math.abs(centres.mark - centres.dot)).toBeLessThanOrEqual(0.5);
  expect(Math.abs(centres.mark - centres.pill)).toBeLessThanOrEqual(0.5);
  expect(centres.markInside).toBe(true);
  // Giving the machine back removes the mark.
  await stage(page).evaluate((el) => (el as HTMLElement).blur());
  await expect(page.locator(".aw-pillmark")).toHaveCount(0);
});

test("resizing a card makes the machine's window follow, and never shows control (D208 A2, A3)", async ({ page }) => {
  await openCanvas(page);
  await openApp(page);
  const before = (await machineState(page)).sizes.length;
  const box = (await appWindow(page).boundingBox())!;
  await dragEast(page, 140);
  const dpr = await page.evaluate(() => devicePixelRatio);
  // The real window followed ...
  await expect.poll(async () => (await machineState(page)).sizes.at(-1)?.width ?? 0).toBeGreaterThan(Math.round(box.width * dpr));
  expect((await machineState(page)).sizes.length).toBeGreaterThan(before);
  // ... and nothing on the page says anyone took control.
  await expect(page.locator(".aw-pillmark")).toHaveCount(0);
  await expect(page.getByText("Controlled from infraternal")).toHaveCount(0);
  await expect(appWindow(page).locator(".aw-control, .cl-sx-badge")).toHaveCount(0);
  // The next click is the first thing that takes control.
  const stageBox = (await stage(page).boundingBox())!;
  await page.mouse.click(stageBox.x + 120, stageBox.y + 160);
  await expect(appWindow(page).locator(".aw-pillmark")).toHaveAttribute("data-tip", "Controlled from infraternal");
});

test("reconnecting is the turning dot and a dimmed picture, with no text strip", async ({ page }) => {
  await openCanvas(page);
  await openApp(page);
  await config(page, { startDelayMs: 60_000 });
  await page.request.post("/__mock/drop-sockets");
  await expect(stage(page)).toHaveAttribute("data-picture", "dim", { timeout: 15_000 });
  await expect(appWindow(page).locator(".ui-window-conn")).toHaveAttribute("data-state", "reconnecting");
  // A text strip, if the state still drew one, lands a moment after the state changes: give it that moment so an absent
  // strip is a fact and not a race.
  await page.waitForTimeout(700);
  await expect(appWindow(page).locator(".cl-sx-strip")).toHaveCount(0);
  // The state card is only for when there is nothing to show; here there is a picture.
  await expect(appWindow(page).locator(".aw-card")).toHaveAttribute("data-shown", "false");
});

test("paused is the pill's pause mark and a dimmed picture, with no text strip", async ({ page }) => {
  await openCanvas(page);
  await openApp(page);
  await pause(page);
  await expect(appWindow(page).locator(".ui-window-pill .aw-pillmark")).toHaveAttribute("data-kind", "paused");
  await expect(appWindow(page).locator(".aw-pillmark")).toHaveAttribute("data-tip", /^Paused\./);
  await expect(appWindow(page).locator(".cl-sx-strip")).toHaveCount(0);
  await expect(appWindow(page).locator(".aw-card")).toHaveAttribute("data-shown", "false");
});

/** The spread (standard deviation) of the luminance of everything inside `clip`, from a real screenshot of the page. */
async function contrast(page: Page, clip: { x: number; y: number; width: number; height: number }): Promise<number> {
  const png = (await page.screenshot({ clip })).toString("base64");
  return page.evaluate(async (data) => {
    const image = new Image();
    image.src = `data:image/png;base64,${data}`;
    await image.decode();
    const canvas = document.createElement("canvas");
    canvas.width = image.width; canvas.height = image.height;
    const context = canvas.getContext("2d")!;
    context.drawImage(image, 0, 0);
    const { data: px } = context.getImageData(0, 0, canvas.width, canvas.height);
    let sum = 0, square = 0, n = 0;
    for (let i = 0; i < px.length; i += 4) { const y = 0.2126 * px[i]! + 0.7152 * px[i + 1]! + 0.0722 * px[i + 2]!; sum += y; square += y * y; n++; }
    const mean = sum / n;
    return Math.sqrt(Math.max(0, square / n - mean * mean));
  }, png);
}

for (const scheme of ["light", "dark"] as const) {
  test(`a dimmed picture keeps its contrast in ${scheme} mode, so it reads as paused and not as a grey slab`, async ({ browser, baseURL }) => {
    const context = await browser.newContext({ baseURL: baseURL!, colorScheme: scheme, viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    try {
      await openCanvas(page);
      await openApp(page);
      const box = (await stage(page).boundingBox())!;
      const clip = { x: box.x, y: box.y, width: box.width, height: box.height };
      const liveSpread = await contrast(page, clip);
      await pause(page);
      await page.waitForTimeout(400); // the dim eases in over 200 ms
      const dimSpread = await contrast(page, clip);
      expect(liveSpread).toBeGreaterThan(10);
      // The old dim (45 % over the card) kept under half of the picture's contrast on the light card.
      expect(dimSpread / liveSpread).toBeGreaterThan(scheme === "light" ? 0.6 : 0.4);
      // Still visibly not live: it must differ from the live picture.
      expect(dimSpread / liveSpread).toBeLessThan(0.97);
    } finally { await context.close(); }
  });
}

test("the header's actions are the shared pill, level with the title pill", async ({ page }) => {
  await openCanvas(page);
  await openApp(page);
  const m = await appWindow(page).evaluate((card) => {
    const rect = (selector: string) => card.querySelector<HTMLElement>(selector)!.getBoundingClientRect();
    const pill = rect(".ui-window-pill"), actions = rect(".ui-window-actions"), close = rect('.ui-window-action[data-action="close"]');
    return { pillH: pill.height, actionsH: actions.height, pillMid: pill.top + pill.height / 2, actionsMid: actions.top + actions.height / 2, closeMid: close.top + close.height / 2, closeInside: close.left >= actions.left && close.right <= actions.right };
  });
  expect(Math.abs(m.pillH - m.actionsH)).toBeLessThanOrEqual(0.5);
  expect(Math.abs(m.pillMid - m.actionsMid)).toBeLessThanOrEqual(0.5);
  expect(Math.abs(m.closeMid - m.actionsMid)).toBeLessThanOrEqual(0.5);
  expect(m.closeInside).toBe(true);
});

test.describe("on a phone", () => {
  test.use({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  test("the header keeps the shared action pill with Close, level with the title pill", async ({ page }) => {
    await openCanvas(page);
    await openApp(page);
    const m = await appWindow(page).evaluate((card) => {
      const rect = (selector: string) => card.querySelector<HTMLElement>(selector)!.getBoundingClientRect();
      const pill = rect(".ui-window-pill"), actions = rect(".ui-window-actions");
      return { pillH: pill.height, actionsH: actions.height, pillMid: pill.top + pill.height / 2, actionsMid: actions.top + actions.height / 2, actionNames: [...card.querySelectorAll(".ui-window-actions > .ui-window-action:not(.ui-window-more)")].map((b) => b.getAttribute("aria-label")) };
    });
    expect(Math.abs(m.pillH - m.actionsH)).toBeLessThanOrEqual(0.5);
    expect(Math.abs(m.pillMid - m.actionsMid)).toBeLessThanOrEqual(0.5);
    expect(m.actionNames).toContain("Close");
  });
});

test("a narrow pill gives up the machine before the title, and the title comes first", async ({ page }) => {
  await openCanvas(page);
  await openApp(page);
  await expect(appWindow(page).locator(".ui-window-host")).toHaveText("stream.ts · Editor");
  // At every width the pill can have, the quiet part (the machine) is cut before the title is touched.
  const result = await appWindow(page).evaluate(async (card) => {
    const pill = card.querySelector<HTMLElement>(".ui-window-pill")!;
    const host = card.querySelector<HTMLElement>(".ui-window-host")!;
    const session = card.querySelector<HTMLElement>(".ui-window-session")!;
    const rows: Array<{ width: number; hostCut: boolean; sessionWidth: number }> = [];
    for (let width = 340; width >= 150; width -= 10) {
      pill.style.maxWidth = `${width}px`;
      await new Promise((resolve) => requestAnimationFrame(() => resolve(null)));
      rows.push({ width, hostCut: host.scrollWidth > host.clientWidth + 0.5, sessionWidth: session.getBoundingClientRect().width });
    }
    pill.style.maxWidth = "";
    return rows;
  });
  for (const row of result) {
    // The title is cut only once the machine has no room left at all.
    if (row.hostCut) expect(row.sessionWidth, `at ${row.width}px the title is cut while the machine still shows`).toBeLessThanOrEqual(1);
  }
  // A card as wide as the product opens one shows the whole title.
  expect(result.find((row) => row.width === 340)!.hostCut).toBe(false);
});

test("two windows of one app stay distinguishable when narrow, by their titles", async ({ page }) => {
  await openCanvas(page, { windows: [
    { window_id: 301, owner_pid: 900, app_name: "Notebook", title: "Today", bundle_id: "t", layer: 0, frame: [0, 0, 800, 600], on_screen: true, app: "notebook" },
    { window_id: 302, owner_pid: 900, app_name: "Notebook", title: "Ideas", bundle_id: "t", layer: 0, frame: [0, 0, 800, 600], on_screen: true, app: "notebook" },
  ] });
  await requireFixtureH264(page);
  for (const title of ["Today", "Ideas"]) {
    await page.getByRole("button", { name: "New window", exact: true }).click();
    await page.getByRole("option", { name: new RegExp(`Notebook, ${title}`) }).click();
    await expect(page.locator(".ui-window[data-kind='app'] .aw-stage[data-picture='live']")).toHaveCount(title === "Today" ? 1 : 2, { timeout: 20_000 });
  }
  const names = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>(".ui-window[data-kind='app'] .ui-window-pill")].map((pill) => {
    pill.style.maxWidth = "150px";
    const host = pill.querySelector<HTMLElement>(".ui-window-host")!;
    return { shown: host.textContent ?? "", cut: host.scrollWidth > host.clientWidth };
  }));
  // Even cut at 150 px, the visible start of each name is the part that differs.
  expect(names.map((n) => n.shown.slice(0, 5)).sort()).toEqual(["Ideas", "Today"]);
});
