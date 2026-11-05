/**
 * App windows and screens on the product canvas (D200, D207, D208), against the app-window double: a Mac that lists windows
 * and streams H.264. Run with `TRACER_DOUBLE_APPWIN=1 bun x playwright test test/appwin.spec.ts`; set
 * `TRACER_APPWIN_BROWSER=chrome` to select a browser channel that can decode the fixture. Without the double, every test here is skipped.
 *
 * What it proves: the flag gate (off by default, the preview door, the Settings switch), the picker (live, searchable, grouped),
 * a window that goes live through the worker and follows its box (A2), control that takes the first press only after the window
 * is active and never on a hover (A3), and every honest state.
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { requireFixtureH264 } from "./appwin/codec-support";

const enabled = process.env.TRACER_DOUBLE_APPWIN === "1";
const fixtures = process.env.APPWIN_FIXTURE_DIR ?? join(homedir(), ".cache/codex-scratch/ui-app-windows/fixtures");
const paletteShortcut = process.platform === "darwin" ? "Meta+K" : "Control+Shift+K";
const selectAllShortcut = process.platform === "darwin" ? "Meta+A" : "Control+A";
test.beforeAll(() => {
  test.skip(!enabled, "needs TRACER_DOUBLE_APPWIN=1 (the app-window double)");
  if (!existsSync(join(fixtures, "editor-tall.h264"))) {
    const run = spawnSync("node", [join(import.meta.dirname, "appwin/render-fixtures.mjs"), fixtures], { stdio: "inherit" });
    if (run.status !== 0) throw new Error("the fixtures need ffmpeg with libx264");
  }
});

const config = (page: Page, data: Record<string, unknown>) => page.request.post("/__mock/appwin/config", { data });
const machineState = async (page: Page) => (await page.request.get("/__mock/appwin/state")).json() as Promise<{ sessions: Array<{ id: string; width: number; height: number; controller: boolean }>; inputs: Array<{ input: { kind: string; state?: number; scalar?: number; x?: number; y?: number; keycode?: number; down?: boolean; modifiers?: number } }>; sizes: Array<{ width: number; height: number }>; attaches: number; repairs: number }>;

async function openCanvas(page: Page, query = "&appwin=1", before: Record<string, unknown> = {}, fresh = true): Promise<void> {
  await page.request.post("/__mock/reset");
  await config(page, { reset: true, ...before });
  // `fresh=1` wipes the page's local state on every load, and the mock preview reloads the page when its socket drops (the product
  // does not): a test that stores a preference and reconnects must not ask for it.
  await page.goto(`/?mock=1&proto=product${fresh ? "&fresh=1" : ""}&bg=none${query}`);
  await expect(page.locator(".ui-window").first()).toBeVisible();
  await hostsLoaded(page);
}

/** The admitted hosts arrive after the first terminal settles: the palette lists them as shells. */
async function hostsLoaded(page: Page): Promise<void> {
  // One shortcut opens the palette; retrying the toggle can close it while host inventory is still arriving.
  await page.keyboard.press(paletteShortcut);
  await expect(page.getByRole("option", { name: /Open shell on build-01/ })).toBeVisible({ timeout: 25_000 });
  await page.keyboard.press("Escape");
}

const plus = (page: Page) => page.getByRole("button", { name: "New window", exact: true });
const appWindow = (page: Page) => page.locator(".ui-window[data-kind='app']");
/** Gives the machine back the way a person does: the window loses typing focus (the pill's mark is not a button). */
const letGo = (page: Page) => appWindow(page).locator(".aw-stage").evaluate((el) => (el as HTMLElement).blur());

async function openEditor(page: Page): Promise<void> {
  await requireFixtureH264(page);
  await plus(page).click();
  await page.getByRole("option", { name: /Editor, stream\.ts/ }).click();
  await expect(appWindow(page).locator(".aw-stage")).toHaveAttribute("data-picture", "live", { timeout: 20_000 });
}

test("off by default: a production-style load has no picker and no desktop capability", async ({ page }) => {
  await page.request.post("/__mock/reset");
  await config(page, { reset: true });
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
  await expect(page.locator(".ui-window").first()).toBeVisible();
  await hostsLoaded(page);
  // "+" opens a shell, not a picker, and the preview door (?appwin=1) is the only thing that turned the feature on elsewhere.
  await plus(page).click();
  await expect(page.locator(".aw-pop")).toHaveCount(0);
});

test("the Settings switch is offered because the server reports the capability, and it remembers the choice", async ({ page }) => {
  await openCanvas(page, "", {}, false);
  // Off: the palette lists the machine's shell but none of its windows.
  await page.keyboard.press(paletteShortcut);
  await page.keyboard.type("open editor");
  await expect(page.getByRole("option", { name: /Open Editor on studio-mac/ })).toHaveCount(0);
  await page.keyboard.press(selectAllShortcut);
  await page.keyboard.type("hosts");
  await page.getByRole("option", { name: /Terminal › Hosts/ }).click();
  const toggle = page.getByRole("switch", { name: /Stream app windows/ });
  await expect(toggle).toBeVisible();
  await expect(toggle).not.toBeChecked();
  expect(await page.evaluate(() => localStorage.getItem("infraternal.app-windows"))).not.toBe("1");
  // Turning it on stores the choice for this browser and reconnects once, so the next Hello declares the capability. (The mock
  // preview reloads itself when its socket drops, which is why the reconnect itself is checked by the picker tests, which load
  // the page with the preview door instead.)
  await toggle.click();
  await expect(toggle).toBeChecked();
  expect(await page.evaluate(() => localStorage.getItem("infraternal.app-windows"))).toBe("1");
});

test("the picker lists every machine's shell, screen and windows, narrows with one field and follows the machine live", async ({ page }) => {
  await openCanvas(page);
  await plus(page).click();
  const rows = page.locator(".aw-pop [data-row]");
  await expect(page.getByRole("option", { name: /Whole screen/ })).toBeVisible();
  await expect(page.getByRole("option", { name: /Editor, stream\.ts/ })).toBeVisible();
  await expect(page.getByRole("option", { name: /Shell, kayg@build-01/ })).toBeVisible();
  const all = await rows.count();
  await page.keyboard.type("note");
  await expect(rows).toHaveCount(2);
  await page.keyboard.press(selectAllShortcut);
  await page.keyboard.type("build-01");
  await expect(rows).toHaveCount(1);
  await page.keyboard.press(selectAllShortcut);
  await page.keyboard.press("Backspace");
  await expect(rows).toHaveCount(all);
  // A window opens on the machine while the picker is open: its row appears without a reload.
  await config(page, { windows: [{ window_id: 777, owner_pid: 888, app_name: "Calendar", title: "October", bundle_id: "t", layer: 0, frame: [0, 0, 800, 600], on_screen: true, app: "notebook" }] });
  await expect(page.getByRole("option", { name: /Calendar, October/ })).toBeVisible({ timeout: 10_000 });
  await expect(page.getByRole("option", { name: /Editor, stream\.ts/ })).toHaveCount(0);
});

test("an app window goes live in a worker, names itself, and the machine's window follows its box", async ({ page }) => {
  await openCanvas(page);
  await openEditor(page);
  await expect(appWindow(page).locator(".ui-window-host")).toHaveText("stream.ts · Editor");
  await expect(appWindow(page)).toHaveAttribute("data-status", "live");
  const first = await machineState(page);
  expect(first.sessions).toHaveLength(1);
  const box = await appWindow(page).boundingBox();
  const grow = appWindow(page).locator('.ui-window-resize[data-edge="e"]');
  const handle = (await grow.boundingBox())!;
  await page.mouse.move(handle.x + handle.width / 2, handle.y + handle.height / 2);
  await page.mouse.down();
  await page.mouse.move(handle.x + 140, handle.y + handle.height / 2, { steps: 8 });
  await page.mouse.up();
  const dpr = await page.evaluate(() => devicePixelRatio);
  await expect.poll(async () => (await machineState(page)).sizes.at(-1)?.width).toBeGreaterThan(Math.round(box!.width * dpr));
  // Decoded and drawn off the main thread: the worker counted pictures, the page thread did not decode.
  const report = await page.evaluate(() => (window as unknown as { __appwin: { report(): Promise<Array<{ stats: { painted: number } }>> } }).__appwin.report());
  expect(report[0]!.stats.painted).toBeGreaterThan(10);
});

test("a delta before the startup keyframe requests one repair and renders the returned picture", async ({ page }) => {
  await openCanvas(page, "&appwin=1", { dropInitialKeyframe: true });
  await openEditor(page);
  await expect.poll(async () => (await machineState(page)).repairs).toBe(1);
  const report = await page.evaluate(() => (window as unknown as { __appwin: { report(): Promise<Array<{ stats: { painted: number; repairs: number } }>> } }).__appwin.report());
  expect(report[0]!.stats).toMatchObject({ painted: expect.any(Number), repairs: 1 });
  expect(report[0]!.stats.painted).toBeGreaterThan(0);
});

test("a window the machine keeps at its own size gives the canvas window its shape, and follows when it changes", async ({ page }) => {
  await openCanvas(page, "&appwin=1", { windowShape: { width: 1600, height: 900 } });
  await openEditor(page);
  const aspect = async (): Promise<number> => {
    const stage = (await appWindow(page).locator(".aw-stage").boundingBox())!;
    return stage.width / stage.height;
  };
  await expect.poll(aspect, { timeout: 5000 }).toBeGreaterThan(1600 / 900 * 0.98);
  expect(await aspect()).toBeLessThan(1600 / 900 * 1.02);
  // Taking the machine's shape is looking: it never takes control or moves anything there.
  await page.waitForTimeout(800);
  expect((await machineState(page)).sessions.every((session) => !session.controller)).toBe(true);
  await expect(appWindow(page).locator(".aw-pillmark")).toHaveCount(0);
  await page.screenshot({ path: test.info().outputPath("shape-wide.png") });
  // The person (or the window manager) makes the machine's window tall: the canvas window follows.
  await config(page, { windowShape: { width: 900, height: 1100 } });
  await expect.poll(aspect, { timeout: 5000 }).toBeLessThan(900 / 1100 * 1.02);
  expect(await aspect()).toBeGreaterThan(900 / 1100 * 0.98);
  await page.screenshot({ path: test.info().outputPath("shape-tall.png") });
});

test("looking never moves the machine: the activating press and a hover send nothing, then a click takes control", async ({ page }) => {
  await openCanvas(page);
  await openEditor(page);
  const stage = appWindow(page).locator(".aw-stage");
  const b = (await stage.boundingBox())!;
  await page.mouse.move(b.x + 80, b.y + 80);
  await page.mouse.move(b.x + 120, b.y + 160);
  await page.waitForTimeout(400);
  expect((await machineState(page)).inputs).toHaveLength(0);
  await expect(page.locator(".aw-pillmark")).toHaveCount(0);
  await page.mouse.click(b.x + 120, b.y + 160);
  await expect(page.locator(".aw-pillmark")).toHaveAttribute("data-tip", "Controlled from infraternal");
  await expect.poll(async () => (await machineState(page)).inputs.map((i) => `${i.input.kind}:${i.input.state ?? ""}`)).toEqual(expect.arrayContaining(["mouse:1", "mouse:2"]));
  await page.keyboard.type("a");
  await expect.poll(async () => (await machineState(page)).inputs.filter((i) => i.input.kind === "text").map(i => i.input.scalar)).toEqual([97]);
  // Letting go: leaving the window (its keys and pointer) releases what is held, and the mark in the pill goes.
  await letGo(page);
  await expect(page.locator(".aw-pillmark")).toHaveCount(0);
});

test("view only says so in plain words", async ({ page }) => {
  await openCanvas(page, "&appwin=1", { viewOnly: true });
  await openEditor(page);
  const b = (await appWindow(page).locator(".aw-stage").boundingBox())!;
  await page.mouse.click(b.x + 100, b.y + 100);
  await expect(page.locator(".aw-pillmark")).toHaveAttribute("data-tip", "View only");
  expect((await machineState(page)).inputs).toHaveLength(0);
});

test("the machine's local-input pause shows for as long as it lasts, then control resumes", async ({ page }) => {
  await openCanvas(page, "&appwin=1", { inputPauseMs: 1500 });
  await openEditor(page);
  const b = (await appWindow(page).locator(".aw-stage").boundingBox())!;
  await page.mouse.click(b.x + 100, b.y + 100);
  await expect(page.locator(".aw-pillmark")).toHaveAttribute("data-tip", "Paused while someone uses studio-mac", { timeout: 10_000 });
  await config(page, { inputPauseMs: 0 });
  await expect(page.locator(".aw-pillmark")).toHaveAttribute("data-tip", "Controlled from infraternal", { timeout: 10_000 });
});

test("every state is honest: closed, permission missing, connecting, reconnecting, unsupported", async ({ page, browser }) => {
  test.setTimeout(120_000);
  await openCanvas(page, "&appwin=1", { startDelayMs: 1500 });
  await requireFixtureH264(page);
  await plus(page).click();
  await page.getByRole("option", { name: /Editor, stream\.ts/ }).click();
  await expect(appWindow(page).locator(".aw-card")).toContainText("Opening Editor");
  await expect(appWindow(page).locator(".aw-stage")).toHaveAttribute("data-picture", "live", { timeout: 20_000 });
  await config(page, { startDelayMs: 0 });
  // The socket drops: the picture stays, dimmed, and the pill's dot turns (TASTE: an icon with motion, never a text strip over
  // the picture); it returns by itself.
  await page.request.post("/__mock/drop-sockets");
  await expect(appWindow(page).locator(".aw-stage")).toHaveAttribute("data-picture", "dim");
  await expect(appWindow(page).locator(".ui-window-conn")).toHaveAttribute("data-state", "reconnecting");
  await expect(appWindow(page).locator(".cl-sx-strip")).toHaveCount(0);
  await expect(appWindow(page).locator(".aw-card")).toHaveAttribute("data-shown", "false");
  await expect(appWindow(page).locator(".aw-stage")).toHaveAttribute("data-picture", "live", { timeout: 20_000 });
  // The app quits.
  await page.request.post("/__mock/appwin/end", { data: { window_id: 201 } });
  await expect(appWindow(page).locator(".aw-card")).toContainText("Editor was closed");
  await expect(appWindow(page).locator(".aw-stage")).toHaveAttribute("data-picture", "none");
  await appWindow(page).locator(".aw-action").click();
  await expect(appWindow(page)).toHaveCount(0);
  // Permission missing on the machine says what to allow.
  await config(page, { screenRecording: false });
  await plus(page).click();
  await page.getByRole("option", { name: /Notebook, Today/ }).click();
  await expect(appWindow(page).locator(".aw-card")).toContainText("System Settings, Privacy & Security, Screen Recording");
  await config(page, { screenRecording: true });
  await appWindow(page).locator(".aw-action").click();
  await expect(appWindow(page).locator(".aw-stage")).toHaveAttribute("data-picture", "live", { timeout: 20_000 });
  // A browser without a video decoder says so instead of showing a blank window.
  await page.close();
  const context = await browser.newContext({ baseURL: process.env.TRACER_BASE_URL ?? `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}` });
  await context.addInitScript(() => { delete (window as unknown as { VideoDecoder?: unknown }).VideoDecoder; });
  const bare = await context.newPage();
  await bare.goto("/?mock=1&proto=product&fresh=1&bg=none&appwin=1");
  await expect(bare.locator(".ui-window").first()).toBeVisible();
  await hostsLoaded(bare);
  await bare.getByRole("button", { name: "New window", exact: true }).click();
  await bare.getByRole("option", { name: /Notebook, Today/ }).click();
  await expect(bare.locator(".aw-card")).toContainText("This browser can't show app windows");
  await context.close();
});

test("the palette lists \"Open <app> on <machine>\" and opens it", async ({ page }) => {
  await openCanvas(page);
  await requireFixtureH264(page);
  await page.keyboard.press(paletteShortcut);
  await page.keyboard.type("open editor");
  await page.getByRole("option", { name: /Open Editor on studio-mac/ }).click();
  await expect(appWindow(page).locator(".aw-stage")).toHaveAttribute("data-picture", "live", { timeout: 20_000 });
});


test("a viewing attachment survives the real resize authority contract", async ({ page }) => {
  await openCanvas(page, "&appwin=1", { controlContract: true });
  await openEditor(page);
  await expect(appWindow(page)).toHaveAttribute("data-status", "live");
  expect((await machineState(page)).sessions[0]?.controller).toBe(false);
  await expect(page.locator(".aw-pillmark")).toHaveCount(0);
});

test("letting go retires the native control lease while viewing continues", async ({ page }) => {
  await openCanvas(page);
  await openEditor(page);
  await appWindow(page).locator(".aw-stage").click({ position: { x: 120, y: 100 } });
  await expect(page.locator(".aw-pillmark")).toHaveAttribute("data-tip", "Controlled from infraternal");
  await letGo(page);
  await expect.poll(async () => (await machineState(page)).sessions[0]?.controller).toBe(false);
  await expect(appWindow(page)).toHaveAttribute("data-status", "live");
});

test("layout text and a shortcut release reach the source without physical text remapping", async ({ page }) => {
  await openCanvas(page);
  await openEditor(page);
  const stage = appWindow(page).locator(".aw-stage");
  await stage.click({ position: { x: 120, y: 100 } });
  await expect(page.locator(".aw-pillmark")).toHaveAttribute("data-tip", "Controlled from infraternal");
  await stage.evaluate(el => {
    for (const [code, key] of [["KeyA", "a"], ["KeyE", "é"], ["KeyQ", "🐈"]] as const) {
      for (const type of ["keydown", "keyup"]) el.dispatchEvent(new KeyboardEvent(type, { bubbles: true, code, key }));
    }
    el.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, code: "KeyC", key: "c", ctrlKey: true }));
    el.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true, code: "KeyC", key: "c" }));
  });
  await expect.poll(async () => (await machineState(page)).inputs.filter(i => i.input.kind === "text").map(i => i.input.scalar)).toEqual([97, 233, 128008]);
  await expect.poll(async () => (await machineState(page)).inputs.filter(i => i.input.kind === "key").map(i => [i.input.keycode, i.input.down])).toEqual([[8, true], [8, false]]);
});


test("CSS letterbox rejects new input and still releases a drag that leaves the picture", async ({ page }) => {
  await openCanvas(page); await openEditor(page);
  const handle = (await appWindow(page).locator('.ui-window-resize[data-edge="e"]').boundingBox())!;
  await page.mouse.move(handle.x + handle.width / 2, handle.y + handle.height / 2);
  await page.mouse.down();
  await page.mouse.move(handle.x + 230, handle.y + handle.height / 2, { steps: 8 });
  await page.mouse.up();
  const stage = appWindow(page).locator(".aw-stage");
  // The resize reached the machine without showing control (D208 A3); the click then takes control, and the mark appears.
  await expect.poll(async () => (await machineState(page)).sizes.length).toBeGreaterThan(0);
  await expect(page.locator(".aw-pillmark")).toHaveCount(0);
  await stage.click();
  await expect(page.locator(".aw-pillmark")).toHaveAttribute("data-tip", "Controlled from infraternal");
  await expect.poll(async () => (await machineState(page)).inputs.filter(i => i.input.kind === "mouse" && i.input.state === 2).length).toBe(1);
  const geometry = await stage.evaluate(el => {
    const canvas = el.querySelector("canvas")!;
    const bounds = el.getBoundingClientRect();
    const ratio = canvas.width / canvas.height;
    const width = Math.min(bounds.width, bounds.height * ratio), height = width / ratio;
    const x = (bounds.width - width) / 2, y = (bounds.height - height) / 2;
    if (Math.max(x, y) < 8) throw new Error("fixture must have a visible CSS band");
    return { left: bounds.left, top: bounds.top, inside: { x: bounds.width / 2, y: bounds.height / 2 }, band: x > y ? { x: x / 2, y: bounds.height / 2 } : { x: bounds.width / 2, y: y / 2 } };
  });
  const before = (await machineState(page)).inputs.length;
  await stage.click({ position: geometry.band });
  await stage.press("a");
  // The text is a same-route processing fence after the band click.
  await expect.poll(async () => (await machineState(page)).inputs.slice(before).map(i => i.input.kind)).toEqual(["text"]);
  await page.mouse.move(geometry.left + geometry.inside.x, geometry.top + geometry.inside.y);
  await page.mouse.down();
  await page.mouse.move(geometry.left + geometry.band.x, geometry.top + geometry.band.y);
  await page.mouse.up();
  await expect.poll(async () => (await machineState(page)).inputs.slice(before).filter(i => i.input.kind === "mouse" && i.input.state !== 0).map(i => i.input.state)).toEqual([1, 2]);
  const [down, up] = (await machineState(page)).inputs.slice(before).filter(i => i.input.kind === "mouse" && i.input.state !== 0);
  expect(down!.input).toMatchObject({ x: expect.any(Number), y: expect.any(Number) });
  expect(up!.input).toMatchObject({ x: down!.input.x, y: down!.input.y });

  // Hold the move callback so the outside release must consume a newer valid
  // position before any queued pointer movement can run after that release.
  await page.mouse.move(geometry.left + geometry.inside.x, geometry.top + geometry.inside.y);
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => resolve())));
  const pendingBefore = (await machineState(page)).inputs.length;
  await page.evaluate(() => {
    const originalRequest = window.requestAnimationFrame, originalCancel = window.cancelAnimationFrame;
    const waiting = new Map<number, FrameRequestCallback>(); let id = 100_000;
    window.requestAnimationFrame = callback => { waiting.set(++id, callback); return id; };
    window.cancelAnimationFrame = key => { waiting.delete(key); };
    Object.assign(window, { flushPendingInputFrames: () => {
      window.requestAnimationFrame = originalRequest; window.cancelAnimationFrame = originalCancel;
      for (const [key, callback] of [...waiting]) { if (waiting.delete(key)) callback(performance.now()); }
    } });
  });
  await page.mouse.down();
  await page.mouse.move(geometry.left + geometry.inside.x + 20, geometry.top + geometry.inside.y);
  await page.mouse.move(geometry.left + geometry.band.x, geometry.top + geometry.band.y);
  await page.mouse.up();
  await page.evaluate(() => (window as unknown as { flushPendingInputFrames(): void }).flushPendingInputFrames());
  await stage.press("b");
  await expect.poll(async () => (await machineState(page)).inputs.slice(pendingBefore).map(i => `${i.input.kind}:${i.input.state ?? ""}`)).toEqual(["mouse:1", "mouse:0", "mouse:2", "text:"]);
  const [pendingDown, pendingMove, pendingUp] = (await machineState(page)).inputs.slice(pendingBefore);
  expect(pendingMove!.input.x).toBeGreaterThan(pendingDown!.input.x!);
  expect(pendingUp!.input).toMatchObject({ x: pendingMove!.input.x, y: pendingMove!.input.y });

  // A native touch contact exercises capture and the long-press drag path.
  const touchBefore = (await machineState(page)).inputs.length;
  const touch = await page.context().newCDPSession(page);
  await touch.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: geometry.left + geometry.inside.x, y: geometry.top + geometry.inside.y }] });
  await expect.poll(async () => (await machineState(page)).inputs.slice(touchBefore).map(i => i.input.state)).toEqual([1]);
  await page.evaluate(() => {
    const originalRequest = window.requestAnimationFrame, originalCancel = window.cancelAnimationFrame;
    const waiting = new Map<number, FrameRequestCallback>(); let id = 200_000;
    window.requestAnimationFrame = callback => { waiting.set(++id, callback); return id; };
    window.cancelAnimationFrame = key => { waiting.delete(key); };
    Object.assign(window, { flushPendingInputFrames: () => {
      window.requestAnimationFrame = originalRequest; window.cancelAnimationFrame = originalCancel;
      for (const [key, callback] of [...waiting]) { if (waiting.delete(key)) callback(performance.now()); }
    } });
  });
  await touch.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: geometry.left + geometry.inside.x + 20, y: geometry.top + geometry.inside.y }] });
  await touch.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: geometry.left + geometry.band.x, y: geometry.top + geometry.band.y }] });
  await touch.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
  await page.evaluate(() => (window as unknown as { flushPendingInputFrames(): void }).flushPendingInputFrames());
  await stage.press("c");
  await expect.poll(async () => (await machineState(page)).inputs.slice(touchBefore).map(i => `${i.input.kind}:${i.input.state ?? ""}`)).toEqual(["mouse:1", "mouse:0", "mouse:2", "text:"]);
  const [touchDown, touchMove, touchUp] = (await machineState(page)).inputs.slice(touchBefore);
  expect(touchMove!.input.x).toBeGreaterThan(touchDown!.input.x!);
  expect(touchUp!.input).toMatchObject({ x: touchMove!.input.x, y: touchMove!.input.y });
  await touch.detach();
});
