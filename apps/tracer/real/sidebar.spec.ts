/**
 * The sidebar is another layer over the canvas (#114): opening or closing it changes no layout. Five toggles with a
 * window at the left edge and with a window in the centre: window rectangles, the camera transform and the canvas
 * size are identical to the pixel, no ResizeObserver callback fires and no terminal refits; only the sidebar moves.
 * Production server binary, real sessions, 1440x900.
 */
import { tracerEvidencePath } from "../test/evidence-path";
import { expect, test, type Page } from "playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { personName, startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });
let server: RealServer;
let page: Page;
const captures = tracerEvidencePath("sidebar-overlay");

test.beforeAll(async ({ browser }) => {
  server = await startRealServer();
  await mkdir(captures, { recursive: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  // Count every ResizeObserver callback (a terminal's fit starts from one).
  await context.addInitScript(() => {
    const w = window as unknown as { __ro: number; ResizeObserver: typeof ResizeObserver };
    w.__ro = 0;
    const Native = w.ResizeObserver;
    w.ResizeObserver = class extends Native {
      constructor(callback: ResizeObserverCallback) {
        // The sidebar's own content (its tree folds open as it appears) is not the canvas: only observers outside it count.
        super((entries, observer) => { w.__ro += entries.filter((e) => !(e.target as Element).closest("#sidebar")).length; callback(entries, observer); });
      }
    };
  });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("sidebar_real"));
  await page.locator("#setup-display-name").fill("Sidebar real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
});
test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

const windows = () => page.locator('.cl[data-view="console"] .ui-window');
const state = () => page.evaluate(() => ({
  rects: [...document.querySelectorAll('.cl[data-view="console"] .ui-window')].map((w) => { const r = w.getBoundingClientRect(); return [r.x, r.y, r.width, r.height]; }),
  camera: (document.querySelector(".cl-world") as HTMLElement).style.transform,
  area: (() => { const r = document.querySelector(".cl-viewport")!.getBoundingClientRect(); return [r.x, r.y, r.width, r.height]; })(),
  panes: (() => { const r = document.querySelector("#panes")!.getBoundingClientRect(); return [r.x, r.width]; })(),
  hosts: [...document.querySelectorAll(".terminal-host")].map((h) => [h.clientWidth, h.clientHeight]),
}));

async function toggleFive(label: string): Promise<void> {
  if (process.env.EXTRA_CSS) await page.addStyleTag({ content: process.env.EXTRA_CSS });
  await page.waitForTimeout(1200);
  const before = await state();
  await page.screenshot({ path: `${captures}/${label}-closed.png` });
  await page.evaluate(() => { (window as unknown as { __ro: number }).__ro = 0; });
  const frames: number[] = [];
  // Frame times are recorded only while a slide runs (the 300 ms after each click), not while the page idles.
  await page.evaluate(() => { const w = window as unknown as { __f: number[]; __stop: boolean; __rec: number }; w.__f = []; w.__stop = false; w.__rec = 0; let last = performance.now(); const tick = (t: number): void => { if (t < w.__rec) w.__f.push(t - last); last = t; if (!w.__stop) requestAnimationFrame(tick); }; requestAnimationFrame(tick); });
  // Control: the same recording with nothing happening, so the machine's own load is visible next to the slide.
  await page.evaluate(() => { (window as unknown as { __rec: number }).__rec = performance.now() + 1500; });
  await page.waitForTimeout(1600);
  const idle = await page.evaluate(() => (window as unknown as { __f: number[] }).__f.splice(0).sort((a, b) => a - b));
  console.log(`SIDEBAR ${label}: idle control p50=${idle[Math.floor(idle.length / 2)]!.toFixed(1)} p95=${idle[Math.floor(idle.length * 0.95)]!.toFixed(1)} max=${idle.at(-1)!.toFixed(1)} ms`);
  for (let i = 0; i < 5; i++) {
    await page.evaluate(() => { (window as unknown as { __rec: number }).__rec = performance.now() + 300; });
    await page.locator("#sidebar-toggle").click();
    await expect(page.locator("#sidebar")).toBeVisible();
    await page.waitForTimeout(450);
    if (i === 0) await page.screenshot({ path: `${captures}/${label}-open.png` });
    expect(await state(), `${label}: open ${i + 1}`).toEqual(before);
    await page.evaluate(() => { (window as unknown as { __rec: number }).__rec = performance.now() + 300; });
    await page.locator("#sidebar-toggle").click();
    await page.waitForTimeout(450);
    expect(await state(), `${label}: closed ${i + 1}`).toEqual(before);
  }
  const f = await page.evaluate(() => { const w = window as unknown as { __f: number[]; __stop: boolean }; w.__stop = true; return w.__f.slice(2); });
  frames.push(...f);
  const sorted = [...frames].sort((a, b) => a - b);
  console.log(`SIDEBAR ${label}: frames n=${sorted.length} p50=${sorted[Math.floor(sorted.length / 2)]!.toFixed(1)} p95=${sorted[Math.floor(sorted.length * 0.95)]!.toFixed(1)} max=${sorted.at(-1)!.toFixed(1)} ms, load ${(await import("node:os")).loadavg().map((x) => x.toFixed(1)).join(" ")}`);
  expect(await page.evaluate(() => (window as unknown as { __ro: number }).__ro), `${label}: ResizeObserver callbacks`).toBe(0);
  expect(await state()).toEqual(before);
}

test("one window in the centre: five toggles change nothing", async () => {
  await expect(windows()).toHaveCount(1);
  await toggleFive("centre");
});

test("windows at the left edge: five toggles change nothing", async () => {
  for (let i = 0; i < 2; i++) { await page.locator(".tab-add").click(); await page.waitForTimeout(800); }
  await expect(windows()).toHaveCount(3);
  await page.keyboard.press("Control+Shift+G"); await page.keyboard.press("Control+Shift+G");
  await page.waitForTimeout(1200);
  const first = (await windows().first().boundingBox())!;
  expect(first.x).toBeLessThan(300); // under where the sidebar opens
  await toggleFive("left-edge");
});
