/**
 * Terminals hold their drawing while the camera moves at a thumbnail scale (#121): a non-active terminal that gets output keeps
 * the very pixels it showed until the camera rests, then draws what arrived once; the active terminal keeps drawing what is typed.
 * Production server binary, real PTYs.
 */
import { expect, test, type Page } from "playwright/test";
import { personName, startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });
let server: RealServer;
let page: Page;

test.beforeAll(async ({ browser }) => {
  server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("freeze_real"));
  await page.locator("#setup-display-name").fill("Freeze real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
});
test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });



const windows = () => page.locator('.cl[data-view="console"] .ui-window');
/** A fingerprint of a window's canvas pixels (a sample of the bitmap, cheap and stable). */
const pixels = (index: number): Promise<string> => page.evaluate((i) => {
  const c = document.querySelectorAll<HTMLCanvasElement>('.cl[data-view="console"] .ui-window')[i]!.querySelector("canvas")!;
  const g = c.getContext("2d");
  if (!g) return "no-2d";
  const d = g.getImageData(0, 0, c.width, Math.min(c.height, 400)).data;
  let h = 2166136261;
  for (let k = 0; k < d.length; k += 7) h = Math.imul(h ^ d[k]!, 16777619);
  return String(h >>> 0);
}, index);

test("frozen at a thumbnail scale: the same pixels while the camera moves, the output drawn once at rest, the active terminal live", async () => {
  test.setTimeout(120_000);
  // Three windows; the first one prints, the last one is active.
  await windows().first().locator(".terminal-host").click({ position: { x: 60, y: 60 } });
  await page.keyboard.type("while :; do date +%N; sleep 0.15; done\n", { delay: 5 });
  for (let i = 0; i < 2; i++) { await page.keyboard.press("Control+Shift+KeyD"); await expect(windows()).toHaveCount(i + 2); await page.waitForTimeout(500); }
  await page.waitForTimeout(800);
  await page.keyboard.press("Control+Shift+KeyG"); // canvas lock off: free zoom
  const zoomed = (ms: number) => page.evaluate((d) => new Promise<void>((done) => {
    const target = document.querySelector(".cl-viewport")!;
    const s0 = performance.now();
    const step = (t: number): void => { if (t - s0 > d) { done(); return; } target.dispatchEvent(new WheelEvent("wheel", { bubbles: true, cancelable: true, clientX: 720, clientY: 450, deltaY: 6, ctrlKey: true })); requestAnimationFrame(step); };
    requestAnimationFrame(step);
  }), ms);
  const zoomOut = zoomed(1800); // keeps the camera moving; ends at the thumbnail scale
  await page.waitForTimeout(900);
  const scale = await page.evaluate(() => Number(/scale\(([\d.]+)\)/.exec(document.querySelector<HTMLElement>(".cl-world")!.style.transform)?.[1] ?? 1));
  expect(scale).toBeLessThan(0.58);
  const p1 = await pixels(0);
  await page.waitForTimeout(500);
  const p2 = await pixels(0);
  const a1 = await pixels(2);
  await page.keyboard.type("echo live-while-moving", { delay: 5 });
  await page.waitForTimeout(150);
  const a2 = await pixels(2);
  await zoomOut;
  expect(p2, "the printing window drew nothing while the camera moved").toBe(p1);
  expect(a2, "the active window drew what was typed while the camera moved").not.toBe(a1);
  // At rest the held output is drawn.
  await page.waitForTimeout(900);
  const rest1 = await pixels(0);
  expect(rest1, "the output that arrived while frozen is drawn at rest").not.toBe(p2);
});
