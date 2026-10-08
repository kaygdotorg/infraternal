/**
 * At rest the canvas does no per-frame work (#114 follow-up). After a camera flight, every spring has settled: from
 * 600 ms after the flight's visible end, no style attribute is written anywhere and no requestAnimationFrame callback
 * runs. The tail is measured too: how long after the flight stopped being visible (the last frame that differs from the
 * final one by a quarter of a device pixel, or a zoom change of 0.05 %) the canvas kept writing styles.
 * Production server binary, real sessions, 1440x900.
 */
import { expect, test, type Page } from "playwright/test";
import { startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });
let server: RealServer;
let page: Page;

test.beforeAll(async ({ browser }) => {
  server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  await context.addInitScript(() => {
    const w = window as unknown as { __raf: number[]; __styles: Array<{ t: number; transform: string }> };
    w.__raf = []; w.__styles = [];
    const native = window.requestAnimationFrame.bind(window);
    window.requestAnimationFrame = (cb: FrameRequestCallback): number => native((t) => { w.__raf.push(performance.now()); cb(t); });
    new MutationObserver((records) => {
      const t = performance.now();
      const world = document.querySelector<HTMLElement>(".cl-world");
      for (const r of records) if (r.attributeName === "style") w.__styles.push({ t, transform: world?.style.transform ?? "" });
    }).observe(document, { attributes: true, attributeFilter: ["style"], subtree: true });
  });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill("rest_real");
  await page.locator("#setup-display-name").fill("Rest real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
});
test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

const parse = (t: string): [number, number, number] => { const m = /translate3d\((-?[\d.]+)px, (-?[\d.]+)px, 0(?:px)?\) scale\(([\d.]+)\)/.exec(t); return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : [0, 0, 1]; };

async function flight(label: string, go: () => Promise<void>): Promise<void> {
  await page.waitForTimeout(3500);
  await page.evaluate(() => { const w = window as unknown as { __raf: number[]; __styles: unknown[] }; w.__raf.length = 0; w.__styles.length = 0; });
  const t0 = await page.evaluate(() => performance.now());
  await go();
  await page.waitForTimeout(6000);
  const r = await page.evaluate(() => { const w = window as unknown as { __raf: number[]; __styles: Array<{ t: number; transform: string }> }; return { raf: [...w.__raf], styles: w.__styles.map((s) => ({ ...s })) }; });
  const finalT = parse(r.styles.filter((s) => s.transform).at(-1)?.transform ?? "");
  const dpr = 1;
  const differs = (s: { transform: string }): boolean => { const [x, y, z] = parse(s.transform); return Math.abs(x - finalT[0]) >= 0.25 / dpr || Math.abs(y - finalT[1]) >= 0.25 / dpr || Math.abs(z - finalT[2]) > 0.0005; };
  const visible = r.styles.filter((s) => s.transform && differs(s)).at(-1)?.t ?? t0;
  const lastWrite = r.styles.at(-1)?.t ?? visible;
  const lastRaf = r.raf.at(-1) ?? visible;
  const tail = Math.max(0, lastWrite - visible);
  const writesAfter = r.styles.filter((s) => s.t > visible + 600).length;
  const rafAfter = r.raf.filter((t) => t > visible + 600).length;
  console.log(`REST ${label}: flight visible for ${(visible - t0).toFixed(0)} ms; style writes continued ${tail.toFixed(0)} ms after it (last rAF ${(lastRaf - visible).toFixed(0)} ms after); from +600 ms: ${writesAfter} style writes, ${rafAfter} rAF callbacks`);
  expect(writesAfter, `${label}: style writes after rest`).toBe(0);
  expect(rafAfter, `${label}: rAF callbacks after rest`).toBe(0);
}

test("after a view flight, zero style writes and zero frames from 600 ms after it ends", async () => {
  await flight("flight to Settings", async () => { await page.locator(".cl-viewsbtn").click(); await page.locator('.cl-viewrow[data-view="settings"]').click(); });
  await flight("flight back to Console", async () => { await page.locator(".cl-viewsbtn").click(); await page.locator('.cl-viewrow[data-view="console"]').click(); });
});

test("after opening a window (layout springs, column flip, camera), the canvas is still", async () => {
  await flight("open a window", async () => { await page.locator(".tab-add").click(); });
});
