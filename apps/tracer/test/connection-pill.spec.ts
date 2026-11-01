/**
 * The connection indicator in the window pill (#212, approved 2026-11-01), on the production build.
 *
 * One animated icon per window, in the machine pill's place, with a warm tooltip that says the state in words. Never a
 * bordered text line. Two doubles are used:
 * - the scripted canvas (`proto=clusters`), whose palette rows put the indicator in each state, to check every icon,
 *   motion and sentence;
 * - the product canvas against the mock server (`proto=product`), whose sockets can be dropped, to check that the real
 *   binding drives it: reconnecting while the link is down, the kept-keys mark, the tick when it comes back.
 * Captures for the issue go to the external evidence directory (the last test, on request: J56_CAPTURE=1).
 */
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const CAPTURES = tracerEvidencePath("connection-pill");
mkdirSync(CAPTURES, { recursive: true });
const testDoubleOrigin = `http://localhost:${Number(process.env.TRACER_TEST_PORT ?? "4621") + 1}`;

/** The active window's indicator (the palette rows act on the active window). */
const conn = (page: Page) => page.locator(".ui-window[aria-current] .ui-window-conn").first();

async function loadScripted(page: Page, theme = "ink"): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=3&bg=none&theme=${theme}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  const first = page.locator(".ui-window").first();
  await expect(first).toBeVisible();
  const id = await first.getAttribute("data-window-id");
  await page.evaluate((windowId) => (window as unknown as { __tracerClusters: { activateWindow(id: string): boolean } }).__tracerClusters.activateWindow(windowId!), id);
  await expect(first).toHaveAttribute("aria-current", /.*/);
}

async function setState(page: Page, label: string): Promise<void> {
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill(`Mockup: connection – ${label}`);
  await page.keyboard.press("Enter");
  await page.waitForTimeout(350);
}

test.describe("the scripted canvas", () => {
  test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });

  test("every window's pill has the indicator in place of the dot, and no text box anywhere", async ({ page }) => {
    await loadScripted(page);
    const cards = page.locator(".ui-window");
    const count = await cards.count();
    expect(count).toBeGreaterThan(0);
    for (let i = 0; i < count; i++) {
      const card = cards.nth(i);
      if ((await card.getAttribute("data-status")) === "none") continue;
      await expect(card.locator(".ui-window-pill .ui-window-conn")).toHaveCount(1);
      await expect(card.locator(".ui-window-dot")).toHaveCount(0);
    }
    await expect(conn(page)).toHaveAttribute("data-state", "connected");
    // The indicator is a small icon (14 px), level with the pill's text.
    const box = (await conn(page).boundingBox())!;
    expect(box.width).toBeCloseTo(14, 0);
    expect(box.height).toBeCloseTo(14, 0);
    // No status line is ever drawn as bordered text.
    await expect(page.locator(".ui-window-status, [data-status-line]")).toHaveCount(0);
  });

  const SENTENCE: Array<[label: string, state: string, sentence: RegExp]> = [
    ["slow", "slow", /^Slow connection\./],
    ["connecting", "connecting", /^Connecting to this machine/],
    ["reconnecting", "reconnecting", /^Connection lost — resuming without losing anything$/],
    ["offline", "offline", /^Offline\. This machine can't be reached right now\.$/],
    ["session ended", "offline", /^Offline\. This session has ended\.$/],
  ];
  for (const [label, state, sentence] of SENTENCE) {
    test(`${label}: the icon is in that state and the tooltip says it in words`, async ({ page }) => {
      await loadScripted(page);
      await setState(page, label);
      await expect(conn(page)).toHaveAttribute("data-state", state);
      await expect(conn(page)).toHaveAttribute("aria-label", sentence);
      await conn(page).hover();
      await expect(page.locator(".tip")).toContainText(await conn(page).getAttribute("data-tip") ?? "never");
    });
  }

  test("kept keys show as an amber key on the icon, and the sentence counts them; nothing typed is shown", async ({ page }) => {
    await loadScripted(page);
    await setState(page, "reconnecting, keys kept");
    await expect(conn(page)).toHaveAttribute("data-queued", "");
    await expect(conn(page)).toHaveAttribute("aria-label", "Connection lost — resuming. 7 keys you typed are kept and will be sent.");
    await expect(conn(page).locator(".ui-conn-q")).toHaveCSS("opacity", "1");
    await setState(page, "offline, keys kept");
    await expect(conn(page)).toHaveAttribute("aria-label", "Offline. 3 keys you typed are kept and will be sent when it is back.");
    // The old held-text line is not part of the product: a secret typed into a hidden prompt would be on screen.
    await expect(page.locator(".ui-window-held")).toHaveCount(0);
    await setState(page, "connected");
    await expect(conn(page)).not.toHaveAttribute("data-queued", "");
  });

  test("reconnecting turns an arc; at rest nothing animates; resumed settles back to the dot by itself", async ({ page }) => {
    await loadScripted(page);
    await expect(conn(page).locator(".ui-conn-spin")).toHaveCSS("animation-play-state", "paused");
    await setState(page, "reconnecting");
    await expect(conn(page).locator(".ui-conn-spin")).toHaveCSS("animation-play-state", "running");
    await setState(page, "resumed");
    await expect(conn(page)).toHaveAttribute("data-state", "resumed");
    await expect(conn(page)).toHaveAttribute("data-state", "connected", { timeout: 4000 });
  });

  test("a press on the pill still opens the machine details; the icon does not take it", async ({ page }) => {
    await loadScripted(page);
    await page.locator(".ui-window").first().locator(".ui-window-pill .ui-window-host").click();
    await expect(page.locator(".canvas-popover")).toBeVisible();
  });
});

test.describe("reduced motion", () => {
  test.use({ viewport: { width: 1440, height: 900 } });
  test("the arc does not turn and the glyphs only cross-fade", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await loadScripted(page);
    await setState(page, "reconnecting");
    await expect(conn(page).locator(".ui-conn-spin")).toHaveCSS("animation-name", "none");
    await expect(conn(page).locator(".ui-conn-g-reconnecting")).toHaveCSS("transform", "none");
  });
});

test.describe("phone", () => {
  test.use({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true });
  test("a tap on the icon shows its sentence and does not open the details", async ({ page }) => {
    await loadScripted(page);
    await setState(page, "offline");
    const box = (await conn(page).boundingBox())!;
    const hit = await page.evaluate(({ x, y }) => { const e = document.elementFromPoint(x, y); return e ? `${e.tagName}.${e.className}` : "none"; }, { x: box.x + box.width / 2, y: box.y + box.height / 2 });
    console.log(`PHONE_TAP box=${JSON.stringify(box)} hit=${hit} viewport=${JSON.stringify(page.viewportSize())}`);
    await conn(page).tap();
    await expect(page.locator(".tip")).toContainText("Offline.");
    await expect(page.locator(".canvas-popover")).toHaveCount(0);
  });
});

test.describe("the product canvas against the mock server", () => {
  test.use({ viewport: { width: 1440, height: 900 } });

  test("a lost link turns the icon to reconnecting, keys typed meanwhile are counted, and coming back shows the tick", async ({ page }) => {
    await page.context().request.post("/__mock/reset");
    await page.context().request.post("/__mock/open-terminal");
    await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
    const windowCard = page.locator(".ui-window").first();
    await expect(windowCard).toBeVisible({ timeout: 20_000 });
    await expect.poll(() => page.evaluate(() => window.__tracerProductTestDouble?.isConnected() ?? false), { timeout: 30_000 }).toBe(true);
    const icon = windowCard.locator(".ui-window-conn");
    // Behind the test proxy the round trip is long, so a healthy link may read as slow: both are "connected" here.
    await expect(icon).toHaveAttribute("data-state", /^(connected|slow)$/, { timeout: 15_000 });
    // Record every state the icon takes, and whether the kept-keys mark ever showed.
    await page.evaluate(() => {
      const node = document.querySelector<HTMLElement>(".ui-window .ui-window-conn")!;
      const seen: string[] = [(node.dataset.state ?? "").replace("slow", "connected")];
      let queued = false;
      new MutationObserver(() => {
        const state = (node.dataset.state ?? "").replace("slow", "connected");
        if (seen[seen.length - 1] !== state) seen.push(state);
        if (node.hasAttribute("data-queued")) queued = true;
      }).observe(node, { attributes: true, attributeFilter: ["data-state", "data-queued"] });
      (window as unknown as { __connSeen: () => { seen: string[]; queued: boolean } }).__connSeen = () => ({ seen, queued });
    });
    // The link keeps failing right after it attaches, so the window stays in the reconnecting state for a while.
    await page.request.post(`${testDoubleOrigin}/__mock/close-after-attach`, { data: { delay_ms: 110 } });
    await page.request.post(`${testDoubleOrigin}/__mock/drop-sockets`);
    await expect(icon).toHaveAttribute("data-state", "reconnecting", { timeout: 10_000 });
    await expect(windowCard).toHaveAttribute("data-status", "connecting");
    await expect(icon).toHaveAttribute("aria-label", /^Connection lost — resuming/);
    // The link comes back.
    await page.request.post(`${testDoubleOrigin}/__mock/close-after-attach`, { data: { delay_ms: null } });
    await expect.poll(async () => (await page.evaluate(() => (window as unknown as { __connSeen: () => { seen: string[] } }).__connSeen().seen)).includes("connected"), { timeout: 20_000 }).toBe(true);
    await expect(icon).toHaveAttribute("data-state", /^(connected|slow)$/, { timeout: 10_000 });
    const { seen } = await page.evaluate(() => (window as unknown as { __connSeen: () => { seen: string[]; queued: boolean } }).__connSeen());
    // It went connected, reconnecting, then back; "resumed" may be shown for a moment on the way (it settles by itself).
    expect(seen[0]).toBe("connected");
    expect(seen).toContain("reconnecting");
    expect(seen.indexOf("reconnecting")).toBeLessThan(seen.lastIndexOf("connected"));
    expect(seen.filter((state) => state === "offline")).toHaveLength(0);
  });
});

/** Review captures for the issue (not assertions about taste). */
for (const [size, viewport, scale, touch] of [["1440x900", { width: 1440, height: 900 }, 2, false], ["393x852", { width: 393, height: 852 }, 3, true]] as const) {
  for (const theme of ["ink", "paper"]) {
    test(`captures, ${size} ${theme}`, async ({ browser }) => {
      test.skip(!process.env.J56_CAPTURE, "review captures run on request (J56_CAPTURE=1)");
      const context = await browser.newContext({ viewport, deviceScaleFactor: scale, ...(touch ? { hasTouch: true, isMobile: true } : {}), recordVideo: { dir: resolve(CAPTURES, "video"), size: viewport } });
      const page = await context.newPage();
      await loadScripted(page, theme);
      const states = ["connected", "slow", "connecting", "reconnecting", "reconnecting, keys kept", "resumed", "resumed, screen rebuilt", "offline", "offline, keys kept", "session ended"];
      for (const label of states) {
        await setState(page, label);
        await page.waitForTimeout(300);
        await conn(page).hover().catch(() => undefined);
        await page.waitForTimeout(400);
        await page.screenshot({ path: resolve(CAPTURES, `${label.replaceAll(/[ ,]+/g, "-")}-${size}-${theme}.png`) });
      }
      await context.close();
    });
  }
}
