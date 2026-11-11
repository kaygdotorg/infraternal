// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The four bugs J509 found on real devices in the hosts sidebar and the machine panel (#500, J528), each checked in a
 * production build at 1440, 402 and 375 px wide:
 *
 * 1. A registered host that is offline because the CA is locked stays listed in the sidebar's Console, says
 *    "locked", and offers "Unlock to connect" inline; unlocking runs the passkey ceremony.
 * 2. A connected host with no session of its own is still a row of the Console tree, so its swipe-to-remove is reachable.
 * 3. On a short phone the Remove question's Keep and Remove buttons are in view as soon as the question opens.
 * 4. The machine panel opens at the height it keeps: reading the host's facts afterwards never moves its height.
 *
 * Functional: the socket interceptor answers the host list and the host facts (the test double has no remote agents); nothing
 * here asserts speed. Heights are layout heights (`offsetHeight`), which the open animation's scale does not change.
 */
import { expect, test, type Page } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";
import { tracerEvidencePath } from "./evidence-path";

/** The admitted id of the one added host. */
const HOST_ID = "33333333-4444-4555-8666-777777777777";
/** The added host's name, as the sidebar lists it. */
const HOST = "worker-j528";
/** What the server's own agent reports once its facts arrive. */
const FACTS = { os: "Debian GNU/Linux", version: "13", kernel: "6.12.57", architecture: "aarch64", model: "Raspberry Pi 5", cpuModel: "Cortex-A76", logicalCpus: 4, memory: { usedBytes: 2e9, totalBytes: 8e9 }, rootDisk: { usedBytes: 1e10, totalBytes: 6e10 }, uptimeSeconds: 86_400, loadAverage: [0.1, 0.2, 0.3], executionUid: 0, mode: "embedded", engines: ["Podman"] };
/** The three review widths; the phone heights are short on purpose (Safari's bars take a third of an iPhone). */
const SIZES = [
  { id: "1440", viewport: { width: 1440, height: 900 }, touch: false },
  { id: "402", viewport: { width: 402, height: 720 }, touch: true },
  { id: "375", viewport: { width: 375, height: 640 }, touch: true },
] as const;
type Size = (typeof SIZES)[number];

/** A context at `size`, as a phone (touch, mobile) or a desktop. */
async function newPage(browser: import("playwright/test").Browser, size: Size): Promise<{ page: Page; close: () => Promise<void> }> {
  const context = await browser.newContext({ viewport: size.viewport, deviceScaleFactor: size.touch ? 3 : 1, ...(size.touch ? { hasTouch: true, isMobile: true } : {}) });
  return { page: await context.newPage(), close: () => context.close() };
}

/**
 * Serves the sockets calls this spec needs: one added host (`online` or not), the server's facts after `factsDelayMs`, and the
 * CA's lock status. Returns the CA calls other than the status read (an unlock attempt shows up there).
 */
async function serve(page: Page, options: { online: boolean; locked?: boolean; factsDelayMs?: number }): Promise<{ caCalls: string[] }> {
  const caCalls: string[] = [];
  await page.route("**/remote/ca/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/status")) { await route.fulfill({ json: { initialized: true, locked: options.locked === true, roots: [] } }); return; }
    caCalls.push(path);
    await route.fulfill({ status: 503, json: {} });
  });
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const server = socket.connectToServer();
    const reply = (callId: number, ok: boolean, value: unknown) => socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId, ok, json: new TextEncoder().encode(JSON.stringify(value)) })));
    socket.onMessage((message) => {
      if (typeof message === "string") { server.send(message); return; }
      const { frame } = decodeMuxedFrame(message);
      if (frame.type === "Call" && frame.actionId === "host.facts.read") {
        // sleep: the host's facts arrive late on purpose, so the panel is measured before and after them
        setTimeout(() => reply(frame.callId, true, FACTS), options.factsDelayMs ?? 0);
        return;
      }
      if (frame.type === "Call" && frame.actionId === "remote.host.list") {
        reply(frame.callId, true, { hosts: [{ id: HOST_ID, name: HOST, user: "operator", os: "Debian GNU/Linux", address: "operator@worker.lan", online: options.online }], next: null });
        return;
      }
      // The test double closes the socket on a session open for a host it does not know.
      if (frame.type === "Call" && frame.actionId === "ssh.session.open") { reply(frame.callId, false, { error: "unavailable" }); return; }
      server.send(message);
    });
    server.onMessage((message) => socket.send(message));
  });
  return { caCalls };
}

/** Opens the product canvas on the double with the interceptor in place and waits for the first window. */
async function openProduct(page: Page): Promise<void> {
  await page.request.post("/__mock/reset");
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none&theme=ink");
  await expect(page.locator(".ui-window").first().locator(".ui-window-host")).toHaveText(/\S/, { timeout: 40_000 });
}

/** Opens the sidebar (the Views list) and waits for the Console's hosts to be drawn. */
async function openSidebar(page: Page): Promise<void> {
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1, { timeout: 30_000 });
}

/** The sidebar's row for the host. */
const hostRow = (page: Page) => page.locator(`#tree li.bm-subhead[data-id="h:${HOST}"]`);

for (const size of SIZES) {
  test(`bug 1 ${size.id}: a host offline behind the CA lock stays listed, says locked and unlocks inline`, async ({ browser }) => {
    const { page, close } = await newPage(browser, size);
    try {
      const { caCalls } = await serve(page, { online: false, locked: true });
      await openProduct(page);
      await openSidebar(page);
      await expect(hostRow(page), "the registered host is listed although it is offline").toBeVisible({ timeout: 30_000 });
      await expect(hostRow(page)).toContainText("locked");
      const unlock = page.locator('#tree .bm-leaf[data-id="u:' + HOST + '"]');
      await expect(unlock, "an inline way to unlock, under the host").toBeVisible();
      await expect(unlock).toContainText("Unlock to connect");
      await page.screenshot({ path: tracerEvidencePath("j528", `bug1-sidebar-${size.id}.png`) });
      await unlock.click();
      await expect.poll(() => caCalls.length, { message: "the unlock row starts the passkey ceremony" }).toBeGreaterThan(0);
    } finally { await close(); }
  });

  test(`bug 2 ${size.id}: a connected host without a session is a row of the Console tree`, async ({ browser }) => {
    const { page, close } = await newPage(browser, size);
    try {
      await serve(page, { online: true });
      await openProduct(page);
      await openSidebar(page);
      await expect(hostRow(page), "every admitted host is in the tree").toBeVisible({ timeout: 30_000 });
      await expect(page.locator('#tree .bm-leaf[data-id^="u:"]'), "a connected host has nothing to unlock").toHaveCount(0);
      await page.screenshot({ path: tracerEvidencePath("j528", `bug2-tree-${size.id}.png`) });
    } finally { await close(); }
  });

  test(`bug 3 ${size.id}: the Remove question's Keep and Remove buttons are in view when it opens`, async ({ browser }) => {
    const { page, close } = await newPage(browser, size);
    try {
      await page.request.post("/__mock/reset");
      await page.goto("/?mock=1&proto=windows&bg=none&fixture=none&removal=1");
      await expect.poll(() => page.evaluate(() => (window as unknown as { __tracerCanvas?: { windows(): string[] } }).__tracerCanvas?.windows().length ?? 0), { timeout: 30_000 }).toBeGreaterThan(2);
      await page.locator(".ui-window").first().locator(".ui-window-pill").click();
      await expect(page.locator(".canvas-popover")).toBeVisible();
      await page.locator(".canvas-popover .ui-tab", { hasText: "Connection" }).click();
      await page.locator(".canvas-popover-action .ui-sp-row").click();
      const ask = page.locator(".canvas-popover-ask");
      await expect(ask).toBeVisible();
      const seen = await page.evaluate(() => {
        const scroller = document.querySelector<HTMLElement>(".canvas-popover-scroll")!;
        const box = scroller.getBoundingClientRect();
        return [...document.querySelectorAll<HTMLElement>(".canvas-popover-ask-actions .ui-button")].map((b) => { const r = b.getBoundingClientRect(); return { name: b.textContent, top: r.top - box.top, bottom: box.bottom - r.bottom, inViewport: r.bottom <= innerHeight && r.top >= 0 }; });
      });
      expect(seen.map((b) => b.name)).toEqual(["Keep", "Remove"]);
      for (const b of seen) {
        expect(b.top, `${b.name} is below the top of the panel's list`).toBeGreaterThanOrEqual(0);
        expect(b.bottom, `${b.name} is above the bottom of the panel's list, with no scrolling`).toBeGreaterThanOrEqual(0);
        expect(b.inViewport, `${b.name} is on the screen`).toBe(true);
      }
      await page.screenshot({ path: tracerEvidencePath("j528", `bug3-question-${size.id}.png`) });
    } finally { await close(); }
  });

  test(`bug 4 ${size.id}: the machine panel opens at the height it keeps when the facts arrive`, async ({ browser }) => {
    const { page, close } = await newPage(browser, size);
    try {
      await serve(page, { online: true, factsDelayMs: 900 });
      await openProduct(page);
      await page.locator(".ui-window").first().locator(".ui-window-pill").click();
      const panel = page.locator(".canvas-popover");
      await expect(panel).toBeVisible();
      // Record the layout height on every frame until the facts have landed (the Kernel row shows its value), and a little after.
      const heights = await page.evaluate(() => new Promise<{ t: number; h: number; loaded: boolean }[]>((resolve) => {
        const out: { t: number; h: number; loaded: boolean }[] = [];
        const start = performance.now();
        const tick = (): void => {
          const el = document.querySelector<HTMLElement>(".canvas-popover");
          const loaded = [...document.querySelectorAll(".canvas-popover .ui-kv-key")].some((k) => k.textContent === "Kernel" && /6\.12/.test(k.parentElement?.textContent ?? ""));
          if (el) out.push({ t: Math.round(performance.now() - start), h: el.offsetHeight, loaded });
          if (performance.now() - start < 2200) requestAnimationFrame(tick); else resolve(out);
        };
        tick();
      }));
      expect(heights.some((s) => s.loaded), "the facts arrived during the recording").toBe(true);
      const opened = heights[0]!.h;
      const spread = Math.max(...heights.map((s) => s.h)) - Math.min(...heights.map((s) => s.h));
      expect(spread, `the panel opened at ${opened}px and never moved (samples: ${JSON.stringify(heights.filter((_, i) => i % 15 === 0))})`).toBeLessThanOrEqual(1);
      await page.screenshot({ path: tracerEvidencePath("j528", `bug4-panel-${size.id}.png`) });
    } finally { await close(); }
  });
}
