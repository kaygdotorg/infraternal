/** Keeps live VT replies out of the PTY when Settings navigation restores the product canvas. */
import { expect, test, type APIRequestContext, type Page } from "playwright/test";
import { QUERY_OUTPUT } from "./terminal-query-fixture";

type MockState = {
  attach_count: number;
  accepted_input_bytes: number;
  output_sequence: string;
  session_id: string;
  active_socket_count: number;
  attached_stream_ids?: number[];
  attach_history?: Array<{ last_out_seq: string; output_sequence: string }>;
};

type ViewportCase = { name: string; width: number; height: number; mobile: boolean };
const VIEWPORTS: ViewportCase[] = [
  { name: "mobile", width: 393, height: 852, mobile: true },
  { name: "desktop", width: 1440, height: 900, mobile: false },
];
const testDoublePort = Number(process.env.TRACER_BACKEND_PORT ?? String(Number(process.env.TRACER_TEST_PORT ?? "4621") + 1));
const testDoubleOrigin = `http://localhost:${testDoublePort}`;
const mockUrl = (path: string): string => new URL(path, testDoubleOrigin).toString();
const SHELL_QUERY_OUTPUT = `\r\n$ printf 'VT_QUERY_FIXTURE\\n'\r\nVT_QUERY_FIXTURE\r\n${QUERY_OUTPUT}\r\n`;

const mockState = async (request: APIRequestContext): Promise<MockState> =>
  (await (await request.get(mockUrl("/__mock/state"))).json()) as MockState;

async function productProbe(page: Page): Promise<{ connected: boolean; screen: string; outputSequence: string; currentView: string }> {
  return page.evaluate(() => {
    const probe = window.__tracerProductTestDouble;
    return {
      connected: probe?.isConnected() ?? false,
      screen: probe?.screenText() ?? "",
      outputSequence: probe?.rendererMetrics()?.outputSequence ?? "0",
      currentView: probe?.currentView() ?? "",
    };
  });
}

async function consoleSurfacePixels(page: Page): Promise<number> {
  return page.evaluate(() => {
    const canvas = document.querySelector<HTMLCanvasElement>('.cl[data-view="console"] .terminal-host canvas');
    return canvas ? canvas.width * canvas.height : -1;
  });
}

async function openProductCanvas(page: Page, viewport: ViewportCase): Promise<void> {
  const request = page.context().request;
  expect((await request.post(mockUrl("/__mock/reset"))).ok()).toBe(true);
  expect((await request.post(mockUrl("/__mock/open-terminal"))).ok()).toBe(true);
  await page.setViewportSize({ width: viewport.width, height: viewport.height });
  await page.goto("/?mock=1&proto=product&layout=server&theme=ink&bg=none");
  await expect(page.locator('.cl[data-view="console"] .ui-window')).toHaveCount(1, { timeout: 30_000 });
  await expect.poll(() => productProbe(page).then((probe) => probe.connected), { timeout: 30_000 }).toBe(true);
  await expect.poll(async () => (await mockState(request)).attach_count, { timeout: 15_000 }).toBeGreaterThan(0);
  await expect.poll(async () => (await mockState(request)).active_socket_count, { timeout: 15_000 }).toBeGreaterThan(0);
  await expect.poll(async () => (await mockState(request)).attached_stream_ids?.length ?? 0, { timeout: 15_000 }).toBeGreaterThan(0);
  await expect.poll(() => consoleSurfacePixels(page), { timeout: 15_000 }).toBeGreaterThan(0);
}

async function waitForOutputToSettle(page: Page, request: APIRequestContext): Promise<void> {
  await expect.poll(async () => {
    const state = await mockState(request);
    const sequence = await productProbe(page).then((probe) => probe.outputSequence);
    return BigInt(sequence) >= BigInt(state.output_sequence);
  }, { timeout: 30_000 }).toBe(true);
}

async function clickPaletteAction(page: Page, label: string, action: string): Promise<void> {
  await page.keyboard.press("Control+Shift+K");
  const input = page.locator("#palette-input");
  await expect(input).toBeVisible({ timeout: 10_000 });
  await input.fill(label);
  const row = page.locator(`.result[data-action="${action}"]`);
  await expect(row).toBeVisible({ timeout: 10_000 });
  await row.click();
}

async function openSettings(page: Page): Promise<void> {
  const toggle = page.locator("#sidebar-toggle");
  if (await toggle.getAttribute("aria-expanded") !== "true") await toggle.click();
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
  await page.locator(".ui-sidebar-foot .ui-sidebar-settings").click();
  await expect.poll(() => productProbe(page).then((probe) => probe.currentView), { timeout: 10_000 }).toBe("settings");
}

async function assertNoNewInputOrScreen(
  page: Page,
  request: APIRequestContext,
  baselineInput: number,
  baselineScreen: string,
): Promise<void> {
  await waitForOutputToSettle(page, request);
  const state = await mockState(request);
  expect(state.accepted_input_bytes, `the PTY accepted ${state.accepted_input_bytes - baselineInput} extra bytes`).toBe(baselineInput);
  expect((await productProbe(page)).screen, "the restored terminal screen gained stray characters").toBe(baselineScreen);
}

for (const viewport of VIEWPORTS) {
  test(`${viewport.name}: Settings, window changes, background and reconnect preserve the PTY input log`, async ({ browser, playwright }, testInfo) => {
    test.setTimeout(360_000);
    const context = await browser.newContext({
      viewport: { width: viewport.width, height: viewport.height },
      deviceScaleFactor: viewport.mobile ? 3 : 1,
      isMobile: viewport.mobile,
      hasTouch: viewport.mobile,
    });
    const page = await context.newPage();
    const request = context.request;
    const errors: string[] = [];
    let testFailed = false;
    page.on("pageerror", (error) => errors.push(error.message));
    try {
      await openProductCanvas(page, viewport);
      // Model the output of a printf command in a shell with echo disabled, so device replies cannot loop back as queries.
      const sent = await request.post(mockUrl("/__mock/text-output"), { data: { text: SHELL_QUERY_OUTPUT, echo_input: false } });
      expect(sent.ok(), `query fixture HTTP ${sent.status()}: ${sent.ok() ? "" : await sent.text()}; state=${JSON.stringify(await mockState(request))}`).toBe(true);
      await expect.poll(async () => (await mockState(request)).accepted_input_bytes, { timeout: 15_000 }).toBeGreaterThan(0);
      await waitForOutputToSettle(page, request);
      const live = await mockState(request);
      const baselineInput = live.accepted_input_bytes;
      const baselineScreen = (await productProbe(page)).screen;
      expect(baselineScreen).toContain("VT_QUERY_FIXTURE");

      const attachHistoryCount = live.attach_history?.length ?? 0;
      for (let cycle = 0; cycle < 5; cycle++) {
        await openSettings(page);
        // Move between Settings sections while the terminal is parked, then return to its Console window.
        await clickPaletteAction(page, "Terminal › Typing", "canvas:settings:terminal.typing");
        await clickPaletteAction(page, "About › Version", "canvas:settings:about.version");
        await clickPaletteAction(page, "Go to Console", "canvas:view:console");
        await expect.poll(() => productProbe(page).then((probe) => probe.currentView), { timeout: 10_000 }).toBe("console");
        await assertNoNewInputOrScreen(page, request, baselineInput, baselineScreen);
      }

      // A PWA restore remounts the terminal with a fresh renderer at output cursor zero.
      await page.locator("#sidebar-toggle").getAttribute("aria-expanded").then(async (expanded) => {
        if (expanded === "true") await page.locator("#sidebar-toggle").click();
      });
      await page.reload({ waitUntil: "domcontentloaded" });
      await expect(page.locator('.cl[data-view="console"] .ui-window')).toHaveCount(1, { timeout: 30_000 });
      await expect.poll(() => productProbe(page).then((probe) => probe.connected), { timeout: 30_000 }).toBe(true);
      await expect.poll(async () => (await mockState(request)).attach_count, { timeout: 15_000 }).toBeGreaterThan(live.attach_count);
      const reopened = await mockState(request);
      expect(reopened.session_id).toBe(live.session_id);
      const newAttaches = reopened.attach_history?.slice(attachHistoryCount) ?? [];
      expect(newAttaches.some((attach) => attach.last_out_seq === "0"), `reload did not replay from cursor zero: ${JSON.stringify(newAttaches)}`).toBe(true);
      await expect.poll(() => consoleSurfacePixels(page), { timeout: 15_000 }).toBeGreaterThan(0);
      await assertNoNewInputOrScreen(page, request, baselineInput, baselineScreen);

      // iOS background/foreground sends visibilitychange without replacing the app document.
      await page.evaluate(() => {
        Object.defineProperty(document, "hidden", { configurable: true, get: () => true });
        Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
        document.dispatchEvent(new Event("visibilitychange"));
      });
      await expect.poll(() => consoleSurfacePixels(page), { timeout: 10_000 }).toBe(0);
      await page.evaluate(() => {
        Object.defineProperty(document, "hidden", { configurable: true, get: () => false });
        Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
        document.dispatchEvent(new Event("visibilitychange"));
      });
      await expect.poll(() => consoleSurfacePixels(page), { timeout: 10_000 }).toBeGreaterThan(0);
      await assertNoNewInputOrScreen(page, request, baselineInput, baselineScreen);

      const beforeReconnect = await mockState(request);
      await context.setOffline(true);
      await page.evaluate(() => window.__tracerProductTestDouble?.dropConnection());
      await expect.poll(() => productProbe(page).then((probe) => probe.connected), { timeout: 30_000 }).toBe(false);
      await context.setOffline(false);
      await expect.poll(() => productProbe(page).then((probe) => probe.connected), { timeout: 30_000 }).toBe(true);
      await expect.poll(async () => (await mockState(request)).attach_count, { timeout: 30_000 }).toBeGreaterThan(beforeReconnect.attach_count);
      await assertNoNewInputOrScreen(page, request, baselineInput, baselineScreen);
      expect(errors).toEqual([]);
      const finalState = await mockState(request);
      const finalProbe = await productProbe(page);
      console.log("SETTINGS_QUERY_ROUNDTRIP", JSON.stringify({
        viewport: `${viewport.width}x${viewport.height}`,
        cycles: 5,
        acceptedInputBytes: { before: baselineInput, after: finalState.accepted_input_bytes },
        outputSequence: finalState.output_sequence,
        reloadAttachCursorZero: newAttaches.some((attach) => attach.last_out_seq === "0"),
        reloadAttachDelta: reopened.attach_count - live.attach_count,
        reconnectAttachDelta: finalState.attach_count - beforeReconnect.attach_count,
        screenUnchanged: finalProbe.screen === baselineScreen,
      }));
      const screenshotPath = testInfo.outputPath(`${viewport.name}-settings-roundtrip.png`);
      await page.screenshot({ path: screenshotPath });
      await testInfo.attach(`${viewport.name} Settings roundtrip`, { path: screenshotPath, contentType: "image/png" });
    } catch (error) {
      testFailed = true;
      throw error;
    } finally {
      const cleanupRequest = await playwright.request.newContext();
      try {
        let cleanupError: unknown;
        try {
          expect((await cleanupRequest.post(mockUrl("/__mock/drop-sockets"))).ok()).toBe(true);
          await expect.poll(async () => (await mockState(cleanupRequest)).active_socket_count, { timeout: 10_000 }).toBe(0);
        } catch (error) {
          cleanupError = error;
        }
        try { await context.close(); } catch (error) { cleanupError ??= error; }
        // Preserve the first regression error if teardown also loses the mock server.
        if (cleanupError !== undefined && !testFailed) throw cleanupError;
      } finally {
        await cleanupRequest.dispose();
      }
    }
  });
}
