// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Proves that the production canvas document carries one account's appearance between real browser clients,
 * while each tab keeps its own camera and old browser-only appearance values migrate once.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { isMacPlatform } from "../../../packages/ui/src/platform";
import { createThemeStore } from "../src/canvas/themes/model";
import { cache, watchLayout } from "./layout-observer";
import { expect, test, type Browser, type Page } from "playwright/test";
import { personName, startRealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";

test.setTimeout(240_000);
/** Finds the first real canvas window so each browser assertion can wait on its rendered document. */
const windows = (page: Page) => page.locator('.cl[data-view="console"] .ui-window');

/** Waits for the server snapshot and the account's outstanding canvas edits to settle. */
async function settled(page: Page): Promise<void> {
  await expect.poll(async () => (await cache(page)).initialized, { timeout: 30_000 }).toBe(true);
  await expect.poll(async () => (await cache(page)).pending.length, { timeout: 30_000 }).toBe(0);
  await expect(page.locator(".ui-toast-message:visible").filter({ hasText: "Not saved — keep this tab open" })).toHaveCount(0);
}

/** Creates one real account with a software passkey and waits for its first canvas window. */
async function enrol(page: Page, server: { origin: string; token: string }): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("appearance_sync"));
  await page.locator("#setup-display-name").fill("Appearance sync");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await expect(windows(page)).toHaveCount(1, { timeout: 60_000 });
}

/** Changes one palette value through the real command palette with the browser's platform shortcut. */
async function choosePaletteValue(page: Page, value: string): Promise<void> {
  await page.keyboard.press(await page.evaluate(isMacPlatform) ? "Meta+K" : "Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible({ timeout: 10_000 });
  await page.locator("#palette-input").fill(value);
  const option = page.locator("#palette-results [role=option]").filter({ hasText: value }).first();
  await expect(option).toBeVisible({ timeout: 10_000 });
  await option.click();
}

/** Changes the browser's OS colour-scheme signal and waits until its media query reports the new value. */
async function changeColorScheme(page: Page, colorScheme: "dark" | "light"): Promise<void> {
  const wasDark = await page.evaluate(() => matchMedia("(prefers-color-scheme: dark)").matches);
  const isDark = colorScheme === "dark";
  if (wasDark === isDark) return;
  const mediaChanged = page.waitForFunction((initial) => matchMedia("(prefers-color-scheme: dark)").matches !== initial, wasDark);
  await page.emulateMedia({ colorScheme });
  await mediaChanged;
}

/** Returns the world transform that represents this tab's camera framing. */
async function cameraTransform(page: Page): Promise<string> {
  return page.locator(".cl-world").evaluate((world) => (world as HTMLElement).style.transform);
}

/** Turns canvas lock off and pans through the same wheel path used by trackpads. */
async function panCamera(page: Page): Promise<void> {
  // The browser may run on a different OS from the Playwright runner, so use the visible control instead of a platform chord.
  await page.getByRole("button", { name: /^Canvas lock on/ }).first().click();
  await expect(page.getByRole("button", { name: /^Canvas lock off/ }).first()).toBeVisible();
  await page.evaluate(() => new Promise<void>((done) => {
    const target = document.querySelector(".cl-viewport")!;
    const start = performance.now();
    const step = (now: number): void => {
      if (now - start >= 300) { done(); return; }
      target.dispatchEvent(new WheelEvent("wheel", {
        deltaX: 24, deltaY: 9, clientX: 640, clientY: 400, bubbles: true, cancelable: true,
      }));
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }));
  // sleep: let the camera's final spring settle after the last trackpad wheel event.
  await page.waitForTimeout(200);
}

/** A rendered frame interval on the client receiving the account appearance. */
interface FrameSample {
  from: number;
  to: number;
  intervalMs: number;
  visibility: DocumentVisibilityState;
  focused: boolean;
}

/** A root appearance attribute changed while the browser was rendering frames. */
interface AppearanceMutation {
  at: number;
  attribute: string;
  value: string | null;
}

/** The frame and appearance observations collected from the receiving client. */
interface FrameTrace {
  samples: FrameSample[];
  mutations: AppearanceMutation[];
}

/** Cumulative renderer counters returned by Chromium's Performance domain. */
type RendererMetrics = Record<string, number>;

/** Reads renderer work counters for one page without recording network or page-content traces. */
async function startRendererMetrics(page: Page): Promise<{ sample(): Promise<RendererMetrics>; close(): Promise<void> }> {
  const session = await page.context().newCDPSession(page);
  await session.send("Performance.enable");
  return {
    async sample() {
      const response = await session.send("Performance.getMetrics") as { metrics: Array<{ name: string; value: number }> };
      return Object.fromEntries(response.metrics.map(({ name, value }) => [name, value]));
    },
    close: () => session.detach(),
  };
}

/** Reports the cumulative main-thread counters that changed between two renderer samples. */
function rendererMetricDelta(before: RendererMetrics | undefined, after: RendererMetrics | undefined): RendererMetrics {
  if (!before || !after) return {};
  const names = ["TaskDuration", "ScriptDuration", "RecalcStyleDuration", "LayoutDuration", "DevToolsCommandDuration", "ProcessTime"];
  return Object.fromEntries(names.flatMap((name) => before[name] === undefined || after[name] === undefined
    ? []
    : [[name, Number((after[name]! - before[name]!).toFixed(4))]]));
}

/** The look window covers the changed frame and twelve following frames, including the 180 ms window-border colour transition. */
const APPEARANCE_FRAME_WINDOW = 12;

/** Waits for a fixed number of rendered frames without tying the spec to a wall-clock sleep. */
async function waitForFrames(page: Page, count: number): Promise<void> {
  await page.evaluate((frames) => new Promise<void>((resolve) => {
    const next = (): void => { if (frames-- <= 1) resolve(); else requestAnimationFrame(next); };
    requestAnimationFrame(next);
  }), count);
}

/** Selects the changed frame and its following transition frames for one visible appearance update. */
function measureAppearanceFrames(trace: FrameTrace, attribute: string, value: string): { mutations: AppearanceMutation[]; samples: FrameSample[] } {
  const mutations = trace.mutations.filter((item) => item.attribute === attribute && item.value === value);
  const indexes = new Set<number>();
  for (const mutation of mutations) {
    const changedAt = trace.samples.findIndex(({ from, to }) => from <= mutation.at && mutation.at <= to);
    if (changedAt < 0) continue;
    for (let index = changedAt; index <= changedAt + APPEARANCE_FRAME_WINDOW && index < trace.samples.length; index++) indexes.add(index);
  }
  return { mutations, samples: [...indexes].sort((left, right) => left - right).map((index) => trace.samples[index]!) };
}

/** Records rendered frame intervals on the foreground client so background scheduling cannot masquerade as lost appearance frames. */
async function startFrameCapture(page: Page): Promise<void> {
  await page.bringToFront();
  await page.evaluate(() => {
    const root = document.documentElement;
    const samples: FrameSample[] = [];
    const mutations: AppearanceMutation[] = [];
    let active = true, previous: number | undefined;
    const observer = new MutationObserver((records) => {
      for (const record of records) {
        const attribute = record.attributeName;
        if (attribute) mutations.push({ at: performance.now(), attribute, value: root.getAttribute(attribute) });
      }
    });
    observer.observe(root, { attributes: true, attributeFilter: ["data-look", "data-font"] });
    const capture = { samples, mutations, stop: () => { active = false; observer.disconnect(); } };
    (window as unknown as { __appearanceFrameCapture?: typeof capture }).__appearanceFrameCapture = capture;
    const frame = (now: number): void => {
      if (!active) return;
      // Use two RAF timestamps: performance.now() just before the first RAF is not its frame boundary.
      if (previous !== undefined) samples.push({ from: previous, to: now, intervalMs: now - previous, visibility: document.visibilityState, focused: document.hasFocus() });
      previous = now;
      requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  });
}

/** Stops the animation-frame sample and returns its frame and appearance observations. */
async function stopFrameCapture(page: Page): Promise<FrameTrace> {
  return page.evaluate(() => {
    const capture = (window as unknown as { __appearanceFrameCapture?: FrameTrace & { stop(): void } }).__appearanceFrameCapture;
    capture?.stop();
    return { samples: capture?.samples ?? [], mutations: capture?.mutations ?? [] };
  });
}

/** Captures the canvas requests and snapshots used by this page for first-paint evidence. */
function observeCanvasWire(page: Page, serverOrigin: string) {
  const calls: Array<{ actionId: string; input: Record<string, unknown> }> = [];
  const snapshots: Array<{ revision: number; carriesLook: boolean; receivedAt: number }> = [];
  const appearanceHttpRequests: string[] = [];
  const origin = new URL(serverOrigin).origin;
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.origin === origin && /appearance|look/i.test(url.pathname)) appearanceHttpRequests.push(`${request.method()} ${url.pathname}`);
  });
  page.on("websocket", (socket) => {
    const sent = new WebSocketFrameDecoder(), received = new WebSocketFrameDecoder();
    socket.on("framesent", ({ payload }) => {
      if (typeof payload === "string") return;
      sent.feed(new Uint8Array(payload), (_stream, frame) => {
        if (frame.type !== "Call") return;
        let input: Record<string, unknown> = {};
        try { input = JSON.parse(new TextDecoder().decode(frame.inputJson)) as Record<string, unknown>; } catch { /* Calls without JSON have no canvas input. */ }
        calls.push({ actionId: frame.actionId, input });
      });
    });
    socket.on("framereceived", ({ payload }) => {
      if (typeof payload === "string") return;
      received.feed(new Uint8Array(payload), (_stream, frame) => {
        if (frame.type !== "Event") return;
        let event: Record<string, unknown>;
        try { event = JSON.parse(new TextDecoder().decode(frame.eventJson)) as Record<string, unknown>; } catch { return; }
        if (event.type !== "canvas.layout.snapshot") return;
        const document = event.document as Record<string, unknown> | undefined;
        snapshots.push({ revision: Number(event.revision), carriesLook: Boolean(document?.look), receivedAt: Date.now() });
      });
    });
  });
  return { calls, snapshots, appearanceHttpRequests };
}

/** Produces the old first-paint cache shape with values that conflict with newer standalone preferences. */
function legacyLookCache(): unknown {
  const saved = createThemeStore({ colors: "mocha", font: "maple-mono-nf", uiSize: 100 }).snapshot();
  const selected = saved.themes.find((theme) => theme.id === saved.selected);
  return { ...saved, themes: selected ? [selected] : [] };
}

test("theme and font changes reach the same account live and after reload without moving either camera", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4567) });
  const evidence = tracerEvidencePath("appearance-sync");
  await mkdir(evidence, { recursive: true });
  const neutralPage = await browser.newPage({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 2 });
  await neutralPage.goto("about:blank");
  await startFrameCapture(neutralPage);
  await waitForFrames(neutralPage, APPEARANCE_FRAME_WINDOW);
  const neutralFrames = await stopFrameCapture(neutralPage);
  expect(neutralFrames.samples.every(({ intervalMs }) => intervalMs >= 0), "frame intervals use consecutive RAF timestamps").toBe(true);
  console.log(`APPEARANCE_NEUTRAL_FRAMES ${JSON.stringify({ intervalsMs: neutralFrames.samples.map(({ intervalMs }) => intervalMs), focusedFrames: neutralFrames.samples.filter(({ focused }) => focused).length })}`);
  await neutralPage.close();
  const first = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 2, ignoreHTTPSErrors: true });
  const second = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 2, ignoreHTTPSErrors: true, colorScheme: "light" });
  /** Keeps the first assertion or navigation error if a disconnected remote browser also rejects cleanup. */
  let bodyFailure: { error: unknown } | undefined;
  let rendererProbe: Awaited<ReturnType<typeof startRendererMetrics>> | undefined;
  try {
    const a = watchLayout(await first.newPage());
    await enrol(a, server); await settled(a);
    await second.addCookies(await first.cookies());
    const b = watchLayout(await second.newPage());
    const wire = observeCanvasWire(b, server.origin);
    const navigationStartedAt = Date.now();
    await b.goto(server.origin + "/");
    await expect(windows(b)).toHaveCount(1); await settled(b);
    const snapshot = wire.snapshots[0];
    expect(snapshot).toBeDefined();
    const aCameraBefore = await cameraTransform(a);
    const bCamera = await cameraTransform(b);
    const firstContentfulPaintMs = await b.evaluate(() => performance.getEntriesByType("paint").find((entry) => entry.name === "first-contentful-paint")?.startTime ?? null);

    await panCamera(a);
    await expect.poll(() => cameraTransform(a)).not.toBe(aCameraBefore);
    let aCamera = await cameraTransform(a);
    expect(await cameraTransform(b)).toBe(bCamera);

    rendererProbe = browser.browserType().name() === "chromium" ? await startRendererMetrics(b) : undefined;
    const baselineRendererBefore = await rendererProbe?.sample();
    await startFrameCapture(b);
    await waitForFrames(b, APPEARANCE_FRAME_WINDOW);
    const baselineFrames = await stopFrameCapture(b);
    const baselineRendererAfter = await rendererProbe?.sample();
    console.log(`APPEARANCE_BASELINE_FRAMES ${JSON.stringify({ intervalsMs: baselineFrames.samples.map(({ intervalMs }) => intervalMs), focusedFrames: baselineFrames.samples.filter(({ focused }) => focused).length })}`);

    await startFrameCapture(b);
    const themeRendererBefore = await rendererProbe?.sample();
    const themeWindowStartedAt = await b.evaluate(() => performance.now());
    await choosePaletteValue(a, "Theme: Solid");
    await expect.poll(async () => {
      const look = (await cache(b)).canonical.look;
      return look?.selected === "solid";
    }, { timeout: 30_000 }).toBe(true);
    await expect.poll(() => b.locator("html").getAttribute("data-look"), { timeout: 30_000 }).toBe("solid");
    const themeRendererApplied = await rendererProbe?.sample();
    await waitForFrames(b, APPEARANCE_FRAME_WINDOW);
    const themeTrace = await stopFrameCapture(b);
    const themeRendererAfter = await rendererProbe?.sample();
    const themeActionMeasures = await b.evaluate((startedAt) => performance.getEntriesByType("measure")
      .filter((entry) => entry.name.startsWith("appearance:") && entry.startTime >= startedAt)
      .map((entry) => ({ name: entry.name, durationMs: entry.duration, startTimeMs: entry.startTime })), themeWindowStartedAt);

    await startFrameCapture(b);
    const fontRendererBefore = await rendererProbe?.sample();
    const fontWindowStartedAt = await b.evaluate(() => performance.now());
    await choosePaletteValue(a, "Fira Code");
    await expect.poll(async () => {
      const look = (await cache(b)).canonical.look;
      return look?.selected === "solid" && look.themes.find((theme) => theme.id === "solid")?.font === "fira-code";
    }, { timeout: 30_000 }).toBe(true);
    await expect.poll(() => b.locator("html").getAttribute("data-font"), { timeout: 30_000 }).toBe("fira-code");
    const fontRendererApplied = await rendererProbe?.sample();
    await waitForFrames(b, APPEARANCE_FRAME_WINDOW);
    const fontTrace = await stopFrameCapture(b);
    const fontRendererAfter = await rendererProbe?.sample();
    const fontActionMeasures = await b.evaluate((startedAt) => performance.getEntriesByType("measure")
      .filter((entry) => entry.name.startsWith("appearance:") && entry.startTime >= startedAt)
      .map((entry) => ({ name: entry.name, durationMs: entry.duration, startTimeMs: entry.startTime })), fontWindowStartedAt);

    await a.keyboard.press(await a.evaluate(isMacPlatform) ? "Meta+K" : "Control+Shift+K");
    await expect(a.locator("#palette-input")).toBeFocused({ timeout: 10_000 });
    await a.locator("#palette-input").fill("Appearance");
    const appearance = a.locator('#palette-results [data-action="canvas:settings:appearance.themes"]');
    await expect(appearance).toBeVisible({ timeout: 10_000 });
    await appearance.click();
    const uiFont = a.locator('[data-window-id="s-appearance-themes"] section[data-kind="ui-font"]');
    await expect(uiFont).toBeVisible({ timeout: 10_000 });
    // Opening a window pans this device's own camera to it. That is the device's choice, not a synced change: take the new resting
    // camera as the reference before the font edit, then assert that neither the edit nor the OS scheme moves it again.
    await expect.poll(async () => { const first = await cameraTransform(a); await a.evaluate(() => new Promise<void>((done) => requestAnimationFrame(() => requestAnimationFrame(() => done())))); return first === await cameraTransform(a); }, { timeout: 10_000 }).toBe(true);
    aCamera = await cameraTransform(a);
    await uiFont.locator('button[data-id="sans"]').click();
    await expect.poll(async () => (await cache(b)).canonical.look?.uiFont, { timeout: 5_000 }).toBe("sans");
    await expect(b.locator("html")).toHaveAttribute("data-ui-font", "sans");
    const themeFrames = measureAppearanceFrames(themeTrace, "data-look", "solid");
    const fontFrames = measureAppearanceFrames(fontTrace, "data-font", "fira-code");
    const frameTraces = [themeTrace, fontTrace];
    const appearanceFrames = [...themeFrames.samples, ...fontFrames.samples];
    const frameIntervalsMs = frameTraces.flatMap((trace) => trace.samples.map(({ intervalMs }) => intervalMs));
    const appearanceFrameIntervalsMs = appearanceFrames.map(({ intervalMs }) => intervalMs);
    const maxFrameIntervalMs = Math.max(0, ...appearanceFrameIntervalsMs);
    const framesOver20ms = appearanceFrameIntervalsMs.filter((interval) => interval > 20).length;
    const themeFramesOver20ms = themeFrames.samples.filter(({ intervalMs }) => intervalMs > 20).length;
    const fontFramesOver20ms = fontFrames.samples.filter(({ intervalMs }) => intervalMs > 20).length;
    const allFramesOver20ms = frameIntervalsMs.filter((interval) => interval > 20).length;
    expect(frameIntervalsMs.length).toBeGreaterThan(10);
    expect(themeFrames.mutations.length).toBeGreaterThan(0);
    expect(fontFrames.mutations.length).toBeGreaterThan(0);
    expect(themeFrames.samples.length).toBeGreaterThan(0);
    expect(fontFrames.samples.length).toBeGreaterThan(0);
    console.log(`APPEARANCE_FRAMES ${JSON.stringify({ visibility: [...new Set(frameTraces.flatMap((trace) => trace.samples.map(({ visibility }) => visibility)))], baselineRendererWorkSeconds: rendererMetricDelta(baselineRendererBefore, baselineRendererAfter), theme: { mutations: themeFrames.mutations, intervalsMs: themeFrames.samples.map(({ intervalMs }) => intervalMs), focusedFrames: themeFrames.samples.filter(({ focused }) => focused).length, rendererApplySeconds: rendererMetricDelta(themeRendererBefore, themeRendererApplied), rendererTransitionSeconds: rendererMetricDelta(themeRendererApplied, themeRendererAfter), rendererWholeWindowSeconds: rendererMetricDelta(themeRendererBefore, themeRendererAfter), actionMeasures: themeActionMeasures }, font: { mutations: fontFrames.mutations, intervalsMs: fontFrames.samples.map(({ intervalMs }) => intervalMs), focusedFrames: fontFrames.samples.filter(({ focused }) => focused).length, rendererApplySeconds: rendererMetricDelta(fontRendererBefore, fontRendererApplied), rendererTransitionSeconds: rendererMetricDelta(fontRendererApplied, fontRendererAfter), rendererWholeWindowSeconds: rendererMetricDelta(fontRendererBefore, fontRendererAfter), actionMeasures: fontActionMeasures }, allFrameSamples: frameIntervalsMs.length, allFramesOver20ms, maxAppearanceFrameIntervalMs: maxFrameIntervalMs, appearanceFramesOver20ms: framesOver20ms })}`);
    expect(
      themeFrames.mutations.filter(({ attribute, value }) => attribute === "data-look" && value === "solid"),
      "one remote look update applies its selected theme once",
    ).toHaveLength(1);

    // The OS colour-scheme fallback is only for an account without a saved look; it cannot replace the canonical look on a new device.
    const accountLookBeforeMediaChange = (await cache(b)).canonical.look!;
    const accountColors = accountLookBeforeMediaChange.themes.find((theme) => theme.id === accountLookBeforeMediaChange.selected)?.colors;
    if (!accountColors) throw new Error("the account's selected theme has no saved colour scheme");
    const fallbackScheme: "dark" | "light" = accountColors === "mocha" ? "light" : "dark";
    if ((await b.evaluate(() => matchMedia("(prefers-color-scheme: dark)").matches)) === (fallbackScheme === "dark")) {
      await changeColorScheme(b, fallbackScheme === "dark" ? "light" : "dark");
      await expect(b.locator("html")).toHaveAttribute("data-theme", accountColors);
    }
    await changeColorScheme(b, fallbackScheme);
    await expect(b.locator("html")).toHaveAttribute("data-theme", accountColors);
    expect((await cache(b)).canonical.look).toEqual(accountLookBeforeMediaChange);

    expect(await cameraTransform(a)).toBe(aCamera);
    expect(await cameraTransform(b)).toBe(bCamera);

    const beforeReload = (await cache(b)).canonical.look;
    await b.reload(); await settled(b);
    const afterReload = (await cache(b)).canonical.look;
    expect(afterReload).toEqual(beforeReload);
    await expect(b.locator("html")).toHaveAttribute("data-look", "solid");
    await expect(b.locator("html")).toHaveAttribute("data-font", "fira-code");
    await expect(b.locator("html")).toHaveAttribute("data-ui-font", "sans");
    expect(await cameraTransform(a)).toBe(aCamera);
    expect(await cameraTransform(b)).toBe(bCamera);

    const appearanceCalls = wire.calls.filter(({ actionId }) => /appearance|look/i.test(actionId)).length;
    const appearanceRoundTrips = appearanceCalls + wire.appearanceHttpRequests.length;
    const lookWritesOnB = wire.calls.filter(({ actionId, input }) => actionId === "canvas.layout.apply" && (input.intent as { type?: string } | undefined)?.type === "look.set").length;
    expect(snapshot?.carriesLook).toBe(true);
    expect(firstContentfulPaintMs).not.toBeNull();
    expect(appearanceRoundTrips).toBe(0);
    expect(lookWritesOnB).toBe(0);
    const measurement = {
      initialSnapshotRevision: snapshot?.revision,
      initialSnapshotElapsedMs: snapshot ? snapshot.receivedAt - navigationStartedAt : null,
      initialSnapshotCarriedLook: snapshot?.carriesLook,
      firstContentfulPaintMs,
      separateAppearanceRoundTrips: appearanceRoundTrips,
      appearanceHttpRequests: wire.appearanceHttpRequests,
      clientBLookWrites: lookWritesOnB,
      frameSamples: appearanceFrameIntervalsMs.length,
      maxFrameIntervalMs,
      framesOver20ms,
      themeFramesOver20ms,
      fontFramesOver20ms,
      allFrameSamples: frameIntervalsMs.length,
      allFramesOver20ms,
      rendererDurationSeconds: {
        baseline: rendererMetricDelta(baselineRendererBefore, baselineRendererAfter),
        themeApply: rendererMetricDelta(themeRendererBefore, themeRendererApplied),
        themeTransition: rendererMetricDelta(themeRendererApplied, themeRendererAfter),
        fontApply: rendererMetricDelta(fontRendererBefore, fontRendererApplied),
        fontTransition: rendererMetricDelta(fontRendererApplied, fontRendererAfter),
      },
      actionMeasures: { theme: themeActionMeasures, font: fontActionMeasures },
      cameraAStayedLocal: true,
      cameraBStayedLocal: true,
      themeAndFontSurvivedReload: true,
      uiFontSurvivedReload: true,
    };
    await b.screenshot({ path: `${evidence}/client-b-synced-look.png` });
    await writeFile(`${evidence}/live-sync.json`, JSON.stringify(measurement, null, 2));
    console.log(`APPEARANCE_SYNC ${JSON.stringify(measurement)}`);
  } catch (error) {
    bodyFailure = { error };
  } finally {
    /** Cleanup failures matter only when the test body itself succeeded. */
    const cleanupErrors: unknown[] = [];
    try { await rendererProbe?.close(); } catch (error) { cleanupErrors.push(error); }
    try { await second.close(); } catch (error) { cleanupErrors.push(error); }
    try { await first.close(); } catch (error) { cleanupErrors.push(error); }
    try { await server.dispose(); } catch (error) { cleanupErrors.push(error); }
    if (bodyFailure) throw bodyFailure.error;
    if (cleanupErrors.length > 0) throw cleanupErrors[0];
  }
});

/** A remote account look updates the page without dismissing a palette query this device is using. */
test("a remote look change keeps the local palette open with its query", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4567) });
  const evidence = tracerEvidencePath("appearance-sync");
  await mkdir(evidence, { recursive: true });
  const first = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true });
  const second = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true });
  try {
    const a = watchLayout(await first.newPage());
    await enrol(a, server);
    await settled(a);
    await second.addCookies(await first.cookies());
    const b = watchLayout(await second.newPage());
    await b.goto(server.origin + "/");
    await expect(windows(b)).toHaveCount(1);
    await settled(b);

    await b.keyboard.press(await b.evaluate(isMacPlatform) ? "Meta+K" : "Control+Shift+K");
    const palette = b.locator("#palette");
    const input = b.locator("#palette-input");
    await expect(palette).toBeVisible();
    await input.fill("Ter");
    await expect(input).toHaveValue("Ter");

    await choosePaletteValue(a, "Theme: Solid");
    await expect(a.locator("#palette")).toBeHidden();
    await expect.poll(async () => (await cache(b)).canonical.look?.selected, { timeout: 30_000 }).toBe("solid");
    await expect(b.locator("html")).toHaveAttribute("data-look", "solid");
    await expect(palette).toBeVisible();
    await expect(input).toHaveValue("Ter");
    await b.screenshot({ path: `${evidence}/remote-look-keeps-palette-query.png` });
  } finally {
    await second.close();
    await first.close();
    await server.dispose();
  }
});

/** Replays J359's close-together edits against the real canvas server; the newer local edit must be the next document revision. */
test("a newer local appearance edit survives an older remote look while its announce is pending", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4567) });
  const first = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true });
  const second = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true });
  try {
    const a = watchLayout(await first.newPage());
    await enrol(a, server);
    await settled(a);
    await second.addCookies(await first.cookies());
    const b = watchLayout(await second.newPage());
    await b.goto(server.origin + "/");
    await expect(windows(b)).toHaveCount(1);
    await settled(b);

    const rounds: Array<{ base: string; older: string; newer: string; gapMs: number }> = [];
    const cap = (value: string): string => value[0]!.toUpperCase() + value.slice(1);
    for (const [base, older, newer] of [
      ["solid", "tinted", "frosted"],
      ["tinted", "frosted", "solid"],
      ["frosted", "solid", "tinted"],
    ] as const) {
      await choosePaletteValue(a, `Theme: ${cap(base)}`);
      await expect.poll(async () => (await cache(b)).canonical.look?.selected).toBe(base);
      await settled(a);
      await settled(b);

      await choosePaletteValue(a, `Theme: ${cap(older)}`);
      const olderPickedAt = Date.now();
      await choosePaletteValue(b, `Theme: ${cap(newer)}`);
      const newerPickedAt = Date.now();
      const round = { base, older, newer, gapMs: newerPickedAt - olderPickedAt };
      console.log(`APPEARANCE_UNSENT_ATTEMPT ${JSON.stringify(round)}`);
      await expect.poll(async () => (await cache(a)).canonical.look?.selected, { timeout: 15_000 }).toBe(newer);
      await expect.poll(async () => (await cache(b)).canonical.look?.selected, { timeout: 15_000 }).toBe(newer);
      await expect(b.locator("html")).toHaveAttribute("data-look", newer);
      await settled(a);
      await settled(b);
      rounds.push(round);
    }
    console.log(`APPEARANCE_UNSENT_CONFLICT ${JSON.stringify({ rounds, expectedNewestWins: true })}`);
  } finally {
    await second.close();
    await first.close();
    await server.dispose();
  }
});

/** Opens two clients on one real account, with the second tab ready to queue an offline look edit; `latencyMs` delays every server message one way. */
async function offlineConflictClients(browser: Browser, latencyMs = 0) {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4567), latencyMs });
  const first = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true });
  const second = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true });
  const a = watchLayout(await first.newPage());
  await enrol(a, server);
  await settled(a);
  await second.addCookies(await first.cookies());
  const b = watchLayout(await second.newPage());
  await b.goto(server.origin + "/");
  await expect(windows(b)).toHaveCount(1, { timeout: 60_000 });
  await settled(b);
  return { server, first, second, a, b };
}

/** A saved newer account look must survive an offline `look.set` based on an older revision. */
test("an offline stale look cannot replace the newer account look", async ({ browser }) => {
  const { server, first, second, a, b } = await offlineConflictClients(browser);
  try {
    await second.setOffline(true);
    await choosePaletteValue(b, "Theme: Frosted");
    await expect(b.locator("html")).toHaveAttribute("data-look", "frosted");
    await expect.poll(async () => (await cache(b)).pending.some((entry) => (entry.intent as { type?: string } | undefined)?.type === "look.set"), { timeout: 15_000 }).toBe(true);

    await choosePaletteValue(a, "Theme: Solid");
    await expect.poll(async () => (await cache(a)).canonical.look?.selected, { timeout: 30_000 }).toBe("solid");
    await settled(a);

    await second.setOffline(false);
    await settled(b);
    await expect.poll(async () => (await cache(b)).canonical.look?.selected, { timeout: 15_000 }).toBe("solid");
    expect((await cache(b)).canonical.look?.selected).toBe("solid");
  } finally {
    await second.close();
    await first.close();
    await server.dispose();
  }
});

/** A definitive stale-look refusal releases the local guard so a later server look can still apply. */
test("a refused offline look does not suppress later remote looks", async ({ browser }) => {
  const { server, first, second, a, b } = await offlineConflictClients(browser);
  try {
    await second.setOffline(true);
    await choosePaletteValue(b, "Theme: Frosted");
    await expect(b.locator("html")).toHaveAttribute("data-look", "frosted");
    await expect.poll(async () => (await cache(b)).pending.some((entry) => (entry.intent as { type?: string } | undefined)?.type === "look.set"), { timeout: 15_000 }).toBe(true);

    await choosePaletteValue(a, "Theme: Solid");
    await expect.poll(async () => (await cache(a)).canonical.look?.selected, { timeout: 30_000 }).toBe("solid");
    await settled(a);
    await second.setOffline(false);
    await settled(b);
    await expect.poll(async () => (await cache(b)).canonical.look?.selected, { timeout: 15_000 }).toBe("solid");

    await choosePaletteValue(a, "Theme: Tinted");
    await expect.poll(async () => (await cache(a)).canonical.look?.selected, { timeout: 30_000 }).toBe("tinted");
    await expect.poll(async () => (await cache(b)).canonical.look?.selected, { timeout: 30_000 }).toBe("tinted");
    await expect(b.locator("html")).toHaveAttribute("data-look", "tinted");
  } finally {
    await second.close();
    await first.close();
    await server.dispose();
  }
});

/** On a slow link a second look made while the first is still unacknowledged must not be refused: the latest pick wins on both devices. */
test("a look picked while the previous one is still in flight is kept on a slow link (1 s one way)", async ({ browser }) => {
  test.setTimeout(240_000);
  const { server, first, second, a, b } = await offlineConflictClients(browser, 1000);
  try {
    await choosePaletteValue(a, "Theme: Frosted");
    // sleep: past the 600 ms announce delay so the first look.set is already on the wire when the next pick is made.
    await a.waitForTimeout(900);
    await choosePaletteValue(a, "Theme: Solid");
    await settled(a); await settled(b);
    await expect.poll(async () => (await cache(a)).canonical.look?.selected, { timeout: 60_000 }).toBe("solid");
    await expect.poll(async () => (await cache(b)).canonical.look?.selected, { timeout: 60_000 }).toBe("solid");
    await expect(b.locator("html")).toHaveAttribute("data-look", "solid");
  } finally {
    await second.close();
    await first.close();
    await server.dispose();
  }
});

/** Three quick picks over the same slow link end on the last pick on both devices. */
test("three quick look picks on a slow link end on the last pick on both devices", async ({ browser }) => {
  test.setTimeout(240_000);
  const { server, first, second, a, b } = await offlineConflictClients(browser, 1000);
  try {
    await choosePaletteValue(a, "Theme: Frosted");
    // sleep: let the first look.set reach the wire before the next pick, so each pick meets one still in flight.
    await a.waitForTimeout(900);
    await choosePaletteValue(a, "Theme: Tinted");
    // sleep: the second pick is announced while the first is still unacknowledged.
    await a.waitForTimeout(900);
    await choosePaletteValue(a, "Theme: Solid");
    await settled(a); await settled(b);
    await expect.poll(async () => (await cache(a)).canonical.look?.selected, { timeout: 90_000 }).toBe("solid");
    await expect.poll(async () => (await cache(b)).canonical.look?.selected, { timeout: 90_000 }).toBe("solid");
  } finally {
    await second.close();
    await first.close();
    await server.dispose();
  }
});

/** Uses light and dark clients on one real account to ensure OS defaults cannot rewrite account basics or Reset. */
test("account basics and Reset stay the same on clients with different OS schemes", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4567) });
  const light = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true, colorScheme: "light" });
  const dark = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true, colorScheme: "dark" });
  try {
    const a = watchLayout(await light.newPage());
    await enrol(a, server);
    await settled(a);
    await choosePaletteValue(a, "Theme: Frosted");
    await expect.poll(async () => {
      const look = (await cache(a)).canonical.look;
      return look?.selected === "frosted" && look.themes.find((theme) => theme.id === "frosted")?.colors === "latte";
    }).toBe(true);
    await settled(a);
    const accountBasicsBefore = (await cache(a)).canonical.look?.basics;
    expect(accountBasicsBefore).toEqual({ colors: "latte", font: "maple-mono-nf", uiSize: 100 });
    expect((await cache(a)).canonical.look?.selected).toBe("frosted");

    await dark.addCookies(await light.cookies());
    const b = watchLayout(await dark.newPage());
    await b.goto(server.origin + "/");
    await expect(windows(b)).toHaveCount(1);
    await settled(b);
    expect(await b.evaluate(() => matchMedia("(prefers-color-scheme: dark)").matches)).toBe(true);
    const deviceCacheBasics = await b.evaluate(() => {
      const key = Object.keys(localStorage).find((candidate) => candidate.startsWith("tracer.look.account."));
      return key ? JSON.parse(localStorage.getItem(key) ?? "null").basics : undefined;
    });

    // The dark client picks a built-in theme based on the account list. This must not copy its OS default into account basics.
    await choosePaletteValue(b, "Theme: Tinted");
    await expect.poll(async () => (await cache(a)).canonical.look?.selected, { timeout: 15_000 }).toBe("tinted");
    await settled(a);
    await settled(b);
    const accountBasicsAfter = (await cache(a)).canonical.look?.basics;
    console.log(`APPEARANCE_ACCOUNT_BASICS ${JSON.stringify({ accountBasicsBefore, deviceCacheBasics, accountBasicsAfter })}`);
    expect(accountBasicsAfter).toEqual(accountBasicsBefore);
    expect(deviceCacheBasics).toEqual(accountBasicsBefore);
  } finally {
    await dark.close();
    await light.close();
    await server.dispose();
  }
});

test("legacy appearance values migrate once into the new account document", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4567) });
  const evidence = tracerEvidencePath("appearance-sync");
  await mkdir(evidence, { recursive: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true });
  try {
    await context.addInitScript((look) => {
      localStorage.setItem("tracer.look", JSON.stringify(look));
      localStorage.setItem("tracer.theme", "latte");
      localStorage.setItem("tracer.font", "geist-mono");
      localStorage.setItem("tracer.ui-size.v2", "125");
      localStorage.setItem("tracer.ui-size", "90");
      localStorage.setItem("tracer.window-size.phone", "full");
      localStorage.setItem("tracer.window-size.desktop", "wide");
      localStorage.setItem("tracer.extended-info", "1");
      localStorage.setItem("tracer.card", "3");
      localStorage.setItem("tracer.windows", "4");
      localStorage.setItem("tracer.background", "mesh");
      localStorage.setItem("tracer.ui-font", "sans");
    }, legacyLookCache());
    const page = watchLayout(await context.newPage());
    await enrol(page, server); await settled(page);
    const accountId = await page.evaluate(async () => (await (await fetch("/auth/session", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).json()).user_id as string);
    // `settled` can return before the seeded look is announced (600 ms), so wait for the account look itself.
    await expect.poll(async () => (await cache(page)).canonical.look, { timeout: 30_000 }).toBeTruthy();
    const document = (await cache(page)).canonical;
    const look = document.look as unknown as {
      selected: string;
      uiFont?: "mono" | "sans";
      themes: Array<{ id: string; font: string; colors: string; uiSize: number; tint: number; blur: number; background: string }>;
      windowSizes?: { phone: string; desktop: string };
      extendedInfo?: boolean;
    };
    const selected = look.themes.find((theme) => theme.id === look.selected)!;
    const legacyKeys = ["tracer.look", "tracer.theme", "tracer.font", "tracer.ui-size.v2", "tracer.ui-size", "tracer.window-size.phone", "tracer.window-size.desktop", "tracer.extended-info", "tracer.card", "tracer.windows", "tracer.background", "tracer.ui-font"];
    const remaining = await page.evaluate((keys) => keys.filter((key) => localStorage.getItem(key) !== null), legacyKeys);
    const uiFontPreference = await page.evaluate(() => localStorage.getItem("tracer.ui-font"));
    expect(selected.colors).toBe("latte");
    expect(selected.font).toBe("geist-mono");
    expect(selected.uiSize).toBe(125);
    expect(selected).toMatchObject({ tint: 75, blur: 25, background: "aurora" });
    expect(look.uiFont).toBe("sans");
    expect(look.windowSizes).toEqual({ phone: "full", desktop: "wide" });
    expect(look.extendedInfo).toBe(true);
    expect(remaining).toEqual([]);
    expect(uiFontPreference).toBeNull();
    await writeFile(`${evidence}/legacy-migration.json`, JSON.stringify({ accountId, look, remainingLegacyKeys: remaining, uiFontPreference }, null, 2));
    console.log(`APPEARANCE_MIGRATION ${JSON.stringify({ accountId, selected: look.selected, font: selected.font, uiSize: selected.uiSize, windowSizes: look.windowSizes, extendedInfo: look.extendedInfo, remainingLegacyKeys: remaining, uiFontPreference })}`);
  } finally { await context.close(); await server.dispose(); }
});

test("superseded appearance levels seed one fresh theme only when there is no saved look", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4567) });
  const evidence = tracerEvidencePath("appearance-sync");
  await mkdir(evidence, { recursive: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true });
  try {
    await context.addInitScript(() => {
      localStorage.setItem("tracer.theme", "latte");
      localStorage.setItem("tracer.font", "geist-mono");
      localStorage.setItem("tracer.ui-size", "110");
      localStorage.setItem("tracer.card", "3");
      localStorage.setItem("tracer.windows", "4");
      localStorage.setItem("tracer.background", "none");
      localStorage.setItem("tracer.window-size.phone", "full");
      localStorage.setItem("tracer.extended-info", "0");
    });
    const page = watchLayout(await context.newPage());
    await enrol(page, server); await settled(page);
    // `settled` can return before the seeded look is announced (600 ms), so wait for the account look itself.
    await expect.poll(async () => (await cache(page)).canonical.look, { timeout: 30_000 }).toBeTruthy();
    const document = (await cache(page)).canonical;
    const look = document.look as unknown as {
      selected: string;
      themes: Array<{ id: string; font: string; colors: string; uiSize: number; tint: number; blur: number; background: string }>;
      windowSizes?: { phone: string; desktop: string };
      extendedInfo?: boolean;
    };
    const selected = look.themes.find((theme) => theme.id === look.selected)!;
    const legacyKeys = ["tracer.theme", "tracer.font", "tracer.ui-size.v2", "tracer.ui-size", "tracer.card", "tracer.windows", "tracer.background", "tracer.window-size.phone", "tracer.window-size.desktop", "tracer.extended-info"];
    const remaining = await page.evaluate((keys) => keys.filter((key) => localStorage.getItem(key) !== null), legacyKeys);
    expect(selected).toMatchObject({ colors: "latte", font: "geist-mono", uiSize: 100, tint: 50, blur: 50, background: "solid" });
    expect(look.windowSizes).toEqual({ phone: "full", desktop: "comfortable" });
    expect(look.extendedInfo).toBe(false);
    expect(remaining).toEqual([]);
    await writeFile(`${evidence}/legacy-standalone-migration.json`, JSON.stringify({ look, remainingLegacyKeys: remaining }, null, 2));
    console.log(`APPEARANCE_LEGACY_SEED ${JSON.stringify({ selected: look.selected, colors: selected.colors, tint: selected.tint, blur: selected.blur, background: selected.background, windowSizes: look.windowSizes, remainingLegacyKeys: remaining })}`);
  } finally { await context.close(); await server.dispose(); }
});
