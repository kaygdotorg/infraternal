// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Proves that the production canvas document carries one account's appearance between real browser clients,
 * while each tab keeps its own camera and old browser-only appearance values migrate once.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { createThemeStore } from "../src/canvas/themes/model";
import { cache, watchLayout } from "./layout-observer";
import { expect, test, type Page } from "playwright/test";
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
  await expect(windows(page)).toHaveCount(1);
}

/** Changes one palette value through the real command palette. */
async function choosePaletteValue(page: Page, value: string): Promise<void> {
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible({ timeout: 10_000 });
  await page.locator("#palette-input").fill(value);
  const option = page.locator("#palette-results [role=option]").filter({ hasText: value }).first();
  await expect(option).toBeVisible({ timeout: 10_000 });
  await option.click();
}

/** Returns the world transform that represents this tab's camera framing. */
async function cameraTransform(page: Page): Promise<string> {
  return page.locator(".cl-world").evaluate((world) => (world as HTMLElement).style.transform);
}

/** Turns canvas lock off and pans through the same wheel path used by trackpads. */
async function panCamera(page: Page): Promise<void> {
  await page.keyboard.press("Control+Shift+G");
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

/** The look window spans the changed frame and twenty following frames, enough to cover the page's short appearance transition. */
const APPEARANCE_FRAME_WINDOW = 20;

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

/** Records rendered frame intervals and appearance changes until {@link stopFrameCapture} ends the sample. */
async function startFrameCapture(page: Page): Promise<void> {
  await page.evaluate(() => {
    const root = document.documentElement;
    const samples: FrameSample[] = [];
    const mutations: AppearanceMutation[] = [];
    let active = true, previous = performance.now();
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
      samples.push({ from: previous, to: now, intervalMs: now - previous, visibility: document.visibilityState });
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
  const first = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 2, ignoreHTTPSErrors: true });
  const second = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 2, ignoreHTTPSErrors: true });
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
    const aCamera = await cameraTransform(a);
    expect(await cameraTransform(b)).toBe(bCamera);

    await startFrameCapture(b);
    await choosePaletteValue(a, "Theme: Solid");
    await expect.poll(async () => {
      const look = (await cache(b)).canonical.look;
      return look?.selected === "solid";
    }, { timeout: 30_000 }).toBe(true);
    await expect.poll(() => b.locator("html").getAttribute("data-look"), { timeout: 30_000 }).toBe("solid");
    await waitForFrames(b, APPEARANCE_FRAME_WINDOW);
    const themeTrace = await stopFrameCapture(b);

    await startFrameCapture(b);
    await choosePaletteValue(a, "Fira Code");
    await expect.poll(async () => {
      const look = (await cache(b)).canonical.look;
      return look?.selected === "solid" && look.themes.find((theme) => theme.id === "solid")?.font === "fira-code";
    }, { timeout: 30_000 }).toBe(true);
    await expect.poll(() => b.locator("html").getAttribute("data-font"), { timeout: 30_000 }).toBe("fira-code");
    await waitForFrames(b, APPEARANCE_FRAME_WINDOW);
    const fontTrace = await stopFrameCapture(b);
    const themeFrames = measureAppearanceFrames(themeTrace, "data-look", "solid");
    const fontFrames = measureAppearanceFrames(fontTrace, "data-font", "fira-code");
    const frameTraces = [themeTrace, fontTrace];
    const appearanceFrames = [...themeFrames.samples, ...fontFrames.samples];
    const frameIntervalsMs = frameTraces.flatMap((trace) => trace.samples.map(({ intervalMs }) => intervalMs));
    const appearanceFrameIntervalsMs = appearanceFrames.map(({ intervalMs }) => intervalMs);
    const maxFrameIntervalMs = Math.max(0, ...appearanceFrameIntervalsMs);
    const framesOver20ms = appearanceFrameIntervalsMs.filter((interval) => interval > 20).length;
    const allFramesOver20ms = frameIntervalsMs.filter((interval) => interval > 20).length;
    expect(frameIntervalsMs.length).toBeGreaterThan(10);
    expect(themeFrames.mutations.length).toBeGreaterThan(0);
    expect(fontFrames.mutations.length).toBeGreaterThan(0);
    expect(themeFrames.samples.length).toBeGreaterThan(0);
    expect(fontFrames.samples.length).toBeGreaterThan(0);
    console.log(`APPEARANCE_FRAMES ${JSON.stringify({ visibility: [...new Set(frameTraces.flatMap((trace) => trace.samples.map(({ visibility }) => visibility)))], theme: { mutations: themeFrames.mutations, intervalsMs: themeFrames.samples.map(({ intervalMs }) => intervalMs) }, font: { mutations: fontFrames.mutations, intervalsMs: fontFrames.samples.map(({ intervalMs }) => intervalMs) }, allFrameSamples: frameIntervalsMs.length, allFramesOver20ms, maxAppearanceFrameIntervalMs: maxFrameIntervalMs, appearanceFramesOver20ms: framesOver20ms })}`);
    expect(themeFrames.samples.filter(({ intervalMs }) => intervalMs > 20).length, "remote theme application and its 20 following frames stay within budget").toBe(0);
    expect(fontFrames.samples.filter(({ intervalMs }) => intervalMs > 20).length, "remote font application and its 20 following frames stay within budget").toBe(0);
    expect(framesOver20ms).toBe(0);
    expect(await cameraTransform(a)).toBe(aCamera);
    expect(await cameraTransform(b)).toBe(bCamera);

    const beforeReload = (await cache(b)).canonical.look;
    await b.reload(); await settled(b);
    const afterReload = (await cache(b)).canonical.look;
    expect(afterReload).toEqual(beforeReload);
    await expect(b.locator("html")).toHaveAttribute("data-look", "solid");
    await expect(b.locator("html")).toHaveAttribute("data-font", "fira-code");
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
      allFrameSamples: frameIntervalsMs.length,
      allFramesOver20ms,
      cameraAStayedLocal: true,
      cameraBStayedLocal: true,
      themeAndFontSurvivedReload: true,
    };
    await b.screenshot({ path: `${evidence}/client-b-synced-look.png` });
    await writeFile(`${evidence}/live-sync.json`, JSON.stringify(measurement, null, 2));
    console.log(`APPEARANCE_SYNC ${JSON.stringify(measurement)}`);
  } finally { await second.close(); await first.close(); await server.dispose(); }
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
    const document = (await cache(page)).canonical;
    const look = document.look as unknown as {
      selected: string;
      themes: Array<{ id: string; font: string; colors: string; uiSize: number; tint: number; blur: number; background: string }>;
      windowSizes?: { phone: string; desktop: string };
      extendedInfo?: boolean;
    };
    const selected = look.themes.find((theme) => theme.id === look.selected)!;
    const legacyKeys = ["tracer.look", "tracer.theme", "tracer.font", "tracer.ui-size.v2", "tracer.ui-size", "tracer.window-size.phone", "tracer.window-size.desktop", "tracer.extended-info", "tracer.card", "tracer.windows", "tracer.background", "tracer.ui-font"];
    const remaining = await page.evaluate((keys) => keys.filter((key) => localStorage.getItem(key) !== null), legacyKeys);
    expect(selected.colors).toBe("latte");
    expect(selected.font).toBe("geist-mono");
    expect(selected.uiSize).toBe(125);
    expect(selected).toMatchObject({ tint: 75, blur: 25, background: "aurora" });
    expect(look).not.toHaveProperty("uiFont");
    expect(look.windowSizes).toEqual({ phone: "full", desktop: "wide" });
    expect(look.extendedInfo).toBe(true);
    expect(remaining).toEqual([]);
    await writeFile(`${evidence}/legacy-migration.json`, JSON.stringify({ accountId, look, remainingLegacyKeys: remaining }, null, 2));
    console.log(`APPEARANCE_MIGRATION ${JSON.stringify({ accountId, selected: look.selected, font: selected.font, uiSize: selected.uiSize, windowSizes: look.windowSizes, extendedInfo: look.extendedInfo, remainingLegacyKeys: remaining })}`);
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
