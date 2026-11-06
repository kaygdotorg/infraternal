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
  await page.locator("#palette-input").fill(value);
  await page.locator("#palette-results [role=option]").filter({ hasText: value }).first().click();
}

/** Returns the world transform that represents this tab's camera framing. */
async function cameraTransform(page: Page): Promise<string> {
  return page.locator(".cl-world").evaluate((world) => (world as HTMLElement).style.transform);
}

/** Records this page's animation-frame intervals until {@link stopFrameCapture} ends the sample. */
async function startFrameCapture(page: Page): Promise<void> {
  await page.evaluate(() => {
    const intervals: number[] = [];
    let active = true, previous = performance.now();
    const capture = { intervals, stop: () => { active = false; } };
    (window as unknown as { __appearanceFrameCapture?: typeof capture }).__appearanceFrameCapture = capture;
    const frame = (now: number): void => {
      if (!active) return;
      intervals.push(now - previous);
      previous = now;
      requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  });
}

/** Stops the animation-frame sample and returns the measured gaps in milliseconds. */
async function stopFrameCapture(page: Page): Promise<number[]> {
  return page.evaluate(() => {
    const capture = (window as unknown as { __appearanceFrameCapture?: { intervals: number[]; stop(): void } }).__appearanceFrameCapture;
    capture?.stop();
    return capture?.intervals ?? [];
  });
}

/** Captures the canvas requests and snapshots used by this page for first-paint evidence. */
function observeCanvasWire(page: Page) {
  const calls: Array<{ actionId: string; input: Record<string, unknown> }> = [];
  const snapshots: Array<{ revision: number; carriesLook: boolean; receivedAt: number }> = [];
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
  return { calls, snapshots };
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
  const first = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true });
  const second = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true });
  try {
    const a = watchLayout(await first.newPage());
    await enrol(a, server); await settled(a);
    await second.addCookies(await first.cookies());
    const b = watchLayout(await second.newPage());
    const wire = observeCanvasWire(b);
    const navigationStartedAt = Date.now();
    await b.goto(server.origin + "/");
    await expect(windows(b)).toHaveCount(1); await settled(b);
    const snapshot = wire.snapshots.find((event) => event.carriesLook);
    expect(snapshot).toBeDefined();
    const bCamera = await cameraTransform(b);
    const firstContentfulPaintMs = await b.evaluate(() => performance.getEntriesByType("paint").find((entry) => entry.name === "first-contentful-paint")?.startTime ?? null);

    await a.keyboard.down("Control");
    await a.mouse.move(640, 400);
    await a.mouse.wheel(0, -500);
    await a.keyboard.up("Control");
    await expect.poll(() => cameraTransform(a)).not.toBe(bCamera);
    const aCamera = await cameraTransform(a);

    await startFrameCapture(b);
    await choosePaletteValue(a, "Theme: Solid");
    await choosePaletteValue(a, "Font: Fira Code");
    await expect.poll(async () => {
      const look = (await cache(b)).canonical.look;
      return look?.selected === "solid" && look.themes.find((theme) => theme.id === "solid")?.font === "fira-code";
    }, { timeout: 30_000 }).toBe(true);
    const frameIntervalsMs = await stopFrameCapture(b);
    const maxFrameIntervalMs = Math.max(0, ...frameIntervalsMs);
    const framesOver50ms = frameIntervalsMs.filter((interval) => interval > 50).length;
    expect(frameIntervalsMs.length).toBeGreaterThan(10);
    expect(framesOver50ms).toBe(0);
    expect(await cameraTransform(a)).toBe(aCamera);
    expect(await cameraTransform(b)).toBe(bCamera);

    const beforeReload = (await cache(b)).canonical.look;
    await b.reload(); await settled(b);
    const afterReload = (await cache(b)).canonical.look;
    expect(afterReload).toEqual(beforeReload);
    expect(await cameraTransform(a)).toBe(aCamera);
    expect(await cameraTransform(b)).toBe(bCamera);

    const appearanceCalls = wire.calls.filter(({ actionId }) => /appearance|look/i.test(actionId)).length;
    const lookWritesOnB = wire.calls.filter(({ actionId, input }) => actionId === "canvas.layout.apply" && (input.intent as { type?: string } | undefined)?.type === "look.set").length;
    expect(snapshot?.carriesLook).toBe(true);
    expect(firstContentfulPaintMs).not.toBeNull();
    expect(appearanceCalls).toBe(0);
    expect(lookWritesOnB).toBe(0);
    const measurement = {
      initialSnapshotRevision: snapshot?.revision,
      initialSnapshotElapsedMs: snapshot ? snapshot.receivedAt - navigationStartedAt : null,
      initialSnapshotCarriedLook: snapshot?.carriesLook,
      firstContentfulPaintMs,
      separateAppearanceRoundTrips: appearanceCalls,
      clientBLookWrites: lookWritesOnB,
      frameSamples: frameIntervalsMs.length,
      maxFrameIntervalMs,
      framesOver50ms,
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
      themes: Array<{ id: string; font: string; colors: string; uiSize: number }>;
      uiFont?: string;
      windowSizes?: { phone: string; desktop: string };
      extendedInfo?: boolean;
    };
    const selected = look.themes.find((theme) => theme.id === look.selected)!;
    const legacyKeys = ["tracer.look", "tracer.theme", "tracer.font", "tracer.ui-size.v2", "tracer.ui-size", "tracer.window-size.phone", "tracer.window-size.desktop", "tracer.extended-info", "tracer.card", "tracer.windows", "tracer.background", "tracer.ui-font"];
    const remaining = await page.evaluate((keys) => keys.filter((key) => localStorage.getItem(key) !== null), legacyKeys);
    expect(selected.colors).toBe("latte");
    expect(selected.font).toBe("geist-mono");
    expect(selected.uiSize).toBe(125);
    expect(look.uiFont).toBe("sans");
    expect(look.windowSizes).toEqual({ phone: "full", desktop: "wide" });
    expect(look.extendedInfo).toBe(true);
    expect(remaining).toEqual([]);
    await writeFile(`${evidence}/legacy-migration.json`, JSON.stringify({ accountId, look, remainingLegacyKeys: remaining }, null, 2));
    console.log(`APPEARANCE_MIGRATION ${JSON.stringify({ accountId, selected: look.selected, font: selected.font, uiSize: selected.uiSize, windowSizes: look.windowSizes, extendedInfo: look.extendedInfo, remainingLegacyKeys: remaining })}`);
  } finally { await context.close(); await server.dispose(); }
});
