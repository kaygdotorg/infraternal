/**
 * The product canvas on real sessions (D177, D178, D183): the production server binary, a production build of
 * the tracer, real PTYs. Opening, closing, splitting and re-tiling windows, the one WebSocket, persistence, and
 * the memory budget on a phone. No test double anywhere.
 */
import { tracerEvidencePath } from "../test/evidence-path";
import { devices, expect, test, type Browser, type CDPSession, type Page } from "playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { WebSocket } from "ws";
import { WebSocketFrameDecoder, encodeMuxedFrame, type WireFrame } from "../../../packages/protocol/src/codec";
import { personName, startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });

let server: RealServer;
let page: Page;
const captures = tracerEvidencePath("canvas-real");

test.beforeAll(async ({ browser }) => {
  server = await startRealServer();
  await mkdir(captures, { recursive: true });
  // One signed-in page for the whole file: the tests continue where the last one stopped.
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  page = await context.newPage();
  await enrol(page);
});
test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

/** Attaches a raw socket to a session, types a command and returns what the shell printed. */
async function probeSession(cookie: string, sessionHex: string, command: string): Promise<string> {
  const socket = new WebSocket(server.backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: server.origin, Cookie: cookie } });
  const decoder = new WebSocketFrameDecoder();
  let output = "";
  let sent = false;
  const send = (stream: number, frame: Parameters<typeof encodeMuxedFrame>[1]) => socket.send(encodeMuxedFrame(stream, frame));
  socket.on("message", (data) => decoder.feed(new Uint8Array(Buffer.from(data as Buffer)), (_stream: number, frame: WireFrame) => {
    if (frame.type === "Hello") send(0, { type: "Hello", version: 1, caps: 0n, clientInfo: "canvas-real-probe" });
    if (frame.type === "Welcome") {
      send(1, { type: "AttachTerm", sessionId: Buffer.from(sessionHex, "hex"), lastOutSeq: 0n, lastInSeq: 0n });
      send(1, { type: "Credit", bytes: 1048576 });
    }
    if (frame.type === "Ack" && !sent) { sent = true; send(1, { type: "Input", inSeq: frame.inSeqAcked, bytes: Buffer.from(command) }); }
    if (frame.type === "Output") output += new TextDecoder().decode(frame.bytes);
    if (frame.type === "Snapshot") output += new TextDecoder().decode(frame.bytes);
  }));
  try {
    const deadline = Date.now() + 15_000;
    while (!output.includes("probe-3") && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    return output;
  } finally { socket.terminate(); }
}

const windows = (page: Page) => page.locator('.cl[data-view="console"] .ui-window');

/** Enrols the first passkey of a fresh server and lands on the canvas. */
async function enrol(page: Page): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("canvas_real"));
  await page.locator("#setup-display-name").fill("Canvas real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
}

/** The sockets that carried terminal streams, newest last. */
const live = () => server.bridges.filter((b) => !b.closed);
const streamsOf = () => [...(live().at(-1)?.attached.keys() ?? [])].sort((a, b) => a - b);
const outputOf = (stream: number) => live().at(-1)?.output.get(stream) ?? "";

async function type(page: Page, window: number, command: string): Promise<void> {
  const win = windows(page).nth(window);
  await win.locator(".terminal-host").click({ position: { x: 40, y: 40 } });
  await page.keyboard.type(command + "\n", { delay: 5 });
}

test("the bootstrap socket keeps text routing and stays outside protocol diagnostics", async () => {
  // The signed-in canvas can mount before its initial protocol socket opens.
  await expect.poll(() => live().at(-1)?.attached.size ?? 0).toBe(1);
  const before = server.bridges.length;
  const response = await page.evaluate(() => new Promise<{ text: boolean; refused: boolean }>((resolve) => {
    const socket = new WebSocket(`${location.origin.replace("https:", "wss:")}/v1/bootstrap/ws`);
    const finish = (text: boolean, refused: boolean): void => {
      clearTimeout(timer);
      socket.close();
      resolve({ text, refused });
    };
    const timer = setTimeout(() => finish(false, false), 5_000);
    socket.onopen = () => socket.send(JSON.stringify({ action: "retry", target: "one" }));
    socket.onmessage = ({ data }) => {
      if (typeof data !== "string") { finish(false, false); return; }
      try {
        const message = JSON.parse(data) as { error?: { message?: string } };
        finish(true, message.error?.message === "Start a host batch first.");
      } catch { finish(true, false); }
    };
    socket.onerror = () => finish(false, false);
  }));
  expect(response).toEqual({ text: true, refused: true });
  expect(server.bridges.length).toBe(before);
});

test("signing in shows the canvas with a Console view and one real shell", async () => {
  await expect(page.locator('.cl[data-view="console"]')).toBeVisible();
  await expect(windows(page)).toHaveCount(1);
  await expect(page.locator("#terminal-host")).toHaveCount(1);
  // The mockup scaffolding is not in the product.
  await expect(page.locator(".cl-mockup, #test-double-badge:not([hidden])")).toHaveCount(0);
  expect(await page.evaluate(() => "__tracerClusters" in window)).toBe(false);
  await expect.poll(() => streamsOf().length).toBe(1);
  await type(page, 0, "echo first-$((6*7))");
  await expect.poll(() => outputOf(streamsOf()[0]!), { timeout: 15_000 }).toContain("first-42");
});

test("windows are sessions on one WebSocket: open from the palette, type in each, nothing crosses", async () => {
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("open shell on");
  await page.locator("#palette-results [role=option]").first().click();
  await expect(windows(page)).toHaveCount(2);
  await expect.poll(() => streamsOf().length).toBe(2);
  expect(live()).toHaveLength(1); // one socket carries both streams
  const [a, b] = streamsOf() as [number, number];
  await page.keyboard.type("echo second-$((6*8))\n", { delay: 5 });
  await expect.poll(() => outputOf(b), { timeout: 15_000 }).toContain("second-48");
  expect(outputOf(a)).not.toContain("second-48");
  const sessions = [...(live()[0]!.attached.values())].flat();
  expect(new Set(sessions).size).toBe(2);
});

test("closing a window leaves its session running", async () => {
  const bridge = live()[0]!;
  const [a] = streamsOf() as [number, number];
  const session = bridge.attached.get(a)![0]!;
  await type(page, 0, "echo keep-me-alive");
  await expect.poll(() => outputOf(a), { timeout: 15_000 }).toContain("keep-me-alive");
  await windows(page).nth(0).locator('[data-action="close"]').click({ force: true });
  await expect(windows(page)).toHaveCount(1);
  await expect.poll(() => bridge.detached).toContain(a);
  // A second socket of the same account can still attach to the closed window's session and talk to its shell.
  const cookie = (await page.context().cookies()).map((c) => `${c.name}=${c.value}`).join("; ");
  expect(await probeSession(cookie, session, "echo probe-$((1+2))\n")).toContain("probe-3");
});

test("the layout survives a reload and the windows re-attach to the same sessions", async () => {
  const count = await windows(page).count();
  const before = [...(live().at(-1)!.attached.values())].flat();
  await page.reload();
  await page.locator(".cl-viewport").waitFor();
  await expect(windows(page)).toHaveCount(count);
  await expect.poll(() => [...(live().at(-1)?.attached.values() ?? [])].flat().length).toBe(count);
  const after = [...(live().at(-1)!.attached.values())].flat();
  for (const id of after) expect(before).toContain(id);
});

test("a page that opens and closes more than 32 windows keeps working: the connection rotates before the server cap", async () => {
  test.setTimeout(240_000);
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.locator(".cl-viewport").waitFor();
  const keep = await windows(page).count();
  const sockets = server.bridges.length;
  for (let i = 0; i < 34; i++) {
    await page.locator(".tab-add").click();
    await expect(windows(page)).toHaveCount(keep + 1);
    await expect.poll(() => live().at(-1)?.attached.size ?? 0, { timeout: 15_000 }).toBeGreaterThan(0);
    // Clicked from the page: the new window is still flying into view, and a pointer click would aim at where it was.
    await windows(page).last().locator('[data-action="close"]').evaluate((b) => (b as HTMLElement).click());
    await expect(windows(page), `closing window ${i}`).toHaveCount(keep);
  }
  expect(server.bridges.length).toBeGreaterThan(sockets); // rotated at least once
  // A window opened after the rotation still gets a real shell.
  await page.locator(".tab-add").click();
  await expect(windows(page)).toHaveCount(keep + 1);
  // The terminal starts after the window exists (font and renderer load); the keys go to it once it has focus.
  await expect(windows(page).last().locator(".terminal-host")).toBeFocused({ timeout: 15_000 });
  await page.keyboard.type("echo after-rotation-$((5*5))\n", { delay: 5 });
  await expect.poll(() => [...(live().at(-1)?.output.values() ?? [])].join(""), { timeout: 20_000 }).toContain("after-rotation-25");
});

type Stats = { n: number; p50: number; p95: number; max: number; dropped: number; cpuMs: number };

/** CPU seconds the browser's renderer and GPU processes have used so far. Frame times move with how busy the
 * machine is; the CPU a gesture costs moves much less, so both are printed. */
async function cpuSeconds(browser: Browser): Promise<number> {
  const session = await browser.newBrowserCDPSession();
  const info = (await session.send("SystemInfo.getProcessInfo" as never)) as { processInfo: Array<{ type: string; cpuTime: number }> };
  await session.detach();
  return info.processInfo.filter((p) => p.type === "renderer" || p.type === "GPU").reduce((sum, p) => sum + p.cpuTime, 0);
}

async function measure(page: Page, run: () => Promise<void>): Promise<Stats> {
  const cpu0 = await cpuSeconds(page.context().browser()!);
  await page.evaluate(() => {
    const w = window as unknown as { __frames: number[]; __stop: boolean };
    w.__frames = []; w.__stop = false;
    let last = performance.now();
    const tick = (t: number): void => { w.__frames.push(t - last); last = t; if (!w.__stop) requestAnimationFrame(tick); };
    requestAnimationFrame(tick);
  });
  await run();
  const cpu = (await cpuSeconds(page.context().browser()!)) - cpu0;
  const frames = await page.evaluate(() => { const w = window as unknown as { __frames: number[]; __stop: boolean }; w.__stop = true; return w.__frames.slice(2); });
  const sorted = [...frames].sort((a, b) => a - b);
  const at = (q: number): number => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * q))]!;
  return { n: frames.length, p50: +at(0.5).toFixed(1), p95: +at(0.95).toFixed(1), max: +sorted[sorted.length - 1]!.toFixed(1), dropped: frames.filter((f) => f > 20).length, cpuMs: Math.round(cpu * 1000) };
}

/** One wheel event per frame from inside the page, like a trackpad: zoom is ctrl+wheel, pan is a plain wheel. */
async function gesture(page: Page, kind: "zoom" | "pan"): Promise<void> {
  await page.evaluate(({ kind: k }) => new Promise<void>((done) => {
    const target = document.querySelector(".cl-viewport")!;
    const start = performance.now();
    const step = (t: number): void => {
      const phase = (t - start) / 2000;
      if (phase >= 1) { done(); return; }
      const dir = phase < 0.5 ? -1 : 1;
      target.dispatchEvent(new WheelEvent("wheel", k === "zoom"
        ? { deltaY: dir * 14, ctrlKey: true, clientX: 720, clientY: 450, bubbles: true, cancelable: true }
        : { deltaX: dir * 24, deltaY: dir * 9, clientX: 720, clientY: 450, bubbles: true, cancelable: true }));
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }), { kind });
  await page.waitForTimeout(200);
}

for (const rate of [1, 4]) {
  test(`frames: a 2 s zoom and a 2 s pan across live terminals at ${rate}x CPU`, async () => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(server.origin + "/?theme=ink&bg=none");
    await page.locator(".cl-viewport").waitFor();
    await expect(windows(page).first()).toBeVisible();
    // Fill the screen with output so the terminals are not idle while the camera moves.
    await type(page, 0, "yes 'frame test line' | head -n 400");
    await page.waitForTimeout(800);
    await page.keyboard.press("Control+Shift+G"); // canvas lock off: free pan and zoom
    await page.waitForTimeout(400);
    const cdp: CDPSession | undefined = rate > 1 ? await page.context().newCDPSession(page) : undefined;
    if (cdp) await cdp.send("Emulation.setCPUThrottlingRate", { rate });
    const zoom = await measure(page, () => gesture(page, "zoom"));
    const pan = await measure(page, () => gesture(page, "pan"));
    if (cdp) await cdp.send("Emulation.setCPUThrottlingRate", { rate: 1 });
    console.log(`FRAMES ${rate}x zoom ${JSON.stringify(zoom)} pan ${JSON.stringify(pan)}`);
    expect(zoom.n).toBeGreaterThan(20);
    console.log(`LOAD ${(await import("node:os")).loadavg().map((x) => x.toFixed(1)).join(" ")}`);
  });
}

test("memory on a phone: windows off screen hold no canvas, and the layer memory stays under budget", async () => {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("Emulation.setDeviceMetricsOverride", { width: 393, height: 852, deviceScaleFactor: 3, mobile: true });
  await cdp.send("Emulation.setTouchEmulationEnabled", { enabled: true });
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.locator(".cl-viewport").waitFor();
  // Four windows, one column each: on a phone only one column is on screen at a time.
  const have = await windows(page).count();
  for (let i = have; i < 4; i++) {
    await page.keyboard.press("Control+Shift+K");
    await page.locator("#palette-input").fill("open shell on");
    await page.locator("#palette-results [role=option]").first().click();
    await page.waitForTimeout(500);
  }
  await expect(windows(page)).toHaveCount(4, { timeout: 15_000 });
  await page.waitForTimeout(1500);
  const canvases = await page.evaluate(() => {
    const vw = innerWidth, vh = innerHeight;
    return [...document.querySelectorAll<HTMLCanvasElement>(".terminal-host canvas")].map((c) => {
      const r = c.getBoundingClientRect();
      const onScreen = r.right > -vw * 0.5 && r.left < vw * 1.5 && r.bottom > 0 && r.top < vh;
      return { w: c.width, h: c.height, onScreen };
    });
  });
  // Focusing a window must never scroll the screen around the canvas (it moved the canvas by a column and kept far
  // terminals alive).
  expect(await page.evaluate(() => document.querySelector("#terminal-screen")!.scrollLeft), "the screen never scrolls").toBe(0);
  const bytes = (c: { w: number; h: number }): number => c.w * c.h * 4;
  const total = canvases.reduce((sum, c) => sum + bytes(c), 0);
  console.log(`MEMORY canvases ${JSON.stringify(canvases)} total=${(total / 1e6).toFixed(1)}MB`);
  for (const c of canvases.filter((x) => !x.onScreen)) expect(bytes(c)).toBe(0);
  // Composited layers (what the GPU holds): the sum of every layer's area at device scale, 4 bytes a pixel.
  const layers: Array<{ width: number; height: number; drawsContent?: boolean }> = [];
  cdp.on("LayerTree.layerTreeDidChange", (e: { layers?: typeof layers }) => { if (e.layers) { layers.length = 0; layers.push(...e.layers); } });
  await cdp.send("LayerTree.enable");
  await page.evaluate(() => { document.body.style.outline = "0"; });
  await page.waitForTimeout(1500);
  const area = layers.filter((l) => l.drawsContent !== false).reduce((sum, l) => sum + l.width * l.height, 0);
  const layerBytes = area * 4;
  console.log(`MEMORY layers n=${layers.length} area=${area} bytes@4=${(layerBytes / 1e6).toFixed(1)}MB (device px, as the layer tree reports them)`);
  expect(total + layerBytes).toBeLessThan(150e6);
  await cdp.send("Emulation.clearDeviceMetricsOverride");
  await cdp.send("Emulation.setTouchEmulationEnabled", { enabled: false });
});

test("captures: ink and paper at desktop and phone size", async ({ browser }) => {
  // The phone is a real phone context (touch, coarse pointer, device scale 3) carrying the same session cookie, so
  // the toolbar and the chrome are the phone's.
  const cookies = await page.context().cookies();
  for (const [name, device] of [["desktop", { viewport: { width: 1440, height: 900 } }], ["phone", devices["iPhone 15"]]] as const) {
    const context = await browser.newContext({ ...device, ignoreHTTPSErrors: true });
    await context.addCookies(cookies);
    const shot = await context.newPage();
    for (const theme of ["ink", "paper"]) {
      await shot.goto(`${server.origin}/?theme=${theme}&bg=none`);
      await shot.locator(".cl-viewport").waitFor();
      await shot.waitForTimeout(1500);
      await shot.screenshot({ path: `${captures}/${name}-${theme}.png` });
    }
    await context.close();
  }
});
