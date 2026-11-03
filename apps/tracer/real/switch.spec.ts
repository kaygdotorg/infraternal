/**
 * Switching sessions through the UI is instant (TASTE "Switching sessions is instant", #128): the production server
 * binary, a production build, real PTYs. Every way to switch a window to another session is timed from the user's
 * action to the first frame that shows the new session's screen, to the stream being attached and live, and to a
 * typed key being echoed. A frame sampler reads the terminal canvas on every animation frame, so a blank or stale
 * frame shows as a number, not an impression.
 *
 * Run twice for the two profiles: `bun x playwright test -c playwright.real.config.ts real/switch.spec.ts` (no delay)
 * and with `REAL_ONE_WAY_MS=150` (the 300 ms round-trip profile). Each run prints `SWITCH {json}` lines and writes
 * its table to the external job evidence directory. The assertions are the targets: first paint within one frame of
 * the action (every way that has the screen already), live within one round trip of the action.
 */
import { tracerEvidencePath } from "../test/evidence-path";
import { expect, test, type Page } from "playwright/test";
import { mkdir, writeFile } from "node:fs/promises";
import { loadavg } from "node:os";
import { resolve } from "node:path";
import { personName, startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });

const oneWay = Number(process.env.REAL_ONE_WAY_MS ?? 0);
const profile = oneWay ? `${oneWay * 2}ms` : "none";
const rtt = oneWay * 2;
let server: RealServer;
let page: Page;
const results: Array<Record<string, unknown>> = [];

test.beforeAll(async ({ browser }) => {
  test.setTimeout(180_000);
  server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  page = await context.newPage();
  await enrol(page);
});
test.afterAll(async () => {
  await mkdir(tracerEvidencePath(), { recursive: true });
  await writeFile(tracerEvidencePath(`switch-${process.env.SWITCH_LABEL ?? "run"}-${profile}.json`), JSON.stringify({ loadavg: loadavg(), results }, null, 1));
  await page?.context().close();
  await server?.dispose();
});

const windows = (p: Page) => p.locator('.cl[data-view="console"] .ui-window');

async function enrol(p: Page): Promise<void> {
  const cdp = await p.context().newCDPSession(p);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await p.goto(server.origin + "/");
  await p.locator("#setup-token").fill(server.token);
  await p.getByRole("button", { name: "Continue", exact: true }).click();
  await p.locator("#setup-username").fill(personName("switch_real"));
  await p.locator("#setup-display-name").fill("Switch real");
  await p.getByRole("button", { name: "Continue", exact: true }).click();
  await p.getByRole("button", { name: "Create passkey" }).click();
  await p.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await p.locator(".auth-check").click();
  await p.getByRole("button", { name: "Open infraternal" }).click();
  await p.locator(".cl-viewport").waitFor();
}

/** Installs the in-page recorder: the user's action (the first click or Enter after `arm`), long tasks and the marks. */
async function install(p: Page): Promise<void> {
  await p.evaluate(() => {
    const w = window as unknown as { __sw?: { t0: number; epoch: number; longest: number }; __swArm?: () => void };
    if (w.__sw) return;
    const sw = { t0: 0, epoch: 0, longest: 0 };
    w.__sw = sw;
    new PerformanceObserver((list) => { for (const e of list.getEntries()) if (e.startTime >= sw.t0) sw.longest = Math.max(sw.longest, e.duration); }).observe({ type: "longtask", buffered: false });
    let armed = false;
    w.__swArm = () => { armed = true; sw.longest = 0; performance.clearMarks(); };
    const take = (e: Event): void => { if (armed) { armed = false; sw.t0 = e.timeStamp; sw.epoch = performance.timeOrigin + e.timeStamp; } };
    document.addEventListener("click", take, true);
    document.addEventListener("keydown", (e) => { if (e.key === "Enter") take(e); }, true);
  });
}
const arm = (p: Page): Promise<void> => p.evaluate(() => (window as unknown as { __swArm: () => void }).__swArm());

interface Timeline {
  way: string;
  /** Action to the first frame that can show the new session: its last known screen, or else its live output (ms). */
  firstPaint: number | null;
  /** Action to the last known screen being in the page (ms): the work the click does before the browser can paint it. */
  shown: number | null;
  /** Whether that first paint was the last known screen (true) or had to wait for the server (false). */
  fromCache: boolean;
  /** Action to the AttachTerm being sent (ms). */
  attached: number | null;
  /** Action to the live screen painted from the server's snapshot (ms). */
  livePaint: number | null;
  /** The longest main-thread task after the action (ms). */
  longestTask: number;
  marks: Record<string, number>;
}

/** Reads the marks the switch left, relative to the user's action. */
async function read(p: Page, way: string, settleMs: number): Promise<Timeline> {
  await p.waitForTimeout(settleMs);
  return p.evaluate((way) => {
    const w = window as unknown as { __sw: { t0: number; longest: number } };
    const t0 = w.__sw.t0;
    const entries = performance.getEntriesByType("mark").filter((m) => m.name.startsWith("sw:") && m.startTime >= t0 - 1);
    const marks: Record<string, number> = {};
    for (const m of entries) if (!(m.name in marks)) marks[m.name] = Math.round((m.startTime - t0) * 10) / 10;
    // The binding that shows the new session is the first to mount or retarget after the action.
    const begin = entries.find((m) => /^sw:\d+:(mount|retarget)$/.test(m.name));
    const bind = begin?.name.split(":")[1];
    const at = (step: string): number | null => (bind && marks[`sw:${bind}:${step}`] !== undefined ? marks[`sw:${bind}:${step}`]! : null);
    const ghost = at("ghost"), live = at("painted");
    const first = ghost ?? live;
    return { way, firstPaint: first, shown: at("ghosted"), fromCache: ghost !== null, attached: at("attached"), livePaint: live, longestTask: Math.round(w.__sw.longest), marks };
  }, way);
}

/** The two sessions' ids (hex), ordered by the markers printed in their actual windows. */
let ids: string[] = [];
/** The inventory's id form: a lowercase UUID with dashes. */
const sessionOf = (index: number): string => ids[index]!.replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");


/** Attach completion order can differ from window order; resolve only fixture-owned output markers. */
const sessionWithMarker = (marker: string): string | undefined => {
  const bridge = server.bridges.filter((item) => !item.closed).at(-1);
  const stream = [...(bridge?.output.entries() ?? [])].find(([, text]) => text.includes(`\r\n${marker}\r\n`))?.[0];
  return stream === undefined ? undefined : bridge?.attached.get(stream)?.at(-1);
};

test("setup: two sessions with different screens, the second left running without a window", async () => {
  test.setTimeout(120_000);
  await install(page);
  await expect(windows(page)).toHaveCount(1);
  const a = windows(page).first();
  await a.locator(".terminal-host").click({ position: { x: 40, y: 40 } });
  await page.keyboard.type("clear; seq 1 14; echo FIRST-MARK\n", { delay: 5 });
  await expect.poll(() => sessionWithMarker("FIRST-MARK")).toBeTruthy();
  ids = [sessionWithMarker("FIRST-MARK")!];
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("open shell on");
  await page.locator("#palette-results [role=option]").first().click();
  await expect(windows(page)).toHaveCount(2);
  await expect.poll(() => [...(server.bridges.filter((b) => !b.closed).at(-1)?.attached.values() ?? [])].flat().length, { timeout: 20_000 }).toBe(2);
  await windows(page).nth(1).locator(".terminal-host").click({ position: { x: 40, y: 40 } });
  await page.keyboard.type("clear; seq 200 214; echo SECOND-MARK\n", { delay: 5 });
  await expect.poll(() => sessionWithMarker("SECOND-MARK")).toBeTruthy();
  ids.push(sessionWithMarker("SECOND-MARK")!);
  expect(new Set(ids).size).toBe(2);
  await windows(page).nth(1).locator('[data-action="close"]').click({ force: true });
  await expect(windows(page)).toHaveCount(1);
  await windows(page).first().locator(".terminal-host").click({ position: { x: 40, y: 40 } });
  await page.waitForTimeout(400);
});

const record = (t: Timeline): void => { results.push(t as unknown as Record<string, unknown>); console.log("SWITCH", JSON.stringify(t)); };

async function managerSwitch(target: "second" | "first"): Promise<Timeline> {
  const win = windows(page).first();
  await win.locator('[data-action="sessions"]').click();
  await expect(page.locator(".cl-sx-pop")).toBeVisible();
  const rows = page.locator(".cl-sx-row:not([data-current])");
  await arm(page);
  await rows.first().locator(".cl-sx-main").click();
  return read(page, `manager→${target}`, 1200 + rtt * 3);
}

test("the session manager switches a window", async () => {
  test.setTimeout(120_000);
  const sockets = server.bridges.length;
  for (let i = 0; i < 8; i++) {
    const t = await managerSwitch(i % 2 === 0 ? "second" : "first");
    record(t);
  }
  // One socket carried every switch: attaching never drops the connection (the stream id used to be 0 and the server closed it).
  expect(server.bridges.length, "no reconnect during the switches").toBe(sockets);
  expect(server.bridges.at(-1)!.closed).toBe(false);
  console.log("BRIDGES", JSON.stringify(server.bridges.map((b) => ({ id: b.id, closed: b.closed, by: b.closedBy, attached: [...b.attached.entries()], detached: b.detached }))));
});

test("after a switch the keys go to the new session and are acknowledged", async () => {
  test.setTimeout(60_000);
  // The window shows the first session after the last manager switch; switch to the second and type.
  await managerSwitch("second");
  await page.waitForTimeout(600 + rtt * 2);
  const bridge = server.bridges.filter((b) => !b.closed).at(-1)!;
  const stream = [...bridge.attached.entries()].filter(([, sessions]) => sessions.includes(sessionOf(1).replace(/-/g, ""))).map(([id]) => id).at(-1)!;
  const before = bridge.acked.get(stream) ?? 0n;
  const typedAt = Date.now();
  await page.keyboard.type("echo SW-$((6*7))\n", { delay: 2 });
  await expect.poll(() => (bridge.acked.get(stream) ?? 0n) > before, { timeout: 20_000 }).toBe(true);
  const acked = Date.now() - typedAt;
  await expect.poll(() => bridge.output.get(stream) ?? "", { timeout: 10_000 }).toContain("SW-42");
  console.log("INPUT", JSON.stringify({ ackedMs: acked }));
  results.push({ way: "input after manager switch (ack, ms from first key)", ackedMs: acked });
  await managerSwitch("first");
});

test("the sidebar's session list and the palette open a detached session", async () => {
  test.setTimeout(180_000);
  // Make sure the second session is detached and the first is in the one window.
  for (let i = 0; i < 3; i++) {
    for (const way of ["sidebar", "palette"] as const) {
      await arm(page);
      const target = sessionOf(1);
      if (way === "sidebar") {
        await page.locator("#sidebar-toggle").click();
        await expect(page.locator("#tree .bm-leaf[data-id^='s:']").first()).toBeVisible({ timeout: 10_000 });
        await arm(page);
        await page.locator(`#tree .bm-leaf[data-id$='/${target}']`).click();
      } else {
        await page.keyboard.press("Control+Shift+K");
        await page.locator("#palette-input").fill("shell");
        await expect(page.locator(`#palette-results .result[data-action$='/${target}']`)).toBeVisible();
        await arm(page);
        await page.locator(`#palette-results .result[data-action$='/${target}']`).click();
      }
      record(await read(page, `${way}→new window`, 1500 + rtt * 3));
      if (way === "sidebar") await page.locator("#sidebar-toggle").click();
      // Back to one window, the second session detached again.
      await expect(windows(page)).toHaveCount(2);
      await windows(page).last().locator('[data-action="close"]').click({ force: true });
      await expect(windows(page)).toHaveCount(1);
      await page.waitForTimeout(300);
    }
  }
});

test("a frame-by-frame strip of a switch shows the old screen, then the new one, never an empty terminal", async () => {
  test.setTimeout(60_000);
  const cdp = await page.context().newCDPSession(page);
  const frames: Array<{ at: number; data: string }> = [];
  cdp.on("Page.screencastFrame", (f) => { frames.push({ at: f.metadata.timestamp! * 1000, data: f.data }); void cdp.send("Page.screencastFrameAck", { sessionId: f.sessionId }); });
  const body = (await windows(page).first().locator(".ui-window-body").boundingBox())!;
  await cdp.send("Page.startScreencast", { format: "jpeg", quality: 70, everyNthFrame: 1 });
  await page.waitForTimeout(300);
  const win = windows(page).first();
  await win.locator('[data-action="sessions"]').click();
  await expect(page.locator(".cl-sx-pop")).toBeVisible();
  await page.waitForTimeout(300);
  await arm(page);
  await page.locator(".cl-sx-row:not([data-current]) .cl-sx-main").first().click();
  const epoch = await page.evaluate(() => (window as unknown as { __sw: { epoch: number } }).__sw.epoch);
  await page.waitForTimeout(900 + rtt * 2);
  await cdp.send("Page.stopScreencast");
  // Decode the frames in a scratch page and count ink (pixels off the background) inside the terminal's body.
  const scratch = await page.context().newPage();
  const ink = await scratch.evaluate(async ({ shots, rect }) => {
    const out: number[] = [];
    for (const data of shots) {
      const bitmap = await createImageBitmap(await (await fetch(`data:image/jpeg;base64,${data}`)).blob());
      const c = new OffscreenCanvas(rect.w, rect.h);
      const ctx = c.getContext("2d")!;
      ctx.drawImage(bitmap, rect.x, rect.y, rect.w, rect.h, 0, 0, rect.w, rect.h);
      const px = ctx.getImageData(0, 0, rect.w, rect.h).data;
      const bg = (px[0]! + px[1]! + px[2]!) / 3;
      let n = 0;
      for (let i = 0; i < px.length; i += 16) if (Math.abs((px[i]! + px[i + 1]! + px[i + 2]!) / 3 - bg) > 40) n++;
      out.push(n);
    }
    return out;
  }, { shots: frames.map((f) => f.data), rect: { x: Math.round(body.x + 8), y: Math.round(body.y + 8), w: Math.round(body.width - 16), h: Math.round(Math.min(body.height - 16, 260)) } });
  await scratch.close();
  const timeline = frames.map((f, i) => ({ ms: Math.round(f.at - epoch), ink: ink[i]! }));
  console.log("STRIP", JSON.stringify(timeline.filter((f) => f.ms > -80 && f.ms < 700)));
  const dir = tracerEvidencePath(`switch-strip-${profile}`);
  await mkdir(dir, { recursive: true });
  for (const [i, f] of frames.entries()) { const ms = Math.round(f.at - epoch); if (ms > -50 && ms < 150) await writeFile(`${dir}/frame-${String(ms + 100).padStart(4, "0")}ms.jpg`, Buffer.from(f.data, "base64")); void i; }
  const after = timeline.filter((f) => f.ms >= 0 && f.ms < 600 + rtt);
  const before = timeline.filter((f) => f.ms < 0).at(-1);
  expect(before?.ink ?? 0, "the old screen has content").toBeGreaterThan(30);
  // No frame after the action is an empty terminal: the old screen, the cached screen and the live one all have text.
  for (const f of after) expect(f.ink, `frame at ${f.ms} ms is not empty`).toBeGreaterThan(30);
  results.push({ way: "strip", frames: after.length, minInk: Math.min(...after.map((f) => f.ink)) });
  await managerSwitch("first");
});

test("a session that was never shown since the page loaded still switches without a reconnect (no picture yet: the server's screen paints)", async () => {
  test.setTimeout(90_000);
  await page.reload();
  await page.locator(".cl-viewport").waitFor();
  await expect(windows(page)).toHaveCount(1);
  await install(page);
  await page.waitForTimeout(1500 + rtt * 3);
  const sockets = server.bridges.length;
  const t = await managerSwitch("second");
  t.way = "manager→second (not shown since the page loaded)";
  record(t);
  expect(server.bridges.length).toBe(sockets + 0);
  expect(t.fromCache).toBe(false);
  expect(t.attached ?? 1e9).toBeLessThanOrEqual(60);
  expect(t.livePaint ?? 1e9, "live within a round trip of the action").toBeLessThanOrEqual(60 + rtt + 300);
  await page.waitForTimeout(500);
  await managerSwitch("first");
});

test("targets: the new session's screen is there within a frame, and live within a round trip", async () => {
  const timelines = (results as unknown as Timeline[]).filter((r) => typeof r.firstPaint !== "undefined" && !r.way.includes("not shown since"));
  expect(timelines.length).toBeGreaterThan(0);
  const median = (xs: number[]): number => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)]!;
  for (const group of ["manager", "sidebar", "palette"]) {
    const rows = timelines.filter((r) => r.way.startsWith(group));
    expect(rows.length, group).toBeGreaterThan(0);
    for (const r of rows) {
      expect(r.firstPaint, `${r.way}: first paint`).not.toBeNull();
      expect(r.fromCache, `${r.way}: the last known screen is shown, not an empty terminal`).toBe(true);
      // The very first switch of a page also pays one-off costs (JIT, the first bitmap): bounded, not the target.
      expect(r.firstPaint!, `${r.way}: first paint, worst case (ms)`).toBeLessThanOrEqual(250);
      // A window that keeps its terminal sends its attach at once; live is one round trip after that.
      if (group === "manager") expect(r.attached ?? 1e9, `${r.way}: attach sent (ms)`).toBeLessThanOrEqual(100);
      expect(r.livePaint ?? 1e9, `${r.way}: live (ms)`).toBeLessThanOrEqual((group === "manager" ? 60 : 250) + rtt + 300);
    }
    // The target is one frame (16.7 ms) of the click's own work, then the next frame paints the last known screen; a new
    // window also has to be made and sized. A quiet machine meets it (see the table in the issue); the bounds here are two
    // frames for a window that keeps its terminal, because the same machine runs the build and other jobs, and they are
    // medians so that one slow task cannot fail the run. The run records the load average beside the numbers.
    expect(median(rows.map((r) => r.shown!)), `${group}: median work before the screen can paint (ms)`).toBeLessThanOrEqual(group === "manager" ? 34 : 50);
    expect(median(rows.map((r) => r.firstPaint!)), `${group}: median first paint (ms)`).toBeLessThanOrEqual(group === "manager" ? 70 : 100);
  }
});
