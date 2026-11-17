/**
 * A repaint replaces the terminal's picture within one painted frame (#528). Production server binary, real PTY, the
 * production tracer, and a 300 ms round trip through the bridge.
 *
 * During an output flood, each key makes the infraternal agent drop its queued raw output and send a repaint
 * (Snapshot) instead. The browser resets its terminal and parses that repaint. Before #528 the reset wiped the canvas
 * in one animation frame and the render loop drew the repaint only in the next, so the person saw an empty terminal
 * (only the cursor) for a frame or two on almost every key.
 *
 * The check samples the canvas once per frame, at the end of the frame's rendering update: after every
 * animation-frame callback has run (the renderer's loop and the tracer's write callbacks alike) and before the browser
 * paints. A resize observer on a 1 px probe whose width flips on every frame delivers exactly that moment. Each sample
 * counts "ink" pixels on a nearest-neighbour quarter-scale copy of the whole canvas: `yes` puts a `y` at the start of
 * every row, so a full screen and a repainted screen both have ink and a wiped one has none. The server's Snapshot count proves the keys exercised the
 * repaint path, so the spec cannot pass because no repaint happened.
 */
import { expect, test, type Page } from "playwright/test";
import { writeFile } from "node:fs/promises";
import { installFrameSampler } from "./frame-sampler";
import { personName, startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });
/** The real server this file starts with a 150 ms delay each way; disposed after the test. */
let server: RealServer;
/** The signed-in page whose single terminal floods. */
let page: Page;

/**
 * The typed program: unbuffered keys, `F` starts `yes` over the whole screen, `S` stops it and ends, and any other key
 * is printed. `-icanon` rather than `raw` keeps output processing, so each `y` line starts in column 1 (in raw mode the
 * lines staircase across the screen and a frame can legitimately hold few glyphs). `bash -c` keeps it independent of
 * the account's login shell.
 */
const FLOOD_PROGRAM =
  "bash --norc -c 'stty -icanon -echo; printf \"\\033[2J\\033[H\"; flood_pid=; while IFS= read -rsn1 c; do " +
  "if [ \"$c\" = F ]; then yes & flood_pid=$!; elif [ \"$c\" = S ]; then kill \"$flood_pid\" 2>/dev/null || :; " +
  "wait \"$flood_pid\" 2>/dev/null || :; break; else printf \"%s\" \"$c\"; fi; done; stty sane'";
/** Keys typed during the flood; J811 saw 17 of 20 blank on dev. */
const KEYS = 20;
/** A step that does not finish within this long counts as a frozen terminal. */
const FREEZE_MS = 15_000;
/** A frame with less ink than this share of the flood's median frame shows an empty terminal. */
const BLANK_SHARE = 0.25;

test.beforeAll(async ({ browser }) => {
  server = await startRealServer({ latencyMs: 150, recordFlow: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 800 } });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  // Probe mode is the single-terminal screen, the same one the same-session flood spec measures.
  await page.goto(server.origin + "/?theme=ink&bg=none&probe=1");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("repaint_frame"));
  await page.locator("#setup-display-name").fill("Repaint frame");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".terminal-host").first().waitFor();
});
test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

/** The newest open bridge with an attached terminal stream. */
function terminalBridge() {
  const bridge = server.bridges.filter((candidate) => !candidate.closed && candidate.attached.size > 0).at(-1);
  if (!bridge) throw new Error("no active terminal bridge");
  return bridge;
}

/** Snapshots the server has sent to the browser on `bridge` so far (the flow trace keeps only those). */
function snapshotsSent(bridge: ReturnType<typeof terminalBridge>): number {
  return (bridge.flowTimes ?? []).filter((event) => event.type === "Snapshot").length;
}

test("a repaint during an output flood never shows an empty terminal for a frame", async () => {
  test.setTimeout(180_000);
  await expect.poll(() => server.bridges.filter((b) => !b.closed).at(-1)?.attached.size ?? 0, { timeout: FREEZE_MS }).toBe(1);
  const panel = page.locator("#probe-panel");
  await panel.evaluate((element) => { (element as HTMLElement).hidden = true; });
  const bridge = terminalBridge();
  // Keep only the Snapshot stage in the bounded flow trace, and no flood text, so the bridge keeps up with the flood.
  bridge.flowFilter = new Set(["down:backend-receive:Snapshot"]);
  bridge.skipOutputText = true;
  /** Whether the terminal still uses the route the flood started on (a reconnect resets and redraws the screen). */
  const routeKept = (): boolean => server.bridges.filter((c) => !c.closed && c.attached.size > 0).at(-1)?.id === bridge.id;
  const started = bridge.outputBytesSeen ?? 0;
  await page.locator(".terminal-host").first().click({ position: { x: 60, y: 60 } });
  await page.keyboard.type(FLOOD_PROGRAM + "\n", { delay: 2 });
  await expect.poll(() => (bridge.outputBytesSeen ?? 0) - started, { timeout: FREEZE_MS }).toBeGreaterThan(0);

  await installFrameSampler(page);
  await page.keyboard.press("F");
  // The flood fills the screen once a few screenfuls have reached the browser.
  await expect.poll(() => (bridge.outputBytesSeen ?? 0) - started, { timeout: FREEZE_MS }).toBeGreaterThan(256 * 1024);
  // Calibrate on the flooding screen: every row holds a `y`.
  await page.evaluate(() => window.__repaintFrames!.arm(-1));
  await expect.poll(() => page.evaluate(() => window.__repaintFrames!.samples.length), { timeout: FREEZE_MS }).toBeGreaterThan(30);
  const calibration = await page.evaluate(() => window.__repaintFrames!.samples.map((s) => s.ink).sort((a, b) => a - b));
  const median = calibration[Math.floor(calibration.length / 2)]!;
  expect(median, "the flooding screen must show ink").toBeGreaterThan(40);
  const threshold = Math.floor(median * BLANK_SHARE);
  await page.evaluate((value) => { window.__repaintFrames!.samples.length = 0; window.__repaintFrames!.arm(value); }, threshold);

  const snapshotsBefore = snapshotsSent(bridge);
  for (let key = 0; key < KEYS; key += 1) {
    await page.keyboard.press(String.fromCharCode(97 + key));
    // sleep: pace keys like a person typing, so each one meets a fresh flood and gets its own repaint (J811's run).
    await page.waitForTimeout(500);
  }
  // sleep: let the last key's repaint (300 ms round trip) arrive and paint before the sampler stops.
  await page.waitForTimeout(1500);
  const result = await page.evaluate(() => {
    const frames = window.__repaintFrames!;
    frames.stop();
    return { samples: frames.samples, firstBlank: frames.firstBlank };
  });
  const snapshots = snapshotsSent(bridge) - snapshotsBefore;
  const blank = result.samples.filter((frame) => frame.ink < threshold);
  const spanMs = result.samples.length > 1 ? result.samples.at(-1)!.at - result.samples[0]!.at : 0;
  const summary = {
    keys: KEYS, snapshots, routeKept: routeKept(), frames: result.samples.length, spanMs: Math.round(spanMs), medianInk: median, threshold,
    blankFrames: blank.length, blankAtMs: blank.slice(0, 10).map((frame) => Math.round(frame.at - (result.samples[0]?.at ?? 0))),
  };
  console.log("REPAINT_FRAME " + JSON.stringify(summary));
  await writeFile(test.info().outputPath("repaint-frame.json"), JSON.stringify({ ...summary, samples: result.samples }));
  if (result.firstBlank) {
    await writeFile(test.info().outputPath("repaint-frame-first-blank.png"), Buffer.from(result.firstBlank.split(",")[1]!, "base64"));
  }

  const bytesBeforeStop = bridge.outputBytesSeen ?? 0;
  await page.keyboard.press("S");
  await expect.poll(() => bridge.outputBytesSeen ?? 0, { timeout: FREEZE_MS }).toBeGreaterThan(bytesBeforeStop);

  // The keys must have produced repaints on the route they started on, and the sampler must have kept sampling (a
  // flooding page on a shared VM paints far below 60 frames per second, so this only rules out a stalled sampler).
  expect(routeKept(), "the flood must not cost the browser its route").toBe(true);
  expect(snapshots, "keys during the flood must make the server repaint").toBeGreaterThanOrEqual(KEYS / 4);
  expect(result.samples.length, "the sampler must keep sampling frames").toBeGreaterThan(spanMs / 1000 * 4);
  expect(blank.length, "no frame may show an empty terminal").toBe(0);
});
