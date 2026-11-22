/**
 * Coming back after the resume window ran out, on the real server and PTY (#569, D265, D375).
 *
 * The page is hidden and frozen, as a phone or a sleeping laptop freezes it; the fixture then cuts the browser socket,
 * so the server starts the connection's resume window at once, while the page cannot notice. After `AWAY_MS` (longer
 * than the 120 s window) the page wakes. It still holds its resume token and sends it; the server finds it stale.
 *
 * Each return prints one `METRIC expired_resume` line:
 *
 * | Field | Meaning |
 * |---|---|
 * | `sockets_opened` | browser sockets opened to come back (one is the floor) |
 * | `resume_refusals` | sockets the server closed with "refused to resume" |
 * | `welcome_ms` | wake to the first Welcome the browser received |
 * | `blank_ms` | time after wake the terminal canvas showed less than half its ink (a blanked screen) |
 * | `last_screen_ms` | wake to the first painted frame of the last screen that stays (one frame when never blanked) |
 * | `live_ms` | wake to the terminal saying it is live (its replay painted, typing goes to the shell) |
 * | `typable_ms` | wake to the echo of a key typed the moment the terminal is live (`live_to_key_ms` is the harness's own lag) |
 * | `replay_bytes` | terminal output bytes the browser received between wake and live |
 *
 * Ink is counted on a small copy of the terminal's canvas each animation frame: pixels that differ clearly from the
 * background. It needs no test hook, so it measures the production build as a person sees it.
 *
 * Settings: `REAL_ONE_WAY_MS` (delay the fixture bridge adds each way; 0 when a network namespace delays instead),
 * `EXPIRED_RESUME_PORT` (fixed bridge port, so a netem filter can match it), `EXPIRED_RESUME_SAMPLES` (default 3),
 * `EXPIRED_RESUME_AWAY_MS` (default 125000), `EXPIRED_RESUME_SCROLLBACK_LINES` (lines printed once before the first
 * return, default 200000) and `EXPIRED_RESUME_AWAY_LINES` (lines printed while the page is away, default 0: the
 * backlog a return must catch up on). It is a measurement, not a gate: run it on its own, never in the functional
 * suite (`EXPIRED_RESUME=1` enables it).
 */
import { expect, test, type CDPSession, type Page } from "playwright/test";
import { personName, startRealServer, type RealServer } from "./server";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";

/** The spec runs only when asked: each return waits out the resume window. */
const enabled = process.env.EXPIRED_RESUME === "1";
/** Delay the fixture bridge adds each way, in ms; 0 when a network namespace delays instead. */
const ONE_WAY_MS = Number(process.env.REAL_ONE_WAY_MS ?? 0);
/** Fixed bridge port, so a netem filter can match it; a free port when unset. */
const PORT = process.env.EXPIRED_RESUME_PORT === undefined ? undefined : Number(process.env.EXPIRED_RESUME_PORT);
/** How many returns to measure. */
const SAMPLES = Number(process.env.EXPIRED_RESUME_SAMPLES ?? 3);
/** How long the page stays frozen; longer than the 120 s resume window. */
const AWAY_MS = Number(process.env.EXPIRED_RESUME_AWAY_MS ?? 125_000);
/** Lines printed once before the first return, to give the terminal a scrollback to lose. */
const SCROLLBACK_LINES = Number(process.env.EXPIRED_RESUME_SCROLLBACK_LINES ?? 200_000);
/** Lines printed while the page is away: the backlog a return must catch up on. */
const AWAY_LINES = Number(process.env.EXPIRED_RESUME_AWAY_LINES ?? 0);
/** How long after wake the canvas is sampled; a return slower than this is a failure in its own right. */
const WATCH_MS = 30_000;

/**
 * What the browser saw on its sockets, from CDP: Welcome and terminal output receive times, and, for the first-key
 * breakdown, when each terminal Input left the page and when Acks and Snapshots arrived.
 */
interface Seen {
  welcomes: number[];
  outputs: Array<{ at: number; bytes: number; text: string }>;
  inputs: Array<{ at: number; inSeq: bigint; bytes: number }>;
  acks: Array<{ at: number; inSeqAcked: bigint }>;
  snapshots: number[];
}

/** Decodes every app frame the page receives on `/v1/ws` and keeps Welcome times and terminal output. */
function watchSockets(cdp: CDPSession): Seen {
  const seen: Seen = { welcomes: [], outputs: [], inputs: [], acks: [], snapshots: [] };
  const decoders = new Map<string, WebSocketFrameDecoder>();
  const sentDecoders = new Map<string, WebSocketFrameDecoder>();
  const text = new TextDecoder();
  cdp.on("Network.webSocketCreated", ({ requestId, url }) => {
    if (new URL(url).pathname !== "/v1/ws") return;
    decoders.set(requestId, new WebSocketFrameDecoder());
    sentDecoders.set(requestId, new WebSocketFrameDecoder());
  });
  cdp.on("Network.webSocketClosed", ({ requestId }) => { decoders.delete(requestId); sentDecoders.delete(requestId); });
  cdp.on("Network.webSocketFrameSent", ({ requestId, response }) => {
    const decoder = sentDecoders.get(requestId);
    if (!decoder || response.opcode !== 2) return;
    const at = Date.now();
    decoder.feed(new Uint8Array(Buffer.from(response.payloadData, "base64")), (stream, frame) => {
      if (frame.type === "Input" && stream !== 0) seen.inputs.push({ at, inSeq: frame.inSeq, bytes: frame.bytes.byteLength });
    });
  });
  cdp.on("Network.webSocketFrameReceived", ({ requestId, response }) => {
    const decoder = decoders.get(requestId);
    if (!decoder || response.opcode !== 2) return;
    const at = Date.now();
    decoder.feed(new Uint8Array(Buffer.from(response.payloadData, "base64")), (stream, frame) => {
      if (frame.type === "Welcome") seen.welcomes.push(at);
      if (frame.type === "Output" && stream !== 0) seen.outputs.push({ at, bytes: frame.bytes.byteLength, text: text.decode(frame.bytes) });
      if (frame.type === "Ack" && stream !== 0) seen.acks.push({ at, inSeqAcked: frame.inSeqAcked });
      if (frame.type === "Snapshot" && stream !== 0) seen.snapshots.push(at);
    });
  });
  return seen;
}

/** Sets the page's visibility the way a browser does when a tab or app goes to the background. */
const setVisibility = (page: Page, hidden: boolean): Promise<void> => page.evaluate((hide) => {
  Object.defineProperty(document, "hidden", { configurable: true, get: () => hide });
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => (hide ? "hidden" : "visible") });
  document.dispatchEvent(new Event("visibilitychange"));
}, hidden);

/**
 * Installs `window.__ink()`: the ink of the terminal's largest canvas, counted on a 160x100 copy. Installed through
 * the debugger protocol, which the page's content security policy does not govern; the page itself never evaluates
 * strings.
 */
const INK_SOURCE = `window.__ink = () => {
  const canvases = [...document.querySelectorAll('.cl[data-view="console"] .ui-window .terminal-host canvas')];
  const canvas = canvases.sort((a, b) => b.width * b.height - a.width * a.height)[0];
  if (!canvas || canvas.width === 0) return 0;
  const copy = window.__inkCopy ??= Object.assign(document.createElement("canvas"), { width: 160, height: 100 });
  const context = copy.getContext("2d", { willReadFrequently: true });
  context.clearRect(0, 0, 160, 100);
  context.drawImage(canvas, 0, 0, 160, 100);
  const pixels = context.getImageData(0, 0, 160, 100).data;
  const r0 = pixels[0], g0 = pixels[1], b0 = pixels[2];
  let ink = 0;
  for (let i = 0; i < pixels.length; i += 4) {
    if (Math.abs(pixels[i] - r0) + Math.abs(pixels[i + 1] - g0) + Math.abs(pixels[i + 2] - b0) > 60) ink++;
  }
  return ink;
}`;

test("coming back after the resume window keeps the screen and resumes in one handshake", async ({ browser }) => {
  test.skip(!enabled, "a measurement: set EXPIRED_RESUME=1");
  test.setTimeout(180_000 + SAMPLES * (AWAY_MS + 60_000));
  const server: RealServer = await startRealServer({ latencyMs: ONE_WAY_MS, port: PORT });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 800 } });
  const page = await context.newPage();
  try {
    const cdp = await context.newCDPSession(page);
    await cdp.send("Network.enable");
    const seen = watchSockets(cdp);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
    await page.goto(server.origin + "/?theme=ink&bg=none");
    // Keep the one-time setup value out of a locator action's failure log.
    await page.locator("#setup-token").evaluate((element, token) => {
      (element as HTMLInputElement).value = token;
      element.dispatchEvent(new Event("input", { bubbles: true }));
    }, server.token);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.locator("#setup-username").fill(personName("expired_resume"));
    await page.locator("#setup-display-name").fill("Expired resume");
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.getByRole("button", { name: "Create passkey" }).click();
    await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
    await page.locator(".auth-check").click();
    await page.getByRole("button", { name: "Open infraternal" }).click();
    await page.locator(".cl-viewport").waitFor();
    const terminal = page.locator('.cl[data-view="console"] .ui-window').first();
    await expect(terminal).toHaveAttribute("data-status", "live", { timeout: 30_000 });
    await terminal.locator(".terminal-host").click({ position: { x: 40, y: 40 } });
    await terminal.locator(".terminal-host textarea").focus();
    const outputText = (): string => seen.outputs.map((output) => output.text).join("");
    await page.evaluate(INK_SOURCE);
    const ink = (): Promise<number> => page.evaluate(() => (window as unknown as { __ink: () => number }).__ink());
    if (SCROLLBACK_LINES > 0) {
      await page.keyboard.type(`seq 1 ${SCROLLBACK_LINES}; echo scrollback-$((6*7))\n`);
      await expect.poll(outputText, { timeout: 120_000 }).toContain("scrollback-42");
    }
    // sleep: let the last frames paint before the canvas baseline is read.
    await page.waitForTimeout(1000);

    for (let sample = 0; sample < SAMPLES; sample++) {
      const marker = `back-${sample}`;
      await page.keyboard.type(`clear; echo ${marker}-$((6*7)); ls -la /\n`);
      await expect.poll(outputText, { timeout: 30_000 }).toContain(`${marker}-42`);
      // sleep: the listing paints over a few frames; the baseline must be the settled screen.
      await page.waitForTimeout(1000);
      const baseline = await ink();
      expect(baseline).toBeGreaterThan(200);
      // Output that lands while the page is away: the backlog the return must catch up on.
      if (AWAY_LINES > 0) await page.keyboard.type(`sleep 3; seq 1 ${AWAY_LINES}; echo away-${sample}-$((6*7))\n`);
      await setVisibility(page, true);
      // sleep: let the visibility notice cross the link before the renderer stops.
      await page.waitForTimeout(1000);
      await cdp.send("Page.setWebLifecycleState", { state: "frozen" });
      const socketsBefore = server.bridges.length;
      // The server sees its socket end now and starts the resume window; the frozen page notices only on wake.
      await server.interruptBrowserRoutes(100);
      // sleep: the person is away for longer than the resume window.
      await page.waitForTimeout(AWAY_MS);

      await cdp.send("Page.setWebLifecycleState", { state: "active" });
      const wokeAt = Date.now();
      const outputsBefore = seen.outputs.length;
      const welcomesBefore = seen.welcomes.length;
      // Sample the canvas every frame from the moment the page is visible again, until it is live.
      const watch = page.evaluate((watchMs) => new Promise<{ frames: Array<[number, number]>; liveMs: number }>((done) => {
        Object.defineProperty(document, "hidden", { configurable: true, get: () => false });
        Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
        const shownAt = performance.now();
        document.dispatchEvent(new Event("visibilitychange"));
        const frames: Array<[number, number]> = [];
        let liveMs = -1;
        const step = (): void => {
          const now = performance.now() - shownAt;
          frames.push([now, (window as unknown as { __ink: () => number }).__ink()]);
          const live = document.querySelector('.cl[data-view="console"] .ui-window[data-status="live"]') !== null;
          // Keep sampling 500 ms past live, so a late blank (a replay painting from an empty screen) is still seen.
          if (live && liveMs < 0) liveMs = now;
          if ((liveMs >= 0 && now - liveMs > 500) || now > watchMs) done({ frames, liveMs });
          else requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
      }), WATCH_MS);
      // Type the moment the page says the terminal is live, as a person waiting at the keyboard would. A polling
      // `expect(...).toHaveAttribute` retries at growing intervals (up to 1 s) and added hundreds of ms of harness wait
      // between live and the key; the page's own observer resolves within a task of the change.
      await page.evaluate((watchMs) => new Promise<void>((done, fail) => {
        const live = (): boolean => document.querySelector('.cl[data-view="console"] .ui-window[data-status="live"]') !== null;
        if (live()) { done(); return; }
        const observer = new MutationObserver(() => { if (live()) { observer.disconnect(); done(); } });
        observer.observe(document.body, { subtree: true, attributes: true, attributeFilter: ["data-status"] });
        setTimeout(() => { observer.disconnect(); fail(new Error("terminal never became live")); }, watchMs);
      }), WATCH_MS);
      // The key goes to the terminal's input whatever had focus while the page was away; both builds pay the same.
      await terminal.locator(".terminal-host textarea").focus();
      const keyAt = Date.now();
      await page.keyboard.type("x");
      const echoed = (): { at: number } | undefined => seen.outputs.slice(outputsBefore).find((output) => output.at >= keyAt && output.text.includes("x"));
      // A missing echo is reported as NaN rather than failing the sample, so the other fields still print.
      await expect.poll(() => echoed() !== undefined, { timeout: 15_000 }).toBe(true).catch(() => undefined);
      const echoAt = echoed()?.at ?? Number.NaN;
      // Where the first key's time goes: still in the page, on the way to the shell, or waiting for the echo.
      const sentAt = seen.inputs.find((input) => input.at >= keyAt)?.at ?? Number.NaN;
      const ackAt = seen.acks.find((ack) => ack.at >= sentAt && ack.inSeqAcked > 0n)?.at ?? Number.NaN;
      const snapshotsAfterKey = seen.snapshots.filter((at) => at >= keyAt && at <= echoAt).length;
      const firstOutputAfterKey = seen.outputs.slice(outputsBefore).find((output) => output.at >= keyAt);
      const firstKey = `key_to_send_ms=${sentAt - keyAt} send_to_ack_ms=${ackAt - sentAt} send_to_echo_ms=${echoAt - sentAt} snapshots_before_echo=${snapshotsAfterKey} first_output_after_key_ms=${(firstOutputAfterKey?.at ?? Number.NaN) - keyAt} first_output_has_key=${firstOutputAfterKey?.text.includes("x") === true}`;
      const { frames, liveMs } = await watch;
      const blank = (ink: number): boolean => ink < baseline / 2;
      let blankMs = 0;
      for (let i = 0; i < frames.length; i++) if (blank(frames[i]![1])) blankMs += (frames[i + 1]?.[0] ?? frames[i]![0]) - frames[i]![0];
      const lastBlank = frames.map(([, ink]) => blank(ink)).lastIndexOf(true);
      const lastScreenMs = frames[lastBlank + 1]?.[0] ?? Number.NaN;
      const opened = server.bridges.slice(socketsBefore);
      const refusals = opened.filter((bridge) => bridge.serverClose === "s0 the server refused to resume the connection").length;
      const replayBytes = seen.outputs.slice(outputsBefore).filter((output) => output.at < keyAt).reduce((sum, output) => sum + output.bytes, 0);
      console.log(`METRIC expired_resume sample=${sample} one_way_ms=${ONE_WAY_MS} away_ms=${AWAY_MS} away_lines=${AWAY_LINES} sockets_opened=${opened.length} resume_refusals=${refusals} hello_resume=${opened.map((bridge) => bridge.helloResume ? 1 : 0).join("")} welcome_ms=${(seen.welcomes[welcomesBefore] ?? Number.NaN) - wokeAt} blank_ms=${blankMs.toFixed(1)} last_screen_ms=${lastScreenMs.toFixed(1)} live_ms=${liveMs.toFixed(1)} typable_ms=${echoAt - wokeAt} replay_bytes=${replayBytes} frames=${frames.length} baseline_ink=${baseline} live_to_key_ms=${(keyAt - wokeAt - liveMs).toFixed(1)} ${firstKey}`);
      await page.keyboard.press("Backspace");
      if (AWAY_LINES > 0) await expect.poll(outputText, { timeout: 60_000 }).toContain(`away-${sample}-42`);
      // sleep: let the erase echo settle before the next sample's command.
      await page.waitForTimeout(500);
    }
  } finally {
    try { await context.close(); }
    finally { await server.dispose(); }
  }
});
