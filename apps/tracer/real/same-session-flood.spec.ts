/**
 * Typing into a terminal whose own program floods it never freezes (#477). Production server binary, real PTY, the
 * production tracer, and a 300 ms round trip through the bridge.
 *
 * Under a flood the infraternal agent may skip raw output and send a repaint instead (its 250 ms credit starvation
 * path), so a key's raw echo can legitimately never arrive. The shell here therefore draws a numbered token on row 1 for
 * every key while `yes` scrolls a region below it: the token survives in raw output and in a repaint alike, which is
 * what a person sees. The first test checks delivery and acknowledgment; the second records 200 actual paint callbacks
 * and compares same-session p99 growth with D375's one-frame budget. Its paint workload overwrites one cell with a key
 * outside `yes !`, so an old key or flood output cannot satisfy a later sample.
 */
import { expect, test, type Page } from "playwright/test";
import { personName, startRealServer, type RealServer } from "./server";
import { scanTokens } from "./flood-token";
import { writeFile } from "node:fs/promises";

test.describe.configure({ mode: "serial" });
/** The real server this file starts with a 150 ms delay each way; disposed after the last test. */
let server: RealServer;
/** The signed-in browser page that types into the flooding terminal. */
let page: Page;

/**
 * The typed program. It draws `<K000001>`, `<K000002>`, ... on row 1, one write per key, and starts `yes` when it reads
 * `F`; the scroll region `ESC [2r` keeps `yes` off row 1. `bash -c` keeps it independent of the account's login shell.
 */
const TOKEN_PROGRAM =
  "bash --norc -c 'stty raw -echo; printf \"\\033[2J\\033[2r\"; n=0; flood_pid=; while IFS= read -rsn1 c; do " +
  "if [ \"$c\" = F ]; then yes & flood_pid=$!; elif [ \"$c\" = S ]; then kill \"$flood_pid\" 2>/dev/null || :; wait \"$flood_pid\" 2>/dev/null || :; break; " +
  "else n=$((n+1)); printf \"\\0337\\033[1;1H<K%06d>\\0338\" \"$n\"; fi; done; stty sane'";
/** Keep each probe key in one overwritten cell outside the independent flood scroll region. */
const PAINT_PROGRAM =
  "bash --norc -c 'stty raw -echo; printf \"\\033[2J\\033[11r\\033[11;1HREADY\\n\"; flood_pid=; " +
  "while IFS= read -rsn1 key; do if [ \"$key\" = F ]; then yes \\! & flood_pid=$!; " +
  "elif [ \"$key\" = S ]; then kill \"$flood_pid\" 2>/dev/null || :; wait \"$flood_pid\" 2>/dev/null || :; break; " +
  "elif [ \"$key\" = R ]; then printf \"\\033[2J\\033[11r\\033[11;1HREADY\\n\"; " +
  "else printf \"\\033[1;1H\\033[2K%s\" \"$key\"; fi; done; stty sane'";
/** How many keys are typed in each phase. */
const KEYS = 20;
/** Quiet baseline count; shorten only diagnostic runs, while the flood p99 always uses 200 samples. */
const QUIET_PAINT_KEYS = Number(process.env.REAL_QUIET_PAINT_KEYS ?? 200);
/** Flood samples for a meaningful nearest-rank p99. */
const FLOOD_PAINT_KEYS = 200;
/** Raw output may spend this full amount while the separate repaint reserve stays protected. */
const BULK_WINDOW_BYTES = 1024 * 1024;
/** The browser reserves this part of its opening grant for an input-triggered repaint. */
const REPAINT_RESERVE_BYTES = 64 * 1024;
/** The complete opening grant includes the repaint reserve beside the raw bulk window. */
const INITIAL_CREDIT_BYTES = BULK_WINDOW_BYTES + REPAINT_RESERVE_BYTES;
/** A key whose token has not arrived after this long counts as a typing freeze. */
const FREEZE_MS = 15_000;
/** Allow all 200 serial paint samples to finish at the shaped 300 ms round trip. */
const FLOOD_PAINT_TIMEOUT_MS = Number(process.env.REAL_FLOOD_PAINT_TIMEOUT_MS ?? 720_000);

test.beforeAll(async ({ browser }) => {
  server = await startRealServer({ latencyMs: 150, recordFlow: true, recordCloses: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 800 } });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/?theme=ink&bg=none&probe=1&n=200");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("flood_real"));
  await page.locator("#setup-display-name").fill("Flood real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  // Probe mode deliberately uses the single-terminal screen, so it has no canvas `.cl-viewport`.
  await page.locator(".terminal-host").first().waitFor();
});
test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

/** The active terminal bridge, selected by its attached stream instead of incidental control sockets. */
function terminalBridge(): NonNullable<ReturnType<typeof activeTerminalBridge>> {
  const bridge = activeTerminalBridge();
  if (!bridge) throw new Error("no active terminal bridge");
  return bridge;
}

/** Find the current active terminal bridge without mistaking a newer control socket for the terminal. */
function activeTerminalBridge() {
  return server.bridges.filter((bridge) => !bridge.closed && bridge.attached.size > 0).at(-1);
}

/** The active bridge and its single terminal stream. */
function terminalStream(): { output: Map<number, string>; acked: Map<number, bigint>; stream: number } {
  const bridge = terminalBridge();
  const stream = [...(bridge?.attached.keys() ?? [])][0];
  if (!bridge || stream === undefined) throw new Error("no attached terminal stream");
  return { output: bridge.output, acked: bridge.acked, stream };
}

/** Credit the live relay has received, minus its Output and Snapshot charges. */
function serverCreditBalance(bridge: ReturnType<typeof terminalBridge>, stream: number): number {
  return (bridge.creditGrantedByStream?.get(stream) ?? 0) - (bridge.creditSpentByStream?.get(stream) ?? 0);
}

/** The newest token seen so far; tokens are trimmed from the bridge's text once they have been read. */
let newestSeen = 0;

/**
 * The newest row-1 token the browser was sent, by raw output or repaint. The bridge appends Output and replaces on
 * Snapshot. Each call scans everything recorded since the last call, then keeps only a tail long enough to hold a
 * token split across frames, so a flood cannot grow that string without bound and no token is trimmed unread.
 * A repaint positions every cell on its own, so `scanTokens` reads tokens with control sequences removed.
 */
function newestToken(): number {
  const { output, stream } = terminalStream();
  const { newest, tail } = scanTokens(output.get(stream) ?? "", newestSeen);
  newestSeen = newest;
  output.set(stream, tail);
  return newestSeen;
}

/** Types one key and returns how long its token took to reach the bridge, in milliseconds. */
async function typeKey(expected: number): Promise<number> {
  const { acked, stream } = terminalStream();
  const ackBefore = acked.get(stream) ?? 0n;
  const started = performance.now();
  await page.keyboard.press("x");
  await expect.poll(newestToken, { timeout: FREEZE_MS, intervals: [5] }).toBeGreaterThanOrEqual(expected);
  const elapsed = performance.now() - started;
  await expect.poll(() => acked.get(stream) ?? 0n, { timeout: FREEZE_MS }).toBeGreaterThan(ackBefore);
  return elapsed;
}

/** The `fraction` percentile of `samples` (nearest rank). */
function p(samples: number[], fraction: number): number {
  const ordered = [...samples].sort((a, b) => a - b);
  return ordered[Math.min(ordered.length - 1, Math.ceil(ordered.length * fraction) - 1)]!;
}

/** Read the aggregate paint p99 from the production latency probe's report. */
function probeP99(report: string): number {
  const match = /^p99: ([0-9.]+) ms$/m.exec(report);
  if (!match) throw new Error("paint probe did not report p99");
  return Number(match[1]);
}

/** A status that says the terminal lost, or is rebuilding, its connection. */
const RECONNECT_STATUS = /Reconnect|Catching up|Connection lost|stopped responding|connection sent something unexpected/;

/**
 * How wide the ink at the start of the terminal's first text row is, in CSS pixels, measured on a screenshot of the
 * rendered page (the production build exposes no screen text). A `<K000042>` token at row 1, column 1 spans nine
 * cells; a lone `y` from flood output spans one, and one at the far end of the row is outside the measured 200 px. Pixels count as ink when they differ clearly from the row's background, so the
 * theme and font do not matter. The probe panel is hidden while measuring because it overlaps the terminal.
 */
async function firstRowInkWidth(): Promise<number> {
  const panel = page.locator("#probe-panel");
  await panel.evaluate((element) => { (element as HTMLElement).hidden = true; });
  const box = (await page.locator(".terminal-host").first().boundingBox())!;
  const shot = await page.screenshot({ clip: { x: box.x, y: box.y, width: box.width, height: Math.min(48, box.height) } });
  await panel.evaluate((element) => { (element as HTMLElement).hidden = false; });
  return page.evaluate(async (bytes: number[]) => {
    const bitmap = await createImageBitmap(new Blob([new Uint8Array(bytes)], { type: "image/png" }));
    const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
    const context = canvas.getContext("2d")!;
    context.drawImage(bitmap, 0, 0);
    const { data, width, height } = context.getImageData(0, 0, bitmap.width, bitmap.height);
    const at = (x: number, y: number) => (y * width + x) * 4;
    const background = at(6, 6);
    let left = Infinity;
    let right = -Infinity;
    // Skip a 4 px frame so the host's border and rounded corners never count as text.
    const end = Math.min(width - 4, Math.round(200 * window.devicePixelRatio));
    for (let y = 4; y < height - 4; y++) for (let x = 4; x < end; x++) {
      const i = at(x, y);
      const distance = Math.abs(data[i]! - data[background]!) + Math.abs(data[i + 1]! - data[background + 1]!) + Math.abs(data[i + 2]! - data[background + 2]!);
      if (distance < 90) continue;
      left = Math.min(left, x);
      right = Math.max(right, x);
    }
    // The screenshot is taken at the device pixel ratio; report CSS pixels.
    return right < left ? 0 : (right - left + 1) / window.devicePixelRatio;
  }, [...shot]);
}

/** Finish when all requested keys paint, or surface the probe's own timeout with its partial trace. */
async function waitForPaintedEchoes(page: Page, count: number, timeoutMs: number): Promise<void> {
  const outcome = await page.waitForFunction((expected: number) => {
    const results = document.querySelector("#probe-results")?.textContent ?? "";
    if (results.includes(`Painted echoes: ${expected} / ${expected}`)) return "complete";
    const message = document.querySelector("#probe-message")?.textContent ?? "";
    return message.startsWith("Timed out after") ? message : false;
  }, count, { timeout: timeoutMs, polling: 50 });
  const result = await outcome.jsonValue();
  if (result !== "complete") throw new Error(`paint probe ended before all ${count} echoes: ${String(result)}`);
}

test("keys typed into a terminal that its own program floods keep showing on screen", async () => {
  test.setTimeout(240_000);
  await expect.poll(() => server.bridges.filter((b) => !b.closed).at(-1)?.attached.size ?? 0).toBe(1);
  await page.locator(".terminal-host").first().click({ position: { x: 60, y: 60 } });
  await page.keyboard.type(TOKEN_PROGRAM + "\n", { delay: 2 });
  let typed = 0;
  // The first token proves the loop is reading keys.
  await typeKey(++typed);
  const quiet: number[] = [];
  for (let i = 0; i < KEYS; i++) quiet.push(await typeKey(++typed));

  const { output, stream } = terminalStream();
  const route = terminalBridge().id;
  await page.keyboard.press("F");
  // `yes` is running once a screenful of its lines has reached the bridge, raw or repainted.
  await expect.poll(() => {
    const tail = (output.get(stream) ?? "").slice(-8192);
    output.set(stream, tail);
    return tail.split("y").length - 1;
  }, { timeout: FREEZE_MS }).toBeGreaterThan(200);
  const flood: number[] = [];
  for (let i = 0; i < KEYS; i++) flood.push(await typeKey(++typed));

  // The keys reached the bridge; now the person must see them. The newest token is drawn on row 1 of the rendered
  // terminal, on the route the flood started on, with no reconnect status (#477: these used to pass on a blank screen).
  const tokenWidth = await expect.poll(firstRowInkWidth, { timeout: 5_000, intervals: [50, 100, 250] })
    .toBeGreaterThan(40).then(() => firstRowInkWidth(), async (error: unknown) => {
      await page.screenshot({ path: test.info().outputPath("same-session-flood-no-token.png") });
      throw error;
    });
  await page.screenshot({ path: test.info().outputPath("same-session-flood.png") });
  expect(activeTerminalBridge()?.id, "typing during the flood must not cost the browser its route").toBe(route);
  await expect(page.locator("#connection-status")).not.toHaveText(RECONNECT_STATUS);
  console.log(`SAME_SESSION_FLOOD_SCREEN token_row_ink_px=${tokenWidth.toFixed(1)} route=${route}`);
  console.log(`SAME_SESSION_FLOOD keys=${KEYS} quiet_p50_ms=${p(quiet, 0.5).toFixed(1)} quiet_max_ms=${p(quiet, 1).toFixed(1)} ` +
    `flood_p50_ms=${p(flood, 0.5).toFixed(1)} flood_max_ms=${p(flood, 1).toFixed(1)} (bridge-observed, 150 ms each way)`);
  const bridge = terminalBridge();
  const beforeStop = bridge.outputBytesSeen ?? 0;
  await page.keyboard.press("S");
  await expect.poll(() => bridge.outputBytesSeen ?? 0, { timeout: FREEZE_MS }).toBeGreaterThan(beforeStop);
});

test("measures 200 same-session keydown-to-paint samples through the 300 ms profile", async () => {
  test.setTimeout(900_000);
  await expect.poll(() => activeTerminalBridge()?.attached.size ?? 0, { timeout: FREEZE_MS }).toBe(1);
  const bridge = terminalBridge();
  const { stream } = terminalStream();
  const probePanel = page.locator("#probe-panel");
  await probePanel.evaluate((element) => { (element as HTMLElement).hidden = true; });
  await page.locator(".terminal-host").first().click({ position: { x: 60, y: 60 } });
  const setupBytes = bridge.outputBytesSeen ?? 0;
  await page.keyboard.type(PAINT_PROGRAM + "\n", { delay: 1 });
  await expect.poll(() => (bridge.outputBytesSeen ?? 0) - setupBytes, { timeout: FREEZE_MS }).toBeGreaterThan(0);

  await probePanel.evaluate((element) => { (element as HTMLElement).hidden = false; });
  await page.locator("#probe-count").fill(String(QUIET_PAINT_KEYS));
  await expect(page.locator("#probe-run")).toBeEnabled({ timeout: FREEZE_MS });
  await page.locator("#probe-run").click();
  await expect(page.locator("#probe-results")).toContainText(`Painted echoes: ${QUIET_PAINT_KEYS} / ${QUIET_PAINT_KEYS}`, { timeout: 150_000 });
  const quietReport = await page.locator("#probe-results").innerText();
  const quietP99 = probeP99(quietReport);
  const quietProbeTrace = await page.evaluate(() => ({
    timeOriginMs: performance.timeOrigin,
    samples: window.__tracerPerformanceProbe?.trace() ?? [],
  }));
  console.log(`SAME_SESSION_PAINT_STAGE quiet_complete samples=${QUIET_PAINT_KEYS} p99_ms=${quietP99.toFixed(2)}`);

  await expect(page.locator("#probe-run")).toBeEnabled({ timeout: FREEZE_MS });
  await page.locator("#probe-count").fill(String(FLOOD_PAINT_KEYS));
  await probePanel.evaluate((element) => { (element as HTMLElement).hidden = true; });
  await page.locator(".terminal-host").first().click({ position: { x: 60, y: 60 } });
  await page.keyboard.press("R");
  await expect(page.locator("#probe-run")).toBeEnabled({ timeout: FREEZE_MS });
  console.log("SAME_SESSION_PAINT_STAGE reset_complete");

  // The opening grant may be split, and setup output may already have spent
  // some of it. Check that the full initial window reached the relay without
  // requiring its outstanding balance to return to the opening value.
  await expect.poll(() => bridge.creditGrantedByStream?.get(stream) ?? 0, {
    timeout: FREEZE_MS,
    intervals: [10],
  }).toBeGreaterThanOrEqual(INITIAL_CREDIT_BYTES);
  const openingCreditFrames = (bridge.flowTimes ?? [])
    .filter((event) => event.stream === stream && event.direction === "up"
      && event.stage === "backend-send" && event.type === "Credit")
    .slice(0, 8)
    .map(({ bytes, at }) => ({ bytes, at }));
  console.log("SAME_SESSION_OPENING_CREDIT " + JSON.stringify({ openingCreditFrames }));
  const rawOutput = bridge.rawOutputBytesSeen;
  if (!rawOutput) throw new Error("the real-server trace did not count raw Output by stream");
  const floodStartBytes = rawOutput.get(stream) ?? 0;
  // Preserve frame counters and stage times, but avoid retaining flood text in
  // the single-threaded test bridge. This measurement only consumes the raw
  // byte count and the focused Input/Ack/Snapshot/Credit trace below.
  bridge.skipOutputText = true;
  bridge.flowFilter = new Set([
    "up:backend-send:Input",
    "up:bridge-receive:Credit",
    "down:backend-receive:Ack",
    "down:backend-receive:Snapshot",
    "down:browser-send:Ack",
    "down:browser-send:Snapshot",
    "up:backend-send:Credit",
  ]);
  bridge.flowTimes?.splice(0);
  console.log("SAME_SESSION_PAINT_STAGE flood_key_begin");
  const floodInputCount = (bridge.flowTimes ?? []).filter((event) => event.stream === stream
    && event.direction === "up" && event.stage === "backend-send" && event.type === "Input").length;
  await page.keyboard.press("F");
  console.log("SAME_SESSION_PAINT_STAGE flood_key_sent");
  await expect.poll(() => (bridge.flowTimes ?? []).filter((event) => event.stream === stream
    && event.direction === "up" && event.stage === "backend-send" && event.type === "Input").length,
  { timeout: FREEZE_MS, intervals: [5, 10, 25] }).toBeGreaterThan(floodInputCount);
  // Start only after raw flood output has spent the ordinary bulk window and
  // the same attached route has no bulk credit left. A short delay after F can
  // accidentally measure ordinary output before the D381 repaint path starts.
  try {
    await expect.poll(() => {
      const rawBytes = (rawOutput.get(stream) ?? 0) - floodStartBytes;
      const creditBalance = serverCreditBalance(bridge, stream);
      return rawBytes >= BULK_WINDOW_BYTES
        && creditBalance <= REPAINT_RESERVE_BYTES
        && activeTerminalBridge()?.id === bridge.id
        && bridge.attached.has(stream);
    }, { timeout: FREEZE_MS, intervals: [5, 10, 25] }).toBe(true);
  } catch (error) {
    const incompleteWindow = {
      stream,
      route: bridge.id,
      activeRoute: activeTerminalBridge()?.id ?? null,
      attached: bridge.attached.has(stream),
      rawBytes: (rawOutput.get(stream) ?? 0) - floodStartBytes,
      creditBalance: serverCreditBalance(bridge, stream),
      routes: server.bridges.slice(-4).map((entry) => ({
        id: entry.id,
        closed: entry.closed,
        closedBy: entry.closedBy,
        closedReason: entry.closedReason,
        serverClose: entry.serverClose,
        rawOutputBytesSeen: [...(entry.rawOutputBytesSeen ?? new Map())],
        flowTail: entry.flowTimes?.slice(-24),
      })),
    };
    await page.screenshot({ path: test.info().outputPath("same-session-window-incomplete.png") });
    await writeFile(test.info().outputPath("same-session-window-incomplete.json"), JSON.stringify(incompleteWindow, null, 2));
    console.error("SAME_SESSION_WINDOW_INCOMPLETE " + JSON.stringify(incompleteWindow));
    throw error;
  }
  console.log(`SAME_SESSION_PAINT_STAGE bulk_credit_exhausted stream=${stream} ` +
    `raw_bytes=${(rawOutput.get(stream) ?? 0) - floodStartBytes} ` +
    `credit_balance=${serverCreditBalance(bridge, stream)} route=${bridge.id}`);

  // The focused trace excludes raw Output and retains flood Credits and keys.
  const flowStart = 0;
  const runButton = page.locator("#probe-run");
  await expect(runButton).toBeDisabled();
  // Normal UI runs wait for quiet output. Dispatch the same handler directly;
  // its count is already prepared and it sends the first key immediately.
  await runButton.dispatchEvent("click");
  await expect(page.locator("#probe-message")).toHaveText("Sending synthetic keys. They are not followed by Enter.", { timeout: FREEZE_MS });
  await page.waitForFunction(
    () => window.__tracerPerformanceProbe?.trace()[0]?.id !== undefined,
    undefined,
    { timeout: FREEZE_MS, polling: 10 },
  );
  const firstSampleId = await page.evaluate(() => window.__tracerPerformanceProbe?.trace()[0]?.id ?? "");
  const firstAckSequence = (BigInt(firstSampleId) + 1n).toString();
  const firstPathObserved = await expect.poll(() => {
    const events = bridge.flowTimes ?? [];
    const input = events.find((event) => event.stream === stream && event.direction === "up"
      && event.stage === "backend-send" && event.type === "Input" && event.sequence === firstSampleId);
    const ack = input && events.find((event) => event.stream === stream && event.direction === "down"
      && event.stage === "backend-receive" && event.type === "Ack"
      && event.sequence === firstAckSequence && event.at >= input.at);
    return Boolean(ack && events.some((event) => event.stream === stream && event.direction === "down"
      && event.stage === "backend-receive" && event.type === "Snapshot" && event.at >= ack.at));
  }, { timeout: 5_000, intervals: [10, 25, 50] }).toBe(true).then(() => true, () => false);
  const firstKeyEvents = (bridge.flowTimes ?? []).filter((event) => event.stream === stream
    && ((event.direction === "up" && event.type === "Input" && event.sequence === firstSampleId)
      || (event.direction === "down" && (event.type === "Ack" || event.type === "Snapshot"))));
  const routeDiagnostics = server.bridges.slice(-4).map((entry) => ({
    id: entry.id,
    closed: entry.closed,
    closedBy: entry.closedBy,
    closedReason: entry.closedReason,
    serverClose: entry.serverClose,
    activeStreams: [...entry.attached.keys()],
    replays: entry.replays,
    terminalCloses: entry.terminalCloses,
    rawOutputBytesSeen: [...(entry.rawOutputBytesSeen ?? new Map())],
    flowTail: entry.flowTimes?.slice(-24),
  }));
  const firstInputEvent = firstKeyEvents.find((event) => event.direction === "up"
    && event.type === "Input" && event.sequence === firstSampleId);
  const firstAckEvent = firstKeyEvents.find((event) => event.direction === "down"
    && event.type === "Ack" && event.sequence === firstAckSequence
    && (!firstInputEvent || event.at >= firstInputEvent.at));
  const firstSnapshotEvent = firstKeyEvents.find((event) => event.direction === "down"
    && event.type === "Snapshot" && (!firstAckEvent || event.at >= firstAckEvent.at));
  const firstPathDiagnostic = {
    firstSampleId,
    firstInputEvent,
    firstAckEvent,
    firstSnapshotEvent,
    firstPathObserved,
    originalBridgeId: bridge.id,
    activeBridgeId: activeTerminalBridge()?.id ?? null,
    bridgeClosed: bridge.closed,
    routes: routeDiagnostics,
  };
  await writeFile(test.info().outputPath("same-session-first-key.json"), JSON.stringify(firstPathDiagnostic, null, 2));
  console.log("SAME_SESSION_FIRST_KEY " + JSON.stringify({
    inputCreditBalance: firstInputEvent?.creditBalance ?? null,
    inputToAckMs: firstInputEvent && firstAckEvent ? firstAckEvent.at - firstInputEvent.at : null,
    acked: Boolean(firstAckEvent),
    snapshot: Boolean(firstSnapshotEvent),
    route: bridge.id,
    activeRoute: activeTerminalBridge()?.id ?? null,
    closed: bridge.closed,
    serverClose: bridge.serverClose,
  }));
  expect(firstInputEvent, "the first paint sample must reach the selected relay bridge").toBeDefined();
  expect(firstInputEvent?.creditBalance ?? Number.POSITIVE_INFINITY,
    "the first paint sample must reach the relay with only its repaint reserve remaining")
    .toBeLessThanOrEqual(REPAINT_RESERVE_BYTES);
  expect(firstAckEvent, "the relay must acknowledge the first input on its selected route").toBeDefined();
  expect(firstSnapshotEvent, "the first key at the exhausted-credit boundary must receive its repaint")
    .toBeDefined();
  expect(activeTerminalBridge()?.id, "the paint measurement must stay on its original real-browser route").toBe(bridge.id);
  try {
    await waitForPaintedEchoes(page, FLOOD_PAINT_KEYS, FLOOD_PAINT_TIMEOUT_MS);
  } catch (error) {
    const flow = bridge.flowTimes?.slice(flowStart) ?? [];
    const floodProbeTrace = await page.evaluate(() => ({
      timeOriginMs: performance.timeOrigin,
      samples: window.__tracerPerformanceProbe?.trace() ?? [],
    }));
    const partial = {
      profile: "real-browser-150ms-each-way",
      phase: "flood-paint-incomplete",
      probe: {
        results: await page.locator("#probe-results").innerText(),
        message: await page.locator("#probe-message").innerText(),
        timeOriginMs: floodProbeTrace.timeOriginMs,
        samples: floodProbeTrace.samples,
      },
      relay: {
        inputs: flow.filter((event) => event.stream === stream && event.direction === "up" && event.type === "Input"),
        acks: flow.filter((event) => event.stream === stream && event.direction === "down" && event.type === "Ack"),
        browserSends: flow.filter((event) => event.stream === stream && event.direction === "down" && event.stage === "browser-send"),
        credits: flow.filter((event) => event.stream === stream && event.direction === "up" && event.type === "Credit"),
        snapshots: flow.filter((event) => event.stream === stream && event.direction === "down" && event.type === "Snapshot"),
      },
      bridges: server.bridges.slice(-4).map((entry) => ({
        id: entry.id,
        closed: entry.closed,
        closedBy: entry.closedBy,
        closedReason: entry.closedReason,
        serverClose: entry.serverClose,
        attachedStreams: [...entry.attached.keys()],
        attachTimes: entry.attachTimes,
        attachCursors: entry.attachCursors,
        terminalEvents: entry.terminalEvents,
        detached: entry.detached,
        replays: entry.replays,
        rawOutputBytesSeen: [...(entry.rawOutputBytesSeen ?? new Map())],
        terminalCloses: entry.terminalCloses,
        flowTail: entry.flowTimes?.slice(-32),
      })),
    };
    await page.screenshot({ path: test.info().outputPath("same-session-paint-incomplete.png") });
    await writeFile(test.info().outputPath("same-session-paint-incomplete.json"), JSON.stringify(partial, null, 2));
    console.error("SAME_SESSION_PAINT_INCOMPLETE " + JSON.stringify({
      painted: partial.probe.results.split("\n", 1)[0],
      message: partial.probe.message,
      inputs: partial.relay.inputs.length,
      acks: partial.relay.acks.length,
      browserSends: partial.relay.browserSends.length,
      credits: partial.relay.credits.length,
      snapshots: partial.relay.snapshots.length,
      samples: partial.probe.samples.length,
      activeBridge: server.bridges.filter((entry) => !entry.closed).at(-1)?.id,
    }));
    throw error;
  }
  const floodReport = await page.locator("#probe-results").innerText();
  const floodP99 = probeP99(floodReport);
  const growth = floodP99 - quietP99;
  const floodProbeTrace = await page.evaluate(() => ({
    timeOriginMs: performance.timeOrigin,
    samples: window.__tracerPerformanceProbe?.trace() ?? [],
  }));
  expect(floodProbeTrace.samples.length, "the browser trace must retain all 200 paint callbacks").toBe(FLOOD_PAINT_KEYS);
  const floodPaintDurations = floodProbeTrace.samples.flatMap((sample) => {
    const started = sample.stages.keydown;
    const painted = sample.stages.paint;
    return started !== undefined && painted !== undefined ? [painted - started] : [];
  });
  expect(floodPaintDurations.length, "each measured sample must contain a real paint callback").toBe(FLOOD_PAINT_KEYS);
  const tracePaintP99 = p(floodPaintDurations, 0.99);
  expect(tracePaintP99).toBeCloseTo(floodP99, 2);
  const flow = bridge.flowTimes?.slice(flowStart) ?? [];
  const snapshots = flow.filter((event) => event.stream === stream && event.direction === "down" && event.type === "Snapshot" && event.stage === "backend-receive");
  const measuredSequences = new Set(floodProbeTrace.samples.map((sample) => sample.id));
  const measuredInputFrames = flow.filter((event) => event.stream === stream && event.direction === "up"
    && event.type === "Input" && event.stage === "backend-send" && measuredSequences.has(event.sequence ?? ""));
  // Count a painted key once by its wire sequence; retain repeated submissions in the trace for diagnosis.
  const inputBySequence = new Map<string, typeof measuredInputFrames[number]>();
  const duplicateInputSequences: string[] = [];
  for (const input of measuredInputFrames) {
    const sequence = input.sequence ?? "";
    if (inputBySequence.has(sequence)) duplicateInputSequences.push(sequence);
    else inputBySequence.set(sequence, input);
  }
  const inputs = [...inputBySequence.values()];
  console.log("SAME_SESSION_PAINT_INPUT_FRAMES " + JSON.stringify({
    measured: measuredInputFrames.length,
    unique: inputs.length,
    duplicateSequences: duplicateInputSequences,
  }));
  const acks = flow.filter((event) => event.stream === stream && event.direction === "down" && event.type === "Ack" && event.stage === "backend-receive");
  const credits = flow.filter((event) => event.stream === stream && event.direction === "up" && event.type === "Credit" && event.stage === "backend-send");
  const browserSends = flow.filter((event) => event.stream === stream && event.direction === "down" && event.stage === "browser-send");
  const ackSpans = floodProbeTrace.samples.flatMap((sample) => {
    const input = inputs.find((candidate) => candidate.sequence === sample.id);
    if (!input || !sample.id) return [];
    const target = (BigInt(sample.id) + 1n).toString();
    const ack = acks.find((candidate) => candidate.sequence === target && candidate.at >= input.at);
    return ack ? [ack.at - input.at] : [];
  });
  console.log("SAME_SESSION_PAINT_BOUNDARY " + JSON.stringify({
    quietP99Ms: quietP99,
    floodP99Ms: floodP99,
    growthMs: floodP99 - quietP99,
    measuredSamples: floodProbeTrace.samples.length,
    measuredInputs: inputs.length,
    inputAckSamples: ackSpans.length,
    inputAckP99Ms: ackSpans.length > 0 ? p(ackSpans, 0.99) : null,
    firstInputCreditBalance: inputs[0]?.creditBalance ?? null,
    firstInputSequence: inputs[0]?.sequence ?? null,
    snapshots: snapshots.length,
  }));
  expect(inputs.length, "the flood profile must send all 200 measured browser inputs").toBe(FLOOD_PAINT_KEYS);
  expect(ackSpans.length, "the bridge trace must pair measured inputs with their server acknowledgements").toBe(FLOOD_PAINT_KEYS);
  expect(inputs[0]?.creditBalance ?? Number.POSITIVE_INFINITY,
    "the first measured input must reach the relay with only its repaint reserve remaining")
    .toBeLessThanOrEqual(REPAINT_RESERVE_BYTES);
  expect(snapshots.length, "the first measured key must exercise the repaint fast path").toBeGreaterThan(0);
  expect(credits.length, "painted output must return client credit to the relay").toBeGreaterThan(0);
  const inputAckP99 = p(ackSpans, 0.99);
  const inputSnapshotSpans = floodProbeTrace.samples.flatMap((sample, index) => {
    const input = sample.id ? inputs.find((candidate) => candidate.sequence === sample.id) : undefined;
    const nextId = floodProbeTrace.samples[index + 1]?.id;
    const nextInput = nextId === undefined ? undefined : inputs.find((candidate) => candidate.sequence === nextId);
    if (!input) return [];
    const snapshot = snapshots.find((candidate) => candidate.at >= input.at && (!nextInput || candidate.at < nextInput.at));
    return snapshot ? [snapshot.at - input.at] : [];
  });
  const keydownToInputSpans = floodProbeTrace.samples.flatMap((sample) => {
    const input = sample.id ? inputs.find((candidate) => candidate.sequence === sample.id) : undefined;
    const keydown = sample.stages.keydown;
    return input && keydown !== undefined
      ? [input.at - (floodProbeTrace.timeOriginMs + keydown)]
      : [];
  });
  const ackToSnapshotSpans = floodProbeTrace.samples.flatMap((sample, index) => {
    const input = sample.id ? inputs.find((candidate) => candidate.sequence === sample.id) : undefined;
    const nextId = floodProbeTrace.samples[index + 1]?.id;
    const nextInput = nextId === undefined ? undefined : inputs.find((candidate) => candidate.sequence === nextId);
    if (!input || !sample.id) return [];
    const target = (BigInt(sample.id) + 1n).toString();
    const ack = acks.find((candidate) => candidate.sequence === target && candidate.at >= input.at);
    const snapshot = snapshots.find((candidate) => candidate.at >= (ack?.at ?? input.at)
      && (!nextInput || candidate.at < nextInput.at));
    return ack && snapshot ? [snapshot.at - ack.at] : [];
  });
  const snapshotToBrowserSendSpans = snapshots.flatMap((snapshot) => {
    const sent = browserSends.find((candidate) => candidate.type === "Snapshot" && candidate.sequence === snapshot.sequence);
    return sent ? [sent.at - snapshot.at] : [];
  });
  const browserSendToPaintSpans = floodProbeTrace.samples.flatMap((sample, index) => {
    const input = sample.id ? inputs.find((candidate) => candidate.sequence === sample.id) : undefined;
    const nextId = floodProbeTrace.samples[index + 1]?.id;
    const nextInput = nextId === undefined ? undefined : inputs.find((candidate) => candidate.sequence === nextId);
    const snapshot = input && snapshots.find((candidate) => candidate.at >= input.at
      && (!nextInput || candidate.at < nextInput.at));
    const sent = snapshot && browserSends.find((candidate) => candidate.type === "Snapshot"
      && candidate.sequence === snapshot.sequence);
    return sent && sample.stages.paint !== undefined
      ? [floodProbeTrace.timeOriginMs + sample.stages.paint - sent.at]
      : [];
  });
  // This is outstanding browser wire credit, not the relay's repaint budget:
  // paint returns old raw bytes while the flood spends them again.
  const serverCreditAtInputs = inputs.map((input) => input.creditBalance);
  expect(keydownToInputSpans.length, "the server trace must pair every painted key with a sent Input")
    .toBe(FLOOD_PAINT_KEYS);
  expect(serverCreditAtInputs.length).toBe(FLOOD_PAINT_KEYS);
  const firstInput = inputs[0];
  const secondInput = inputs[1];
  const firstSnapshot = firstInput && snapshots.find((candidate) => candidate.at >= firstInput.at
    && (!secondInput || candidate.at < secondInput.at));
  expect(firstSnapshot, "the first measured key must receive its key-triggered Snapshot").toBeDefined();
  expect(flow.length, "the focused stage trace must retain all keys without storing continuous flood Output")
    .toBeLessThan(FLOOD_PAINT_KEYS * 10);
  const trace = {
    profile: "real-browser-150ms-each-way",
    keysPerRun: 200,
    quietP99Ms: quietP99,
    floodP99Ms: floodP99,
    growthMs: growth,
    targetMs: 1000 / 120,
    paintCallbackP99Ms: tracePaintP99,
    keydownToInputP99Ms: p(keydownToInputSpans, 0.99),
    inputAckP99Ms: inputAckP99,
    inputSnapshotP99Ms: inputSnapshotSpans.length > 0 ? p(inputSnapshotSpans, 0.99) : null,
    ackToSnapshotP99Ms: ackToSnapshotSpans.length > 0 ? p(ackToSnapshotSpans, 0.99) : null,
    snapshotToBrowserSendP99Ms: snapshotToBrowserSendSpans.length > 0 ? p(snapshotToBrowserSendSpans, 0.99) : null,
    browserSendToPaintP99Ms: browserSendToPaintSpans.length > 0 ? p(browserSendToPaintSpans, 0.99) : null,
    serverCreditAtInputs,
    flowEventCount: flow.length,
    probe: { quiet: quietReport, flood: floodReport, quietTrace: quietProbeTrace, floodTrace: floodProbeTrace },
    relay: { inputs, duplicateInputSequences, acks, browserSends, credits, snapshots },
  };
  await writeFile(test.info().outputPath("same-session-paint-trace.json"), JSON.stringify(trace, null, 2));
  await page.screenshot({ path: test.info().outputPath("same-session-paint.png") });
  console.log("SAME_SESSION_PAINT keys=200 quiet_p99_ms=" + quietP99.toFixed(2) +
    " flood_p99_ms=" + floodP99.toFixed(2) + " growth_ms=" + growth.toFixed(2) +
    " input_ack_p99_ms=" + inputAckP99.toFixed(2) +
    " keydown_to_server_input_p99_ms=" + p(keydownToInputSpans, 0.99).toFixed(2) +
    " ack_to_snapshot_p99_ms=" + (ackToSnapshotSpans.length > 0 ? p(ackToSnapshotSpans, 0.99).toFixed(2) : "none") +
    " snapshot_to_browser_send_p99_ms=" + (snapshotToBrowserSendSpans.length > 0 ? p(snapshotToBrowserSendSpans, 0.99).toFixed(2) : "none") +
    " browser_send_to_paint_p99_ms=" + (browserSendToPaintSpans.length > 0 ? p(browserSendToPaintSpans, 0.99).toFixed(2) : "none") +
    " paint_callback_p99_ms=" + tracePaintP99.toFixed(2) +
    " input_snapshot_p99_ms=" + (inputSnapshotSpans.length > 0 ? p(inputSnapshotSpans, 0.99).toFixed(2) : "none") +
    " target_ms=" + (1000 / 120).toFixed(2) + " snapshots=" + snapshots.length + " credits=" + credits.length +
    " source=Ghostty-paint-callback rtt_ms=300");

  await probePanel.evaluate((element) => { (element as HTMLElement).hidden = false; });
  await page.screenshot({ path: test.info().outputPath("same-session-paint.png") });
  const beforeStop = bridge.outputBytesSeen ?? 0;
  await probePanel.evaluate((element) => { (element as HTMLElement).hidden = true; });
  await page.locator(".terminal-host").first().click({ position: { x: 60, y: 60 } });
  await page.keyboard.press("S");
  await expect.poll(() => bridge.outputBytesSeen ?? 0, { timeout: FREEZE_MS }).toBeGreaterThan(beforeStop);
  expect(growth, "same-session flood growth measured through Ghostty paint").toBeLessThanOrEqual(1000 / 120);
});
