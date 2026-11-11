/**
 * Typing into a terminal whose own program floods it never freezes (#477). Production server binary, real PTY, the
 * production tracer, and a 300 ms round trip through the bridge.
 *
 * Under a flood the infraternal agent may skip raw output and send a repaint instead (its 250 ms credit starvation
 * path), so a key's raw echo can legitimately never arrive. The shell here therefore draws a numbered token on row 1 for
 * every key while `yes` scrolls a region below it: the token survives in raw output and in a repaint alike, which is
 * what a person sees. The spec asserts only that every key's token arrives and its input is acknowledged; it reports
 * the times without asserting them (speed belongs to the latency harness on the perf VM).
 */
import { expect, test, type Page } from "playwright/test";
import { personName, startRealServer, type RealServer } from "./server";
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
/** Keep each probe key in a screen cell the independent scroll region cannot remove. */
const PAINT_PROGRAM =
  "bash --norc -c 'stty raw -echo; printf \"\\033[2J\\033[11r\\033[11;1HREADY\\n\"; n=0; flood_pid=; " +
  "while IFS= read -rsn1 key; do if [ \"$key\" = F ]; then yes \\! & flood_pid=$!; " +
  "elif [ \"$key\" = S ]; then kill \"$flood_pid\" 2>/dev/null || :; wait \"$flood_pid\" 2>/dev/null || :; break; " +
  "elif [ \"$key\" = R ]; then n=0; printf \"\\033[2J\\033[11r\\033[11;1H\"; " +
  "else if [ $n -gt 0 ]; then pr=$(((n-1)/20+1)); pc=$(((n-1)%20+1)); printf \"\\033[%s;%sH \" \"$pr\" \"$pc\"; fi; " +
  "n=$((n+1)); row=$(((n-1)/20+1)); col=$(((n-1)%20+1)); printf \"\\033[%s;%sH%s\" \"$row\" \"$col\" \"$key\"; fi; done; stty sane'";
/** How many keys are typed in each phase. */
const KEYS = 20;
/** Quiet baseline count; shorten only diagnostic runs, while the flood p99 always uses 200 samples. */
const QUIET_PAINT_KEYS = Number(process.env.REAL_QUIET_PAINT_KEYS ?? 200);
/** Flood samples for a meaningful nearest-rank p99. */
const FLOOD_PAINT_KEYS = 200;
/** The raw-output window that must be spent before a key belongs to the blocked-flood sample. */
const BULK_WINDOW_BYTES = 1024 * 1024;
/** A key whose token has not arrived after this long counts as a typing freeze. */
const FREEZE_MS = 15_000;
/** Bound the flood paint batch and let short diagnostic runs retain their partial stage trace. */
const FLOOD_PAINT_TIMEOUT_MS = Number(process.env.REAL_FLOOD_PAINT_TIMEOUT_MS ?? 150_000);

test.beforeAll(async ({ browser }) => {
  server = await startRealServer({ latencyMs: 150, recordFlow: true });
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

/** The newest token seen so far; tokens are trimmed from the bridge's text once they have been read. */
let newestSeen = 0;

/**
 * The newest row-1 token the browser was sent, by raw output or repaint. The bridge appends Output and replaces on
 * Snapshot. Each call scans everything recorded since the last call, then keeps only a tail long enough to hold a
 * token split across frames, so a flood cannot grow that string without bound and no token is trimmed unread.
 */
function newestToken(): number {
  const { output, stream } = terminalStream();
  const text = output.get(stream) ?? "";
  for (const match of text.matchAll(/<K(\d{6})>/g)) newestSeen = Math.max(newestSeen, Number(match[1]));
  output.set(stream, text.slice(-16));
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
  await page.keyboard.press("F");
  // `yes` is running once a screenful of its lines has reached the bridge, raw or repainted.
  await expect.poll(() => {
    const tail = (output.get(stream) ?? "").slice(-8192);
    output.set(stream, tail);
    return tail.split("y").length - 1;
  }, { timeout: FREEZE_MS }).toBeGreaterThan(200);
  const flood: number[] = [];
  for (let i = 0; i < KEYS; i++) flood.push(await typeKey(++typed));

  await page.screenshot({ path: test.info().outputPath("same-session-flood.png") });
  console.log(`SAME_SESSION_FLOOD keys=${KEYS} quiet_p50_ms=${p(quiet, 0.5).toFixed(1)} quiet_max_ms=${p(quiet, 1).toFixed(1)} ` +
    `flood_p50_ms=${p(flood, 0.5).toFixed(1)} flood_max_ms=${p(flood, 1).toFixed(1)} (bridge-observed, 150 ms each way)`);
  const bridge = terminalBridge();
  const beforeStop = bridge.outputBytesSeen ?? 0;
  await page.keyboard.press("S");
  await expect.poll(() => bridge.outputBytesSeen ?? 0, { timeout: FREEZE_MS }).toBeGreaterThan(beforeStop);
});

test("measures 200 same-session keydown-to-paint samples through the 300 ms profile", async () => {
  test.setTimeout(420_000);
  await expect.poll(() => activeTerminalBridge()?.attached.size ?? 0, { timeout: FREEZE_MS }).toBe(1);
  const bridge = terminalBridge();
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
  console.log(`SAME_SESSION_PAINT_STAGE quiet_complete samples=${QUIET_PAINT_KEYS} p99_ms=${quietP99.toFixed(2)}`);

  await expect(page.locator("#probe-run")).toBeEnabled({ timeout: FREEZE_MS });
  await probePanel.evaluate((element) => { (element as HTMLElement).hidden = true; });
  await page.locator(".terminal-host").first().click({ position: { x: 60, y: 60 } });
  await page.keyboard.press("R");
  await expect(page.locator("#probe-run")).toBeEnabled({ timeout: FREEZE_MS });
  console.log("SAME_SESSION_PAINT_STAGE reset_complete");

  const flowStart = bridge.flowTimes?.length ?? 0;
  const priorCredits = (bridge.flowTimes ?? []).slice(0, flowStart).filter((event) => event.type === "Credit");
  await probePanel.evaluate((element) => { (element as HTMLElement).hidden = true; });
  await page.locator(".terminal-host").first().click({ position: { x: 60, y: 60 } });
  const floodStartBytes = bridge.outputBytesSeen ?? 0;
  console.log("SAME_SESSION_PAINT_STAGE flood_key_begin");
  await page.keyboard.press("F");
  console.log("SAME_SESSION_PAINT_STAGE flood_key_sent");
  // Start the paint samples only after the raw 1 MiB window is exhausted. A
  // screenful of output is a flood, but it is not yet waiting for credit.
  await expect.poll(() => (bridge.outputBytesSeen ?? 0) - floodStartBytes, { timeout: FREEZE_MS }).toBeGreaterThanOrEqual(BULK_WINDOW_BYTES);
  console.log(`SAME_SESSION_PAINT_STAGE bulk_window_spent bytes=${(bridge.outputBytesSeen ?? 0) - floodStartBytes}`);

  await probePanel.evaluate((element) => { (element as HTMLElement).hidden = false; });
  await page.locator("#probe-count").fill(String(FLOOD_PAINT_KEYS));
  await page.locator("#probe-run").click();
  await expect(page.locator("#probe-message")).toHaveText("Sending synthetic keys. They are not followed by Enter.", { timeout: FREEZE_MS });
  try {
    await expect(page.locator("#probe-results")).toContainText(`Painted echoes: ${FLOOD_PAINT_KEYS} / ${FLOOD_PAINT_KEYS}`, { timeout: FLOOD_PAINT_TIMEOUT_MS });
  } catch (error) {
    const flow = bridge.flowTimes?.slice(flowStart) ?? [];
    const partial = {
      profile: "real-browser-150ms-each-way",
      phase: "flood-paint-incomplete",
      probe: {
        results: await page.locator("#probe-results").innerText(),
        message: await page.locator("#probe-message").innerText(),
      },
      relay: {
        priorCredits,
        inputs: flow.filter((event) => event.direction === "up" && event.type === "Input"),
        outputs: flow.filter((event) => event.direction === "down" && event.type === "Output"),
        acks: flow.filter((event) => event.direction === "down" && event.type === "Ack"),
        credits: flow.filter((event) => event.direction === "up" && event.type === "Credit"),
        snapshots: flow.filter((event) => event.direction === "down" && event.type === "Snapshot"),
      },
    };
    await writeFile(test.info().outputPath("same-session-paint-incomplete.json"), JSON.stringify(partial, null, 2));
    console.error("SAME_SESSION_PAINT_INCOMPLETE " + JSON.stringify({
      painted: partial.probe.results.split("\n", 1)[0],
      message: partial.probe.message,
      inputs: partial.relay.inputs.length,
      acks: partial.relay.acks.length,
      credits: partial.relay.credits.length,
      snapshots: partial.relay.snapshots.length,
    }));
    throw error;
  }
  const floodReport = await page.locator("#probe-results").innerText();
  const floodP99 = probeP99(floodReport);
  const growth = floodP99 - quietP99;
  const flow = bridge.flowTimes?.slice(flowStart) ?? [];
  const snapshots = flow.filter((event) => event.direction === "down" && event.type === "Snapshot" && event.stage === "backend-receive");
  const outputs = flow.filter((event) => event.direction === "down" && event.type === "Output");
  const inputs = flow.filter((event) => event.direction === "up" && event.type === "Input" && event.stage === "backend-send");
  const acks = flow.filter((event) => event.direction === "down" && event.type === "Ack" && event.stage === "backend-receive");
  const credits = flow.filter((event) => event.direction === "up" && event.type === "Credit" && event.stage === "backend-send");
  const ackSpans = inputs.flatMap((input) => {
    if (!input.sequence) return [];
    const target = (BigInt(input.sequence) + BigInt(input.bytes)).toString();
    const ack = acks.find((candidate) => candidate.sequence === target && candidate.at >= input.at);
    return ack ? [ack.at - input.at] : [];
  });
  expect(inputs.length, "the flood profile must send all 200 measured browser inputs").toBeGreaterThanOrEqual(FLOOD_PAINT_KEYS);
  expect(ackSpans.length, "the bridge trace must pair measured inputs with their server acknowledgements").toBeGreaterThan(0);
  const inputAckP99 = p(ackSpans, 0.99);
  const trace = {
    profile: "real-browser-150ms-each-way",
    keysPerRun: 200,
    quietP99Ms: quietP99,
    floodP99Ms: floodP99,
    growthMs: growth,
    targetMs: 1000 / 120,
    inputAckP99Ms: inputAckP99,
    probe: { quiet: quietReport, flood: floodReport },
    relay: { priorCredits, inputs, outputs, acks, credits, snapshots },
  };
  await writeFile(test.info().outputPath("same-session-paint-trace.json"), JSON.stringify(trace, null, 2));
  console.log("SAME_SESSION_PAINT keys=200 quiet_p99_ms=" + quietP99.toFixed(2) +
    " flood_p99_ms=" + floodP99.toFixed(2) + " growth_ms=" + growth.toFixed(2) +
    " input_ack_p99_ms=" + inputAckP99.toFixed(2) +
    " target_ms=" + (1000 / 120).toFixed(2) + " snapshots=" + snapshots.length + " outputs=" + outputs.length +
    " source=Ghostty-paint-callback rtt_ms=300");

  const beforeStop = bridge.outputBytesSeen ?? 0;
  await probePanel.evaluate((element) => { (element as HTMLElement).hidden = true; });
  await page.locator(".terminal-host").first().click({ position: { x: 60, y: 60 } });
  await page.keyboard.press("S");
  await expect.poll(() => bridge.outputBytesSeen ?? 0, { timeout: FREEZE_MS }).toBeGreaterThan(beforeStop);
  await page.screenshot({ path: test.info().outputPath("same-session-paint.png") });
  expect(growth, "same-session flood growth measured through Ghostty paint").toBeLessThanOrEqual(1000 / 120);
});
