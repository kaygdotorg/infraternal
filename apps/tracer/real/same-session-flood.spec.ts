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

test.describe.configure({ mode: "serial" });
let server: RealServer;
let page: Page;

/**
 * The typed program. It draws `<K000001>`, `<K000002>`, ... on row 1, one write per key, and starts `yes` when it reads
 * `F`; the scroll region `ESC [2r` keeps `yes` off row 1. `bash -c` keeps it independent of the account's login shell.
 */
const TOKEN_PROGRAM =
  "bash --norc -c 'stty raw -echo; printf \"\\033[2J\\033[2r\"; n=0; while IFS= read -rsn1 c; do " +
  "if [ \"$c\" = F ]; then yes & else n=$((n+1)); printf \"\\0337\\033[1;1H<K%06d>\\0338\" \"$n\"; fi; done'";
/** How many keys are typed in each phase. */
const KEYS = 20;
/** A key whose token has not arrived after this long counts as a typing freeze. */
const FREEZE_MS = 15_000;

test.beforeAll(async ({ browser }) => {
  server = await startRealServer({ latencyMs: 150 });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 800 } });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("flood_real"));
  await page.locator("#setup-display-name").fill("Flood real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
});
test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

/** The newest bridge and the single terminal stream it carries. */
function terminalStream(): { output: Map<number, string>; acked: Map<number, bigint>; stream: number } {
  // Bridges record the server's input acknowledgement per stream.
  const bridge = server.bridges.filter((b) => !b.closed).at(-1);
  const stream = [...(bridge?.attached.keys() ?? [])][0];
  if (!bridge || stream === undefined) throw new Error("no attached terminal stream");
  return { output: bridge.output, acked: bridge.acked, stream };
}

/**
 * The newest row-1 token the browser was sent, by raw output or repaint. The bridge appends Output and replaces on
 * Snapshot; trimming it to a tail keeps a flood from growing that string without bound.
 */
function newestToken(): number {
  const { output, stream } = terminalStream();
  const tail = (output.get(stream) ?? "").slice(-8192);
  output.set(stream, tail);
  let newest = 0;
  for (const match of tail.matchAll(/<K(\d{6})>/g)) newest = Math.max(newest, Number(match[1]));
  return newest;
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
});
