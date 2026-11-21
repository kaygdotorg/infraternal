/**
 * Key-to-photon breakdown on the real server (#569, D130, D375): where the time goes between a key press and its
 * letter on screen, hop by hop, with no test double anywhere in the path.
 *
 * The production `infraternal` binary serves the production tracer; its embedded infraternal agent, the shim and a
 * real PTY running the account's login shell echo each key the way a person's shell prompt does. The fixture's TLS
 * bridge sits between the browser and the server, delays every message by `REAL_ONE_WAY_MS` in each direction (the
 * emulated network), and records content-free frame times. The browser's own `?probe=1` latency probe types
 * `REAL_KEYS` keys one after another and stamps each key's browser hops. This spec joins the two by input sequence
 * number, so every key gets one row:
 *
 * | Segment | From → to | What it holds |
 * |---|---|---|
 * | `browser_out` | keydown → `ws.send` | key handling, encoding, the send call |
 * | `to_bridge` | `ws.send` → bridge receive | the browser's socket and TLS, on loopback |
 * | `net_up` | bridge receive → bridge send to the server | the emulated one-way network delay |
 * | `server_agent_pty` | bridge send → bridge receive of the echo | server, embedded agent, shim, PTY, shell echo, and back |
 * | `net_down` | echo received → sent on to the browser | the emulated one-way network delay |
 * | `to_browser` | bridge send → `ws.onmessage` | loopback TLS and the browser's message dispatch |
 * | `browser_in` | `ws.onmessage` → paint | decode, terminal write, render callback |
 *
 * With `REAL_PREDICT=1` the page also runs predictive echo (D130) and each row records when the predicted glyph
 * became visible. The result is written as JSON to `J1059_OUT` and summarised in `METRIC` lines. It is a
 * measurement, not a gate: run it on the perf VM through `perf-run`, never on a shared build host.
 */
import { expect, test, type Page } from "playwright/test";
import { writeFile } from "node:fs/promises";
import { personName, startRealServer, type Bridge, type RealServer } from "./server";

/** One-way delay the bridge adds, in milliseconds; the round trip is twice this. */
const ONE_WAY_MS = Number(process.env.REAL_ONE_WAY_MS ?? 0);
/** How many keys the probe types; 200 makes the nearest-rank p99 the second-slowest key. */
const KEYS = Number(process.env.REAL_KEYS ?? 200);
/** Whether the page runs predictive echo (`?predict=1`). */
const PREDICT = process.env.REAL_PREDICT === "1";
/** Where the per-key rows go; defaults to the Playwright output folder's parent. */
const OUT = process.env.J1059_OUT ?? "key-to-photon.json";

/** The real server for this file; disposed after the test. */
let server: RealServer;
/** The signed-in probe page. */
let page: Page;

test.beforeAll(async ({ browser }) => {
  server = await startRealServer({ latencyMs: ONE_WAY_MS, recordFlow: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 800 } });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(`${server.origin}/?theme=ink&bg=none&probe=1&n=${KEYS}${PREDICT ? "&predict=1" : ""}`);
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("photon_real"));
  await page.locator("#setup-display-name").fill("Photon real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".terminal-host").first().waitFor();
});
test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

/** One bridge stage of one frame, as recorded by the fixture. */
type Flow = NonNullable<Bridge["flowTimes"]>[number];

/** Nearest-rank percentile of `values` (fraction 0..1); NaN when empty. */
function pct(values: number[], fraction: number): number {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (sorted.length === 0) return Number.NaN;
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * fraction) - 1))]!;
}

test("key to photon, hop by hop, on the real server", async () => {
  test.setTimeout(600_000);
  // Let the shell print its prompt and go quiet before the first key.
  await expect.poll(() => server.bridges.some((b) => !b.closed && b.attached.size > 0), { timeout: 30_000 }).toBe(true);
  // sleep: the login shell's prompt and startup output must finish before the first timed key.
  await page.waitForTimeout(1_500);
  const bridge = server.bridges.filter((b) => !b.closed && b.attached.size > 0).at(-1)!;
  const stream = [...bridge.attached.keys()][0]!;
  bridge.flowTimes!.length = 0;
  await page.locator("#probe-run").click();
  await expect.poll(async () => (await page.locator("#probe-results").textContent()) ?? "", { timeout: 540_000, intervals: [250] })
    .toContain(`Painted echoes: ${KEYS} / ${KEYS}`);
  const origin = await page.evaluate(() => performance.timeOrigin);
  const trace = await page.evaluate(() => window.__tracerPerformanceProbe?.trace() ?? []);
  const flows = bridge.flowTimes!.filter((f) => f.stream === stream);
  const inputs = new Map<string, { receive?: Flow; send?: Flow }>();
  for (const f of flows) {
    if (f.direction !== "up" || f.type !== "Input" || f.sequence === undefined) continue;
    const entry = inputs.get(f.sequence) ?? {};
    if (f.stage === "bridge-receive") entry.receive = f;
    if (f.stage === "backend-send") entry.send = f;
    inputs.set(f.sequence, entry);
  }
  const outputs = flows.filter((f) => f.direction === "down" && (f.type === "Output" || f.type === "Snapshot"));
  const backendReceives = outputs.filter((f) => f.stage === "backend-receive");
  const browserSends = outputs.filter((f) => f.stage === "browser-send");
  const rows = trace.map((sample) => {
    // Page stamps are `performance.now()`; the bridge's are epoch milliseconds from Node's clock on the same host.
    const at = (stage: string): number => {
      const value = (sample.stages as Record<string, number | undefined>)[stage];
      return value === undefined ? Number.NaN : origin + value;
    };
    const input = inputs.get(sample.id);
    const upSend = input?.send?.at ?? Number.NaN;
    // The echo is the first frame the server sent after this key reached it.
    const echoIndex = backendReceives.findIndex((f) => f.at >= upSend);
    const echoIn = echoIndex >= 0 ? backendReceives[echoIndex]!.at : Number.NaN;
    const echoOut = echoIndex >= 0 ? (browserSends.find((f) => f.at >= echoIn)?.at ?? Number.NaN) : Number.NaN;
    const keydown = at("keydown");
    return {
      id: sample.id,
      total: at("paint") - keydown,
      predicted: at("prediction") - keydown,
      browser_out: at("wsSend") - keydown,
      to_bridge: (input?.receive?.at ?? Number.NaN) - at("wsSend"),
      net_up: upSend - (input?.receive?.at ?? Number.NaN),
      server_agent_pty: echoIn - upSend,
      net_down: echoOut - echoIn,
      to_browser: at("wsMessage") - echoOut,
      browser_in: at("paint") - at("wsMessage"),
      write_to_callback: at("writeCallback") - at("termWrite"),
    };
  });
  const keys = ["total", "predicted", "browser_out", "to_bridge", "net_up", "server_agent_pty", "net_down", "to_browser", "browser_in", "write_to_callback"] as const;
  const summary = Object.fromEntries(keys.map((key) => {
    const values = rows.map((row) => row[key]);
    return [key, { n: values.filter(Number.isFinite).length, p50: pct(values, 0.5), p90: pct(values, 0.9), p99: pct(values, 0.99) }];
  }));
  await writeFile(OUT, JSON.stringify({ oneWayMs: ONE_WAY_MS, predict: PREDICT, keys: KEYS, summary, rows }, null, 1));
  for (const key of keys) {
    const s = summary[key] as { n: number; p50: number; p90: number; p99: number };
    console.log(`METRIC name=k2p_${key} one_way_ms=${ONE_WAY_MS} predict=${PREDICT ? 1 : 0} n=${s.n} p50_ms=${s.p50.toFixed(2)} p90_ms=${s.p90.toFixed(2)} p99_ms=${s.p99.toFixed(2)}`);
  }
  expect(rows.length).toBe(KEYS);
});
