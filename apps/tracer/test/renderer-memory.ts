/** Measures production Chromium renderer RSS and Ghostty WASM pages at 1 and 8 sessions. */
import { createServer } from "node:net";
import { readFile, rm, mkdir } from "node:fs/promises";
import { cpus, homedir, loadavg, release, totalmem } from "node:os";
import { resolve } from "node:path";
import { chromium, type BrowserContext, type CDPSession, type Page } from "playwright";

const APP_ROOT = resolve(import.meta.dir, "..");
const SERVER_PORT = Number(process.env.TRACER_TEST_PORT ?? "4621");
const SCRATCH_ROOT = resolve(homedir(), ".cache/codex-scratch", `tracer-renderer-${SERVER_PORT}`);
const BASE_URL = `http://localhost:${SERVER_PORT}`;
const BEHEMOTH = "behemoth.txt";
const BEHEMOTH_BYTES = 50_000_000;
const SAMPLE_INTERVAL_MS = 75;
const GRID = { cols: 205, rows: 56 };

interface RendererMetrics {
  cols: number;
  rows: number;
  cellWidth: number;
  cellHeight: number;
  configuredScrollback: number;
  outputSequence: string;
  scrollbackRows: number;
  wasmMemoryBytes: number;
}

interface MemoryScenario {
  name: string;
  sessions: number;
  scrollback: number;
  peakRendererRssBytes: number;
  steadyRendererRssBytes: number;
  peakRendererCount: number;
  steadyRendererCount: number;
  chromiumVersion: string;
  wasmMemoryBytesBySession: number[];
  configuredScrollbackBySession: number[];
  scrollbackRowsBySession: number[];
  outputSequenceBySession: string[];
  elapsedMs: number;
  sampleCount: number;
}

await mkdir(SCRATCH_ROOT, { recursive: true });
await removeOldProfiles();
await assertPortAvailable();
const mockServer = Bun.spawn(["python3", "../../scripts/latency_proxy.py", "serve-tracer"], {
  cwd: APP_ROOT,
  env: {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: process.env.HOME ?? "",
    TRACER_TEST_PORT: String(SERVER_PORT),
    TRACER_BACKEND_PORT: String(SERVER_PORT + 1),
    INFRATERNAL_TEST_RTT: process.env.INFRATERNAL_TEST_RTT ?? "300",
  },
  stdout: "inherit",
  stderr: "inherit",
});
let browserContexts: BrowserContext[] = [];
let persistentContext: BrowserContext | undefined;
let browserCdp: CDPSession | undefined;

try {
  await waitForMockServer();
  const loadAverageBefore = loadavg();
  const reports: MemoryScenario[] = [];
  reports.push(await measureScenario("tracer-default-1-session", 1, 10_000));
  reports.push(await measureScenario("scrollback-one-control-1-session", 1, 1));
  reports.push(await measureScenario("tracer-default-8-sessions", 8, 10_000));
  process.stdout.write(`${JSON.stringify({
    host: {
      platform: process.platform,
      kernel: release(),
      cpu: cpus()[0]?.model ?? "unknown",
      logicalCpus: cpus().length,
      totalRamBytes: totalmem(),
      loadAverageBefore,
      loadAverageAfter: loadavg(),
      chromium: reports[0]?.chromiumVersion ?? "unknown",
    },
    measurement: "sum of Chromium renderer VmRSS from /proc, sampled every 75 ms; WASM memory is WebAssembly.Memory.buffer.byteLength",
    reports,
  }, null, 2)}\n`);
} finally {
  await closeContexts();
  mockServer.kill("SIGTERM");
  await mockServer.exited;
  await rm(SCRATCH_ROOT, { recursive: true, force: true });
}

async function measureScenario(name: string, sessionCount: number, scrollback: number): Promise<MemoryScenario> {
  await fetch(`${BASE_URL}/__mock/reset`, { method: "POST" });
  const profilePath = resolve(SCRATCH_ROOT, `profile-${name}`);
  persistentContext = await chromium.launchPersistentContext(profilePath, {
    headless: true,
    viewport: { width: 1280, height: 720 },
    args: ["--disable-renderer-backgrounding"],
  });
  const browser = persistentContext.browser();
  if (!browser) throw new Error("persistent Chromium context has no browser");
  browserContexts = [persistentContext];
  browserCdp = await browser.newBrowserCDPSession();
  const pages: Page[] = [];

  for (let index = 0; index < sessionCount; index += 1) {
    const context = index === 0 ? persistentContext : await browser.newContext({ viewport: { width: 1280, height: 720 } });
    if (index > 0) browserContexts.push(context);
    await context.request.post(`${BASE_URL}/__mock/open-terminal`);
    const page = context.pages()[0] ?? await context.newPage();
    page.setDefaultTimeout(60_000);
    await page.goto(`${BASE_URL}/?mock=1&scrollback=${scrollback}`);
    await waitForPage(page, () => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true));
    const initial = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
    if (!initial) throw new Error(`renderer diagnostics did not load in session ${index + 1}`);
    await page.setViewportSize({
      width: Math.ceil(initial.cellWidth * GRID.cols) + 16,
      height: Math.ceil(initial.cellHeight * GRID.rows) + 16,
    });
    await waitForPage(page, async () => {
      const metrics = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
      return metrics?.cols === GRID.cols && metrics.rows === GRID.rows;
    });
    pages.push(page);
  }

  let sampling = false;
  let peakRendererRssBytes = 0;
  let peakRendererCount = 0;
  let sampleCount = 0;
  const sample = async (): Promise<void> => {
    if (sampling || !browserCdp) return;
    sampling = true;
    try {
      const info = await browserCdp.send("SystemInfo.getProcessInfo") as {
        processInfo: Array<{ id: number; type: string }>;
      };
      const renderers = info.processInfo.filter((process) => process.type === "renderer");
      const rssValues = await Promise.all(renderers.map((process) => rendererRss(process.id)));
      const total = rssValues.reduce((sum, value) => sum + value, 0);
      peakRendererRssBytes = Math.max(peakRendererRssBytes, total);
      peakRendererCount = Math.max(peakRendererCount, renderers.length);
      sampleCount += 1;
    } finally {
      sampling = false;
    }
  };
  await sample();
  const timer = setInterval(() => { void sample(); }, SAMPLE_INTERVAL_MS);
  const startedAt = performance.now();
  try {
    const response = await pages[0]!.context().request.post(`${BASE_URL}/__mock/fixture`, { data: { name: BEHEMOTH } });
    if (!response.ok()) throw new Error(`mock fixture load failed: HTTP ${response.status()}`);
    const fixture = await response.json() as { bytes: number };
    if (fixture.bytes !== BEHEMOTH_BYTES) throw new Error(`behemoth byte count ${fixture.bytes} did not match manifest`);
    await Promise.all(pages.map((page) => waitForPage(page, async () => {
      const metrics = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
      return metrics !== undefined && BigInt(metrics.outputSequence) >= BigInt(BEHEMOTH_BYTES);
    }, 10 * 60_000)));
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 2_000));
    await sample();
  } finally {
    clearInterval(timer);
  }

  const finalSnapshot = await rendererSnapshot(browserCdp);
  peakRendererRssBytes = Math.max(peakRendererRssBytes, finalSnapshot.rssBytes);
  const metricsBySession = await Promise.all(pages.map((page) => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics())));
  const elapsedMs = performance.now() - startedAt;
  const report: MemoryScenario = {
    name,
    sessions: sessionCount,
    scrollback,
    peakRendererRssBytes,
    steadyRendererRssBytes: finalSnapshot.rssBytes,
    peakRendererCount,
    steadyRendererCount: finalSnapshot.rendererCount,
    chromiumVersion: browser.version(),
    wasmMemoryBytesBySession: metricsBySession.map((metrics) => metrics?.wasmMemoryBytes ?? 0),
    configuredScrollbackBySession: metricsBySession.map((metrics) => metrics?.configuredScrollback ?? -1),
    scrollbackRowsBySession: metricsBySession.map((metrics) => metrics?.scrollbackRows ?? 0),
    outputSequenceBySession: metricsBySession.map((metrics) => metrics?.outputSequence ?? "0"),
    elapsedMs: Math.round(elapsedMs),
    sampleCount,
  };
  await closeContexts();
  return report;
}

async function rendererSnapshot(session: CDPSession): Promise<{ rssBytes: number; rendererCount: number }> {
  const info = await session.send("SystemInfo.getProcessInfo") as { processInfo: Array<{ id: number; type: string }> };
  const renderers = info.processInfo.filter((process) => process.type === "renderer");
  const rss = await Promise.all(renderers.map((process) => rendererRss(process.id)));
  return { rssBytes: rss.reduce((sum, value) => sum + value, 0), rendererCount: renderers.length };
}

async function rendererRss(pid: number): Promise<number> {
  try {
    const status = await readFile(`/proc/${pid}/status`, "utf8");
    return Number(/^VmRSS:\s+(\d+) kB/m.exec(status)?.[1] ?? 0) * 1024;
  } catch {
    return 0;
  }
}

async function waitForPage(page: Page, predicate: () => Promise<boolean>, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await page.waitForTimeout(100);
  }
  throw new Error(`timed out waiting for page state at ${page.url()}`);
}

async function waitForMockServer(): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${BASE_URL}/health`);
      if (response.ok) return;
    } catch { /* server is still binding */ }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
  }
  throw new Error("mock server did not become ready on port " + SERVER_PORT);
}

async function assertPortAvailable(): Promise<void> {
  await new Promise<void>((resolvePromise, rejectPromise) => {
    const probe = createServer();
    probe.once("error", () => rejectPromise(new Error("port " + SERVER_PORT + " is already in use")));
    probe.listen(SERVER_PORT, "127.0.0.1", () => probe.close((error) => error ? rejectPromise(error) : resolvePromise()));
  });
}

async function closeContexts(): Promise<void> {
  for (const context of browserContexts.slice(1)) await context.close().catch(() => undefined);
  if (persistentContext) await persistentContext.close().catch(() => undefined);
  browserContexts = [];
  persistentContext = undefined;
  browserCdp = undefined;
}

async function removeOldProfiles(): Promise<void> {
  await rm(SCRATCH_ROOT, { recursive: true, force: true });
  await mkdir(SCRATCH_ROOT, { recursive: true });
}
