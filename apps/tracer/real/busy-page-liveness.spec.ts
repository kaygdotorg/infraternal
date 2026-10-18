/** Production-browser liveness measurements for #245; run only on the locked perf VM. */
import { expect, test, type Page } from "playwright/test";
import { loadavg } from "node:os";
import { startRealServer } from "./server";
import type { CanvasDocument } from "../src/canvas/model/document";

test.skip(process.env.BUSY_PAGE_MEASURE !== "1", "explicit perf-VM measurement only");
// Trust only this disposable fixture's TLS front for the browser measurement.
test.use({ launchOptions: { args: ["--disable-renderer-backgrounding", "--ignore-certificate-errors"] } });

type Receipt = { closes: Array<{ code: number; reason: string; at: number }>; tasks: number[]; reconnecting: number[] };

async function enrol(page: Page, origin: string, token: string): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  const url = origin + "/?theme=ink&bg=none";
  await page.goto(url).catch(async () => { await page.waitForTimeout(250); await page.goto(url); });
  await page.locator("#setup-token").fill(token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill("busy_page");
  await page.locator("#setup-display-name").fill("Busy page");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
}

test("busy page preserves healthy routes and idle silence still retires", async ({ page }, info) => {
  test.setTimeout(12 * 60_000);
  const rtt = Number(process.env.BUSY_PAGE_RTT ?? 150);
  const server = await startRealServer({ latencyMs: rtt / 2 });
  try {
    await page.addInitScript(() => {
      const receipt: Receipt = { closes: [], tasks: [], reconnecting: [] };
      (window as unknown as { receipt: Receipt }).receipt = receipt;
      const close = WebSocket.prototype.close;
      WebSocket.prototype.close = function (code?: number, reason?: string) {
        receipt.closes.push({ code: code ?? 0, reason: reason ?? "", at: performance.now() });
        return close.call(this, code, reason);
      };
      new PerformanceObserver((list) => receipt.tasks.push(...list.getEntries().map((entry) => entry.duration))).observe({ type: "longtask" });
      new MutationObserver((records) => {
        if (records.some((record) => record.target instanceof Element && record.target.matches('.ui-window[data-status="connecting"]'))) receipt.reconnecting.push(performance.now());
      }).observe(document, { subtree: true, attributes: true, attributeFilter: ["data-status"] });
    });
    await enrol(page, server.origin, server.token);
    const windows = page.locator('.cl[data-view="console"] .ui-window');
    await expect(windows.first()).toHaveAttribute("data-status", "live", { timeout: 30_000 });
    await page.waitForTimeout(3000);
    if (process.env.BUSY_PAGE_IDLE_ONLY === "1") {
      // Block once on an idle terminal with no extra sockets or output workload.
      const idleBefore = await page.evaluate(() => (window as unknown as { receipt: Receipt }).receipt.closes.length);
      await page.evaluate(() => { const end = performance.now() + 1000; while (performance.now() < end) { /* prescribed one-second renderer suspension */ } });
      await page.waitForTimeout(2500);
      const closes = await page.evaluate((before) => (window as unknown as { receipt: Receipt }).receipt.closes.slice(before), idleBefore);
      console.log(`BUSY_PAGE idle_block ${JSON.stringify({ rtt, closes, load: loadavg() })}`);
      if (process.env.BUSY_PAGE_EXPECT_HEALTHY === "1") expect(closes.filter((item) => item.code === 4000 && item.reason === "connection unresponsive")).toHaveLength(0);
    }

    if (process.env.BUSY_PAGE_IDLE_ONLY !== "1") {
      for (let i = 1; i < 65; i++) {
        await page.evaluate((direction) => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: `canvas:split:${direction}`, source: "pointer" } })), i % 4 === 0 ? "right" : "down");
        await expect(windows).toHaveCount(i + 1);
        await page.waitForTimeout(100);
      }
      await page.waitForTimeout(3000);
      const sessions = () => new Set(server.bridges.flatMap((bridge) => [...bridge.attached.values()].flat())).size;
      await expect.poll(sessions, { timeout: 60_000 }).toBe(65);
      console.log(`BUSY_PAGE ready ${JSON.stringify({ sessions: sessions(), sockets: server.bridges.filter((bridge) => !bridge.closed).length, live: await page.locator('.cl[data-view="console"] .ui-window[data-status="live"]').count(), routes: server.bridges.map((bridge) => ({ id: bridge.id, closed: bridge.closed, by: bridge.closedBy, reason: bridge.closedReason, serverClose: bridge.serverClose, attached: bridge.attached.size })), clientCloses: await page.evaluate(() => (window as unknown as { receipt: Receipt }).receipt.closes), load: loadavg() })}`);
      if (process.env.BUSY_PAGE_DIAGNOSTIC === "1") return;
      const cdp = await page.context().newCDPSession(page);
      type TraceEvent = { name: string; ph: string; dur?: number; pid: number; tid: number; args?: { name?: string; data?: { functionName?: string } } };
      const trace: TraceEvent[] = [];
      if (process.env.BUSY_PAGE_TRACE === "1") {
        cdp.on("Tracing.dataCollected", (data) => { trace.push(...data.value as unknown as TraceEvent[]); });
        await cdp.send("Tracing.start", { categories: "toplevel,devtools.timeline", transferMode: "ReportEvents" });
      }
      await cdp.send("Emulation.setCPUThrottlingRate", { rate: 6 });
      await page.evaluate(() => {
        const account = localStorage.getItem("tracer.user-id");
        const key = `infraternal.canvas.${account}`;
        const doc = JSON.parse(localStorage.getItem(key) ?? "null") as CanvasDocument | null;
        const consoleView = doc?.views.find((view) => view.id === "console");
        if (!doc || consoleView?.layout.type !== "tiled") throw new Error("fixture canvas unavailable");
        const windows = consoleView.layout.columns.flatMap((column) => column.windows).map(({ id, target }) => ({ id, target, height: 1 }));
        if (windows.length !== 65) throw new Error(`fixture canvas has ${windows.length} session references`);
        // Repeated interactive splits can exceed the persisted band bounds.
        // Keep the actual session references in a plain valid 13-by-5 grid.
        consoleView.layout.columns = Array.from({ length: 13 }, (_, i) => ({ id: `bench-column-${i}`, weight: 1, windows: windows.slice(i * 5, i * 5 + 5) }));
        doc.views = [consoleView];
        const save = () => localStorage.setItem(key, JSON.stringify(doc));
        save();
        window.addEventListener("pagehide", save, { once: true });
      });
      await page.reload();
      const scaleStart = await page.evaluate(() => performance.now());
      await expect(windows).toHaveCount(65, { timeout: 60_000 });
      await page.keyboard.press("Escape");
      await page.waitForTimeout(60_000);
      if (process.env.BUSY_PAGE_TRACE === "1") {
        const done = new Promise<void>((resolve) => cdp.once("Tracing.tracingComplete", () => resolve()));
        await cdp.send("Tracing.end");
        await done;
        const mainThreads = new Set(trace.filter((event) => event.ph === "M" && event.name === "thread_name" && event.args?.name === "CrRendererMain").map((event) => `${event.pid}:${event.tid}`));
        const longest = trace.filter((event) => event.ph === "X" && mainThreads.has(`${event.pid}:${event.tid}`)).sort((a, b) => (b.dur ?? 0) - (a.dur ?? 0)).slice(0, 40).map((event) => ({ name: event.name, function: event.args?.data?.functionName, ms: (event.dur ?? 0) / 1000 }));
        console.log(`BUSY_PAGE trace ${JSON.stringify(longest)}`);
      }
      const receipt = await page.evaluate(() => (window as unknown as { receipt: Receipt }).receipt);
      const statuses = await windows.evaluateAll((nodes) => nodes.reduce<Record<string, number>>((counts, node) => { const state = node.getAttribute("data-status") ?? "unknown"; counts[state] = (counts[state] ?? 0) + 1; return counts; }, {}));
      console.log(`BUSY_PAGE scale ${JSON.stringify({ rtt, cpu: 6, sessions: 65, elapsedMs: await page.evaluate(() => performance.now()) - scaleStart, closes4000: receipt.closes.filter((item) => item.code === 4000 && item.reason === "connection unresponsive").length, receipt, statuses, load: loadavg() })}`);
      await page.screenshot({ path: info.outputPath("65-sessions.png") });
      await cdp.send("Emulation.setCPUThrottlingRate", { rate: 1 });
      if (process.env.BUSY_PAGE_EXPECT_HEALTHY === "1") {
        expect(receipt.closes.filter((item) => item.code === 4000 && item.reason === "connection unresponsive")).toHaveLength(0);
        expect(statuses.live).toBe(65);
      }
      return;
    }
    // Keep the real browser socket open across a stopped backend. The TLS
    // front retains only existing routes; replacement routes remain ordinary.
    for (let trial = 0; trial < 5; trial++) {
      await page.reload();
      await expect(windows.first()).toHaveAttribute("data-status", "live", { timeout: 30_000 });
      await page.waitForTimeout(5000);
      const start = await page.evaluate(() => performance.now());
      server.retainBrowserRoutes();
      await server.restart(async () => {
        try {
          await expect.poll(() => page.evaluate(() => (window as unknown as { receipt: Receipt }).receipt.closes.some((item) => item.code === 4000)), { intervals: [5], timeout: 5000 }).toBe(true);
        } catch (error) {
          console.log(`BUSY_PAGE dead_link_failure ${JSON.stringify({ rtt, trial, receipt: await page.evaluate(() => (window as unknown as { receipt: Receipt }).receipt), statuses: await windows.evaluateAll((nodes) => nodes.map((node) => node.getAttribute("data-status"))) })}`);
          throw error;
        }
      });
      const receipt = await page.evaluate(() => (window as unknown as { receipt: Receipt }).receipt);
      const retired = receipt.closes.find((item) => item.code === 4000)!;
      const reconnecting = receipt.reconnecting.find((at) => at >= start);
      console.log(`BUSY_PAGE dead_link ${JSON.stringify({ rtt, trial, reconnectingMs: reconnecting === undefined ? null : reconnecting - start, retiredMs: retired.at - start, load: loadavg() })}`);
    }
  } finally {
    await page.close();
    await server.dispose();
  }
});
