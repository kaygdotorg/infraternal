/** Production-browser liveness measurements for #245; run only on the locked perf VM. */
import { expect, test, type Page } from "playwright/test";
import { loadavg } from "node:os";
import { personName, startRealServer } from "./server";
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
  await page.locator("#setup-username").fill(personName("busy_page"));
  await page.locator("#setup-display-name").fill("Busy page");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
}

test("busy page preserves healthy routes and idle silence still retires", async ({ page }, info) => {
  test.skip(process.env.BUSY_PAGE_DEAD_BUSY === "1", "separate stopped-route workload");
  test.skip(process.env.BUSY_PAGE_RESTORE_INPUT === "1", "separate restore-input workload");
  test.setTimeout(20 * 60_000);
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
      const restoredIds = await page.evaluate(() => {
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
        return windows.map((window) => window.id);
      });
      await page.reload();
      const scaleStart = await page.evaluate(() => performance.now());
      await expect(windows).toHaveCount(65, { timeout: 60_000 });
      expect(await windows.evaluateAll((nodes) => nodes.map((node) => (node as HTMLElement).dataset.windowId))).toEqual(restoredIds);
      await page.keyboard.press("Escape");
      if (process.env.BUSY_PAGE_PRINTING === "1") {
        await expect(page.locator('.cl[data-view="console"] .ui-window[data-status="live"]')).toHaveCount(65, { timeout: 60_000 });
        // Real shell output continues across the observation window. The fixture
        // ends these private sessions on disposal, even if an assertion fails.
        for (let printer = 0; printer < 3; printer++) {
          await windows.nth(printer).evaluate((node) => {
            node.dispatchEvent(new PointerEvent("pointerdown"));
            node.querySelector<HTMLTextAreaElement>("textarea")?.focus();
          });
          await expect(windows.nth(printer)).toHaveAttribute("data-active", "");
          await page.keyboard.insertText(`for review_tick in $(seq 1 900); do printf 'REVIEW_LINE_${printer}_%s\\n' "$review_tick"; seq 1 100; sleep 1; done`);
          await page.keyboard.press("Enter");
          await expect.poll(() => server.bridges.flatMap((bridge) => [...bridge.output.values()]).some((output) => output.includes(`REVIEW_LINE_${printer}_1`)), { timeout: 15_000 }).toBe(true);
          await page.waitForTimeout(500);
        }
        await page.waitForTimeout(3000);
        const printers = server.bridges.flatMap((bridge) => [...bridge.output.values()]).filter((output) => (output.match(/REVIEW_LINE_\d+_\d+/g) ?? []).length >= 3).length;
        console.log(`BUSY_PAGE printers ${JSON.stringify({ printers })}`);
        expect(printers).toBe(3);
      }
      await page.waitForTimeout(Number(process.env.BUSY_PAGE_OBSERVE_MS ?? 60_000));
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

test("typing into a restored terminal stays with that terminal while others initialize", async ({ page }, info) => {
  test.skip(process.env.BUSY_PAGE_RESTORE_INPUT !== "1", "explicit restore-input workload only");
  const server = await startRealServer({ latencyMs: 75 });
  try {
    await enrol(page, server.origin, server.token);
    const windows = page.locator('.cl[data-view="console"] .ui-window');
    for (let index = 1; index < 8; index++) {
      await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:split:down", source: "pointer" } })));
      await expect(windows).toHaveCount(index + 1);
      await page.waitForTimeout(250);
    }
    await expect(page.locator('.cl[data-view="console"] .ui-window[data-status="live"]')).toHaveCount(8);
    // Widen the scheduling gap between promise-resolver zero-delay tasks. Input tasks can arrive
    // between renderer initializations in an ordinary busy browser too; this
    // makes that interleaving deterministic without changing the production code.
    await page.addInitScript(() => {
      const schedule = window.setTimeout.bind(window);
      let next = 0;
      window.setTimeout = ((handler: TimerHandler, timeout?: number, ...args: unknown[]) => {
        // Ordinary UI callbacks retain their scheduling: delaying those too
        // would also change existing deferred-focus behavior on the baseline.
        if (timeout === 0 && typeof handler === "function" && Function.prototype.toString.call(handler).includes("[native code]")) { next = Math.max(next, performance.now()) + 150; return schedule(handler, next - performance.now(), ...args); }
        return schedule(handler, timeout, ...args);
      }) as typeof window.setTimeout;
    });
    await page.reload({ waitUntil: "domcontentloaded" });
    const input = page.locator('.cl[data-view="console"] .terminal-host textarea').first();
    await input.waitFor({ state: "attached" });
    const initializing = await page.locator('.cl[data-view="console"] .terminal-host textarea').count();
    expect(initializing).toBeGreaterThan(0);
    await input.focus();
    const chosen = await input.evaluate((node) => node.closest<HTMLElement>(".ui-window")?.dataset.windowId);
    await page.keyboard.type("echo restore-$((6*7))\n", { delay: 35 });
    const result = () => server.bridges.flatMap((bridge) => [...bridge.output.values()]).filter((output) => output.includes("restore-42")).length;
    await page.waitForTimeout(3000);
    console.log(`BUSY_PAGE restore_input ${JSON.stringify({ initializing, chosen, executed: result(), focused: await page.evaluate(() => document.activeElement?.closest<HTMLElement>(".ui-window")?.dataset.windowId) })}`);
    await page.screenshot({ path: info.outputPath("restore-input.png") });
    expect(result()).toBe(1);
  } finally {
    await page.close();
    await server.dispose();
  }
});

test("repeated busy tasks do not keep a stopped route live", async ({ page }, info) => {
  test.skip(process.env.BUSY_PAGE_DEAD_BUSY !== "1", "explicit stopped-route workload only");
  const server = await startRealServer({ latencyMs: 75 });
  try {
    await page.addInitScript(() => {
      const closes: Array<{ code: number; reason: string }> = [];
      (window as unknown as { reviewCloses: typeof closes }).reviewCloses = closes;
      const close = WebSocket.prototype.close;
      WebSocket.prototype.close = function (code?: number, reason?: string) {
        closes.push({ code: code ?? 0, reason: reason ?? "" });
        return close.call(this, code, reason);
      };
    });
    await enrol(page, server.origin, server.token);
    const terminal = page.locator('.cl[data-view="console"] .ui-window').first();
    await expect(terminal).toHaveAttribute("data-status", "live");
    await page.waitForTimeout(3000);
    await terminal.locator(".terminal-host textarea").focus();
    server.retainBrowserRoutes();
    await server.restart(async () => {
      // Input issued on the retained, now silent route must stay buffered and
      // activate the existing fast-probe cadence while the page still runs tasks.
      await page.keyboard.type("x");
      await page.evaluate(() => {
        const until = performance.now() + 6500;
        const spin = () => {
          const end = performance.now() + 75;
          while (performance.now() < end) { /* prescribed busy-page workload */ }
          if (performance.now() < until) setTimeout(spin, 0);
        };
        setTimeout(spin, 0);
      });
      await page.waitForTimeout(6000);
      const closes = await page.evaluate(() => (window as unknown as { reviewCloses: Array<{ code: number; reason: string }> }).reviewCloses);
      console.log(`BUSY_PAGE stopped_busy ${JSON.stringify({ closes, status: await terminal.getAttribute("data-status"), load: loadavg() })}`);
      await page.screenshot({ path: info.outputPath("stopped-busy.png") });
      expect(closes.some((close) => close.code === 4000 && close.reason === "connection unresponsive")).toBe(true);
    });
  } finally {
    await page.close();
    await server.dispose();
  }
});

/** Restores real sessions with deterministic task gaps so input can precede later renderers. */
async function reviewRestore(page: Page, server: Awaited<ReturnType<typeof startRealServer>>, count: number): Promise<void> {
  await enrol(page, server.origin, server.token);
  const windows = page.locator('.cl[data-view="console"] .ui-window');
  const savedCount = () => page.evaluate(() => {
    const key = `infraternal.canvas.${localStorage.getItem("tracer.user-id")}`;
    const doc = JSON.parse(localStorage.getItem(key) ?? "null") as CanvasDocument | null;
    const view = doc?.views.find((entry) => entry.id === "console");
    return view?.layout.type === "tiled" ? view.layout.columns.flatMap((column) => column.windows).length : 0;
  });
  for (let index = 1; index < count; index++) {
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:split:down", source: "pointer" } })));
    await expect(windows).toHaveCount(index + 1);
    // A window with no created session cannot be restored. Historical bridges
    // can include references that later retries replaced, so read the document.
    await expect.poll(savedCount, { timeout: 15_000 }).toBe(index + 1);
  }
  await expect.poll(savedCount).toBe(count);
  await page.evaluate(() => {
    const key = `infraternal.canvas.${localStorage.getItem("tracer.user-id")}`;
    const doc = JSON.parse(localStorage.getItem(key) ?? "null") as CanvasDocument;
    const view = doc.views.find((entry) => entry.id === "console");
    if (view?.layout.type !== "tiled") throw new Error("missing saved terminal view");
    const windows = view.layout.columns.flatMap((column) => column.windows).map(({ id, target }) => ({ id, target, height: 1 }));
    view.layout.columns = [{ id: "review-column", weight: 1, windows }];
    doc.views = [view];
    const save = () => localStorage.setItem(key, JSON.stringify(doc));
    save();
    window.addEventListener("pagehide", save, { once: true });
  });
  await page.addInitScript(() => {
    const schedule = window.setTimeout.bind(window);
    let next = 0;
    window.setTimeout = ((handler: TimerHandler, timeout?: number, ...args: unknown[]) => {
      if (timeout === 0 && typeof handler === "function" && Function.prototype.toString.call(handler).includes("[native code]")) {
        next = Math.max(next, performance.now()) + 150;
        return schedule(handler, next - performance.now(), ...args);
      }
      return schedule(handler, timeout, ...args);
    }) as typeof window.setTimeout;
  });
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.locator('.terminal-host textarea').first().waitFor({ state: "attached" });
  expect(await page.locator('.terminal-host textarea').count()).toBeLessThan(count);
}

for (const surface of ["palette", "button", "removed input"] as const) test(`round-2 restore preserves ${surface} focus across 30 windows`, async ({ page }, info) => {
  const server = await startRealServer({ latencyMs: 75 });
  try {
    await reviewRestore(page, server, 30);
    if (surface === "palette") {
      await page.keyboard.press("Control+Shift+K");
      await page.locator("#palette-input").fill("review focus stays here");
    } else if (surface === "button") {
      await page.locator("#sidebar-toggle").focus();
      // Closing the selected window while another surface has focus must not
      // leave a deferred focus request on the next selected renderer.
      await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:close", source: "keyboard" } })));
    } else {
      await page.evaluate(() => {
        const field = document.createElement("input");
        document.body.append(field);
        field.focus();
        field.value = "review";
        field.dispatchEvent(new Event("input", { bubbles: true }));
        field.remove();
      });
    }
    const focus = await page.evaluate(() => document.activeElement?.id || document.activeElement?.tagName);
    // Inspect every subsequent focus change, including a steal that is later
    // hidden by a palette refocus, rather than checking only the final element.
    await page.evaluate(() => {
      const changes: string[] = [];
      (window as unknown as { reviewFocusChanges: string[] }).reviewFocusChanges = changes;
      document.addEventListener("focusin", (event) => {
        if (event.target instanceof Element && event.target.closest(".terminal-host")) changes.push(event.target.tagName);
      }, true);
    });
    const count = surface === "button" ? 29 : 30;
    await expect(page.locator('.cl[data-view="console"] .terminal-host textarea')).toHaveCount(count, { timeout: 30_000 });
    await page.waitForTimeout(1000);
    expect(await page.evaluate(() => document.activeElement?.id || document.activeElement?.tagName)).toBe(focus);
    expect(await page.evaluate(() => (window as unknown as { reviewFocusChanges: string[] }).reviewFocusChanges)).toEqual([]);
    await page.screenshot({ path: info.outputPath(`restore-${surface.replaceAll(" ", "-")}.png`) });
    console.log(`REVIEW_FOCUS ${JSON.stringify({ surface, count, focus })}`);
  } finally {
    await page.close();
    await server.dispose();
  }
});

for (const coarse of [false, true]) test(`round-2 single-window open ${coarse ? "waits for a tap" : "takes desktop focus"}`, async ({ browser }, info) => {
  const server = await startRealServer({ latencyMs: 75 });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, hasTouch: coarse, isMobile: coarse, viewport: coarse ? { width: 393, height: 852 } : { width: 1440, height: 900 } });
  const page = await context.newPage();
  try {
    await enrol(page, server.origin, server.token);
    const input = page.locator('.terminal-host textarea').first();
    await input.waitFor({ state: "attached" });
    expect(await page.evaluate(() => matchMedia("(pointer: coarse)").matches)).toBe(coarse);
    if (coarse) {
      await page.waitForTimeout(1000);
      await expect(input).not.toBeFocused();
      await input.locator("..").tap({ position: { x: 40, y: 40 } });
      await expect(input).toBeFocused();
    } else {
      await expect(input).toBeFocused();
    }
    await page.screenshot({ path: info.outputPath(coarse ? "phone-tap.png" : "desktop-open.png") });
    console.log(`REVIEW_FOCUS ${JSON.stringify({ coarse, focused: await input.evaluate((node) => node === document.activeElement) })}`);
  } finally {
    await context.close();
    await server.dispose();
  }
});

test("round-2 only the selected restored window takes initial focus", async ({ page }) => {
  const server = await startRealServer({ latencyMs: 75 });
  try {
    await page.addInitScript(() => {
      const windows: string[] = [];
      (window as unknown as { reviewFocusedWindows: string[] }).reviewFocusedWindows = windows;
      document.addEventListener("focusin", (event) => {
        if (!(event.target instanceof Element) || !event.target.closest(".terminal-host")) return;
        const id = event.target.closest<HTMLElement>(".ui-window")?.dataset.windowId;
        if (id) windows.push(id);
      }, true);
    });
    await reviewRestore(page, server, 8);
    await expect(page.locator('.cl[data-view="console"] .terminal-host textarea')).toHaveCount(8);
    await page.waitForTimeout(1000);
    const chosen = await page.locator('.cl[data-view="console"] .ui-window[data-active]').getAttribute("data-window-id");
    expect(await page.evaluate(() => [...new Set((window as unknown as { reviewFocusedWindows: string[] }).reviewFocusedWindows)])).toEqual([chosen]);
  } finally {
    await page.close();
    await server.dispose();
  }
});

test("round-2 typing during 30-window restore remains in one shell", async ({ page }) => {
  const server = await startRealServer({ latencyMs: 75 });
  try {
    await reviewRestore(page, server, 30);
    const input = page.locator('.terminal-host textarea').first();
    await input.focus();
    const chosen = await input.evaluate((node) => node.closest<HTMLElement>(".ui-window")?.dataset.windowId);
    await page.keyboard.type("echo review-thirty-$((6*7))\n", { delay: 35 });
    await expect(page.locator('.cl[data-view="console"] .terminal-host textarea')).toHaveCount(30);
    await expect.poll(() => server.bridges.flatMap((bridge) => [...bridge.output.values()]).filter((output) => output.includes("review-thirty-42")).length, { timeout: 15_000 }).toBe(1);
    expect(await page.evaluate(() => document.activeElement?.closest<HTMLElement>(".ui-window")?.dataset.windowId)).toBe(chosen);
    console.log(`REVIEW_FOCUS ${JSON.stringify({ typingWindows: 30, chosen, executed: 1 })}`);
  } finally {
    await page.close();
    await server.dispose();
  }
});
