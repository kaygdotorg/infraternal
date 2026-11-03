/**
 * What a background tab costs and how soon it answers on return, on the real server and PTY (#317, D265, D300).
 *
 * Cost is sampled while the page is visible but idle and while it is hidden: renderer main-thread tasks and timer fires
 * (from a trace), renderer task time, frames on the wire by kind, and the CPU time of the browser and server processes.
 * A frozen hidden page is then woken after each hidden duration, after a server restart, and on a half-open link (the
 * relay keeps the browser socket while the server is gone). On every return a key is typed at once; the first terminal
 * byte is that key's echo, and the first frame is the first painted frame with the terminal shown live.
 *
 * Every return also records when the page first knows its link works: the first correlated Pong or, after a reconnect,
 * the first Welcome.
 *
 * Every number is printed as a `METRIC` line. `TRACER_MEASURE_ONLY=1` skips the assertions about probes, so an older
 * build can be measured the same way as a baseline. `TRACER_BACKGROUND_HIDDEN_MS` lists the hidden durations in ms.
 * `TRACER_BACKGROUND_LINK_ONLY=1` measures without a terminal (no key, no echo) where the host cannot open one; the
 * server probes only routes with an attached terminal, so that mode sees client probes alone.
 */
import { expect, test, type CDPSession, type Page } from "playwright/test";
import { readdirSync, readFileSync } from "node:fs";
import { startRealServer, type RealServer } from "./server";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";

const strict = process.env.TRACER_MEASURE_ONLY !== "1";
const linkOnly = process.env.TRACER_BACKGROUND_LINK_ONLY === "1";
const hiddenDurations = (process.env.TRACER_BACKGROUND_HIDDEN_MS ?? "5000,30000").split(",").map(Number);
const SAMPLE_MS = 10_000;
const TICK_MS = 10; // USER_HZ is 100 on the Linux VMs.

/** Frames the browser saw, by direction and kind. A control Ping/Pong is a native WebSocket frame. */
interface Wire { appIn: number; appOut: number; nativePingIn: number; nativePongOut: number; appPingIn: number; appPingOut: number; outputIn: number }
const emptyWire = (): Wire => ({ appIn: 0, appOut: 0, nativePingIn: 0, nativePongOut: 0, appPingIn: 0, appPingOut: 0, outputIn: 0 });
const wireDelta = (after: Wire, before: Wire): Wire =>
  Object.fromEntries(Object.entries(after).map(([key, value]) => [key, value - before[key as keyof Wire]])) as unknown as Wire;

/** CPU ticks of the server's process tree and of every other descendant of this worker (the browser). */
function cpuTicks(serverPid: number): { server: number; browser: number } {
  const parent = new Map<number, number>();
  const ticks = new Map<number, number>();
  for (const name of readdirSync("/proc")) {
    const pid = Number(name);
    if (!Number.isInteger(pid)) continue;
    try {
      const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
      const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      parent.set(pid, Number(fields[1]));
      ticks.set(pid, Number(fields[11]) + Number(fields[12]));
    } catch { /* The process exited between listing and reading. */ }
  }
  const under = (pid: number, root: number): boolean => {
    for (let at = pid, hops = 0; at > 1 && hops < 64; at = parent.get(at) ?? 0, hops++) if (at === root) return true;
    return false;
  };
  let server = 0;
  let browser = 0;
  for (const [pid, value] of ticks) {
    if (under(pid, serverPid)) server += value;
    else if (pid !== process.pid && under(pid, process.pid)) browser += value;
  }
  return { server, browser };
}

/** Renderer main-thread tasks and timer fires while `run` waits. */
async function traceDuring(cdp: CDPSession, run: () => Promise<void>): Promise<{ tasks: number; timers: number }> {
  interface TraceEvent { name?: string; ph?: string; pid?: number; tid?: number; args?: { name?: string } }
  const events: TraceEvent[] = [];
  const collect = ({ value }: { value: TraceEvent[] }): void => { events.push(...value); };
  cdp.on("Tracing.dataCollected", collect);
  await cdp.send("Tracing.start", { categories: "toplevel,devtools.timeline", transferMode: "ReportEvents" });
  try {
    await run();
  } finally {
    const stopped = new Promise<void>((done) => cdp.once("Tracing.tracingComplete", () => done()));
    await cdp.send("Tracing.end");
    await stopped;
    cdp.off("Tracing.dataCollected", collect);
  }
  const main = new Set(events.filter((e) => e.ph === "M" && e.name === "thread_name" && e.args?.name === "CrRendererMain").map((e) => `${e.pid}:${e.tid}`));
  const onMain = (e: TraceEvent): boolean => main.has(`${e.pid}:${e.tid}`);
  return {
    tasks: events.filter((e) => e.name === "RunTask" && e.ph === "X" && onMain(e)).length,
    timers: events.filter((e) => e.name === "TimerFire" && onMain(e)).length,
  };
}

const setVisibility = (page: Page, hidden: boolean): Promise<void> => page.evaluate((hide) => {
  Object.defineProperty(document, "hidden", { configurable: true, get: () => hide });
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => (hide ? "hidden" : "visible") });
  document.dispatchEvent(new Event("visibilitychange"));
}, hidden);

test("a background tab stays quiet and answers its first key promptly on return", async ({ browser }) => {
  test.setTimeout(120_000 + hiddenDurations.reduce((sum, ms) => sum + ms + 30_000, 0));
  const server: RealServer = await startRealServer({ latencyMs: Number(process.env.MOBILE_ONE_WAY_MS ?? 75), remoteListen: `127.0.0.1:${Number(process.env.TRACER_TEST_PORT ?? 4444) + 1001}` });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 393, height: 852 }, isMobile: true, hasTouch: true });
  const page = await context.newPage();
  try {
    const cdp = await context.newCDPSession(page);
    await cdp.send("Network.enable");
    await cdp.send("Performance.enable");
    const wire = emptyWire();
    let firstOutputAt: number | undefined;
    let firstProofAt: number | undefined;
    let welcomedAt: number | undefined;
    const decoders = new Map<string, { sent: WebSocketFrameDecoder; received: WebSocketFrameDecoder }>();
    cdp.on("Network.webSocketCreated", ({ requestId, url }) => {
      if (new URL(url).pathname === "/v1/ws") decoders.set(requestId, { sent: new WebSocketFrameDecoder(), received: new WebSocketFrameDecoder() });
    });
    cdp.on("Network.webSocketClosed", ({ requestId }) => decoders.delete(requestId));
    cdp.on("Network.webSocketFrameSent", ({ requestId, response }) => {
      if (!decoders.has(requestId)) return;
      if (response.opcode === 10) wire.nativePongOut++;
      if (response.opcode !== 2) return;
      wire.appOut++;
      decoders.get(requestId)!.sent.feed(new Uint8Array(Buffer.from(response.payloadData, "base64")), (_stream, frame) => {
        if (frame.type === "Ping") wire.appPingOut++;
      });
    });
    cdp.on("Network.webSocketFrameReceived", ({ requestId, response }) => {
      if (!decoders.has(requestId)) return;
      if (response.opcode === 9) wire.nativePingIn++;
      if (response.opcode !== 2) return;
      wire.appIn++;
      decoders.get(requestId)!.received.feed(new Uint8Array(Buffer.from(response.payloadData, "base64")), (_stream, frame) => {
        if (frame.type === "Ping") wire.appPingIn++;
        if (frame.type === "Pong" || frame.type === "Welcome") firstProofAt ??= Date.now();
        if (frame.type === "Welcome") welcomedAt ??= Date.now();
        if (frame.type === "Output") {
          wire.outputIn++;
          firstOutputAt ??= Date.now();
        }
      });
    });
    const taskSeconds = async (): Promise<number> =>
      (await cdp.send("Performance.getMetrics")).metrics.find((metric) => metric.name === "TaskDuration")?.value ?? 0;

    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
    await page.goto(server.origin + "/?theme=ink&bg=none");
    await page.locator("#setup-token").evaluate((element, token) => {
      (element as HTMLInputElement).value = token;
      element.dispatchEvent(new Event("input", { bubbles: true }));
    }, server.token);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.locator("#setup-username").fill("background_tab");
    await page.locator("#setup-display-name").fill("Background tab");
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.getByRole("button", { name: "Create passkey" }).click();
    await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
    await page.locator(".auth-check").click();
    await page.getByRole("button", { name: "Open infraternal" }).click();
    // The same host setup as the #244 mobile check: unlock the host CA so the local terminal can attach.
    await page.locator(".cl-viewport").waitFor();
    const unlock = page.getByLabel("Hosts settings").getByRole("button", { name: "Unlock", exact: true, includeHidden: true });
    await expect(unlock).toHaveAttribute("data-shown", "true");
    await unlock.evaluate((button) => (button as HTMLButtonElement).click());
    await expect.poll(() => page.evaluate(async () => (await fetch("/remote/ca/status", { method: "POST" })).json())).toEqual({ locked: false, initialized: true });
    const terminal = page.locator('.cl[data-view="console"] .ui-window').first();
    if (!linkOnly) {
      await expect(terminal).toHaveAttribute("data-status", "live", { timeout: 30_000 });
      await terminal.locator(".terminal-host").click({ position: { x: 40, y: 40 } });
      await terminal.locator(".terminal-host textarea").focus();
    }
    // Let startup sampling, layout and the first prompt settle before sampling idle cost.
    await page.waitForTimeout(3000);

    const sample = async (label: string): Promise<Wire> => {
      const wireBefore = { ...wire };
      const cpuBefore = cpuTicks(server.pid);
      const taskBefore = await taskSeconds();
      const trace = await traceDuring(cdp, () => new Promise((done) => setTimeout(done, SAMPLE_MS)));
      const taskMs = (await taskSeconds() - taskBefore) * 1000;
      const cpuAfter = cpuTicks(server.pid);
      const seen = wireDelta(wire, wireBefore);
      console.log(`METRIC background_${label} sample_ms=${SAMPLE_MS} renderer_main_tasks=${trace.tasks} timer_fires=${trace.timers} renderer_task_ms=${taskMs.toFixed(1)} browser_cpu_ms=${(cpuAfter.browser - cpuBefore.browser) * TICK_MS} server_cpu_ms=${(cpuAfter.server - cpuBefore.server) * TICK_MS} native_ping_in=${seen.nativePingIn} native_pong_out=${seen.nativePongOut} app_frames_in=${seen.appIn} app_frames_out=${seen.appOut} app_ping_in=${seen.appPingIn} app_ping_out=${seen.appPingOut}`);
      return seen;
    };

    /** Wake a frozen hidden page, type one key at once, and time the first frame, link proof and the key's echo. */
    const wake = async (label: string, extra = ""): Promise<void> => {
      await cdp.send("Page.setWebLifecycleState", { state: "active" });
      firstOutputAt = undefined;
      firstProofAt = undefined;
      welcomedAt = undefined;
      const startedAt = Date.now();
      const firstFrame = page.evaluate((needLive) => new Promise<number>((done) => {
        Object.defineProperty(document, "hidden", { configurable: true, get: () => false });
        Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
        const shownAt = performance.now();
        document.dispatchEvent(new Event("visibilitychange"));
        const step = (): void => {
          if (!needLive || document.querySelector('.cl[data-view="console"] .ui-window[data-status="live"]')) done(performance.now() - shownAt);
          else requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
      }), !linkOnly);
      if (!linkOnly) await page.keyboard.type("x");
      const firstFrameMs = await firstFrame;
      await expect.poll(() => firstProofAt, { timeout: 30_000 }).toBeDefined();
      const proof = `link_proof_ms=${firstProofAt! - startedAt} reconnected=${welcomedAt !== undefined}`;
      if (linkOnly) {
        console.log(`METRIC background_return_${label} first_frame_ms=${firstFrameMs.toFixed(1)} ${proof} sockets_opened=${server.bridges.length}${extra}`);
        await page.waitForTimeout(1000);
        return;
      }
      await expect.poll(() => firstOutputAt, { timeout: 30_000 }).toBeDefined();
      console.log(`METRIC background_return_${label} first_live_frame_ms=${firstFrameMs.toFixed(1)} first_terminal_byte_ms=${firstOutputAt! - startedAt} ${proof} sockets_opened=${server.bridges.length}${extra}`);
      await page.keyboard.press("Backspace");
      await expect(terminal).toHaveAttribute("data-status", "live", { timeout: 30_000 });
      await page.waitForTimeout(500);
    };
    const hideAndFreeze = async (): Promise<void> => {
      await setVisibility(page, true);
      // Let the visibility notice cross the relay before the renderer stops.
      await page.waitForTimeout(1000);
      await cdp.send("Page.setWebLifecycleState", { state: "frozen" });
    };

    // A. Visible but idle: no client liveness probe, no page wakeup for liveness.
    const visible = await sample("visible_idle");
    if (strict) expect(visible.appPingOut).toBe(0);

    // B. Hidden but still running (a desktop background tab): nothing on the wire for liveness.
    await setVisibility(page, true);
    await page.waitForTimeout(1000);
    const hidden = await sample("hidden");
    if (strict) {
      expect(hidden.appPingOut).toBe(0);
      expect(hidden.appPingIn + hidden.nativePingIn).toBe(0);
    }
    await setVisibility(page, false);
    await page.waitForTimeout(1000);

    // C. Frozen hidden page, woken after each duration over a link that stayed up.
    for (const duration of hiddenDurations) {
      await hideAndFreeze();
      const before = { ...wire };
      const sockets = server.bridges.length;
      await page.waitForTimeout(duration);
      const frozen = wireDelta(wire, before);
      if (strict) expect(frozen.nativePingIn + frozen.appPingIn).toBe(0);
      await wake(`after_${duration}ms`, ` frozen_native_ping_in=${frozen.nativePingIn} frozen_app_frames_in=${frozen.appIn}`);
      if (strict) expect(server.bridges.length).toBe(sockets);
    }

    // D. The server restarted while the page was hidden: the browser socket is closed when it wakes.
    const marker = `return-${Date.now()}`;
    await hideAndFreeze();
    const resumedFrom = server.bridges.length;
    await server.restart();
    await wake("after_server_restart");
    if (!linkOnly) {
      await page.keyboard.type(`echo ${marker}-$((6*7))\n`);
      const output = (): string => server.bridges.slice(resumedFrom).flatMap((bridge) => [...bridge.output.values()]).join("");
      await expect.poll(output, { timeout: 30_000 }).toContain(`${marker}-42`);
      expect(output().split(`${marker}-42`).length - 1).toBe(1);
    }

    // E. Half-open link: the relay keeps the browser socket open while the server behind it restarts, so only the
    // return probe's deadline can tell the page its link is gone.
    await hideAndFreeze();
    server.retainBrowserRoutes();
    await server.restart();
    await wake("half_open_link");
  } finally {
    try { await context.close(); }
    finally { await server.dispose(); }
  }
});
