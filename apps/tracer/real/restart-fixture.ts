/** Keeps the production browser and real PTY across a server-only stop (#199, D13, D259). */
import { expect, type Browser } from "playwright/test";
import { WebSocket } from "ws";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { encodeMuxedFrame, WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { startRealServer } from "./server";
import type { RealServer } from "./server";

/** Adds real, idle PTYs through authenticated production actions; private cookies remain in memory. */
async function populate(server: RealServer, count: number): Promise<void> {
  if (count === 0) return;
  const socket = new WebSocket(server.backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: server.origin, Cookie: server.bridges[0]!.cookie } });
  const decoder = new WebSocketFrameDecoder();
  const send = (frame: Parameters<typeof encodeMuxedFrame>[1]) => socket.send(encodeMuxedFrame(0, frame));
  try {
    await new Promise<void>((resolve, reject) => {
      let opened = 0;
      socket.on("error", reject);
      socket.on("message", (data) => decoder.feed(new Uint8Array(Buffer.from(data as Buffer)), (_stream, frame) => {
        if (frame.type === "Hello") send({ type: "Hello", version: 1, caps: 0n, clientInfo: "restart-scale" });
        if (frame.type === "Welcome") send({ type: "Call", callId: 1, actionId: "ssh.session.open", inputJson: new TextEncoder().encode("{}") });
        if (frame.type === "Result") {
          if (!frame.ok) { reject(new Error("scale fixture session open refused")); return; }
          if (++opened === count) resolve();
          else send({ type: "Call", callId: opened + 1, actionId: "ssh.session.open", inputJson: new TextEncoder().encode("{}") });
        }
      }));
    });
  } finally { socket.terminate(); }
}

export async function exerciseRestart(browser: Browser, unlock: boolean, retainBrowserRoute = false): Promise<void> {
  const server = await startRealServer({ systemd: process.env.REAL_ROOT_NAMESPACE !== "1", remoteListen: "127.0.0.1:4398" });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: unlock ? { width: 393, height: 852 } : { width: 1440, height: 900 }, isMobile: unlock, hasTouch: unlock });
  const page = await context.newPage();
  let routes = 0;
  let supersededRoutes = 0;
  let stoppedRoutes = 0;
  if (retainBrowserRoute) await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const id = ++routes;
    const superseded = () => id <= supersededRoutes;
    const upstream = socket.connectToServer();
    // Model an intermediary retaining the browser socket after its upstream
    // stops. Replacement routes still reach the real restarted server.
    socket.onMessage((message) => { if (!superseded()) upstream.send(message); });
    upstream.onMessage((message) => { if (!superseded()) socket.send(message); });
    upstream.onClose((code, reason) => {
      if (superseded()) { stoppedRoutes++; return; }
      socket.close({ code, reason });
    });
  });
  page.on("pageerror", (error) => console.log("browser error kind:", error.name));
  try {
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
    await page.goto(server.origin);
    await page.locator("#setup-token").fill(server.token);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.locator("#setup-username").fill("restart_test");
    await page.locator("#setup-display-name").fill("Restart test");
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.getByRole("button", { name: "Create passkey" }).click();
    await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
    await page.locator(".auth-check").click();
    await page.getByRole("button", { name: "Open infraternal" }).click();
    await page.locator(".cl-viewport").waitFor();
    console.log("restart fixture: signed in");
    const authority = () => page.evaluate(async () => {
      const response = await fetch("/remote/ca/status", { method: "POST" });
      if (!response.ok) throw new Error("fixture CA status refused");
      return await response.json() as { locked: boolean; initialized: boolean };
    });
    const unlockAuthority = async () => {
      console.log("restart fixture: authority status", await authority());
      await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
      const action = page.getByLabel("Hosts settings").getByRole("button", { name: "Unlock", exact: true, includeHidden: true });
      await expect(action).toHaveAttribute("data-shown", "true");
      // The Hosts card is in another canvas view; invoke its shared real ceremony
      // without making a camera flight part of this transport regression.
      await action.evaluate((button) => (button as HTMLButtonElement).click());
      await expect.poll(authority).toEqual({ locked: false, initialized: true });
    };
    await unlockAuthority();
    console.log("restart fixture: CA initialized");
    const output = () => server.bridges.filter((b) => !b.closed).flatMap((b) => [...b.output.values()]).join("");
    await expect.poll(output, { timeout: 15_000 }).not.toBe("");
    await page.locator(".terminal-host").first().click({ position: { x: 40, y: 40 } });
    await page.locator(".terminal-host textarea").first().focus();
    await page.keyboard.type("echo before-42", { delay: 5 });
    await page.keyboard.press("Enter");
    await expect.poll(output, { timeout: 15_000 }).toMatch(/\r?\nbefore-42\r?\n/);
    console.log("restart fixture: initial typing works");
    const scale = Number(process.env.RESTART_SESSIONS ?? 1);
    if (!Number.isInteger(scale) || scale < 1 || scale > 72) throw new Error("invalid restart fixture scale");
    await populate(server, scale - 1);
    if (process.env.RESTART_MEASURE === "1") {
      const measurement = spawn("python3", [resolve(import.meta.dirname, "../../../scripts/restart-rss.py"), "/run/infraternal", String(server.pid)], { stdio: ["ignore", "pipe", "ignore"] });
      let result = "";
      measurement.stdout.on("data", (bytes) => { result += bytes; });
      const [code] = await once(measurement, "exit");
      if (code !== 0) throw new Error("private fixture RSS measurement failed");
      console.log(result.trim());
    }
    if (process.env.RESTART_MEASURE === "1") await page.evaluate(async () => {
      const stage = document.querySelector<HTMLElement>("#terminal-screen")!;
      await new Promise<void>((done) => requestAnimationFrame(() => done()));
      const canvas = document.querySelector<HTMLCanvasElement>(".terminal-host canvas")!;
      const fingerprint = (): number => {
        const pixels = canvas.getContext("2d")!.getImageData(0, 0, canvas.width, canvas.height).data;
        let hash = 2166136261;
        for (let i = 0; i < pixels.length; i += 4) hash = Math.imul(hash ^ pixels[i]!, 16777619);
        return hash >>> 0;
      };
      const before = fingerprint();
      const probe = { lostAt: 0, liveAt: 0, retained: false, frameMs: 0, verifyRetained() { this.retained = fingerprint() === before; } };
      (window as unknown as { restartProbe: typeof probe }).restartProbe = probe;
      new MutationObserver(() => {
        const now = performance.timeOrigin + performance.now();
        if (stage.dataset.connected === "false" && !probe.lostAt) {
          probe.lostAt = now;
          requestAnimationFrame(() => {
            probe.frameMs = performance.timeOrigin + performance.now() - probe.lostAt;
          });
        }
        else if (stage.dataset.connected === "true" && probe.lostAt) probe.liveAt ||= now;
      }).observe(stage, { attributes: true, attributeFilter: ["data-connected"] });
    });
    // Only the client's clock advances: expire resume credentials without expiring server auth.
    await page.evaluate(() => { const now = Date.now; Date.now = () => now() + 86_400_000; });
    if (retainBrowserRoute) supersededRoutes = routes;
    await server.restart(async () => {
      console.log("restart fixture: server stopped");
      console.log("restart fixture: bridge state", server.bridges.map((bridge) => ({ closed: bridge.closed, closedBy: bridge.closedBy })));
      console.log("restart fixture: page state", await page.locator("#terminal-screen").getAttribute("data-connected"));
      if (retainBrowserRoute) {
        await expect.poll(() => stoppedRoutes).toBeGreaterThan(0);
      } else {
        await expect(page.locator("#terminal-screen")).toHaveAttribute("data-connected", "false");
        await expect(page.locator('.cl[data-view="console"] .ui-window').first()).toHaveAttribute("data-status", "connecting");
      }
      // GPU readback belongs before the path recovers: it must not delay the
      // replay/paint timestamp used by the latency measurement.
      if (process.env.RESTART_MEASURE === "1") await page.evaluate(() => {
        (window as unknown as { restartProbe: { verifyRetained(): void } }).restartProbe.verifyRetained();
      });
      if (process.env.RESTART_CAPTURE_DIR) {
        await mkdir(process.env.RESTART_CAPTURE_DIR, { recursive: true });
        await page.screenshot({ path: resolve(process.env.RESTART_CAPTURE_DIR, `restart-${unlock ? "unlock" : "locked"}-catching-up.png`) });
      }
      console.log("restart fixture: disconnected indicator confirmed");
      await page.keyboard.type("echo waiting-49", { delay: 5 });
      console.log("restart fixture: queued text entered");
      await page.keyboard.press("Enter");
      console.log("restart fixture: queued return entered");
    });
    console.log("restart fixture: server restarted");
    if (retainBrowserRoute) {
      // Fresh input after the real server is healthy must trigger eventual
      // recovery without reload, focus changes or a forced client close.
      await page.keyboard.type("echo recovered-$((8*8))");
      await page.keyboard.press("Enter");
      try {
        await expect.poll(output, { timeout: 15_000 }).toMatch(/\r?\nrecovered-64\r?\n/);
      } finally {
        console.log(`real route recovery: routes=${routes} superseded_routes=${supersededRoutes} stopped_routes=${stoppedRoutes} window_status=${await page.locator('.cl[data-view="console"] .ui-window').first().getAttribute("data-status")} connected=${await page.locator("#terminal-screen").getAttribute("data-connected")}`);
      }
    }
    await expect.poll(authority).toEqual({ locked: true, initialized: true });
    if (unlock) await unlockAuthority();
    await expect.poll(() => server.bridges.filter((b) => !b.closed).some((b) => b.acked.size > 0), { timeout: 15_000 }).toBe(true);
    await expect.poll(output, { timeout: 15_000 }).toMatch(/\r?\nwaiting-49\r?\n/);
    await page.locator(".terminal-host").first().click({ position: { x: 40, y: 40 } });
    await page.locator(".terminal-host textarea").first().focus();
    await page.keyboard.type("echo after-48", { delay: 5 });
    await page.keyboard.press("Enter");
    await expect.poll(output, { timeout: 15_000 }).toMatch(/\r?\nafter-48\r?\n/);
    await expect(page.locator('.cl[data-view="console"] .ui-window').first()).toHaveAttribute("data-status", "live");
    if (process.env.RESTART_CAPTURE_DIR) await page.screenshot({ path: resolve(process.env.RESTART_CAPTURE_DIR, `restart-${unlock ? "unlock" : "locked"}-ready.png`) });
    if (process.env.RESTART_MEASURE === "1") {
      const probe = await page.evaluate(() => (window as unknown as { restartProbe: { liveAt: number; retained: boolean; frameMs: number } }).restartProbe);
      const recovery = Math.max(0, probe.liveAt - server.recoveredAt!);
      const roundTrip = 2 * Number(process.env.REAL_ONE_WAY_MS ?? 0);
      console.log(`METRIC restart_sessions=${scale} viewport=${unlock ? "393x852" : "1440x900"} ca_after_recovery=${unlock ? "unlocked" : "locked"} path_to_typable_ms=${recovery.toFixed(3)} rtt_ms=${roundTrip} budget_ms=${roundTrip + 50} last_screen_retained=${probe.retained} screen_restore_ms=0 first_verification_frame_ms=${probe.frameMs.toFixed(3)}`);
      expect(probe.retained).toBe(true);
      expect(recovery).toBeLessThanOrEqual(roundTrip + 50);
    }
  } finally { await server.dispose(); await context.close(); }
}
