/** Keeps the production browser and real PTY across a server-only stop (#199, D13, D259). */
import { expect, type Browser, type BrowserContext } from "playwright/test";
import { WebSocket } from "ws";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { encodeMuxedFrame, WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { startRealServer } from "./server";
import { personName, type RealServer } from "./server";

/** Adds private PTYs; optional attached scale uses the production per-socket cap and answers real probes. */
async function populate(server: RealServer, count: number): Promise<() => void> {
  const sockets: WebSocket[] = [];
  const attached = process.env.RESTART_ATTACHED_SCALE === "1";
  const cleanup = () => { for (const socket of sockets) socket.terminate(); };
  try {
    for (let remaining = count; remaining > 0;) {
      const batch = Math.min(remaining, attached ? 28 : count);
      const socket = new WebSocket(server.backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: server.origin, Cookie: server.bridges[0]!.cookie } });
      sockets.push(socket);
      const decoder = new WebSocketFrameDecoder();
      const send = (stream: number, frame: Parameters<typeof encodeMuxedFrame>[1]) => socket.send(encodeMuxedFrame(stream, frame));
      await new Promise<void>((resolve, reject) => {
        let opened = 0;
        const acked = new Set<number>();
        // A dropped setup route is a failed measurement, never an indefinite wait.
        const timeout = setTimeout(() => reject(new Error(`scale attachment stalled: opened=${opened} acknowledged=${acked.size} batch=${batch}`)), 15_000);
        const complete = () => { clearTimeout(timeout); resolve(); };
        socket.once("close", (code) => { clearTimeout(timeout); reject(new Error(`scale attachment closed: code=${code} opened=${opened} acknowledged=${acked.size} batch=${batch}`)); });
        const open = () => send(0, { type: "Call", callId: opened + 1, actionId: "ssh.session.open", inputJson: new TextEncoder().encode("{}") });
        socket.on("error", reject);
        socket.on("message", (data) => decoder.feed(new Uint8Array(Buffer.from(data as Buffer)), (stream, frame) => {
          if (frame.type === "Hello") send(0, { type: "Hello", version: 1, caps: 0n, clientInfo: "restart-scale" });
          if (frame.type === "Welcome") open();
          // Auxiliary load clients model the browser profile's RTT for route proofs;
          // the measured browser itself traverses real TLS and port-scoped netem.
          if (frame.type === "Ping") setTimeout(() => {
            if (socket.readyState === WebSocket.OPEN) send(stream, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs });
          }, Number(process.env.REAL_NETWORK_RTT_MS ?? 2 * Number(process.env.REAL_ONE_WAY_MS ?? 0)));
          if (frame.type === "Result") {
            if (!frame.ok) {
              const refusal = JSON.parse(new TextDecoder().decode(frame.json)) as { reason?: unknown };
              const reason = ["invalid", "unavailable", "resource_unavailable", "host_memory_low", "host_memory_unavailable"].includes(String(refusal.reason)) ? String(refusal.reason) : "other";
              reject(new Error(`scale fixture session open refused: opened=${opened} batch=${batch} reason=${reason}`)); return;
            }
            if (attached) {
              const result = JSON.parse(new TextDecoder().decode(frame.json)) as { session_id: string };
              if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(result.session_id)) { reject(new Error("invalid fixture session identity")); return; }
              const id = Buffer.from(result.session_id.replaceAll("-", ""), "hex");
              const stream = opened * 2 + 1;
              send(stream, { type: "AttachTerm", sessionId: id, lastOutSeq: 0n, lastInSeq: 0n });
              send(stream, { type: "Credit", bytes: 1024 * 1024 });
            }
            if (++opened === batch) { if (!attached || acked.size === batch) complete(); }
            else open();
          }
          if (frame.type === "Ack") { acked.add(stream); if (opened === batch && acked.size === batch) complete(); }
        }));
      });
      remaining -= batch;
    }
    if (!attached) cleanup();
    return cleanup;
  } catch (error) { cleanup(); throw error; }
}

/** Keep live sessions across a real restart using an isolated listener and owned fixture cleanup. */
export async function exerciseRestart(browser: Browser, unlock: boolean, retainBrowserRoute = false, upstream?: "daemon" | "shim", visibleSessions = 1): Promise<void> {
  const server = await startRealServer({ systemd: process.env.REAL_ROOT_NAMESPACE !== "1", remoteListen: "127.0.0.1:0", ...(process.env.RESTART_MEASURE === "1" ? { port: Number(process.env.TRACER_TEST_PORT), address: "::" } : {}) });
  const mobile = unlock && visibleSessions === 1;
  let context: BrowserContext | undefined;
  let retainedBridges: number[] = [];
  let measuringRecovery = false;
  let cleanupScale = () => {};
  try {
    context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: mobile ? { width: 393, height: 852 } : { width: 1440, height: 900 }, isMobile: mobile, hasTouch: mobile });
    const page = await context.newPage();
    page.on("pageerror", (error) => console.log("browser error kind:", error.name));
    const cdp = await context.newCDPSession(page);
    if (process.env.RESTART_MEASURE === "1") {
      const sockets = new Map<string, WebSocketFrameDecoder>();
      await cdp.send("Network.enable");
      cdp.on("Network.webSocketCreated", ({ requestId, url }) => {
        if (new URL(url).pathname === "/v1/ws") sockets.set(requestId, new WebSocketFrameDecoder());
      });
      cdp.on("Network.webSocketClosed", ({ requestId }) => sockets.delete(requestId));
      cdp.on("Network.webSocketFrameReceived", ({ requestId, response }) => {
        // Decode in memory; never log frame bodies or request headers. Automatic upstream
        // rebinding may finish before a window ever needs to leave its live state.
        if (!measuringRecovery || response.opcode !== 2) return;
        sockets.get(requestId)?.feed(new Uint8Array(Buffer.from(response.payloadData, "base64")), (stream, frame) => {
          if (stream === 0 || frame.type !== "Event" || frame.eventJson.byteLength > 1024) return;
          const notice = JSON.parse(new TextDecoder().decode(frame.eventJson)) as { type?: unknown; session_id?: unknown };
          const target = server.bridges.flatMap((bridge) => [...bridge.attached.values()].flat())[0];
          if (notice.type !== "terminal.replay_complete" || typeof notice.session_id !== "string"
            || notice.session_id.replaceAll("-", "") !== target) return;
          void page.evaluate(() => new Promise<void>((done) => requestAnimationFrame(() => {
            const probe = (window as unknown as { restartProbe: { liveAt: number } }).restartProbe;
            if (document.querySelector<HTMLElement>('.cl[data-view="console"] .ui-window')?.dataset.status === "live")
              probe.liveAt ||= performance.timeOrigin + performance.now();
            done();
          }))).catch(() => {});
        });
      });
    }
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
    await page.goto(server.origin);
    await page.locator("#setup-token").fill(server.token);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.locator("#setup-username").fill(personName("restart_test"));
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
      await expect.poll(authority, { timeout: 15_000 }).toEqual({ locked: false, initialized: true });
    };
    await unlockAuthority();
    console.log("restart fixture: CA initialized");
    const windows = page.locator('.cl[data-view="console"] .ui-window');
    if (visibleSessions !== 1 && visibleSessions !== 3) throw new Error("invalid visible restart session count");
    for (let i = 1; i < visibleSessions; i++) {
      await windows.nth(i - 1).locator('[data-action="split-down"]').evaluate((button) => (button as HTMLElement).click());
      await expect(windows).toHaveCount(i + 1);
      try { await expect(windows.nth(i)).toHaveAttribute("data-status", "live"); }
      catch (error) {
        console.log("restart fixture: opening statuses", await windows.evaluateAll((nodes) => nodes.map((node) => (node as HTMLElement).dataset.status)));
        console.log("restart fixture: recent opening routes", server.bridges.slice(-3).map((bridge) => ({ closed: bridge.closed, serverClose: bridge.serverClose, acknowledgments: bridge.acked.size, actions: bridge.control.filter((frame) => frame.type === "Call" || frame.type === "Result").map((frame) => frame.detail) })));
        throw error;
      }
    }
    // Every requested window must own a real live terminal before attachment accounting.
    for (let i = 0; i < visibleSessions; i++) await expect(windows.nth(i)).toHaveAttribute("data-status", "live");
    // All three windows share a real multiplexed route, rather than merely
    // counting unattached PTYs. Preserve identities to check isolation after restart.
    await expect.poll(() => new Set(server.bridges.filter((bridge) => !bridge.closed)
      .flatMap((bridge) => [...bridge.attached.values()].flat())).size).toBe(visibleSessions);
    const liveSessionIds = [...new Set(server.bridges.filter((bridge) => !bridge.closed)
      .flatMap((bridge) => [...bridge.attached.values()].flat()))];
    const sessionIds = visibleSessions === 1 ? liveSessionIds : [] as string[];
    const sessionOutput = (session: string) => server.bridges.flatMap((bridge) =>
      [...bridge.attached].filter(([, ids]) => ids.includes(session)).map(([stream]) => bridge.output.get(stream) ?? "")).join("");
    if (visibleSessions === 3) for (let i = 0; i < visibleSessions; i++) {
      await windows.nth(i).locator(".terminal-host").click({ position: { x: 40, y: 40 } });
      await windows.nth(i).locator(".terminal-host textarea").focus();
      await page.keyboard.type(`echo sibling-${i}-$((20+${i}))`);
      await page.keyboard.press("Enter");
      const marker = `sibling-${i}-${20 + i}`;
      // Attachment arrival order is independent of canvas row order. Identify each
      // window by its executed marker, then require three distinct surviving sessions.
      await expect.poll(() => liveSessionIds.filter((session) => sessionOutput(session).includes(marker)).length, { timeout: 15_000 }).toBe(1);
      sessionIds.push(liveSessionIds.find((session) => sessionOutput(session).includes(marker))!);
    }
    expect(new Set(sessionIds).size).toBe(visibleSessions);
    // An executed command remains evidence when a later route closes. A resumed
    // client need not replay output it already consumed on the preceding route.
    const output = () => server.bridges.flatMap((b) => [...b.output.values()]).join("");
    await expect.poll(output, { timeout: 15_000 }).not.toBe("");
    await page.locator(".terminal-host").first().click({ position: { x: 40, y: 40 } });
    await page.locator(".terminal-host textarea").first().focus();
    // Computed markers cannot be satisfied by the PTY echoing unexecuted input,
    // and remain valid when a replay Snapshot adds cursor controls or a prompt.
    await page.keyboard.type("echo before-$((6*7))", { delay: 5 });
    await page.keyboard.press("Enter");
    await expect.poll(output, { timeout: 15_000 }).toContain("before-42");
    console.log("restart fixture: initial typing works");
    const scale = Number(process.env.RESTART_SESSIONS ?? visibleSessions);
    if (!Number.isInteger(scale) || scale < visibleSessions || scale > 72) throw new Error("invalid restart fixture scale");
    cleanupScale = await populate(server, scale - visibleSessions);
    if (process.env.RESTART_MEASURE === "1") {
      const measurement = spawn("python3", [resolve(import.meta.dirname, "../../../scripts/restart-rss.py"), "/run/infraternal", String(server.pid)], { stdio: ["ignore", "pipe", "ignore"] });
      let result = "";
      measurement.stdout.on("data", (bytes) => { result += bytes; });
      const [code] = await once(measurement, "exit");
      if (code !== 0) throw new Error("private fixture RSS measurement failed");
      console.log(result.trim());
    }
    if (process.env.RESTART_MEASURE === "1") await page.evaluate(async () => {
      const card = document.querySelector<HTMLElement>('.cl[data-view="console"] .ui-window')!;
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
        if (card.dataset.status === "connecting" && !probe.lostAt) {
          probe.lostAt = now;
          requestAnimationFrame(() => {
            probe.frameMs = performance.timeOrigin + performance.now() - probe.lostAt;
          });
        }
        else if (card.dataset.status === "live" && probe.lostAt) probe.liveAt ||= now;
      }).observe(card, { attributes: true, attributeFilter: ["data-status"] });
    });
    // Only the client's clock advances: expire resume credentials without expiring server auth.
    await page.evaluate(() => { const now = Date.now; Date.now = () => now() + 86_400_000; });
    if (retainBrowserRoute) {
      await expect.poll(() => server.bridges.some((bridge) => !bridge.closed && bridge.acked.size > 0)).toBe(true);
      retainedBridges = server.bridges.filter((bridge) => !bridge.closed).map((bridge) => bridge.id);
      server.retainBrowserRoutes();
    }
    const replaysBefore = new Map(server.bridges.map((bridge) => [bridge.id, bridge.replays]));
    measuringRecovery = true;
    const disrupt = (during: () => Promise<void>) => upstream
      ? server.pauseUpstream(upstream, during, sessionIds[0]) : server.restart(during);
    await disrupt(async () => {
      console.log("restart fixture: server stopped");
      console.log("restart fixture: bridge state", server.bridges.map((bridge) => ({ closed: bridge.closed, closedBy: bridge.closedBy })));
      console.log("restart fixture: page state", await page.locator("#terminal-screen").getAttribute("data-connected"));
      if (retainBrowserRoute) {
        await expect.poll(() => server.bridges.filter((bridge) => retainedBridges.includes(bridge.id) && bridge.closed).length).toBeGreaterThan(0);
      } else {
        // Other sessions may remain writable; readiness belongs to this window.
        if (!upstream) await expect(page.locator("#terminal-screen")).toHaveAttribute("data-connected", "false");
      }
      // Typing during the outage must be visibly queued, even when the browser socket stays open.
      // A daemon may already have been replaced/rebound within its lease; a completed
      // real replay proves that recovery and does not require an artificial UI outage.
      await expect.poll(async () => await page.locator('.cl[data-view="console"] .ui-window').first().getAttribute("data-status") === "connecting"
        || upstream === "daemon" && server.bridges.some((bridge) => bridge.replays > (replaysBefore.get(bridge.id) ?? 0))).toBe(true);
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
      await page.keyboard.type("echo waiting-$((7*7))", { delay: 5 });
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
        await expect.poll(output, { timeout: 15_000 }).toContain("recovered-64");
      } finally {
        console.log(`real route recovery: routes=${server.bridges.length} retained_routes=${retainedBridges.length} window_status=${await page.locator('.cl[data-view="console"] .ui-window').first().getAttribute("data-status")} connected=${await page.locator("#terminal-screen").getAttribute("data-connected")}`);
      }
    }
    await expect.poll(authority).toEqual({ locked: !upstream, initialized: true });
    if (unlock) await unlockAuthority();
    await expect.poll(() => server.bridges.filter((b) => !b.closed).some((b) => b.acked.size > 0), { timeout: 15_000 }).toBe(true);
    await expect.poll(output, { timeout: 15_000 }).toContain("waiting-49");
    if (visibleSessions === 3) {
      await expect.poll(() => sessionOutput(sessionIds[0]!), { timeout: 15_000 }).toContain("waiting-49");
      for (const session of sessionIds.slice(1)) expect(sessionOutput(session)).not.toContain("waiting-49");
    }
    await page.locator(".terminal-host").first().click({ position: { x: 40, y: 40 } });
    await page.locator(".terminal-host textarea").first().focus();
    await page.keyboard.type("echo after-$((6*8))", { delay: 5 });
    await page.keyboard.press("Enter");
    await expect.poll(output, { timeout: 15_000 }).toContain("after-48");
    await expect(page.locator('.cl[data-view="console"] .ui-window').first()).toHaveAttribute("data-status", "live");
    // Recovery completes with the same focused input; only then exercise siblings.
    for (let i = 0; i < visibleSessions; i++) await expect(windows.nth(i)).toHaveAttribute("data-status", "live");
    if (visibleSessions === 3) for (let i = 0; i < visibleSessions; i++) {
      await windows.nth(i).locator(".terminal-host").click({ position: { x: 40, y: 40 } });
      await windows.nth(i).locator(".terminal-host textarea").focus();
      await page.keyboard.type(`echo resumed-${i}-$((30+${i}))`);
      await page.keyboard.press("Enter");
      const marker = `resumed-${i}-${30 + i}`;
      await expect.poll(() => sessionOutput(sessionIds[i]!), { timeout: 15_000 }).toContain(marker);
      for (let other = 0; other < visibleSessions; other++) if (other !== i)
        expect(sessionOutput(sessionIds[other]!)).not.toContain(marker);
    }
    if (process.env.RESTART_CAPTURE_DIR) await page.screenshot({ path: resolve(process.env.RESTART_CAPTURE_DIR, `restart-${unlock ? "unlock" : "locked"}-ready.png`) });
    if (process.env.RESTART_MEASURE === "1") {
      const probe = await page.evaluate(() => (window as unknown as { restartProbe: { liveAt: number; retained: boolean; frameMs: number } }).restartProbe);
      const recovery = Math.max(0, probe.liveAt - server.recoveredAt!);
      expect(probe.liveAt).toBeGreaterThan(0);
      const roundTrip = Number(process.env.REAL_NETWORK_RTT_MS ?? 2 * Number(process.env.REAL_ONE_WAY_MS ?? 0));
      console.log(`METRIC restart_sessions=${scale} viewport=${unlock ? "393x852" : "1440x900"} ca_after_recovery=${unlock || upstream ? "unlocked" : "locked"} mode=${upstream ?? (retainBrowserRoute ? "retained" : "closed")} transport=${process.env.REAL_NETWORK_RTT_MS ? "tcp-tls-netem" : "message-delay"} path_to_typable_ms=${recovery.toFixed(3)} rtt_ms=${roundTrip} budget_ms=${upstream ? roundTrip + 50 : roundTrip * 4 + 50} last_screen_retained=${probe.retained} screen_restore_ms=0 first_verification_frame_ms=${probe.frameMs.toFixed(3)}`);
      expect(probe.retained).toBe(true);
      expect(recovery).toBeLessThanOrEqual(upstream ? roundTrip + 50 : roundTrip * 3 + 50);
    }
  } finally { cleanupScale(); try { await server.dispose(); } finally { await context?.close(); } }
}
