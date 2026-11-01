/** Records the machine pill state during 9 Hz redraws from a shell in the real server's PTY. */
import { expect, test, type BrowserContext, type CDPSession, type Locator, type Page } from "playwright/test";
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { startRealServer, type RealServer } from "./server";

let server: RealServer;
let context: BrowserContext;
let page: Page;
let workloadLaunchDir: string | undefined;
let recording: { cdp: CDPSession; frames: Array<{ at: number; data: Buffer }>; startedAt: number; host: Locator; previousFilter: string; path: string } | undefined;

async function startScreenRecording(host: Locator, path: string, redact: boolean): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const handle = await host.elementHandle();
  if (!handle) throw new Error("terminal host is missing for screen recording");
  const previousFilter = await handle.evaluate((element) => (element as HTMLElement).style.filter);
  if (redact) await handle.evaluate((element) => { (element as HTMLElement).style.filter = "blur(20px)"; });
  const cdp = await context.newCDPSession(page);
  const frames: Array<{ at: number; data: Buffer }> = [];
  const startedAt = performance.now();
  cdp.on("Page.screencastFrame", ({ data, sessionId }) => {
    frames.push({ at: performance.now(), data: Buffer.from(data, "base64") });
    void cdp.send("Page.screencastFrameAck", { sessionId }).catch(() => {});
  });
  await cdp.send("Page.startScreencast", { format: "jpeg", quality: 80, maxWidth: 1440, maxHeight: 900 });
  recording = { cdp, frames, startedAt, host, previousFilter, path };
}

async function stopScreenRecording(): Promise<void> {
  const current = recording;
  recording = undefined;
  if (!current) return;
  await current.cdp.send("Page.stopScreencast").catch(() => {});
  await current.cdp.detach().catch(() => {});
  await current.host.evaluate((element, filter) => { (element as HTMLElement).style.filter = filter; }, current.previousFilter).catch(() => {});
  if (current.frames.length === 0) throw new Error("browser did not capture screen frames");
  if ((current.frames.at(-1)?.at ?? current.startedAt) - current.startedAt < 10_000) {
    throw new Error("screen recording was shorter than 10 seconds");
  }
  const ffmpeg = spawn("ffmpeg", [
    "-y", "-hide_banner", "-loglevel", "error", "-f", "image2pipe", "-framerate", "30", "-vcodec", "mjpeg",
    "-i", "pipe:0", "-t", "10", "-an", "-c:v", "libx264", "-preset", "veryfast", "-crf", "24",
    "-pix_fmt", "yuv420p", "-movflags", "+faststart", current.path,
  ], { stdio: ["pipe", "ignore", "pipe"] });
  let errorOutput = "";
  ffmpeg.stderr?.on("data", (chunk: Buffer) => { errorOutput = (errorOutput + chunk.toString("utf8")).slice(-500); });
  const finished = new Promise<number>((resolve, reject) => {
    ffmpeg.once("error", reject);
    ffmpeg.once("close", (code) => resolve(code ?? 1));
  });
  // Sample by capture time so a high-rate screencast still spans the full workload.
  let captureIndex = 0;
  for (let frameIndex = 0; frameIndex < 300; frameIndex += 1) {
    const targetAt = current.startedAt + frameIndex * (1000 / 30);
    while (captureIndex + 1 < current.frames.length && current.frames[captureIndex + 1]!.at <= targetAt) captureIndex += 1;
    const frame = current.frames[captureIndex] ?? current.frames[0]!;
    if (!ffmpeg.stdin?.write(frame.data)) await new Promise<void>((resolve) => ffmpeg.stdin?.once("drain", resolve));
  }
  ffmpeg.stdin?.end();
  const exitCode = await finished;
  current.frames.length = 0;
  if (exitCode !== 0) throw new Error(`screen video encoding failed (${exitCode}): ${errorOutput}`);
}

test.beforeAll(async ({ browser }) => {
  server = await startRealServer({ systemd: false });
  context = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 900 },
  });
  await context.addInitScript(() => {
    const calls: Array<{ at: number; socketId: number; path: string; readyState: number; code?: number; reason?: string }> = [];
    (window as unknown as { __machinePillSocketCloses: typeof calls }).__machinePillSocketCloses = calls;
    const ids = new WeakMap<WebSocket, number>();
    let nextId = 0;
    const NativeWebSocket = window.WebSocket;
    window.WebSocket = new Proxy(NativeWebSocket, {
      construct(target, args, newTarget) {
        const socket = Reflect.construct(target, args, newTarget) as WebSocket;
        if (new URL(String(args[0]), location.href).pathname === "/v1/ws") ids.set(socket, ++nextId);
        return socket;
      },
    });
    const close = NativeWebSocket.prototype.close;
    NativeWebSocket.prototype.close = function (code?: number, reason?: string): void {
      const path = new URL(this.url).pathname;
      if (path === "/v1/ws") calls.push({ at: Date.now(), socketId: ids.get(this) ?? 0, path, readyState: this.readyState, ...(code === undefined ? {} : { code }), ...(reason === undefined ? {} : { reason }) });
      close.apply(this, arguments as [number?, string?]);
    };
  });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      hasPrf: true,
    },
  });
  await page.goto(server.origin + "/");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill("pill_flicker");
  await page.locator("#setup-display-name").fill("Pill Flicker");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
});

test.afterAll(async () => {
  await stopScreenRecording();
  await context?.close();
  await server?.dispose();
  if (workloadLaunchDir) await rm(workloadLaunchDir, { recursive: true, force: true });
});

test("machine pill state stays tied to the session connection during PTY redraws", async () => {
  const windowCard = page.locator('.cl[data-view="console"] .ui-window').first();
  await expect(windowCard).toBeVisible();
  await expect(windowCard).toHaveAttribute("data-status", "live", { timeout: 30_000 });
  // Account setup swaps the bootstrap socket for the regular session socket. Do not count that startup handoff as
  // a redraw-induced pill transition.
  await page.waitForTimeout(3_500);
  const redrawScript = [
    "i=0",
    "printf '\\033[?1049h\\033[?25l\\033[?2004h\\033[?1004h'",
    "while [ \"$i\" -lt 90 ]; do",
    "  printf '\\033[?2026h\\033[H\\033[2J'",
    "  row=1",
    "  while [ \"$row\" -le 24 ]; do",
    "    printf '\\033[%s;1H%-80s' \"$row\" \"terminal sign-in frame $i row $row\"",
    "    row=$((row + 1))",
    "  done",
    "  printf '\\033]0;sign-in-%s\\007\\033[?2026l' \"$i\"",
    "  sleep 0.111",
    "  i=$((i + 1))",
    "done",
    "printf '\\033[?2026l\\033[?25h\\033[?1049l\\033[?2004l\\033[?1004l'",
  ].join("\n");
  const workloadScript = process.env.PILL_FLICKER_SCRIPT
    ? await readFile(process.env.PILL_FLICKER_SCRIPT, "utf8")
    : redrawScript;
  const scriptedWorkload = process.env.PILL_FLICKER_SCRIPT !== undefined;
  const workloadPath = join(server.dataDir, "pill-redraw.sh");
  const runnerPath = join(server.dataDir, "run-pill-redraw.sh");
  await writeFile(workloadPath, workloadScript, { mode: 0o700 });
  const quotedWorkloadPath = `'${workloadPath.replaceAll("'", "'\\''")}'`;
  await writeFile(runnerPath, `#!/bin/sh\nprintf '\\r\\nPILL_STAGE:workload-start\\r\\n'\nsh ${quotedWorkloadPath}\nresult=$?\nprintf '\\r\\nPILL_STAGE:workload-finished\\r\\n'\nprintf '\\r\\nPILL_FLICKER_WORKLOAD_DONE:%s\\r\\n' "$result"\n`, { mode: 0o700 });
  await chmod(workloadPath, 0o700);
  await chmod(runnerPath, 0o700);
  // Keep terminal keystrokes below the 250 ms proof lease; the long script path is executed by the shell.
  workloadLaunchDir = await mkdtemp(join(tmpdir(), "pf-"));
  await symlink(runnerPath, join(workloadLaunchDir, "r"));
  const traceDuration = Number(process.env.PILL_FLICKER_TRACE_MS ?? "10500");
  await page.evaluate((durationMs) => {
    const root = document.querySelector<HTMLElement>('.cl[data-view="console"] .ui-window');
    const dot = root?.querySelector<HTMLElement>(".ui-window-conn");
    if (!root || !dot) throw new Error("machine pill is missing");
    const trace = {
      epoch: Date.now(),
      startedAt: performance.now(),
      mutations: [] as Array<{ at: number; attribute: string; old: string | null; next: string | null }>,
      frames: [] as Array<{ at: number; state: string | undefined; color: string; classes: string }>,
    };
    const observer = new MutationObserver((records) => {
      const relevant = records.filter((record) =>
        (record.target === root && record.attributeName === "data-status")
        || (record.target === dot && record.attributeName === "class"));
      for (let index = 0; index < relevant.length; index += 1) {
        const record = relevant[index];
        if (!record) continue;
        const nextRecord = relevant.slice(index + 1).find((next) => next.target === record.target && next.attributeName === record.attributeName);
        const next = nextRecord?.oldValue ?? (record.target as Element).getAttribute(record.attributeName ?? "");
        if (record.oldValue !== next) {
          trace.mutations.push({ at: performance.now() - trace.startedAt, attribute: record.attributeName ?? "", old: record.oldValue, next });
        }
      }
    });
    observer.observe(root, { attributes: true, attributeOldValue: true, subtree: true });
    const startedAt = trace.startedAt;
    const sample = (): void => {
      trace.frames.push({ at: performance.now() - startedAt, state: root.dataset.status, color: getComputedStyle(dot).backgroundColor, classes: dot.className });
      if (performance.now() - startedAt < durationMs) requestAnimationFrame(sample);
      else observer.disconnect();
    };
    requestAnimationFrame(sample);
    (window as unknown as { __machinePillTrace: typeof trace }).__machinePillTrace = trace;
  }, traceDuration);

  const terminal = windowCard.locator(".terminal-host");
  await terminal.click({ position: { x: 40, y: 40 } });
  const measureMainThread = process.env.PILL_FLICKER_COST === "1";
  const costSession = measureMainThread ? await page.context().newCDPSession(page) : undefined;
  if (costSession) await costSession.send("Performance.enable");
  const readTaskDuration = async (): Promise<number> => {
    if (!costSession) return 0;
    const { metrics } = await costSession.send("Performance.getMetrics");
    const taskDuration = metrics.find((metric: { name: string }) => metric.name === "TaskDuration");
    if (!taskDuration) throw new Error("browser did not report main-thread task duration");
    return taskDuration.value;
  };
  const taskDurationBefore = await readTaskDuration();
  const outputFramesBefore = server.bridges.reduce((sum, bridge) => sum + (bridge.outputTimes?.length ?? 0), 0);
  const videoPath = process.env.PILL_FLICKER_VIDEO_PATH;
  if (videoPath) await startScreenRecording(terminal, videoPath, scriptedWorkload);
  await page.keyboard.type(`sh ${join(workloadLaunchDir, "r")}\n`);
  if (scriptedWorkload && process.env.PILL_FLICKER_INTERRUPT === "1") {
    await page.waitForTimeout(Number(process.env.PILL_FLICKER_HOLD_MS ?? "3000"));
    await page.keyboard.press("Control+C");
  }
  await expect.poll(() => [...server.bridges].flatMap((bridge) => [...bridge.output.values()]).join("").includes("PILL_FLICKER_WORKLOAD_DONE:"), { timeout: 20_000 }).toBe(true);
  if (costSession) {
    await page.evaluate(() => new Promise<void>((resolve) => {
      let frames = 0;
      const flush = (): void => { if (++frames === 3) resolve(); else requestAnimationFrame(flush); };
      requestAnimationFrame(flush);
    }));
    const taskDurationAfter = await readTaskDuration();
    const outputFramesAfter = server.bridges.reduce((sum, bridge) => sum + (bridge.outputTimes?.length ?? 0), 0);
    const outputFrames = outputFramesAfter - outputFramesBefore;
    // The perf runner aggregates several identical trials to reach 1,000 output frames per build.
    if (outputFrames < 100) throw new Error(`workload produced only ${outputFrames} timed output frames`);
    const taskMs = (taskDurationAfter - taskDurationBefore) * 1000;
    console.log(`PILL_MAIN_THREAD outputFrames=${outputFrames} taskMs=${taskMs.toFixed(3)} msPer1000=${(taskMs * 1000 / outputFrames).toFixed(3)}`);
    await costSession.detach();
  }
  await page.waitForTimeout(400);
  await stopScreenRecording();

  const trace = await page.evaluate(() => (window as unknown as { __machinePillTrace: { epoch: number; mutations: Array<{ at: number; attribute: string; old: string | null; next: string | null }>; frames: Array<{ at: number; state: string | undefined; color: string; classes: string }> } }).__machinePillTrace);
  const streamEvidence = server.bridges.map((bridge) => ({
    id: bridge.id,
    closed: bridge.closed,
    closedBy: bridge.closedBy,
    closedReason: bridge.closedReason,
    closedAt: bridge.closedAt === undefined ? undefined : bridge.closedAt - trace.epoch,
    serverClose: bridge.serverClose,
    attaches: [...bridge.attached].map(([stream, sessions]) => ({ stream, count: sessions.length })),
    attachTimes: bridge.attachTimes?.map((entry) => ({ ...entry, at: entry.at - trace.epoch })),
    attachCursors: bridge.attachCursors?.map((entry) => ({ ...entry, at: entry.at - trace.epoch })),
    terminalEvents: bridge.terminalEvents?.map((entry) => ({ ...entry, at: entry.at - trace.epoch })),
    terminalCloses: bridge.terminalCloses?.map((entry) => ({ ...entry, at: entry.at - trace.epoch })),
    markers: bridge.markers?.map((entry) => ({ ...entry, at: entry.at - trace.epoch })),
    replays: bridge.replays,
    outputRanges: bridge.outputRanges?.map((entry) => ({ ...entry, at: entry.at - trace.epoch })),
    outputTimes: bridge.outputTimes?.map((at) => at - trace.epoch).filter((at) => at >= 0 && at <= traceDuration),
  }));
  const output = [...server.bridges].flatMap((bridge) => [...bridge.output.values()]).join("");
  const count = (pattern: RegExp): number => [...output.matchAll(pattern)].length;
  const controls = {
    bytes: new TextEncoder().encode(output).byteLength,
    altScreen: count(/\x1b\[\?1049[hl]/g),
    cursorVisibility: count(/\x1b\[\?25[hl]/g),
    bracketedPaste: count(/\x1b\[\?2004[hl]/g),
    focusReporting: count(/\x1b\[\?1004[hl]/g),
    synchronizedOutput: count(/\x1b\[\?2026[hl]/g),
    oscTitle: count(/\x1b\](?:0|2);/g),
    osc8Hyperlink: count(/\x1b\]8;;/g),
    primaryDeviceAttributes: count(/\x1b\[c/g),
    secondaryDeviceAttributes: count(/\x1b\[>c/g),
    deviceStatusReports: count(/\x1b\[[56]n/g),
    versionQueries: count(/\x1b\[>q/g),
    keyboardProtocolQueries: count(/\x1b\[\?u/g),
    graphicsProtocolQueries: count(/\x1b_G/g),
    clearScreen: count(/\x1b\[[0-9;?]*2J/g),
    cursorAddress: count(/\x1b\[[0-9;]*H/g),
  };
  const workloadExitCode = output.match(/PILL_FLICKER_WORKLOAD_DONE:(\d+)/)?.[1];
  const clientSocketCloses = await page.evaluate(() => (window as unknown as { __machinePillSocketCloses: Array<{ at: number; path: string; readyState: number; code?: number; reason?: string }> }).__machinePillSocketCloses);
  const workloadMarkers = streamEvidence.flatMap((bridge) => bridge.markers ?? []);
  const workloadStart = workloadMarkers.find((marker) => marker.name === "workload-start");
  const workloadEnd = workloadMarkers.find((marker) => marker.name === "workload-finished");
  expect(workloadStart).toBeDefined();
  expect(workloadEnd).toBeDefined();
  const mutationsDuringWorkload = trace.mutations.filter((mutation) => mutation.attribute === "data-status"
    && mutation.at >= workloadStart!.at && mutation.at <= workloadEnd!.at);
  const closesDuringWorkload = clientSocketCloses.filter((close) => {
    const at = close.at - trace.epoch;
    return at >= workloadStart!.at && at <= workloadEnd!.at;
  }).map((close) => ({ ...close, at: close.at - trace.epoch }));
  const serverClosesDuringWorkload = streamEvidence.filter((bridge) => bridge.closedAt !== undefined
    && bridge.closedAt >= workloadStart!.at && bridge.closedAt <= workloadEnd!.at)
    .map((bridge) => ({ id: bridge.id, at: bridge.closedAt, closedBy: bridge.closedBy, reason: bridge.closedReason }));
  const framesDuringWorkload = trace.frames.filter((frame) => frame.at >= workloadStart!.at && frame.at <= workloadEnd!.at);
  const colorsDuringWorkload = [...new Set(framesDuringWorkload.map((frame) => frame.color))];
  console.log(`PILL_TRACE real epoch=${trace.epoch} workload=${JSON.stringify({ start: workloadStart, end: workloadEnd, statusMutations: mutationsDuringWorkload, frameSamples: framesDuringWorkload.length, colors: colorsDuringWorkload, clientSocketCloses: closesDuringWorkload, serverSocketCloses: serverClosesDuringWorkload })} mutations=${JSON.stringify(trace.mutations)} frames=${JSON.stringify(trace.frames)} controls=${JSON.stringify(controls)} workloadExit=${workloadExitCode ?? "n/a"} clientSocketCloses=${JSON.stringify(clientSocketCloses.map((close) => ({ ...close, at: close.at - trace.epoch })))} streams=${JSON.stringify(streamEvidence)}`);
  expect(framesDuringWorkload.length).toBeGreaterThan(100);
  expect(mutationsDuringWorkload).toHaveLength(0);
  expect(closesDuringWorkload).toHaveLength(0);
  expect(serverClosesDuringWorkload).toHaveLength(0);
  if (!scriptedWorkload) {
    expect(controls.altScreen).toBeGreaterThan(0);
    expect(controls.cursorVisibility).toBeGreaterThan(0);
    expect(controls.clearScreen).toBeGreaterThan(0);
    expect(controls.cursorAddress).toBeGreaterThan(0);
    expect(controls.oscTitle).toBeGreaterThanOrEqual(90);
  }
  await expect(windowCard).toHaveAttribute("data-status", "live");
});
