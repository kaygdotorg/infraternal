/**
 * What the canvas costs with many real sessions open (#121): 54 shells in one tiled Console view on the production
 * server binary, about ten of them printing (`top -b -d 1`, a `seq` loop), the rest idle at a prompt. For each of idle,
 * typing, pan, zoom, split and a window step it records, from a trace of the renderer main thread, the CPU time it
 * spent per second (`mainCpuMsPerSec`), the longest main-frame task and the frame intervals the page saw, then
 * prints one `SCALE ...` line per scenario so a change can be compared before and after on the same host:
 *
 *   REAL_SCALE=1 REAL_SCALE_LABEL=after INFRATERNAL_BIN=... TRACER_DIST=... \
 *     bun x playwright test -c playwright.real.config.ts real/scale.spec.ts
 *
 * It runs only with `REAL_SCALE=1` (it opens 54 PTYs and takes minutes). `REAL_SCALE_N` changes the session count.
 * Times are CPU (thread time), not wall time, so a busy host moves them far less than frame intervals; the browser
 * is started with a software GPU so raster and compositing stay in-process and the numbers compare run to run.
 */
import { chromium, expect, test, type CDPSession, type Page } from "playwright/test";
import { WebSocket } from "ws";
import { WebSocketFrameDecoder, encodeMuxedFrame, type WireFrame } from "../../../packages/protocol/src/codec";
import { personName, startRealServer, type RealServer } from "./server";

const ENABLED = process.env.REAL_SCALE === "1";
/** `REAL_REMOTE_ORIGIN` + `REAL_REMOTE_TOKEN`: the server runs elsewhere (another machine, standalone TLS), the browser here. */
const REMOTE = process.env.REAL_REMOTE_ORIGIN;
/** `REAL_SCALE_GPU=1`: the browser is the new headless Chromium with the machine's GPU (no software rasteriser), and the trace adds the GPU and compositor threads. */
const GPU = process.env.REAL_SCALE_GPU === "1";
/** The shortcuts of the page's platform: the app's "mod" is Command on a Mac and Control elsewhere (and the split keys differ, see canvas/toolbar/shortcuts.ts). */
/** `REAL_SCALE_VIEW=2502x1326` sets the browser's viewport (default 1440x900; the owner's screen is 2502x1326 points at 2x). */
const [VW, VH] = (process.env.REAL_SCALE_VIEW ?? "1440x900").split("x").map(Number) as [number, number];
const VIEW = { width: VW, height: VH };
const MAC = process.platform === "darwin";
const MOD = MAC ? "Meta" : "Control";
const SPLIT_RIGHT = MAC ? "Meta+KeyD" : "Control+Shift+KeyD";
const SPLIT_DOWN = MAC ? "Meta+Shift+KeyD" : "Control+Shift+KeyE";
// Next and previous window: ⌘] and ⌘[ on a Mac, Ctrl+Shift+] and [ elsewhere (D222).
const WALK_FORWARD = MAC ? "Meta+BracketRight" : "Control+Shift+BracketRight";
const WALK_BACK = MAC ? "Meta+BracketLeft" : "Control+Shift+BracketLeft";
const N = Number(process.env.REAL_SCALE_N ?? 54);
const LABEL = process.env.REAL_SCALE_LABEL ?? "run";
test.skip(!ENABLED, "set REAL_SCALE=1 to run the many-session benchmark");
test.describe.configure({ mode: "serial" });

let server: RealServer;
let page: Page;
let close: () => Promise<void>;
/** Sessions that were told to print: stopped again at the end, because a session outlives the server's own shutdown and `top` would run on for hours. */
let printing: string[] = [];
let cookies = "";

test.beforeAll(async () => {
  if (!ENABLED) return;
  server = REMOTE
    ? { origin: REMOTE, backend: "", bridges: [], token: process.env.REAL_REMOTE_TOKEN ?? "", binary: "", dispose: async () => undefined }
    : await startRealServer({ lean: true });
  const browser = await chromium.launch(GPU
    ? { channel: "chromium", args: ["--disable-renderer-backgrounding"] }
    : { args: ["--disable-renderer-backgrounding", "--use-angle=swiftshader", "--enable-unsafe-swiftshader", "--ignore-gpu-blocklist"] });
  if (GPU) {
    const info = await (await browser.newBrowserCDPSession()).send("SystemInfo.getInfo" as never) as { gpu: { devices: Array<{ vendorString: string; deviceString: string }>; auxAttributes?: Record<string, unknown> }; featureStatus?: Record<string, unknown> };
    console.log(`GPUINFO ${JSON.stringify({ devices: info.gpu.devices.map((d) => `${d.vendorString} ${d.deviceString}`), featureStatus: info.featureStatus, glRenderer: info.gpu.auxAttributes?.glRenderer, glVendor: info.gpu.auxAttributes?.glVendor })}`);
    const probe = await browser.newPage();
    console.log(`GPUINFO webgl ${await probe.evaluate(() => { const gl = document.createElement("canvas").getContext("webgl"); const ext = gl?.getExtension("WEBGL_debug_renderer_info"); return gl && ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : "none"; })}`);
    await probe.goto("chrome://gpu").catch(() => undefined);
    await probe.waitForTimeout(2500);
    const text = await probe.evaluate(() => { const walk = (n: Node, out: string[]): void => { if (n.nodeType === 3) out.push(n.textContent ?? ""); const e = n as Element; (e.shadowRoot ? [...e.shadowRoot.childNodes] : []).forEach((c) => walk(c, out)); n.childNodes.forEach((c) => walk(c, out)); }; const o: string[] = []; walk(document.body, o); return o.join(" "); }).catch(() => "");
    console.log(`GPUINFO chrome://gpu ${(text.match(/(Canvas|Compositing|Rasterization|Video Decode|WebGL|WebGL2|WebGPU|Skia Graphite)\s*:\s*[A-Za-z ,.]+/g) ?? []).slice(0, 12).join(" | ")}`);
    await probe.close();
  }
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: VIEW, deviceScaleFactor: Number(process.env.REAL_SCALE_DPR ?? 2) });
  page = await context.newPage();
  page.on("console", (m) => { if (m.text().startsWith("CLOSE-REASON")) console.log(m.text()); });
  if (process.env.REAL_SCALE_TRACE === "1") await page.addInitScript(() => {
    const w = window as unknown as { __wsLog: string[] };
    w.__wsLog = [];
    const close = WebSocket.prototype.close;
    WebSocket.prototype.close = function (code?: number, reason?: string) { w.__wsLog.push(`client close(${code}, ${reason}) ${new Error().stack?.split("\n").slice(2, 5).map((l) => l.trim().split("/").pop()).join(" < ")}`); return close.call(this, code, reason); };
    (window as unknown as { WebSocket: unknown }).WebSocket = new Proxy(WebSocket, { construct(target, args: [string, string?]) { const ws = new target(...args); ws.addEventListener("close", (e) => { w.__wsLog.push(`closed code=${e.code} clean=${e.wasClean} reason=${e.reason}`); }); return ws; } });
  });
  close = async () => { await browser.close(); await server.dispose(); };
  await enrol(page);
});
test.afterAll(async () => {
  // Ctrl-C twice, then exit: the loops and `top` end, then the shells.
  for (const s of printing) await feed(cookies, s, "\x03\x03exit\n").catch(() => undefined);
  await close?.();
});

async function enrol(p: Page): Promise<void> {
  const cdp = await p.context().newCDPSession(p);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await p.goto(server.origin + "/?theme=ink&bg=none");
  await p.locator("#setup-token").fill(server.token);
  await p.getByRole("button", { name: "Continue", exact: true }).click();
  await p.locator("#setup-username").fill(personName("scale_real"));
  await p.locator("#setup-display-name").fill("Scale real");
  await p.getByRole("button", { name: "Continue", exact: true }).click();
  await p.getByRole("button", { name: "Create passkey" }).click();
  await p.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await p.locator(".auth-check").click();
  await p.getByRole("button", { name: "Open infraternal" }).click();
  await p.locator(".cl-viewport").waitFor();
}

const windows = (p: Page) => p.locator('.cl[data-view="console"] .ui-window');
const live = () => server.bridges.filter((b) => !b.closed);

/** Types a command into a session through a socket of its own (the window stays where it is; no camera moves). */
async function feed(cookie: string, sessionHex: string, command: string): Promise<void> {
  const socket = new WebSocket(server.backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: server.origin, Cookie: cookie } });
  const decoder = new WebSocketFrameDecoder();
  let sent = false;
  const send = (stream: number, frame: Parameters<typeof encodeMuxedFrame>[1]) => socket.send(encodeMuxedFrame(stream, frame));
  socket.on("message", (data) => decoder.feed(new Uint8Array(Buffer.from(data as Buffer)), (_s: number, frame: WireFrame) => {
    if (frame.type === "Hello") send(0, { type: "Hello", version: 1, caps: 0n, clientInfo: "scale-feed" });
    if (frame.type === "Welcome") { send(1, { type: "AttachTerm", sessionId: Buffer.from(sessionHex, "hex"), lastOutSeq: 0n, lastInSeq: 0n }); send(1, { type: "Credit", bytes: 65536 }); }
    if (frame.type === "Ack" && !sent) { sent = true; send(1, { type: "Input", inSeq: frame.inSeqAcked, bytes: Buffer.from(command) }); setTimeout(() => socket.terminate(), 300); }
  }));
  await new Promise((r) => socket.once("close", r));
}

type Ev = { name: string; ph: string; dur?: number; tdur?: number; ts: number; pid: number; tid: number; args?: Record<string, any> };
interface Stat { threads?: string; hz?: number; mainCpuMsPerSec: number; maxTaskMs: number; frames: number; p50: number; p95: number; maxInterval: number; bmfCpuP50: number; bmfCpuP95: number; top: string; extra?: unknown }
const PROFILE = process.env.REAL_SCALE_PROFILE === "1";
/** Self time per function from the sampling profiler (readable build: `TRACER_NO_MINIFY=1 bun run build`). */
async function printProfile(cdp: CDPSession, name: string, wall: number): Promise<void> {
  const { profile } = (await cdp.send("Profiler.stop")) as { profile: { nodes: Array<{ id: number; children?: number[]; callFrame: { functionName: string; url: string; lineNumber: number }; }>; samples: number[]; timeDeltas: number[] } };
  const byId = new Map(profile.nodes.map((n) => [n.id, n]));
  const self = new Map<string, number>();
  profile.samples.forEach((id, i) => { const n = byId.get(id)!; const k = `${n.callFrame.functionName || "(anon)"} ${n.callFrame.url.split("/").pop()}:${n.callFrame.lineNumber + 1}`; self.set(k, (self.get(k) ?? 0) + (profile.timeDeltas[i] ?? 0)); });
  const rows = [...self].sort((a, b) => b[1] - a[1]).slice(0, 14).map(([k, v]) => `${(v / 1000 / wall).toFixed(1)} ${k}`);
  console.log(`PROFILE ${LABEL} ${name} ms/s self: ${rows.join(" | ")}`);
  // Who calls the top native functions (a native function's own time is only useful with its callers).
  const parent = new Map<number, number>();
  for (const n of profile.nodes) for (const c of n.children ?? []) parent.set(c, n.id);
  const label = (id: number): string => { const n = byId.get(id)!; return `${n.callFrame.functionName || "(anon)"}@${n.callFrame.url.split("/").pop()}:${n.callFrame.lineNumber + 1}`; };
  const via = new Map<string, Map<string, number>>();
  profile.samples.forEach((id, i) => {
    const n = byId.get(id)!;
    if (n.callFrame.url !== "" || n.callFrame.functionName.startsWith("(")) return;
    const chain = []; let at = parent.get(id); for (let d = 0; d < 3 && at; d++, at = parent.get(at)) chain.push(label(at));
    const m = via.get(n.callFrame.functionName) ?? new Map<string, number>(); via.set(n.callFrame.functionName, m);
    const k = chain.join(" < "); m.set(k, (m.get(k) ?? 0) + (profile.timeDeltas[i] ?? 0));
  });
  for (const [fn] of [...self].filter(([k]) => /:0$/.test(k) && !k.startsWith("(")).sort((a, b) => b[1] - a[1]).slice(0, 4)) {
    const name = fn.split(" ")[0]!; const m = via.get(name); if (!m) continue;
    console.log(`CALLERS ${LABEL} ${name}: ${[...m].sort((a, b) => b[1] - a[1]).slice(0, 4).map(([k, v]) => `${(v / 1000 / wall).toFixed(1)} ${k}`).join(" || ")}`);
  }
}
const pct = (a: number[], q: number): number => { const s = [...a].sort((x, y) => x - y); return s.length ? s[Math.min(s.length - 1, Math.floor(s.length * q))]! : 0; };

/** Runs `act` while tracing and sampling frame intervals; returns the main thread's CPU and the frame picture. */
async function measure(cdp: CDPSession, name: string, act: () => Promise<void>): Promise<Stat> {
  const events: Ev[] = [];
  const onData = (e: { value: Ev[] }): void => { events.push(...e.value); };
  (cdp as unknown as { on(n: string, f: typeof onData): void }).on("Tracing.dataCollected", onData);
  await page.evaluate(() => { const w = window as unknown as { __f: number[]; __stop: boolean }; w.__f = []; w.__stop = false; let last = performance.now(); const tick = (t: number): void => { w.__f.push(t - last); last = t; if (!w.__stop) requestAnimationFrame(tick); }; requestAnimationFrame(tick); });
  if (PROFILE) { await cdp.send("Profiler.enable"); await cdp.send("Profiler.setSamplingInterval", { interval: 400 }); await cdp.send("Profiler.start"); }
  await cdp.send("Tracing.start", { categories: `toplevel,devtools.timeline,disabled-by-default-devtools.timeline${GPU ? ",cc,viz,gpu" : ""}`, transferMode: "ReportEvents" });
  const t0 = Date.now();
  const opened0 = server.bridges.length;
  await act();
  const wall = (Date.now() - t0) / 1000;
  if (PROFILE) await printProfile(cdp, name, wall);
  const done = new Promise<void>((r) => cdp.once("Tracing.tracingComplete", () => r()));
  await cdp.send("Tracing.end"); await done;
  (cdp as unknown as { off?(n: string, f: typeof onData): void }).off?.("Tracing.dataCollected", onData);
  const frames = (await page.evaluate(() => { const w = window as unknown as { __f: number[]; __stop: boolean }; w.__stop = true; return w.__f.slice(2); }));
  const names: Record<string, string> = {};
  for (const e of events) if (e.ph === "M" && e.name === "thread_name") names[`${e.pid}:${e.tid}`] = e.args!.name;
  const isMain = (e: Ev): boolean => names[`${e.pid}:${e.tid}`] === "CrRendererMain";
  const D = (e: Ev): number => (e.tdur ?? e.dur ?? 0) / 1000;
  const tasks = events.filter((e) => e.ph === "X" && isMain(e) && e.name === "RunTask");
  const bmf = events.filter((e) => e.ph === "X" && isMain(e) && e.name === "ProxyMain::BeginMainFrame").map(D);
  const agg: Record<string, number> = {};
  for (const e of events) if (e.ph === "X" && isMain(e) && e.name !== "RunTask" && e.name !== "ThreadControllerImpl::RunTask") {
    const fn = e.args?.data?.functionName ? `${e.name}:${String(e.args.data.functionName).slice(0, 30)}@${String(e.args.data.url ?? "").split("/").pop()}:${e.args.data.lineNumber ?? ""}` : e.name;
    agg[fn] = (agg[fn] ?? 0) + D(e);
  }
  const top = Object.entries(agg).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => `${k} ${(v / wall).toFixed(1)}`).join(" | ");
  const stat: Stat = {
    mainCpuMsPerSec: +(tasks.reduce((a, e) => a + D(e), 0) / wall).toFixed(1), maxTaskMs: +Math.max(0, ...tasks.map(D)).toFixed(1),
    frames: frames.length, p50: +pct(frames, 0.5).toFixed(1), p95: +pct(frames, 0.95).toFixed(1), maxInterval: +Math.max(0, ...frames).toFixed(1),
    bmfCpuP50: +pct(bmf, 0.5).toFixed(1), bmfCpuP95: +pct(bmf, 0.95).toFixed(1), top,
  };
  if (GPU) {
    // Where the work went: CPU per second on each thread (the page's main thread, the compositor, the GPU process, raster workers).
    const busy: Record<string, number> = {};
    for (const e of events) if (e.ph === "X" && e.name === "ThreadControllerImpl::RunTask") { const n = names[`${e.pid}:${e.tid}`] ?? "?"; busy[n] = (busy[n] ?? 0) + D(e); }
    stat.threads = Object.entries(busy).filter(([, v]) => v / wall > 1).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => `${k} ${(v / wall).toFixed(0)}`).join(" | ");
    stat.hz = +(1000 / (stat.p50 || 16.7)).toFixed(0);
    // What the GPU process, the compositor and the raster workers spent their time on (the leaf-most events, by name).
    const per: Record<string, Record<string, number>> = {};
    const cnt: Record<string, number> = {};
    for (const e of events) if (e.ph === "X" && e.name !== "ThreadControllerImpl::RunTask" && e.name !== "RunTask" && (e.tdur ?? e.dur ?? 0) > 0) {
      const n = names[`${e.pid}:${e.tid}`] ?? "?"; const grp = /Gpu|Viz|Compositor|Raster|TileWorker/.test(n) ? n.replace(/\d+$/, "") : "";
      if (!grp) continue;
      (per[grp] ??= {})[e.name] = ((per[grp] ??= {})[e.name] ?? 0) + D(e);
      if (e.name === "RasterTask" || e.name === "DrawFrame" || e.name === "Display::DrawAndSwap") cnt[e.name] = (cnt[e.name] ?? 0) + 1;
    }
    (stat as Stat & { gpuTop?: string }).gpuTop = Object.entries(per).map(([g, m]) => `${g}: ${Object.entries(m).filter(([k]) => !/^(Scheduler::|GpuChannel|GPUTask|CommandBuffer|Graphics.Pipeline|DisplayScheduler|Display::|ProxyImpl|MainFrame)/.test(k)).sort((a, b) => b[1] - a[1]).slice(0, 9).map(([k, v]) => `${k.slice(0, 56)} ${(v / wall).toFixed(0)}`).join(", ")}`).join(" || ") + ` || counts ${JSON.stringify(cnt)}`;
  }
  stat.extra = { socketsOpened: server.bridges.length - opened0, closedBy: server.bridges.slice(opened0).map((b) => `${b.closedBy ?? (b.closed ? "?" : "open")} ${b.serverClose ?? ""}`.trim()) };
  console.log(`SCALE ${LABEL} n=${N} ${name} ${JSON.stringify(stat)}`);
  return stat;
}

const wheelDrive = (opts: (ph: number) => Record<string, unknown>, ms = 2000) => page.evaluate(({ f, ms: d }) => new Promise<void>((done) => {
  const target = document.querySelector(".cl-viewport")!;
  const s0 = performance.now();
  const fn = new Function("ph", `return (${f})(ph)`) as (ph: number) => Record<string, unknown>;
  const step = (t: number): void => { const ph = (t - s0) / d; if (ph >= 1) { done(); return; } target.dispatchEvent(new WheelEvent("wheel", { bubbles: true, cancelable: true, clientX: 720, clientY: 450, ...fn(ph) })); requestAnimationFrame(step); };
  requestAnimationFrame(step);
}), { f: opts.toString(), ms });

test(`${N} real sessions: what scales with the session count`, async () => {
  test.setTimeout(30 * 60_000);
  const split = (d: string) => page.evaluate((dir) => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: `canvas:split:${dir}`, source: "pointer" } })), d);
  for (let i = 0; i < N * 3 && (await windows(page).count()) < N; i++) {
    const before = await windows(page).count();
    await split(i % 4 === 3 ? "right" : "down");
    await expect.poll(() => windows(page).count(), { timeout: 20_000 }).toBeGreaterThan(before);
    await page.waitForTimeout(150);
  }
  await expect(windows(page)).toHaveCount(N);
  await page.waitForTimeout(Number(process.env.REAL_SCALE_SETTLE_MS ?? 20_000));
  // About one session in five prints: half `top -b -d 1`, half a seq loop. The commands are typed into the windows
  // themselves, stepping from window to window with the keyboard. (A second socket that attaches the same sessions
  // from outside makes the server end the page's own socket, over and over: it is not what a person does.)
  const index = (): Promise<number> => page.evaluate(() => [...document.querySelectorAll('.cl[data-view="console"] .ui-window')].findIndex((w) => w.hasAttribute("data-active")));
  const typed = new Set<number>();
  let printers = 0;
  if (process.env.REAL_SCALE_NOFEED !== "1") {
    for (let step = 0; step < N + 2; step++) {
      const at = await index();
      if (process.env.REAL_SCALE_DEBUG === "1") console.log(`step ${step} at ${at}`);
      if (at >= 0 && at % 5 === 2 && !typed.has(at)) { typed.add(at); await page.keyboard.type((printers++ % 2 ? "top -b -d 1" : "while :; do seq 1 40; sleep 1; done") + "\n", { delay: 2 }); }
      await page.keyboard.press(WALK_BACK); // the last window is active: walk back
      await page.waitForTimeout(260);
    }
  }
  const cookie = (await page.context().cookies()).map((c) => `${c.name}=${c.value}`).join("; ");
  const sessions = [...new Set(server.bridges.flatMap((b) => [...b.attached.values()].flat()))];
  printing = sessions; cookies = cookie; // every session is stopped at the end (cheap, and no shell is left behind)
  await page.waitForTimeout(3000);
  if (process.env.REAL_SCALE_CSS) await page.addStyleTag({ content: process.env.REAL_SCALE_CSS }); // an experiment: take a look away and see what the zoom stops costing
  const cdp = await page.context().newCDPSession(page);
  const results: Record<string, Stat> = {};
  const status: Record<string, number> = {};
  for (const w of await page.locator('.cl[data-view="console"] .ui-window').all()) { const st = (await w.getAttribute("data-status")) ?? "?"; status[st] = (status[st] ?? 0) + 1; }
  console.log(`SCALE ${LABEL} n=${N} sockets ${JSON.stringify({ opened: server.bridges.length, open: live().length, status, attachedPerSocket: server.bridges.map((b) => [...b.attached.keys()].length) })}`);
  const info = await page.evaluate(() => ({ windows: document.querySelectorAll(".ui-window").length, canvases: document.querySelectorAll("canvas").length, nodes: document.querySelectorAll("*").length }));
  console.log(`SCALE ${LABEL} n=${N} setup ${JSON.stringify({ ...info, printers, load: (await import("node:os")).loadavg()[0] })}`);

  const only = (process.env.REAL_SCALE_ONLY ?? "").split(",").filter(Boolean);
  const want = (n: string): boolean => only.length === 0 || only.includes(n);
  if (want("idle")) results.idle = await measure(cdp, "idle", () => page.waitForTimeout(6000));

  // Keystroke to paint: the browser's own Event Timing duration for each keydown (processing, then the next paint).
  await page.evaluate(() => { const w = window as unknown as { __kd: number[] }; w.__kd = []; new PerformanceObserver((l) => { for (const e of l.getEntries()) if (e.name === "keydown") w.__kd.push(e.duration); }).observe({ type: "event", durationThreshold: 16, buffered: false } as PerformanceObserverInit); });
  if (want("typing")) results.typing = await measure(cdp, "typing", async () => { await page.keyboard.type("echo scale-typing-0123456789", { delay: 60 }); await page.waitForTimeout(300); });
  const kd = await page.evaluate(() => (window as unknown as { __kd: number[] }).__kd);
  console.log(`SCALE ${LABEL} n=${N} typing-keydown-event-durations ${JSON.stringify({ n: kd.length, p50: pct(kd, 0.5), max: Math.max(0, ...kd) })}`);

  await page.keyboard.press(`${MOD}+Shift+G`); // canvas lock off: free pan and zoom
  await page.waitForTimeout(600);
  if (want("pan")) results.pan = await measure(cdp, "pan", () => wheelDrive((ph) => ({ deltaX: (ph < 0.5 ? -1 : 1) * 24, deltaY: (ph < 0.5 ? -1 : 1) * 9 })));
  await page.waitForTimeout(500);
  if (process.env.REAL_SCALE_ZOOM_PRE) await page.evaluate(process.env.REAL_SCALE_ZOOM_PRE); // an experiment hook: runs just before the zoom is measured
  if (want("zoom")) results.zoom = await measure(cdp, "zoom", () => wheelDrive((ph) => ({ deltaY: (ph < 0.5 ? 1 : -1) * 14, ctrlKey: true })));
  await page.waitForTimeout(500);
  await page.keyboard.press(`${MOD}+Shift+G`);
  await page.waitForTimeout(800);
  if (want("step")) results.step = await measure(cdp, "window-step", async () => { for (let i = 0; i < 6; i++) { await page.keyboard.press(WALK_FORWARD); await page.waitForTimeout(450); } });
  if (want("split")) results.split = await measure(cdp, "split", async () => { for (let i = 0; i < 3; i++) { await page.keyboard.press(i % 2 ? SPLIT_DOWN : SPLIT_RIGHT); await page.waitForTimeout(1000); } });
  if (process.env.REAL_SCALE_TRACE === "1") { const log = await page.evaluate(() => (window as unknown as { __wsLog: string[] }).__wsLog); const tally: Record<string, number> = {}; for (const l of log) tally[l] = (tally[l] ?? 0) + 1; console.log(`WSLOG ${JSON.stringify(Object.entries(tally).sort((a, b) => b[1] - a[1]).slice(0, 12))}`); }
  expect(Object.keys(results)).toHaveLength(only.length || 6);
});
