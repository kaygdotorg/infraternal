/**
 * TEST DOUBLE: a Mac that streams app windows, for the tracer's browser checks (D208). It is the machine side of
 * contracts/wire.md section 9 and of the `desktop.*` actions, behind `TRACER_DOUBLE_APPWIN=1`; without that variable
 * the double behaves exactly as before and the server Hello advertises nothing.
 *
 * What it does, honestly: it lists a few generic windows and a display, starts a session per request, and streams a
 * looping Annex-B H.264 picture (apps rendered by `appwin/render-fixtures.mjs`) at the rate the test asks for, with
 * a keyframe every half second, repair on request, a wide or a tall variant chosen from the size the page asked for,
 * and the sequence rules of the real server. It records every size and input it receives, so a check can assert what
 * reached "the machine". It does not capture, resize or inject anything.
 *
 * Controls for checks: `/__mock/appwin/state` (read what the machine saw), `/__mock/appwin/config` (rate, windows,
 * permissions, view-only rights, local-input pause) and `/__mock/appwin/end` (the app closes).
 */
import { randomUUID } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { WebSocket } from "ws";
import { encodeMuxedFrame, type WireFrame } from "../../../packages/protocol/src/codec";
import type { VideoInput } from "../../../packages/protocol/src/desktop";
import { FORMAT, VERSION, parseDocument, type CanvasDocument } from "../src/canvas/model/schema";
import { reduce } from "../src/canvas/model/reducer";
import type { Intent } from "../src/canvas/model/operations";

export const appwinEnabled = process.env.TRACER_DOUBLE_APPWIN === "1";
const FIXTURES = process.env.APPWIN_FIXTURE_DIR ?? join(homedir(), ".cache/codex-scratch/ui-app-windows/fixtures");
const text = (value: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(value));

// A production canvas requires its ordinary account layout subscription. Reuse
// the actual reducer; this fixture supplies receipts, never a second layout engine.
let layout: CanvasDocument = { format: FORMAT, version: VERSION, revision: 0, views: [] };
let layoutInitialized = false;
const layoutSubscribers = new Map<WebSocket, Set<number>>();
const layoutReceipts = new Map<string, number>();
function layoutSnapshot(): Record<string, unknown> {
  return { type: "canvas.layout.snapshot", initialized: layoutInitialized, revision: layout.revision, document: layout };
}
function publishLayout(event: Record<string, unknown>): void {
  for (const [socket, subscriptions] of layoutSubscribers) for (const subId of subscriptions) {
    if (socket.readyState === 1) socket.send(encodeMuxedFrame(0, { type: "Event", subId, eventJson: text(event) }));
  }
}
export function appwinLayoutFrame(socket: WebSocket, frame: WireFrame): boolean {
  if (!appwinEnabled) return false;
  if (frame.type === "Subscribe" && JSON.parse(new TextDecoder().decode(frame.filterJson))?.topic === "canvas.layout") {
    const subscriptions = layoutSubscribers.get(socket) ?? new Set<number>();
    subscriptions.add(frame.subId); layoutSubscribers.set(socket, subscriptions);
    socket.send(encodeMuxedFrame(0, { type: "Event", subId: frame.subId, eventJson: text(layoutSnapshot()) }));
    return true;
  }
  if (frame.type !== "Call" || !["canvas.layout.initialize", "canvas.layout.apply"].includes(frame.actionId)) return false;
  const input = JSON.parse(new TextDecoder().decode(frame.inputJson)) as { op_id: string; document?: unknown; intent: Intent };
  let revision = layoutReceipts.get(input.op_id);
  if (revision === undefined) {
    if (frame.actionId === "canvas.layout.initialize") {
      const document = parseDocument(input.document);
      if (!document) throw Error("invalid test canvas document");
      layout = { ...document, revision: layout.revision + 1 }; layoutInitialized = true;
      publishLayout(layoutSnapshot());
    } else {
      reduce(layout, input.intent); layout.revision++;
      publishLayout({ type: "canvas.layout.operation", revision: layout.revision, op_id: input.op_id, intent: input.intent, noop: false });
    }
    revision = layout.revision; layoutReceipts.set(input.op_id, revision);
  }
  socket.send(encodeMuxedFrame(0, { type: "Result", callId: frame.callId, ok: true, json: text({ revision }) }));
  return true;
}

export const MAC_HOST_ID = "11111111-1111-4111-8111-111111111111";
const LINUX_HOST_ID = "22222222-2222-4222-8222-222222222222";
export const appwinHosts = (): unknown[] => appwinEnabled ? [
  { id: MAC_HOST_ID, name: "studio-mac", online: true, user: "kayg", os: "macOS 15.1" },
  { id: LINUX_HOST_ID, name: "build-01", online: true, user: "kayg", os: "Ubuntu 24.04" },
] : [];

interface Win { window_id: number; owner_pid: number; app_name: string; title: string; bundle_id: string; layer: number; frame: [number, number, number, number]; on_screen: boolean; app: string }
const defaults = (): Win[] => [
  { window_id: 101, owner_pid: 501, app_name: "Notebook", title: "Today", bundle_id: "test.notebook", layer: 0, frame: [40, 60, 900, 640], on_screen: true, app: "notebook" },
  { window_id: 102, owner_pid: 501, app_name: "Notebook", title: "Ideas", bundle_id: "test.notebook", layer: 0, frame: [90, 100, 900, 640], on_screen: true, app: "notebook" },
  { window_id: 201, owner_pid: 502, app_name: "Editor", title: "stream.ts", bundle_id: "test.editor", layer: 0, frame: [120, 80, 1100, 760], on_screen: true, app: "editor" },
  { window_id: 301, owner_pid: 503, app_name: "Browser", title: "Getting started", bundle_id: "test.browser", layer: 0, frame: [60, 40, 1200, 800], on_screen: true, app: "browser" },
  { window_id: 302, owner_pid: 503, app_name: "Browser", title: "", bundle_id: "test.browser", layer: 0, frame: [60, 40, 1200, 800], on_screen: false, app: "browser" },
  { window_id: 9, owner_pid: 1, app_name: "Window Server", title: "Menubar", bundle_id: "", layer: 25, frame: [0, 0, 2560, 30], on_screen: true, app: "screen" },
];

const config = {
  fps: 60,
  windows: defaults(),
  screenRecording: true,
  accessibility: true,
  viewOnly: false,
  /** Enforce the real server resize lease and metadata/native-status split. */
  controlContract: true,
  /** Remote input waits this long (the machine's local-input rule, D208 A3); the status reply reports it once. */
  inputPauseMs: 0,
  /** The next start is refused (the machine did not answer), once. */
  refuseNextStart: false,
  /** The answer to `desktop.windows` is delayed by this long. */
  windowsDelayMs: 0,
  /** The answer to `desktop.session.start` is delayed by this long (the connecting state). */
  startDelayMs: 0,
  /** The first viewer gets a delta instead of the startup IDR; its repair gets the IDR. */
  dropInitialKeyframe: false,
  /**
   * The machine's window keeps its own size (a window manager owns it, or it refuses a size): status replies report this
   * capture rectangle with reason "managed". Unset, they report no rectangle, as before.
   */
  windowShape: undefined as { width: number; height: number } | undefined,
};

interface Session { id: string; target: { type: "window"; window_id: number; owner_pid: number } | { type: "screen"; display_id: number }; app: string; width: number; height: number; density: number; controller?: { socket: WebSocket; stream: number }; viewers: Set<Viewer>; startedAt: number }
interface Viewer { socket: WebSocket; stream: number; session: Session; sequence: bigint; index: number; timer: ReturnType<typeof setInterval> | undefined; variant: string; sent: number; startupFaultPending: boolean }
const sessions = new Map<string, Session>();
const inputs: Array<{ session: string; stream: number; input: VideoInput }> = [];
const sizes: Array<{ session: string; width: number; height: number; densityMilli: number }> = [];
const starts: Array<{ target: unknown; size: unknown }> = [];
let attaches = 0;
let repairs = 0;

interface Unit { bytes: Uint8Array; keyframe: boolean }
const unitCache = new Map<string, Unit[]>();
/** Splits an Annex-B file into access units at its delimiters (the fixtures are written with one in front of every unit). */
function units(name: string): Unit[] {
  const cached = unitCache.get(name);
  if (cached) return cached;
  const path = join(FIXTURES, `${name}.h264`);
  if (!existsSync(path)) throw new Error(`missing fixture ${path}; run test/appwin/render-fixtures.mjs`);
  const video = new Uint8Array(readFileSync(path));
  const starts: number[] = [];
  const idr = new Set<number>();
  for (let i = 0; i + 4 < video.length;) {
    const prefix = video[i] === 0 && video[i + 1] === 0 ? (video[i + 2] === 1 ? 3 : video[i + 2] === 0 && video[i + 3] === 1 ? 4 : 0) : 0;
    if (!prefix) { i++; continue; }
    const type = video[i + prefix]! & 31;
    if (type === 9) starts.push(i);
    if (type === 5) idr.add(starts.length - 1);
    i += prefix + 1;
  }
  const out = starts.map((start, k) => ({ bytes: video.subarray(start, starts[k + 1] ?? video.length), keyframe: idr.has(k) }));
  unitCache.set(name, out);
  return out;
}

const variantFor = (s: Session): string => `${s.app}-${s.width >= s.height ? "wide" : "tall"}`;

function sendVideo(v: Viewer, unit: Unit): void {
  if (v.socket.readyState !== 1) return;
  v.sequence += 1n;
  v.sent++;
  const frame: WireFrame = { type: "Desktop", message: { kind: "video", sequence: v.sequence, captureNs: process.hrtime.bigint(), keyframe: unit.keyframe, bytes: unit.bytes } };
  v.socket.send(Buffer.from(encodeMuxedFrame(v.stream, frame)), { binary: true });
}

function startViewer(v: Viewer): void {
  stopTimer(v);
  v.variant = variantFor(v.session);
  const list = units(v.variant);
  if (v.startupFaultPending) {
    v.startupFaultPending = false;
    const delta = list.findIndex((unit) => !unit.keyframe);
    if (delta < 0) throw new Error("the app-window fixture needs a delta picture");
    sendVideo(v, list[delta]!);
    v.index = delta + 1;
  } else {
    v.index = 0;
    sendVideo(v, list[0]!);
    v.index = 1;
  }
  const period = 1000 / config.fps;
  // One timer per viewer; drift-corrected so a long run keeps its rate.
  let next = performance.now() + period;
  v.timer = setInterval(() => {
    const now = performance.now();
    let guard = 0;
    while (next <= now && guard++ < 4) {
      const unit = list[v.index % list.length]!;
      // A loop wraps to its first unit, which is a keyframe: the sequence stays continuous.
      sendVideo(v, unit);
      v.index++;
      next += period;
    }
    if (next <= now) next = now + period;
  }, Math.max(1, Math.floor(period / 2)));
}

function stopTimer(v: Viewer): void { if (v.timer) clearInterval(v.timer); v.timer = undefined; }
function detach(v: Viewer): void { stopTimer(v); v.session.viewers.delete(v); if (v.session.controller?.socket === v.socket && v.session.controller.stream === v.stream) delete v.session.controller; }

/** Every viewer on a closed socket goes with it. */
export function appwinSocketClosed(socket: WebSocket): void {
  layoutSubscribers.delete(socket);
  for (const s of sessions.values()) for (const v of [...s.viewers]) if (v.socket === socket) detach(v);
}

const reply = (socket: WebSocket, callId: number, ok: boolean, json: unknown): void => {
  socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId, ok, json: text(json) })), { binary: true });
};

/** Handles a `desktop.*` call. Returns false for any other action. */
export function appwinCall(socket: WebSocket, callId: number, action: string, input: Record<string, unknown>): boolean {
  if (!appwinEnabled || !action.startsWith("desktop.")) return false;
  const hostOk = input.host_id === MAC_HOST_ID;
  switch (action) {
    case "desktop.windows": {
      if (!hostOk) { reply(socket, callId, false, { error: "unavailable" }); return true; }
      const answer = (): void => reply(socket, callId, true, {
        windows: config.windows.map(({ app: _app, ...w }) => w),
        displays: [{ display_id: 1, backing_scale: 2, pixel_width: 2880, pixel_height: 1800 }],
        permission_state: { screen_recording: config.screenRecording, accessibility: config.accessibility },
        source: "test-double",
      });
      if (config.windowsDelayMs) setTimeout(answer, config.windowsDelayMs); else answer();
      return true;
    }
    case "desktop.session.start": {
      const start = input.start as { target?: Session["target"]; size?: { width: number; height: number; backing_scale: number } } | undefined;
      starts.push({ target: start?.target, size: start?.size });
      if (!hostOk || !start?.target || !start.size || input.delivery !== "reliable" || config.refuseNextStart || !config.screenRecording) {
        config.refuseNextStart = false;
        reply(socket, callId, false, { error: "unavailable" });
        return true;
      }
      const t = start.target;
      const win = t.type === "window" ? config.windows.find((w) => w.window_id === t.window_id && w.owner_pid === t.owner_pid) : undefined;
      if (t.type === "window" && !win) { reply(socket, callId, false, { error: "unavailable" }); return true; }
      const id = randomUUID();
      const made = (): void => { reply(socket, callId, true, { session_id: id }); };
      sessions.set(id, { id, target: t, app: t.type === "screen" ? "screen" : win!.app, width: start.size.width, height: start.size.height, density: start.size.backing_scale, viewers: new Set(), startedAt: performance.now() });
      if (config.startDelayMs) setTimeout(made, config.startDelayMs); else made();
      return true;
    }
    case "desktop.session.stop": {
      const s = sessions.get(String(input.session_id));
      if (s) { for (const v of [...s.viewers]) detach(v); sessions.delete(s.id); }
      reply(socket, callId, true, { stopped: true });
      return true;
    }
    case "desktop.session.status":
    case "desktop.session.clock": {
      // Native Status includes the clock; source.status is worker metadata only.
      if (action === "desktop.session.status" && config.controlContract) { reply(socket, callId, true, { enabled: true, active_work: 1 }); return true; }
      const s = sessions.get(String(input.session_id));
      if (!s) { reply(socket, callId, false, { error: "unavailable" }); return true; }
      const wait = config.inputPauseMs;
      const shape = config.windowShape ? { reason: "managed", capture_rect: { x: 40, y: 60, ...config.windowShape } } : {};
      reply(socket, callId, true, { state: "capturing", ...shape, ...(wait ? { input: { pause_remaining_ms: wait } } : {}) });
      return true;
    }
    case "desktop.session.control": {
      const streamId = Number(input.stream_id);
      const viewer = [...sessions.values()].flatMap((s) => [...s.viewers]).find((v) => v.socket === socket && v.stream === streamId);
      if (!viewer || config.viewOnly || (viewer.session.controller && viewer.session.controller.socket !== socket)) { reply(socket, callId, false, { error: "unavailable" }); return true; }
      viewer.session.controller = { socket, stream: streamId };
      reply(socket, callId, true, { controller: true, stream_id: streamId });
      return true;
    }
    default:
      reply(socket, callId, false, { error: "unknown action" });
      return true;
  }
}

/** Handles a Desktop frame on a client stream. */
export function appwinFrame(socket: WebSocket, streamId: number, frame: WireFrame): void {
  if (frame.type === "Close") {
    for (const s of sessions.values()) for (const v of [...s.viewers]) if (v.socket === socket && v.stream === streamId) detach(v);
    return;
  }
  if (frame.type !== "Desktop") return;
  const m = frame.message;
  if (m.kind === "attach") {
    const id = [...m.sessionId].map((b) => b.toString(16).padStart(2, "0")).join("").replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
    const session = sessions.get(id);
    if (!session) { socket.send(Buffer.from(encodeMuxedFrame(streamId, { type: "Close", code: 4404, reason: "viewer ended" })), { binary: true }); return; }
    attaches++;
    const v: Viewer = { socket, stream: streamId, session, sequence: 0n, index: 0, timer: undefined, variant: "", sent: 0, startupFaultPending: config.dropInitialKeyframe };
    session.viewers.add(v);
    startViewer(v);
    return;
  }
  const v = [...sessions.values()].flatMap((s) => [...s.viewers]).find((x) => x.socket === socket && x.stream === streamId);
  if (!v) return;
  if (m.kind === "repair") { repairs++; startViewer(v); return; }
  if (m.kind === "size") {
    if (config.controlContract && (v.session.controller?.socket !== socket || v.session.controller.stream !== streamId)) {
      socket.send(Buffer.from(encodeMuxedFrame(streamId, { type: "Close", code: 4404, reason: "viewer ended" })), { binary: true });
      detach(v); return;
    }
    sizes.push({ session: v.session.id, width: m.width, height: m.height, densityMilli: m.densityMilli });
    v.session.width = m.width; v.session.height = m.height;
    // A different shape is a different picture: the machine's window followed the size, and its encoder starts a new keyframe.
    if (variantFor(v.session) !== v.variant) startViewer(v);
    return;
  }
  if (m.kind === "input") {
    if (v.session.controller?.socket !== socket || v.session.controller.stream !== streamId) return;
    if (inputs.length < 5000) inputs.push({ session: v.session.id, stream: streamId, input: m.input });
  }
}

/** The HTTP controls. Returns true when the request was one of them. */
export async function appwinHttp(request: IncomingMessage, response: ServerResponse, pathname: string, readJson: (r: IncomingMessage) => Promise<unknown>, sendJson: (r: ServerResponse, status: number, body: unknown) => void): Promise<boolean> {
  if (!appwinEnabled || !pathname.startsWith("/__mock/appwin")) return false;
  if (request.method === "GET" && pathname === "/__mock/appwin/state") {
    sendJson(response, 200, {
      sessions: [...sessions.values()].map((s) => ({ id: s.id, target: s.target, width: s.width, height: s.height, density: s.density, controller: Boolean(s.controller), viewers: [...s.viewers].map((v) => ({ stream: v.stream, sent: v.sent, variant: v.variant })) })),
      inputs, sizes, starts, attaches, repairs, config: { fps: config.fps, viewOnly: config.viewOnly, screenRecording: config.screenRecording },
    });
    return true;
  }
  if (request.method === "POST" && pathname === "/__mock/appwin/config") {
    const body = await readJson(request) as Partial<typeof config> & { reset?: boolean } | undefined;
    if (!body || typeof body !== "object") { sendJson(response, 400, { error: "invalid request" }); return true; }
    // A reset is a new test source: prior pages may leave server-held sessions
    // intentionally alive, so retire their timers and registrations as well.
    if (body.reset) {
      for (const session of sessions.values()) for (const viewer of [...session.viewers]) detach(viewer);
      sessions.clear(); layout = { format: FORMAT, version: VERSION, revision: 0, views: [] };
      layoutInitialized = false; layoutSubscribers.clear(); layoutReceipts.clear();
    }
    if (body.reset) { Object.assign(config, { fps: 60, windows: defaults(), screenRecording: true, accessibility: true, viewOnly: false, controlContract: true, inputPauseMs: 0, refuseNextStart: false, windowsDelayMs: 0, startDelayMs: 0, dropInitialKeyframe: false, windowShape: undefined }); inputs.length = 0; sizes.length = 0; starts.length = 0; attaches = 0; repairs = 0; }
    for (const key of ["controlContract", "fps", "screenRecording", "accessibility", "viewOnly", "inputPauseMs", "refuseNextStart", "windowsDelayMs", "startDelayMs", "dropInitialKeyframe", "windowShape"] as const) if (key in body) (config as Record<string, unknown>)[key] = body[key];
    if (Array.isArray(body.windows)) config.windows = body.windows as Win[];
    sendJson(response, 200, { ok: true });
    return true;
  }
  if (request.method === "POST" && pathname === "/__mock/appwin/end") {
    // The app closes: its window leaves the list and every viewer of it is ended, as the real server ends a viewer.
    const body = await readJson(request) as { window_id?: number } | undefined;
    for (const s of [...sessions.values()]) {
      if (body?.window_id !== undefined && !(s.target.type === "window" && s.target.window_id === body.window_id)) continue;
      for (const v of [...s.viewers]) { v.socket.send(Buffer.from(encodeMuxedFrame(v.stream, { type: "Close", code: 4404, reason: "viewer ended" })), { binary: true }); detach(v); }
      sessions.delete(s.id);
    }
    if (body?.window_id !== undefined) config.windows = config.windows.filter((w) => w.window_id !== body.window_id);
    sendJson(response, 200, { ok: true });
    return true;
  }
  sendJson(response, 404, { error: "unknown" });
  return true;
}
