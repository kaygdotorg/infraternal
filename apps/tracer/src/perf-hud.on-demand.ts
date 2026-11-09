/**
 * The frame meter and the frame-drop recorder (issue #116). A development instrument for mockup previews: a small
 * readout of the frame rate, and an automatic record of every drop and freeze, with what the app was doing, delivered
 * to the preview server (`POST /__perf`, one JSON line per incident) so nobody has to describe a stutter.
 *
 * Cost rules (a meter that causes drops is worse than none):
 * - The only per-frame work is `body`: `FrameDetector.frame` (one ring write and a compare) and a branch. No
 *   allocation, no DOM, no layout read. `?fps=bench` times that body in isolation (see `bench`).
 * - The readout repaints from a 4 Hz timer, not from the frame callback: one `textContent` per changed string and
 *   one 2D canvas draw. It lives in a fixed-size, `contain: strict` box, and opening or closing the detail changes
 *   opacity and a transform, never the box, so nothing is laid out for it.
 * - The reasons for a drop are collected only when a drop happens, one task after it. The performance observers
 *   (long animation frames, long tasks, slow input events) are the browser's own: they report only frames and tasks
 *   over 50 ms, and a browser without them (Safari) simply sends incidents without script attribution.
 *
 * Evidence for a stall at rest (`diag`, see `Diag`): a 100 ms heartbeat timer (late = the main thread was blocked, on time =
 * the stall was in the compositor or the GPU), WebSocket traffic in the 500 ms before, JS heap falls (a collection;
 * Chromium), page-state changes, the last user input and which observers the browser has. The rings are fixed typed
 * arrays written by one-line listeners; they are read only when an incident opens, never per frame.
 *
 * Incidents that follow each other within 400 ms are one incident (a stutter is not a hundred records). Incidents
 * are batched and sent with `sendBeacon` ten seconds after the first one waits, and when the page is hidden. A tab
 * sends at most 600 incidents an hour.
 *
 * Loaded by main.ts after the first idle, only in preview builds (the module is left out of production builds) and
 * not when the address has `?fps=0`.
 */
import { randomUuid } from "./identifiers";
import { buildVersion } from "./build-version";
import { readLocal, writeLocal } from "../../../packages/ui/src/local-pref";
import { activityIn, readPerfProbe, wsBetween } from "./perf-activity";
import { DROP, FREEZE, FrameDetector, RING, THROTTLE_MS, type FrameVerdict } from "./perf-detector";

/** The browser-local key under which the readout's open or closed state is saved. */
const OPEN_KEY = "tracer.fps-hud-open";
/** How often the readout repaints: every 250 ms. */
const REPAINT_MS = 250;
/** Late frames closer together than this belong to one incident. */
const COALESCE_MS = 400;
/** How long after the last late frame an open incident is closed. */
const CLOSE_AFTER_MS = 800;
/** How long a long interval waits before it is reported, to learn whether it started a throttled run (more than two throttled frames fit in it). */
const THROTTLE_WAIT_MS = 2500;
/** How long collected incidents wait before they are sent. */
const FLUSH_AFTER_MS = 10_000;
/** The most incidents one tab sends in an hour. */
const MAX_INCIDENTS_PER_HOUR = 600;
/** The size (JSON characters) at which a batch of incidents is closed; the rest wait for the next send. */
const MAX_BODY = 40_000;
/** The time span the sparkline shows. */
const SPARK_MS = 2000;
/** The sparkline's drawing size in pixels. */
const SPARK_W = 64;
const SPARK_H = 12;

/** One script that ran during a long animation frame, as the browser reports it. */
interface Script { inv: string; type: string; src: string; fn: string; pos: number; ms: number; forced: number; pause: number }
/** A long animation frame: its timing split and the scripts that ran in it. */
interface Loaf { start: number; ms: number; block: number; render: number; styleLayout: number; forced: number; scripts: Script[] }
/** A long task. */
interface Task { start: number; ms: number; kind: string }
/** A slow input event. */
interface Slow { start: number; ms: number; delay: number; name: string; target: string }

/** One recorded stall: a run of late frames that is sent to the preview server as one line. */
export interface Incident {
  kind: "drop" | "freeze";
  /** Wall-clock time of the first late frame (ms since the epoch). */
  at: number;
  /** The longest interval in this incident, and how many late frames it holds. */
  worstMs: number;
  drops: number;
  /** Display refresh the meter estimated, Hz. */
  refreshHz: number;
  /** What the app was doing during the slow frame (perf-activity.ts). */
  activity: string;
  animations: { count: number; names: string[] };
  ctx: Record<string, string | number | boolean>;
  /** The 30 frame intervals around the first late frame, ms. */
  intervals: number[];
  loaf: Loaf[];
  longtasks: Task[];
  slowEvents: Slow[];
  /** What else was going on, read once when the incident opens (see `diagnose`). */
  diag: Diag;
}

/**
 * The evidence a freeze at rest needs, because a stall can come from the page's own main thread (a task, a timer, a
 * garbage collection) or from outside it (the compositor, the GPU process, the window server) and the frame times alone
 * cannot tell which:
 * - `stalls`: late wake-ups of a 100 ms heartbeat timer around the incident. A late heartbeat means the main thread was
 *   blocked (a script, a GC, a layout); on time while frames were late means the main thread was free and the stall
 *   was elsewhere. Works in every browser, unlike long-task entries (not in Safari).
 * - `animations`/`transitions`: how many CSS animations and transitions were running (in `animations`, above).
 * - `ws`: WebSocket messages and bytes that arrived in the 500 ms before the late frame.
 * - `heap`: JS heap in MB now and the largest fall between the last samples (a fall is a collection); Chromium only.
 * - `events`: the latest visibility, focus, resize and page-lifecycle changes, with their age.
 * - `action`: the last user input before the incident, and how long before it.
 * - `support`: which of the observers this browser has (an empty `loaf`/`longtasks` is only news when it does).
 */
interface Diag {
  stalls: Array<{ ago: number; late: number }>;
  ws: { msgs: number; bytes: number };
  heap: { usedMB: number; fellMB: number } | null;
  events: Array<{ type: string; ago: number }>;
  action: { type: string; ago: number } | null;
  support: { loaf: boolean; longtask: boolean; event: boolean };
}

/** An incident still being collected, with the ring positions and times that bound it. */
interface Open extends Incident { firstIdx: number; firstT: number; lastT: number; endT: number }

/** The first `n` characters of any value as text. */
const clip = (s: unknown, n = 120): string => String(s ?? "").slice(0, n);
/** Rounds to one decimal. */
const r1 = (v: number): number => Math.round(v * 10) / 10;
/** A URL as a path when it is on this page's origin, otherwise in full. */
const pathOf = (url: string): string => { try { const u = new URL(url, location.href); return u.origin === location.origin ? u.pathname : u.href; } catch { return clip(url); } };

/**
 * Shows the frame meter and starts recording incidents. Pass `{ bench: true }` for the `?fps=bench` mode that times the
 * per-frame work alone. Returns a handle whose `dispose()` removes the meter and its observers.
 */
export function mountPerfHud(options: { bench?: boolean } = {}): { dispose(): void } {
  const det = new FrameDetector();
  const sid = randomUuid();
  const startedAt = Date.now() - performance.now();
  const stage = document.querySelector<HTMLElement>(".terminal-screen") ?? document.body;

  // ---- the readout -------------------------------------------------------------------------------------
  const style = document.createElement("style");
  style.textContent = HUD_CSS;
  document.head.append(style);
  const box = document.createElement("div");
  box.className = "perf-hud";
  // The open detail is a floating card: the one shared overlay material, like the other popovers.
  const detail = document.createElement("div");
  detail.className = "perf-hud-detail ui-overlay-surface";
  const headText = document.createElement("div");
  headText.className = "perf-hud-head";
  const bodyText = document.createElement("div");
  bodyText.className = "perf-hud-body";
  detail.append(headText, bodyText);
  const row = document.createElement("button");
  row.type = "button";
  row.className = "perf-hud-row";
  row.setAttribute("aria-label", "Frame meter details");
  row.setAttribute("aria-pressed", "false");
  const fpsText = document.createElement("span");
  fpsText.className = "perf-hud-fps";
  const spark = document.createElement("canvas");
  spark.className = "perf-hud-spark";
  const dpr = Math.max(1, Math.round(devicePixelRatio || 1));
  spark.width = SPARK_W * dpr; spark.height = SPARK_H * dpr;
  const g = spark.getContext("2d");
  row.append(fpsText, spark);
  box.append(detail, row);
  stage.append(box);
  // The box takes no clicks except on the row. The focus ring comes from the shared keyboard-modality rule in
  // packages/ui/styles.css (Tab only), so the row only clears the browser's own outline.
  let expanded = readLocal(OPEN_KEY) === "1";
  const setExpanded = (open: boolean): void => {
    expanded = open;
    box.toggleAttribute("data-open", open);
    row.setAttribute("aria-pressed", String(open));
    writeLocal(OPEN_KEY, open ? "1" : "0");
    paint();
  };
  row.addEventListener("click", () => setExpanded(!expanded));

  let cOk = "#888", cDrop = "#c90", cFreeze = "#c33";
  const readColors = (): void => {
    const cs = getComputedStyle(box);
    cOk = cs.getPropertyValue("--fg-3").trim() || cOk;
    cDrop = cs.getPropertyValue("--warn").trim() || cDrop;
    cFreeze = cs.getPropertyValue("--danger").trim() || cFreeze;
  };
  // Colours are read when the theme changes, never per paint (a style read would force a recalculation).
  const themeWatch = new MutationObserver(() => { readColors(); paint(); });
  themeWatch.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

  // ---- detection: the only per-frame code ------------------------------------------------------------
  const dropTimes = new Float64Array(256);
  let dropCount = 0;
  const pendT = new Float64Array(32), pendDt = new Float64Array(32), pendIdx = new Int32Array(32), pendVerdict = new Uint8Array(32);
  let pendN = 0, drainScheduled = false;

  const noteDrop = (d: FrameDetector, t: number, v: FrameVerdict): void => {
    if (pendN < 32) { pendT[pendN] = t; pendDt[pendN] = d.at(0); pendIdx[pendN] = d.n - 1; pendVerdict[pendN] = v; pendN++; }
    // A long interval may be the start of a throttled run; wait to see whether the next one is long too.
    if (!drainScheduled) { drainScheduled = true; setTimeout(drain, d.at(0) >= THROTTLE_MS ? THROTTLE_WAIT_MS : 0); }
  };
  /** The whole per-frame cost. Takes the detector so `bench` can time it on a scratch one. */
  const body = (d: FrameDetector, t: number): void => {
    const v = d.frame(t);
    if (v !== 0) noteDrop(d, t, v);
  };
  let raf = 0;
  const tick = (t: number): void => { body(det, t); raf = requestAnimationFrame(tick); };
  let selfTotal = 0, selfFrames = 0;
  const tickTimed = (t: number): void => {
    const a = performance.now();
    body(det, t);
    selfTotal += performance.now() - a; selfFrames++;
    raf = requestAnimationFrame(tickTimed);
  };
  raf = requestAnimationFrame(options.bench ? tickTimed : tick);

  // ---- the reasons: observers keep a few recent entries; nothing is read until a drop --------------------
  const loafs: Loaf[] = [], tasks: Task[] = [], slows: Slow[] = [];
  const keep = <T>(list: T[], item: T, max = 16): void => { list.push(item); if (list.length > max) list.shift(); };
  const observers: PerformanceObserver[] = [];
  const supported = PerformanceObserver.supportedEntryTypes ?? [];
  const watch = (type: string, init: Record<string, unknown>, onEntry: (e: PerformanceEntry) => void): void => {
    if (!supported.includes(type)) return;
    try {
      const o = new PerformanceObserver((list) => { for (const e of list.getEntries()) onEntry(e); });
      o.observe({ type, ...init } as PerformanceObserverInit);
      observers.push(o);
    } catch { /* an entry type this browser lists but refuses */ }
  };
  watch("long-animation-frame", {}, (e) => {
    const f = e as PerformanceEntry & { blockingDuration?: number; renderStart?: number; styleAndLayoutStart?: number; scripts?: Array<Record<string, unknown>> };
    const end = f.startTime + f.duration;
    const scripts = (f.scripts ?? []).slice(0, 6).map((s) => ({
      inv: clip(s.invoker), type: clip(s.invokerType, 40), src: pathOf(String(s.sourceURL ?? "")), fn: clip(s.sourceFunctionName, 80),
      pos: Number(s.sourceCharPosition ?? -1), ms: r1(Number(s.duration ?? 0)), forced: r1(Number(s.forcedStyleAndLayoutDuration ?? 0)), pause: r1(Number(s.pauseDuration ?? 0)),
    }));
    keep(loafs, {
      start: r1(f.startTime), ms: r1(f.duration), block: r1(f.blockingDuration ?? 0),
      render: f.renderStart ? r1(end - f.renderStart) : 0, styleLayout: f.styleAndLayoutStart ? r1(end - f.styleAndLayoutStart) : 0,
      forced: r1(scripts.reduce((sum, s) => sum + s.forced, 0)), scripts,
    });
  });
  watch("longtask", {}, (e) => keep(tasks, { start: r1(e.startTime), ms: r1(e.duration), kind: clip((e as PerformanceEntry & { attribution?: Array<{ containerType?: string }> }).attribution?.[0]?.containerType ?? e.name, 40) }));
  watch("event", { durationThreshold: 80 }, (e) => {
    const ev = e as PerformanceEntry & { processingStart?: number; target?: Element | null };
    keep(slows, { start: r1(e.startTime), ms: r1(e.duration), delay: r1((ev.processingStart ?? e.startTime) - e.startTime), name: clip(e.name, 30), target: clip(ev.target?.tagName?.toLowerCase() ?? "", 20) });
  });

  // ---- the evidence rings: assignments into fixed arrays, nothing allocated, nothing read from the page --------------
  // Last user input. A capture listener per type that only stores a string and a number.
  let actType = "", actT = 0;
  const onAct = (e: Event): void => { actType = e.type; actT = performance.now(); };
  const ACT_TYPES = ["pointerdown", "pointerup", "keydown", "wheel", "touchstart", "pointermove"];
  for (const t of ACT_TYPES) window.addEventListener(t, onAct, { capture: true, passive: true });
  // Page state changes: visibility, focus, size, lifecycle.
  const EV = 12;
  const evT = new Float64Array(EV), evType = new Array<string>(EV).fill("");
  let evHead = 0;
  const onState = (e: Event): void => { evHead = (evHead + 1) % EV; evT[evHead] = performance.now(); evType[evHead] = e.type === "visibilitychange" ? `visibility:${document.visibilityState}` : e.type; };
  const STATE_TYPES = ["visibilitychange", "focus", "blur", "resize", "pageshow", "pagehide", "freeze", "resume", "online", "offline", "fullscreenchange", "orientationchange"];
  for (const t of STATE_TYPES) window.addEventListener(t, onState, true);
  // A heartbeat: a timer that is late was blocked behind main-thread work. 10 wake-ups a second, no allocation.
  const HB = 100, ST = 16;
  const stT = new Float64Array(ST), stLate = new Float64Array(ST);
  let stHead = 0, hbLast = performance.now();
  const heartbeat = window.setInterval(() => {
    const now = performance.now();
    const late = now - hbLast - HB;
    hbLast = now;
    if (late > 30) { stHead = (stHead + 1) % ST; stT[stHead] = now; stLate[stHead] = late; }
  }, HB);
  // JS heap samples (Chromium): taken with the 4 Hz repaint, so a collection shows as a fall between two of them.
  const HS = 16;
  const hpT = new Float64Array(HS), hpV = new Float64Array(HS);
  let hpHead = 0;
  const memory = (performance as Performance & { memory?: { usedJSHeapSize: number } }).memory;
  const sampleHeap = (): void => { if (!memory) return; hpHead = (hpHead + 1) % HS; hpT[hpHead] = performance.now(); hpV[hpHead] = memory.usedJSHeapSize; };

  // ---- incidents --------------------------------------------------------------------------------------
  let open: Open | undefined;
  let closeTimer = 0, flushTimer = 0;
  let lastIncident: Incident | undefined;
  const outbox: Incident[] = [];
  let capStart = 0, capCount = 0, suppressed = 0;

  const animationsNow = (): Incident["animations"] => {
    const list = document.getAnimations();
    const names = new Map<string, number>();
    for (const a of list) {
      const named = a as Animation & { animationName?: string; transitionProperty?: string };
      const target = (a.effect as KeyframeEffect | null)?.target;
      const label = named.animationName ?? (named.transitionProperty ? `transition:${named.transitionProperty}` : `animate:${clip((target as Element | null)?.className || (target as Element | null)?.tagName || "?", 40)}`);
      names.set(label, (names.get(label) ?? 0) + 1);
    }
    return { count: list.length, names: [...names].slice(0, 12).map(([n, c]) => (c > 1 ? `${n} x${c}` : n)) };
  };
  const context = (): Incident["ctx"] => {
    const root = document.documentElement;
    return {
      ...readPerfProbe(),
      dpr: devicePixelRatio, viewport: `${innerWidth}x${innerHeight}`, visibility: document.visibilityState,
      theme: root.dataset.theme ?? "", bg: root.dataset.bg ?? "", glassBlur: root.style.getPropertyValue("--ui-overlay-blur"),
      sidebar: !!stage.querySelector("[data-sidebar-open]") || stage.hasAttribute("data-sidebar-open"),
    };
  };
  /** Reads the rings for an incident that began at `t0` (performance.now time). Called once per incident, not per frame. */
  const diagnose = (t0: number, t1: number): Diag => {
    const now = performance.now();
    const stalls: Diag["stalls"] = [];
    for (let i = 0; i < ST; i++) if (stT[i]! > t0 - 1000 && stLate[i]! > 0) stalls.push({ ago: Math.round(now - stT[i]!), late: Math.round(stLate[i]!) });
    const events: Diag["events"] = [];
    for (let n = 0; n < EV; n++) { const i = (evHead - n + EV) % EV; if (evType[i] && evT[i]! > 0) events.push({ type: evType[i]!, ago: Math.round(now - evT[i]!) }); }
    let heap: Diag["heap"] = null;
    if (memory) {
      let fell = 0, prev = -1;
      const samples: Array<[number, number]> = [];
      for (let n = 0; n < HS; n++) { const i = (hpHead - n + HS) % HS; if (hpT[i]! > 0) samples.push([hpT[i]!, hpV[i]!]); }
      samples.reverse();
      for (const [t, v] of samples) { if (t >= t0 - 1500 && prev >= 0) fell = Math.max(fell, prev - v); prev = v; }
      heap = { usedMB: r1(memory.usedJSHeapSize / 1048576), fellMB: r1(fell / 1048576) };
    }
    return {
      stalls: stalls.slice(0, 8), ws: wsBetween(t0 - 500, t1), heap, events: events.slice(0, 8),
      action: actType ? { type: actType, ago: Math.round(t0 - actT) } : null,
      support: { loaf: supported.includes("long-animation-frame"), longtask: supported.includes("longtask"), event: supported.includes("event") },
    };
  };
  function drain(): void {
    drainScheduled = false;
    const n = pendN;
    pendN = 0;
    if (document.hidden) return;
    for (let i = 0; i < n; i++) {
      const t = pendT[i]!, dt = pendDt[i]!, kind = pendVerdict[i] === FREEZE ? "freeze" : "drop";
      // Not stalls: a throttled page (a run of long intervals, or a long one in a window that has lost focus).
      if (dt >= THROTTLE_MS && (det.inLongRun(pendIdx[i]!) || (dt >= 500 && !document.hasFocus()))) continue;
      dropTimes[dropCount++ & 255] = t;
      if (open && t - open.lastT <= COALESCE_MS) {
        open.drops++; open.lastT = t; open.endT = t;
        if (dt > open.worstMs) open.worstMs = r1(dt);
        if (kind === "freeze") open.kind = "freeze";
      } else {
        if (open) finish();
        open = {
          kind, at: Math.round(startedAt + t - dt), worstMs: r1(dt), drops: 1, refreshHz: det.refresh,
          activity: activityIn(t - dt, t), animations: animationsNow(), ctx: context(), intervals: [], loaf: [], longtasks: [], slowEvents: [], diag: diagnose(t - dt, t),
          firstIdx: pendIdx[i]!, firstT: t - dt, lastT: t, endT: t,
        };
        lastIncident = open;
      }
    }
    clearTimeout(closeTimer);
    closeTimer = window.setTimeout(finish, CLOSE_AFTER_MS);
  }
  function finish(): void {
    clearTimeout(closeTimer);
    const o = open;
    if (!o) return;
    open = undefined;
    const { firstIdx, firstT, lastT: _lastT, endT, ...incident } = o;
    incident.intervals = det.window(firstIdx, 20, 9);
    const within = (start: number, ms: number): boolean => start + ms >= firstT - 50 && start <= endT + 50;
    incident.loaf = loafs.filter((e) => within(e.start, e.ms));
    incident.longtasks = tasks.filter((e) => within(e.start, e.ms));
    incident.slowEvents = slows.filter((e) => within(e.start, e.ms));
    const now = Date.now();
    if (now - capStart > 3_600_000) { capStart = now; capCount = 0; }
    if (capCount >= MAX_INCIDENTS_PER_HOUR) { suppressed++; return; }
    capCount++;
    outbox.push(incident);
    lastIncident = incident;
    if (!flushTimer) flushTimer = window.setTimeout(flush, FLUSH_AFTER_MS);
  }
  const sessionInfo = (): Record<string, unknown> => {
    const nav = navigator as Navigator & { deviceMemory?: number; userAgentData?: { platform?: string } };
    return {
      startedAt: Math.round(startedAt), ua: navigator.userAgent, platform: nav.userAgentData?.platform ?? navigator.platform, dpr: devicePixelRatio,
      refreshHz: det.refresh, cores: navigator.hardwareConcurrency, memoryGb: nav.deviceMemory ?? null, build: buildVersion().full,
      screen: `${screen.width}x${screen.height}`, hud: 1,
    };
  };
  function flush(): void {
    clearTimeout(flushTimer);
    flushTimer = 0;
    while (outbox.length) {
      const batch: Incident[] = [];
      let size = 600;
      while (outbox.length && size < MAX_BODY) { const next = outbox[0]!; size += JSON.stringify(next).length; if (batch.length && size >= MAX_BODY) break; batch.push(outbox.shift()!); }
      const body = JSON.stringify({ v: 1, sid, page: location.pathname + location.search, session: sessionInfo(), suppressed, incidents: batch });
      suppressed = 0;
      let sent = false;
      try { sent = navigator.sendBeacon("/__perf", new Blob([body], { type: "application/json" })); } catch { /* fall through to fetch */ }
      if (!sent) void fetch("/__perf", { method: "POST", body, keepalive: true, headers: { "Content-Type": "application/json" }, credentials: "same-origin" }).catch(() => undefined);
    }
  }
  const onHide = (): void => {
    if (document.visibilityState === "hidden") { finish(); flush(); clearInterval(repaintTimer); repaintTimer = 0; }
    else { det.resume(); hbLast = performance.now(); if (!repaintTimer) repaintTimer = window.setInterval(() => { sampleHeap(); paint(); }, REPAINT_MS); }
  };
  document.addEventListener("visibilitychange", onHide);
  window.addEventListener("pagehide", onHide);

  // ---- painting: 4 Hz, off the frame callback --------------------------------------------------------------
  const colMax = new Float32Array(SPARK_W);
  let lastFps = "", lastDetail = "", lastState = "", lastHead = "";
  /** The activity tags in plain words, for "Last drop: 33 ms while panning". */
  const WHILE: Record<string, string> = { none: " while idle", pan: " while panning", zoom: " while zooming", flight: " while moving between views", drag: " while dragging", scroll: " while scrolling", typing: " while typing", output: " while the terminal printed", split: " while splitting a window", sidebar: " while the sidebar slid" };
  function paint(): void {
    det.estimate();
    const hz = det.refresh;
    const fps = det.fps();
    const text = fps > 0 ? String(Math.round(fps)) : "–";
    if (text !== lastFps) { fpsText.textContent = text; lastFps = text; }
    const state = hz && fps < hz * 0.85 ? "slow" : "";
    if (state !== lastState) { lastState = state; if (state) box.dataset.state = state; else delete box.dataset.state; }
    drawSpark();
    if (!expanded) return;
    const now = performance.now();
    let minute = 0, recent = 0;
    for (let i = 0; i < 256 && i < dropCount; i++) { const age = now - dropTimes[i]!; if (age < 60_000) minute++; if (age < 10_000) recent++; }
    const last = lastIncident;
    const freezing = !!last && last.kind === "freeze" && Date.now() - last.at < 5000;
    const head = freezing ? "Freezing" : recent > 0 ? "Some drops" : "Smooth";
    const lines = [`${hz || "–"} Hz · p95 ${det.n > 30 ? Math.round(det.p95()) : "–"} ms`];
    lines.push(minute === 0 ? "No drops in the last minute" : `${minute} ${minute === 1 ? "drop" : "drops"} in the last minute`);
    if (last) {
      lines.push(`Last drop: ${Math.round(last.worstMs)} ms${WHILE[last.activity] ?? ""}`);
      const top = last.loaf[0]?.scripts.reduce<Script | undefined>((best, s) => (!best || s.ms > best.ms ? s : best), undefined);
      if (top) lines.push(`Slowest code: ${top.fn || top.inv || top.type} in ${top.src.split("/").pop() ?? ""}`);
      else if (last.animations.count) lines.push(`${last.animations.count} ${last.animations.count === 1 ? "animation" : "animations"} running`);
    } else lines.push("No drops yet");
    const next = lines.join("\n");
    if (head !== lastHead) { headText.textContent = head; lastHead = head; }
    if (next !== lastDetail) { bodyText.textContent = next; lastDetail = next; }
  }
  function drawSpark(): void {
    if (!g) return;
    colMax.fill(0);
    let elapsed = 0;
    for (let i = 0; i < RING && i < det.n && elapsed < SPARK_MS; i++) {
      const dt = det.at(i);
      elapsed += dt;
      const col = SPARK_W - 1 - Math.min(SPARK_W - 1, Math.floor((elapsed / SPARK_MS) * SPARK_W));
      if (dt > colMax[col]!) colMax[col] = dt;
    }
    g.clearRect(0, 0, spark.width, spark.height);
    const base = det.refresh ? 1000 / det.refresh : 16.7;
    const drop = base * 1.5;
    for (let x = 0; x < SPARK_W; x++) {
      const v = colMax[x]!;
      if (v === 0) continue;
      g.fillStyle = v > 100 ? cFreeze : v > drop ? cDrop : cOk;
      const h = Math.max(1, Math.min(1, v / (base * 4)) * SPARK_H);
      g.fillRect(x * dpr, (SPARK_H - h) * dpr, dpr, h * dpr);
    }
  }
  let repaintTimer = window.setInterval(() => { sampleHeap(); paint(); }, REPAINT_MS);
  readColors();
  setExpanded(expanded);

  // ---- the isolated cost of the frame body (`?fps=bench`) ----------------------------------------------------
  const bench = (calls = 200_000, batch = 100): { meanUs: number; p99Us: number; maxUs: number } => {
    const d = new FrameDetector();
    let t = 1000;
    for (let i = 0; i < 2000; i++) { t += 8.33; body(d, t); } // warm the code and the ring
    d.estimate();
    const per: number[] = [];
    for (let b = 0; b < calls / batch; b++) {
      const a = performance.now();
      for (let i = 0; i < batch; i++) { t += 8.33; body(d, t); }
      per.push(((performance.now() - a) / batch) * 1000);
    }
    per.sort((x, y) => x - y);
    return { meanUs: per.reduce((s, v) => s + v, 0) / per.length, p99Us: per[Math.floor(per.length * 0.99)]!, maxUs: per[per.length - 1]! };
  };
  if (options.bench) {
    (window as unknown as { __perfHud: unknown }).__perfHud = {
      bench,
      /** Mean cost (ms) of the real frame callback over the frames since the last call (timed with the page clock). */
      selfTime: () => { const out = { frames: selfFrames, meanMs: selfFrames ? selfTotal / selfFrames : 0 }; selfTotal = 0; selfFrames = 0; return out; },
      /** Stops the 4 Hz repaint so the cost of the frame callback alone can be traced. */
      pauseRepaint: () => { clearInterval(repaintTimer); repaintTimer = 0; },
      flush, finish, state: () => ({ sid, incidents: outbox.length + (open ? 1 : 0), refresh: det.refresh }),
    };
  }

  return {
    dispose() {
      cancelAnimationFrame(raf);
      clearInterval(repaintTimer); clearInterval(heartbeat); clearTimeout(closeTimer); clearTimeout(flushTimer);
      for (const t of ACT_TYPES) window.removeEventListener(t, onAct, true);
      for (const t of STATE_TYPES) window.removeEventListener(t, onState, true);
      for (const o of observers) o.disconnect();
      themeWatch.disconnect();
      document.removeEventListener("visibilitychange", onHide);
      window.removeEventListener("pagehide", onHide);
      finish(); flush();
      box.remove(); style.remove();
    },
  };
}

/** Plain on purpose: a dev instrument. Tokens and the caption type of the product, faint, in the pane's bottom-right
    corner (nothing may sit bottom-left, TASTE; on desktop it rests above the mock badge, in the free band beside the windows). */
const HUD_CSS = `
.perf-hud { position: absolute; z-index: calc(var(--z-content) + 2); right: calc(var(--gutter, 12px) + env(safe-area-inset-right)); bottom: calc(52px + env(safe-area-inset-bottom)); width: 272px; height: 150px; contain: strict; pointer-events: none; color: var(--fg-2); font: var(--fw-label, 550) var(--text-caption, 11px)/1.35 var(--font-mono, monospace); font-variant-numeric: tabular-nums; --perf-gap: 24px; }
.perf-hud-row { position: absolute; right: 0; bottom: 0; display: flex; align-items: center; gap: 8px; height: 22px; padding: 0 6px; margin: 0; border: 0; border-radius: 6px; outline: none; background: transparent; color: inherit; font: inherit; cursor: pointer; pointer-events: auto; opacity: 0.7; -webkit-tap-highlight-color: transparent; }
.perf-hud-fps { min-width: 3ch; text-align: right; }
.perf-hud-spark { width: ${SPARK_W}px; height: ${SPARK_H}px; display: block; }
/* The card grows from the readout: its transform origin is the readout's corner, a little below the card's own corner. */
.perf-hud-detail { position: absolute; right: 0; bottom: var(--perf-gap); width: 264px; box-sizing: border-box; padding: 10px 12px; border-radius: var(--r-lg, 14px); color: var(--fg); transform-origin: 100% calc(100% + var(--perf-gap)); opacity: 0; visibility: hidden; transform: scale(0.9); transition: opacity 140ms ease-out, transform 200ms cubic-bezier(0.32, 0.72, 0, 1), visibility 0s linear 200ms; }
.perf-hud[data-open] .perf-hud-detail { opacity: 1; visibility: visible; transform: none; transition-delay: 0s; }
.perf-hud-head { margin-bottom: 4px; font-weight: var(--fw-title, 650); }
.perf-hud[data-state="slow"] .perf-hud-fps { color: var(--warn); }
.perf-hud-body { white-space: pre-wrap; color: var(--ui-text-secondary, var(--fg-2)); }
.perf-hud-row:hover { opacity: 1; }
/* Touch: the only free strip is the 16 px gap between the windows and the key bar, so the readout sits in it, at the right (one
   14 px line) and its 44 px target reaches up over the window's bottom edge. The card rises above the mock badge that sits just over the strip. */
@media (pointer: coarse) {
  .perf-hud { bottom: calc(var(--keybar-inset, 8px) + var(--keybar-height, 48px) + env(safe-area-inset-bottom) + 1px); height: 190px; --perf-gap: 54px; }
  .perf-hud-row { height: 14px; padding: 0 14px 0 6px; }
  .perf-hud-row::before { content: ""; position: absolute; inset: -30px 0 0 0; }
}
@media (prefers-reduced-motion: reduce) { .perf-hud-detail { transition: opacity 120ms linear, visibility 0s linear 120ms; transform: none; } }
`;
