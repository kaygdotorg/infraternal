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
 * Incidents that follow each other within 400 ms are one incident (a stutter is not a hundred records). Incidents
 * are batched and sent with `sendBeacon` ten seconds after the first one waits, and when the page is hidden. A tab
 * sends at most 600 incidents an hour.
 *
 * Loaded by main.ts after the first idle, only in preview builds (the module is left out of production builds) and
 * not when the address has `?fps=0`.
 */
import { buildVersion } from "./build-version";
import { readLocal, writeLocal } from "../../../packages/ui/src/local-pref";
import { activityIn, readPerfProbe } from "./perf-activity";
import { DROP, FREEZE, FrameDetector, RING, type FrameVerdict } from "./perf-detector";

const OPEN_KEY = "tracer.fps-hud-open";
const REPAINT_MS = 250;
const COALESCE_MS = 400;
const CLOSE_AFTER_MS = 800;
const FLUSH_AFTER_MS = 10_000;
const MAX_INCIDENTS_PER_HOUR = 600;
const MAX_BODY = 40_000;
const SPARK_MS = 2000;
const SPARK_W = 64;
const SPARK_H = 12;

interface Script { inv: string; type: string; src: string; fn: string; pos: number; ms: number; forced: number; pause: number }
interface Loaf { start: number; ms: number; block: number; render: number; styleLayout: number; forced: number; scripts: Script[] }
interface Task { start: number; ms: number; kind: string }
interface Slow { start: number; ms: number; delay: number; name: string; target: string }

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
}

interface Open extends Incident { firstIdx: number; firstT: number; lastT: number; endT: number }

const clip = (s: unknown, n = 120): string => String(s ?? "").slice(0, n);
const r1 = (v: number): number => Math.round(v * 10) / 10;
const pathOf = (url: string): string => { try { const u = new URL(url, location.href); return u.origin === location.origin ? u.pathname : u.href; } catch { return clip(url); } };

export function mountPerfHud(options: { bench?: boolean } = {}): { dispose(): void } {
  const det = new FrameDetector();
  const sid = typeof crypto.randomUUID === "function" ? crypto.randomUUID() : Math.random().toString(36).slice(2) + Date.now().toString(36);
  const startedAt = Date.now() - performance.now();
  const stage = document.querySelector<HTMLElement>(".terminal-screen") ?? document.body;

  // ---- the readout -------------------------------------------------------------------------------------
  const style = document.createElement("style");
  style.textContent = HUD_CSS;
  document.head.append(style);
  const box = document.createElement("div");
  box.className = "perf-hud";
  const detail = document.createElement("div");
  detail.className = "perf-hud-detail";
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
    dropTimes[dropCount++ & 255] = t;
    if (pendN < 32) { pendT[pendN] = t; pendDt[pendN] = d.at(0); pendIdx[pendN] = d.n - 1; pendVerdict[pendN] = v; pendN++; }
    if (!drainScheduled) { drainScheduled = true; setTimeout(drain, 0); }
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
  function drain(): void {
    drainScheduled = false;
    const n = pendN;
    pendN = 0;
    if (document.hidden) return;
    for (let i = 0; i < n; i++) {
      const t = pendT[i]!, dt = pendDt[i]!, kind = pendVerdict[i] === FREEZE ? "freeze" : "drop";
      if (open && t - open.lastT <= COALESCE_MS) {
        open.drops++; open.lastT = t; open.endT = t;
        if (dt > open.worstMs) open.worstMs = r1(dt);
        if (kind === "freeze") open.kind = "freeze";
      } else {
        if (open) finish();
        open = {
          kind, at: Math.round(startedAt + t - dt), worstMs: r1(dt), drops: 1, refreshHz: det.refresh,
          activity: activityIn(t - dt, t), animations: animationsNow(), ctx: context(), intervals: [], loaf: [], longtasks: [], slowEvents: [],
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
    else { det.resume(); if (!repaintTimer) repaintTimer = window.setInterval(paint, REPAINT_MS); }
  };
  document.addEventListener("visibilitychange", onHide);
  window.addEventListener("pagehide", onHide);

  // ---- painting: 4 Hz, off the frame callback --------------------------------------------------------------
  const colMax = new Float32Array(SPARK_W);
  let lastFps = "", lastDetail = "", lastState = "";
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
    let minute = 0;
    for (let i = 0; i < 256 && i < dropCount; i++) if (now - dropTimes[i]! < 60_000) minute++;
    const lines = [`${hz || "–"} Hz · p95 ${det.n > 30 ? r1(det.p95()) : "–"} ms`, `${minute} drops in 1 min`];
    const last = lastIncident;
    if (last) {
      const top = last.loaf[0]?.scripts.reduce<Script | undefined>((best, s) => (!best || s.ms > best.ms ? s : best), undefined);
      lines.push(`last: ${last.activity} ${Math.round(last.worstMs)} ms${last.drops > 1 ? ` x${last.drops}` : ""}`);
      if (top) lines.push(`${top.fn || top.inv || top.type} ${top.src.split("/").pop() ?? ""}`.slice(0, 30));
      else if (last.animations.count) lines.push(`${last.animations.count} animations`);
    }
    const next = lines.join("\n");
    if (next !== lastDetail) { detail.textContent = next; lastDetail = next; }
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
  let repaintTimer = window.setInterval(paint, REPAINT_MS);
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
      clearInterval(repaintTimer); clearTimeout(closeTimer); clearTimeout(flushTimer);
      for (const o of observers) o.disconnect();
      themeWatch.disconnect();
      document.removeEventListener("visibilitychange", onHide);
      window.removeEventListener("pagehide", onHide);
      finish(); flush();
      box.remove(); style.remove();
    },
  };
}

/** Plain on purpose: a dev instrument. Tokens and the caption type of the product, faint, in the pane's corner. */
const HUD_CSS = `
.perf-hud { position: absolute; z-index: 3; left: calc(var(--gutter, 12px) + env(safe-area-inset-left)); bottom: calc(10px + env(safe-area-inset-bottom)); width: 176px; height: 84px; contain: strict; pointer-events: none; color: var(--fg-2); font: var(--fw-label, 550) var(--text-caption, 11px)/1.35 var(--font-mono, monospace); font-variant-numeric: tabular-nums; }
.perf-hud-row { position: absolute; left: 0; bottom: 0; display: flex; align-items: center; gap: 8px; height: 22px; padding: 0 6px; margin: 0; border: 0; border-radius: 6px; outline: none; background: transparent; color: inherit; font: inherit; cursor: pointer; pointer-events: auto; opacity: 0.7; -webkit-tap-highlight-color: transparent; }
.perf-hud-fps { min-width: 3ch; text-align: right; }
.perf-hud-spark { width: ${SPARK_W}px; height: ${SPARK_H}px; display: block; }
.perf-hud-detail { position: absolute; left: 0; bottom: 24px; width: 164px; box-sizing: border-box; padding: 4px 6px; border-radius: 6px; background: color-mix(in oklab, var(--bg) 78%, transparent); white-space: pre; overflow: hidden; text-overflow: ellipsis; opacity: 0; transform: translateY(4px); transition: opacity 160ms ease-out, transform 200ms cubic-bezier(0.32, 0.72, 0, 1); }
.perf-hud[data-open] .perf-hud-detail { opacity: 0.7; transform: none; }
.perf-hud[data-state="slow"] .perf-hud-fps { color: var(--warn); }
.perf-hud-row:hover { opacity: 1; }
/* Touch: the only free strip is the 16 px gap between the windows and the key bar, so the readout sits in it (one
   14 px line) and its 44 px target reaches up over the window's bottom edge; the open detail is drawn over the window. */
@media (pointer: coarse) {
  .perf-hud { bottom: calc(var(--keybar-inset, 8px) + var(--keybar-height, 48px) + env(safe-area-inset-bottom) + 1px); height: 98px; }
  .perf-hud-row { height: 14px; padding: 0 14px 0 6px; }
  .perf-hud-row::before { content: ""; position: absolute; inset: -30px 0 0 0; }
  .perf-hud-detail { bottom: 18px; }
}
@media (prefers-reduced-motion: reduce) { .perf-hud-detail { transition: opacity 120ms linear; transform: none; } }
`;
