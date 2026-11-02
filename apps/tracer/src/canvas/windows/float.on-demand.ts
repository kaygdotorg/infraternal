/**
 * The floating terminal (D177): opening a session while the camera is somewhere else does not move the camera.
 * The top pill morphs into a floating window that shows that same Console window; "Open in Console" flies the
 * float into its slot while the camera follows, one continuous motion. The float resizes with its aspect locked
 * (the shared engine in packages/ui), by drag or by pinch, and the terminal inside is re-measured from the new
 * box: text is never scaled.
 *
 * What it shows is the window's content: a binding that can mirror itself shows the live session, otherwise the
 * window's preview lines. Product canvases that cannot mirror yet leave this module off (`flags.float`).
 */
import { createWindowCard } from "../../../../../packages/ui/src/window-card";
import { createPillMorph, type PillMorph } from "../../../../../packages/ui/src/pill-morph";
import { Spring } from "../../../../../packages/ui/src/spring";
import { aspectFrame, aspectRange, attachWindowResize, settleResize, type ResizeFrame, type ResizeStart, type WindowResizeHost } from "../../../../../packages/ui/src/window-resize";
import type { WindowCard } from "../../../../../packages/ui/src/window-card";
import { clamp } from "../camera/camera";
import type { Ctx, ViewRec, WinRec } from "../context";
import { el, reduced } from "../dom";
import type { Pt } from "../layout/geometry";
import { ICON, iconFor } from "../views/icons";
import { SCALE_REST, restAt } from "../springs";
import { previewLine } from "./preview";

export interface FloatModule {
  open(rec: WinRec): void;
  close(instant?: boolean): void;
  expand(): void;
  /** True while a float is open and not flying into its slot. */
  isOpen(): boolean;
  /** Its size in cells, once measured. */
  info(): { cols: number; rows: number; width: number; height: number } | undefined;
  dispose(): void;
}

export function createFloat(cx: Ctx): FloatModule {
  const { stage, camera, state, views } = cx;
  void ({} as ViewRec);
  interface Float { rec: WinRec; morph: PillMorph; card: WindowCard; expanding: boolean; stopResize: () => void; cells: { cols: number; rows: number } }
  let current: Float | undefined;
  const capsule = stage.querySelector<HTMLElement>("#capsule")!;
  const badge = el("div", "cl-badge ui-overlay-surface");
  badge.hidden = true;
  stage.append(badge);
  let badgeTimer = 0;
  const showBadge = (): void => {
    // Counts the shells opened from elsewhere (a container list); the mockup's only float source.
    const n = [...(views.get("console")?.wins.keys() ?? [])].filter((k) => k.startsWith("w-shell")).length || 1;
    badge.textContent = `${n} session${n === 1 ? "" : "s"} in Console`;
    badge.hidden = false;
    badge.dataset.open = "false";
    const r = capsule.getBoundingClientRect(), s = stage.getBoundingClientRect();
    badge.style.left = `${r.left - s.left + r.width / 2}px`;
    badge.style.top = `${r.bottom - s.top + 8}px`;
    requestAnimationFrame(() => { badge.dataset.open = "true"; });
    window.clearTimeout(badgeTimer);
    badgeTimer = window.setTimeout(() => { badge.dataset.open = "false"; window.setTimeout(() => { badge.hidden = true; }, 220); }, 2600);
  };
  const FULL = '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>';
  const dropFloat = (f: Float): void => { f.stopResize(); f.card.dispose(); if (current === f) current = undefined; };
  const closeFloat = (instant = false): void => {
    const f = current;
    if (!f || f.expanding) return;
    f.morph.close(instant);
    if (instant) dropFloat(f); else showBadge();
  };
  const openFloat = (rec: WinRec): void => {
    cx.viewList.close(true);
    if (current) { current.morph.close(true); dropFloat(current); }
    const m = rec.model;
    const card = createWindowCard({
      id: `f-${m.id}`, title: { host: m.host, ...(m.user ? { user: m.user } : {}), ...(m.session ? { session: m.session } : {}) }, icon: iconFor(m), status: "live",
      actions: [
        { id: "expand", label: "Open in Console", icon: FULL, onSelect: () => expandFloat() },
        { id: "close", label: "Close", icon: ICON.close, onSelect: () => closeFloat() },
      ],
      label: `${m.host} ${m.session ?? "shell"}, floating`,
    });
    card.root.dataset.kind = "terminal";
    const pre = el("pre", "canvas-preview cl-preview");
    pre.innerHTML = `${(m.lines ?? []).map(previewLine).join("\n")}<span class="cl-cursor" aria-hidden="true"></span>`;
    card.body.append(pre);
    const panel = el("section", "cl-float ui-overlay-surface");
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", `${m.host} terminal, floating`);
    panel.append(card.root);
    // The float is the top part of the Console window it shows; it keeps that window's width.
    const W0 = Math.min(rec.card.root.offsetWidth || state.metrics.colW, stage.clientWidth - 24);
    const H0 = state.metrics.narrow ? 300 : 330;
    panel.style.height = `${H0}px`;
    const morph = createPillMorph({
      pill: capsule, stage, panel, content: [card.root], width: W0,
      onClosed: () => { const f = current; if (f && f.card === card) dropFloat(f); },
    });
    // Resizing is the shared engine (window-resize.ts) with the aspect locked, anchored at the top
    // centre. The terminal's cells are re-measured from the new box; text is never scaled.
    const cellW = (() => { const probe = el("span", "", "0000000000"); probe.style.cssText = "position:absolute;visibility:hidden;font:inherit"; pre.append(probe); const w = probe.offsetWidth / 10 || 8.4; probe.remove(); return w; })();
    const measure = (): void => {
      const cols = Math.max(20, Math.floor((card.body.clientWidth - 32) / cellW));
      const rows = Math.max(4, Math.floor((card.body.clientHeight - 28) / (14 * 1.2857)));
      panel.dataset.cols = String(cols); panel.dataset.rows = String(rows);
      if (current) current.cells = { cols, rows };
    };
    const limits = (): ResizeStart => ({
      width: panel.offsetWidth, height: panel.offsetHeight, top: 0,
      minWidth: W0 * 0.78, minHeight: H0 * 0.78, maxWidth: Math.min(W0 * 1.7, stage.clientWidth - 24), areaHeight: Math.min(H0 * 1.7, stage.clientHeight - 90),
    });
    const host: WindowResizeHost = {
      aspect: W0 / H0, centered: true, rubber: true,
      begin: limits,
      apply: (f) => { morph.setBox(f.width, f.height, f.height); },
      snap: (f) => (Math.abs(f.width / W0 - 1) < 0.06 ? { width: W0, height: H0, top: 0, shiftX: 0 } : f),
      end: measure,
    };
    const resize = attachWindowResize(card, host);
    // Touch: pinch inside the float resizes it too, with the same rubber band and settle.
    const fingers = new Map<number, Pt>();
    let pinchStart: { d0: number; start: ResizeStart; frame: ResizeFrame; cancel?: () => void } | undefined;
    const onDown = (e: PointerEvent): void => {
      if (e.pointerType !== "touch") return;
      fingers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (fingers.size === 2) {
        const [a, b] = [...fingers.values()] as [Pt, Pt];
        pinchStart = { d0: Math.hypot(a.x - b.x, a.y - b.y), start: limits(), frame: { width: panel.offsetWidth, height: panel.offsetHeight, top: 0, shiftX: 0 } };
      }
    };
    const onMove = (e: PointerEvent): void => {
      if (!fingers.has(e.pointerId)) return;
      fingers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (!pinchStart || fingers.size < 2) return;
      const [a, b] = [...fingers.values()] as [Pt, Pt];
      pinchStart.frame = aspectFrame(pinchStart.start, W0 / H0, Math.hypot(a.x - b.x, a.y - b.y) / pinchStart.d0, true);
      host.apply(pinchStart.frame);
    };
    const onUp = (e: PointerEvent): void => {
      fingers.delete(e.pointerId);
      if (!pinchStart || fingers.size >= 2) return;
      const ps = pinchStart;
      pinchStart = undefined;
      const range = aspectRange(ps.start, W0 / H0);
      let rest = aspectFrame(ps.start, W0 / H0, Math.min(range.max, Math.max(range.min, ps.frame.width / ps.start.width)), false);
      rest = host.snap!(rest);
      settleResize((fr) => host.apply(fr), ps.frame, rest, measure);
    };
    panel.addEventListener("pointerdown", onDown, true);
    panel.addEventListener("pointermove", onMove, true);
    panel.addEventListener("pointerup", onUp, true);
    panel.addEventListener("pointercancel", onUp, true);
    panel.style.touchAction = "none";
    const stopResize = (): void => { resize.dispose(); };
    current = { rec, morph, card, expanding: false, stopResize, cells: { cols: 0, rows: 0 } };
    morph.open();
    requestAnimationFrame(measure);
  };
  /** The float flies into its Console slot while the camera follows, one continuous motion. */
  const expandFloat = (): void => {
    const f = current;
    if (!f || f.expanding) return;
    f.expanding = true;
    f.stopResize();
    const root = f.rec.card.root;
    const panel = f.morph.panel;
    // Lay the panel out at the Console window's own width and full height, and scale it back down to
    // the size it has now, so nothing visibly changes before the flight starts.
    const rect0 = panel.getBoundingClientRect();
    const w0 = panel.offsetWidth, shown0 = panel.offsetHeight;
    const wc = root.offsetWidth || w0, fullH = root.offsetHeight;
    const s0 = w0 / wc;
    f.morph.setBox(wc, fullH, shown0 / s0);
    panel.style.transformOrigin = "0 0";
    panel.style.pointerEvents = "none";
    const rest0 = f.morph.restRect();
    const x0 = rect0.left - rest0.left, y0 = rect0.top - rest0.top;
    panel.style.transform = `translate(${x0}px, ${y0}px) scale(${s0})`;
    root.style.opacity = "0";
    cx.nav.focusWindow(f.rec);
    const done = (): void => {
      root.style.opacity = "";
      panel.style.transform = "";
      f.morph.close(true);
      dropFloat(f);
      cx.win.setActive(f.rec);
    };
    if (reduced.matches) { done(); return; }
    const progress = new Spring(0, (v) => {
      f.morph.setReveal(v);
      const rest = f.morph.restRect();
      const target = root.getBoundingClientRect();
      const sT = target.width / rest.width;
      const s = s0 + (sT - s0) * v;
      panel.style.transform = `translate(${x0 + (target.left - rest.left - x0) * v}px, ${y0 + (target.top - rest.top - y0) * v}px) scale(${s})`;
      // The last stretch crossfades float material into the window's own, so there is no pop.
      const fade = clamp((v - 0.88) / 0.12, 0, 1);
      panel.style.opacity = String(1 - fade);
      root.style.opacity = String(fade);
      if (v === 1) done();
    }, { visualDuration: 0.85 });
    restAt(progress, SCALE_REST);
    progress.set(1);
  };

  return {
    open: openFloat,
    close: closeFloat,
    expand: expandFloat,
    isOpen: () => Boolean(current && !current.expanding),
    info: () => (current ? { cols: current.cells.cols, rows: current.cells.rows, width: current.morph.panel.offsetWidth, height: current.morph.panel.offsetHeight } : undefined),
    dispose() { if (current) { current.morph.close(true); dropFloat(current); } badge.remove(); },
  };
}
