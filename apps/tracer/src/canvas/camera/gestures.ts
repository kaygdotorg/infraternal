/**
 * Gestures on the canvas: wheel, trackpad, touch and pointer, and what each does in each mode (D118, D159, D177).
 *
 * Canvas lock on (snapped):
 * - a wheel or trackpad gesture moves one column or window (a long flick, two); no zoom;
 * - touch: one finger always scrolls the terminal it is on; two fingers move between windows: a horizontal drag
 *   follows the fingers and springs to the nearest column (a flick may pass two), a vertical drag steps to the
 *   window above or below in the column under them;
 * - a tap on a neighbour peeking in at the edge moves there.
 * Canvas lock off (free): wheel and drag pan, pinch and ctrl-wheel zoom, around the pointer; a tap on a view's
 * region flies in when zoomed out. The input lock freezes all of it.
 *
 * Scroll routing follows D118: a terminal under the pointer scrolls first; only a gesture it cannot use moves the
 * canvas. Everything goes through `camera.drive` so the springs always agree with what the fingers did.
 */
import { stepWindow } from "../layout/columns";
import type { Ctx, ViewRec } from "../context";
import type { Pt } from "../layout/geometry";
import type { ViewId } from "../model/types";
import { clamp } from "./camera";

export function installGestures(cx: Ctx): void {
  const { viewport, world, signal, camera, state, views } = cx;
  const cam = camera.cam;
  const touches = new Map<number, Pt>();
  let pinch: { d0: number; z0: number; wp: Pt } | undefined;
  let pan: { id: number; x: number; y: number; cx: number; cy: number; moved: boolean; target: Element } | undefined;
  const interactive = (t: EventTarget | null): boolean => !!(t as Element | null)?.closest?.(".ui-window, .cl-label, .cl-edge, .cl-port, .cl-empty-add, .cl-arrow-handle");
  // ---- snapped gestures: a wheel or trackpad gesture moves one column or window (a long flick, two) ------
  const wheelG = { t: 0, x: 0, y: 0, fired: 0, axis: "", m: 0, fell: false, s: 0 };
  const snapWheel = (e: WheelEvent): void => {
    e.preventDefault();
    if (e.ctrlKey || e.metaKey) return; // no zoom while snapped
    const now = performance.now();
    let dx = e.deltaX, dy = e.deltaY;
    if (e.shiftKey && !dx) { dx = dy; dy = 0; }
    // A new swipe can start inside the previous one's momentum tail, so idleness alone cannot end a gesture: the
    // tail only ever decays, so a clear rise after a fall (or a flip of direction) is a finger on the pad again.
    const m = Math.hypot(dx, dy), sign = Math.sign(dx || dy);
    const fresh = wheelG.fell && m - wheelG.m >= 4 && m > wheelG.m * 1.5 || !!wheelG.s && !!sign && sign !== wheelG.s;
    if (now - wheelG.t > 140 || fresh) { wheelG.x = 0; wheelG.y = 0; wheelG.fired = 0; wheelG.axis = ""; wheelG.fell = false; }
    if (m < wheelG.m * 0.9) wheelG.fell = true;
    wheelG.m = m; wheelG.s = sign || wheelG.s;
    wheelG.t = now;
    wheelG.x += dx; wheelG.y += dy;
    if (!wheelG.axis && Math.hypot(wheelG.x, wheelG.y) > 24) wheelG.axis = Math.abs(wheelG.x) > Math.abs(wheelG.y) ? "x" : "y";
    if (!wheelG.axis) return;
    const total = wheelG.axis === "x" ? wheelG.x : wheelG.y;
    const due = wheelG.fired === 0 ? Math.abs(total) >= 24 : wheelG.fired === 1 && Math.abs(total) >= 900;
    if (!due) return;
    wheelG.fired++;
    const dir = Math.sign(total);
    if (wheelG.axis === "x") {
      const c = views.get(state.currentView);
      if (c) {
        // Within the current view only: past the first or last window the camera rubber-bands and comes back. It
        // never crosses into another view (that is the pill swipe, the number keys, the switcher and the sidebar).
        const last = cx.nav.stopsFor(c).lefts.length - 1, next = state.snapIdx + dir;
        if (next < 0 || next > last) camera.drive({ cx: cam.cx + dir * 36 / cam.z });
        cx.nav.goStop(c, next);
      }
    } else {
      const colEl = (e.target as Element).closest<HTMLElement>(".cl-col");
      if (colEl) stepWindow(colEl, dir);
    }
  };
  /**
   * Touch: one finger always scrolls the terminal it is on. Two fingers move between windows: a
   * horizontal drag follows the fingers and springs to the nearest column (a flick may pass two), a
   * vertical drag steps to the window above or below in the column under them.
   */
  let two: { x: number; y: number; cx0: number; idx0: number; axis: "" | "x" | "y"; stepped: boolean; col: HTMLElement | null; samples: Array<{ x: number; t: number }> } | undefined;
  const centroid = (e: TouchEvent): Pt => ({ x: (e.touches[0]!.clientX + e.touches[1]!.clientX) / 2, y: (e.touches[0]!.clientY + e.touches[1]!.clientY) / 2 });
  viewport.addEventListener("touchstart", (e) => {
    if (!state.canvasLock || cx.inputLock.state || e.touches.length !== 2) return;
    const c = centroid(e);
    camera.takeOver();
    two = { x: c.x, y: c.y, cx0: cam.cx, idx0: state.snapIdx, axis: "", stepped: false, col: (document.elementFromPoint(c.x, c.y) as Element | null)?.closest<HTMLElement>(".cl-col") ?? null, samples: [{ x: c.x, t: e.timeStamp }] };
  }, { passive: true, capture: true, signal });
  viewport.addEventListener("touchmove", (e) => {
    if (!two || e.touches.length !== 2) return;
    const c = centroid(e);
    if (!two.axis) {
      const dx = c.x - two.x, dy = c.y - two.y;
      if (Math.hypot(dx, dy) < 10) return;
      two.axis = Math.abs(dx) > Math.abs(dy) ? "x" : "y";
    }
    if (e.cancelable) e.preventDefault();
    if (two.axis === "y") {
      if (!two.stepped && Math.abs(c.y - two.y) > 36 && two.col) { two.stepped = true; stepWindow(two.col, Math.sign(two.y - c.y)); }
      return;
    }
    const cl = views.get(state.currentView);
    if (!cl) return;
    const st = cx.nav.stopsFor(cl);
    const lo = st.lefts[0]! + st.view / 2, hi = st.lefts[st.lefts.length - 1]! + st.view / 2;
    let x = two.cx0 - (c.x - two.x) / cam.z;
    if (x < lo) x = lo - Math.min(60, (lo - x) * 0.3); else if (x > hi) x = hi + Math.min(60, (x - hi) * 0.3);
    camera.drive({ cx: x });
    two.samples.push({ x: c.x, t: e.timeStamp });
    if (two.samples.length > 6) two.samples.shift();
  }, { passive: false, capture: true, signal });
  const twoEnd = (e: TouchEvent): void => {
    const t = two;
    if (!t || e.touches.length >= 2) return;
    two = undefined;
    if (t.axis !== "x") return;
    const cl = views.get(state.currentView);
    if (!cl) return;
    const first = t.samples[0]!, last = t.samples[t.samples.length - 1]!;
    const v = last.t > first.t ? (last.x - first.x) / (last.t - first.t) : 0; // px per ms, finger direction
    const projected = cam.cx - (v * 160) / cam.z;
    const allowed = Math.abs(v) > 1.2 ? 2 : 1;
    cx.nav.goStop(cl, clamp(cx.nav.nearestStop(cl, projected), t.idx0 - allowed, t.idx0 + allowed));
  };
  viewport.addEventListener("touchend", twoEnd, { capture: true, signal });
  viewport.addEventListener("touchcancel", twoEnd, { capture: true, signal });
  // A tap on empty canvas (a gap between windows) clears the active window and gives up input focus, so the toolbar shows its canvas row.
  viewport.addEventListener("click", (e) => {
    if ((e.target as Element).closest(".ui-window, .cl-label, .cl-edge, button")) return;
    cx.win.setActive(undefined);
    const active = document.activeElement;
    if (active instanceof HTMLElement && active !== document.body) active.blur();
  }, { signal });
  // A tap on a neighbour peeking in at the edge moves there.
  viewport.addEventListener("click", (e) => {
    if (!state.canvasLock || cx.inputLock.state) return;
    const colEl = (e.target as Element).closest<HTMLElement>(".cl-col");
    if (!colEl || (e.target as Element).closest("button, .ui-window-pill, .cl-port")) return;
    const first = colEl.querySelector<HTMLElement>(":scope > .ui-window");
    // The window's own box decides whether it is peeking in: its column also holds the gap, which at the last
    // stop reaches past the viewport although the window is fully shown (a tap there was swallowed every time).
    const vp = viewport.getBoundingClientRect(), r = (first ?? colEl).getBoundingClientRect();
    if (r.left > vp.left - 1 && r.right < vp.right + 1) return;
    const rec = first ? [...views.values()].flatMap((cl) => [...cl.wins.values()]).find((w) => w.card.root === first) : undefined;
    if (rec) { e.stopPropagation(); e.preventDefault(); cx.win.setActive(rec); cx.nav.focusWindow(rec); }
  }, { capture: true, signal });
  // While input is locked to a terminal, the wheel belongs to that terminal and to nothing else (D177, #113): its
  // scrollback, or the running program (mouse reporting, alternate screen: the terminal decides). The strip and the
  // canvas never move, on a wheel or on trackpad momentum. This runs in the capture phase, before any terminal or
  // column sees the event. Over the locked terminal the event goes on untouched (the terminal always consumes a
  // wheel: no native scroll, so no chaining to the strip when it reaches its top or bottom). Anywhere else on the
  // canvas it is held back and handed to the locked terminal. The work is a few property reads and one dispatch.
  viewport.addEventListener("wheel", (e) => {
    const locked = cx.inputLock.state;
    if (!locked) return;
    const host = locked.win.card.body.querySelector<HTMLElement>(".terminal-host");
    if (host && host.contains(e.target as Node)) return;
    e.preventDefault();
    e.stopPropagation();
    if (!host || e.ctrlKey || e.metaKey) return;
    const r = host.getBoundingClientRect();
    const forwarded = new WheelEvent("wheel", {
      deltaX: e.deltaX, deltaY: e.deltaY, deltaMode: e.deltaMode, bubbles: true, cancelable: true, composed: true,
      clientX: r.left + r.width / 2, clientY: r.top + r.height / 2, shiftKey: e.shiftKey,
    });
    host.dispatchEvent(forwarded);
  }, { passive: false, capture: true, signal });
  viewport.addEventListener("wheel", (e) => {
    if (state.canvasLock) { if (cx.inputLock.state) { e.preventDefault(); return; } snapWheel(e); return; }
    const inCol = (e.target as Element).closest(".cl-col");
    if (!(e.ctrlKey || e.metaKey) && inCol && Math.abs(e.deltaY) > Math.abs(e.deltaX) && camera.lod === "live") {
      const colEl = inCol as HTMLElement;
      const canScroll = colEl.scrollHeight > colEl.clientHeight + 1 && (e.deltaY < 0 ? colEl.scrollTop > 0 : colEl.scrollTop + colEl.clientHeight < colEl.scrollHeight - 1);
      if (canScroll) return;
    }
    e.preventDefault();
    camera.takeOver();
    if (e.ctrlKey || e.metaKey) { camera.zoomAt(e.clientX, e.clientY, cam.z * Math.exp(-e.deltaY * (e.ctrlKey ? 0.01 : 0.0025))); return; }
    const dx = e.shiftKey && !e.deltaX ? e.deltaY : e.deltaX, dy = e.shiftKey ? 0 : e.deltaY;
    camera.drive({ cx: cam.cx + dx / cam.z, cy: cam.cy + dy / cam.z });
  }, { passive: false, signal });
  viewport.addEventListener("pointerdown", (e) => {
    if (e.pointerType === "touch") touches.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (state.canvasLock) return;
    if (e.pointerType === "touch") {
      if (touches.size === 2) {
        const [a, b] = [...touches.values()] as [Pt, Pt];
        camera.stop();
        camera.target = undefined;
        pan = undefined;
        pinch = { d0: Math.hypot(a.x - b.x, a.y - b.y), z0: cam.z, wp: camera.toWorld((a.x + b.x) / 2, (a.y + b.y) / 2) };
        return;
      }
    }
    if (interactive(e.target) || e.button === 2) return;
    const target = e.target as Element;
    pan = { id: e.pointerId, x: e.clientX, y: e.clientY, cx: cam.cx, cy: cam.cy, moved: false, target };
    viewport.setPointerCapture(e.pointerId);
  }, { signal, capture: true });
  viewport.addEventListener("pointermove", (e) => {
    if (e.pointerType === "touch" && touches.has(e.pointerId)) touches.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (state.canvasLock) return;
    if (pinch && touches.size >= 2) {
      const [a, b] = [...touches.values()] as [Pt, Pt];
      const z = clamp(pinch.z0 * (Math.hypot(a.x - b.x, a.y - b.y) / pinch.d0), 0.08, 2);
      const r = viewport.getBoundingClientRect();
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      camera.drive({ z, cx: pinch.wp.x - (mx - r.left - camera.vw / 2) / z, cy: pinch.wp.y - (my - r.top - camera.vh / 2) / z });
      return;
    }
    if (!pan || e.pointerId !== pan.id) return;
    if (!pan.moved && Math.hypot(e.clientX - pan.x, e.clientY - pan.y) < 6) return;
    if (!pan.moved) { pan.moved = true; camera.takeOver(); viewport.dataset.panning = ""; cx.view.hideSummary(); }
    camera.drive({ cx: pan.cx - (e.clientX - pan.x) / cam.z, cy: pan.cy - (e.clientY - pan.y) / cam.z });
  }, { signal });
  const pointerEnd = (e: PointerEvent): void => {
    touches.delete(e.pointerId);
    if (state.canvasLock) return;
    if (touches.size < 2) pinch = undefined;
    if (!pan || e.pointerId !== pan.id) return;
    const p = pan;
    pan = undefined;
    delete viewport.dataset.panning;
    if (p.moved) return;
    // A tap on a Mesh cluster frame: the pan captured the pointer, so the frame never got its click; give it one.
    const chip = p.target.closest?.<HTMLElement>(".cl-chip");
    if (chip) { chip.click(); return; }
    // A tap: on a view's region it flies in; on empty canvas it clears the active window.
    const region = p.target.closest?.(".cl-region");
    const c = [...views.values()].find((x) => x.region === region);
    if (c && (camera.band === "out" || camera.lod === "thumb")) cx.nav.flyView(c.view.id);
    else if (!region) cx.win.setActive(undefined);
  };
  viewport.addEventListener("pointerup", pointerEnd, { signal });
  viewport.addEventListener("pointercancel", pointerEnd, { signal });
  // A thumbnail window is read-only: a tap on it flies into its view.
  world.addEventListener("click", (e) => {
    if (camera.lod !== "thumb") return;
    const cl = (e.target as Element).closest<HTMLElement>(".cl");
    if (cl?.dataset.view && !(e.target as Element).closest(".cl-label") && !pan) cx.nav.flyView(cl.dataset.view as ViewId);
  }, { signal });
  document.addEventListener("pointerdown", (e) => {
    if (cx.mesh?.reachPinned() && !(e.target as Element).closest(".cl-port, .ui-window-pill, .ui-confirm-tip, .cl-edge")) cx.mesh.hideReach();
  }, { signal, capture: true });

}
