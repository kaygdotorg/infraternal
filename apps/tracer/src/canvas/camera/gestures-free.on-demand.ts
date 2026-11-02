/**
 * The free canvas's gestures (the canvas lock off, D177): a wheel pans, Ctrl/Cmd+wheel zooms about the pointer, a drag pans,
 * two fingers pinch, a tap on a view's region flies in when zoomed out and a tap on bare canvas clears the active window.
 *
 * Its own chunk (D188): the canvas starts locked to windows and only the lock toggle, the overview, a free view (Mesh) or the
 * input lock's restore turn it off, so none of this is needed for the first interaction. `gestures.ts` fetches it when the lock
 * first turns off and hands wheel events to `wheel`; the pointer listeners below already check the lock themselves.
 */
import type { Ctx } from "../context";
import type { Pt } from "../layout/geometry";
import type { ViewId } from "../model/types";
import { clamp } from "./camera";
import { setActivity } from "../../perf-activity";

export function installFreeGestures(cx: Ctx): { wheel(e: WheelEvent): void } {
  const { viewport, world, signal, camera, state, views } = cx;
  const cam = camera.cam;
  const touches = new Map<number, Pt>();
  let pinch: { d0: number; z0: number; wp: Pt } | undefined;
  let pan: { id: number; x: number; y: number; cx: number; cy: number; moved: boolean; target: Element } | undefined;
  const interactive = (t: EventTarget | null): boolean => !!(t as Element | null)?.closest?.(".ui-window, .cl-label, .cl-edge, .cl-port, .cl-empty-add, .cl-arrow-handle");
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
      setActivity("zoom");
      camera.drive({ z, cx: pinch.wp.x - (mx - r.left - camera.vw / 2) / z, cy: pinch.wp.y - (my - r.top - camera.vh / 2) / z });
      return;
    }
    if (!pan || e.pointerId !== pan.id) return;
    if (!pan.moved && Math.hypot(e.clientX - pan.x, e.clientY - pan.y) < 6) return;
    if (!pan.moved) { pan.moved = true; camera.takeOver(); viewport.dataset.panning = ""; cx.view.hideSummary(); }
    setActivity("pan");
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
  return {
    wheel(e) {
      e.preventDefault();
      camera.takeOver();
      if (e.ctrlKey || e.metaKey) { setActivity("zoom"); camera.zoomAt(e.clientX, e.clientY, cam.z * Math.exp(-e.deltaY * (e.ctrlKey ? 0.01 : 0.0025))); return; }
      const dx = e.shiftKey && !e.deltaX ? e.deltaY : e.deltaX, dy = e.shiftKey ? 0 : e.deltaY;
      setActivity("pan");
      camera.drive({ cx: cam.cx + dx / cam.z, cy: cam.cy + dy / cam.z });
    },
  };
}
