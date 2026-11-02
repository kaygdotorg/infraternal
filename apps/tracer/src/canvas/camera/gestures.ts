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
 * Scroll routing follows D275 (see `wheelRoute`): a vertical wheel gesture belongs to the content under the pointer
 * when that content can scroll the way it goes; only a gesture it cannot use moves the canvas. Everything goes
 * through `camera.drive` so the springs always agree with what the fingers did.
 */
import { columnEls, columnRect, stepWindow } from "../layout/columns";
import type { Ctx, ViewRec } from "../context";
import type { Pt } from "../layout/geometry";
import { clamp } from "./camera";
import { onDemand } from "../../on-demand";
import { setActivity } from "../../perf-activity";

export function installGestures(cx: Ctx): void {
  const { viewport, signal, camera, state, views } = cx;
  const cam = camera.cam;
  // ---- snapped gestures: a wheel or trackpad gesture moves one column or window (a long flick, two) ------
  /**
   * The column a vertical swipe steps: the one under the pointer. Columns take no pointer events (their windows do), so a
   * wheel over the 12 px gap between two stacked windows, or a window that moved under the pointer mid-step, lands on the
   * canvas and `closest` finds nothing: that swipe used to be lost (TASTE: every swipe moves). The column's box is found
   * from its geometry instead.
   */
  const columnAt = (e: WheelEvent): HTMLElement | undefined =>
    (e.target as Element).closest<HTMLElement>(".cl-col") ?? columnEls(views.get(state.currentView)!.colsEl).find((col) => { const r = columnRect(col); return e.clientX >= r.left && e.clientX <= r.right; });
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
        // Within the current view only: `goStop` clamps, so past the first or last window the camera re-aims at the stop it is
        // on, which does not move. (It used to be nudged 36 px past the end and fly back; that elastic bump is the overshoot
        // the owner asked to remove, TASTE section 3.) It never crosses into another view (that is the pill swipe, the number
        // keys, the switcher and the sidebar).
        cx.nav.goStop(c, state.snapIdx + dir);
      }
    } else {
      const colEl = columnAt(e);
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
    setActivity("pan");
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
  // While input is locked to a terminal (or to an app window or a screen, D208: its stage takes the wheel the same way), the wheel belongs to that terminal and to nothing else (D177, #113): its
  // scrollback, or the running program (mouse reporting, alternate screen: the terminal decides). The strip and the
  // canvas never move, on a wheel or on trackpad momentum. This runs in the capture phase, before any terminal or
  // column sees the event. Over the locked terminal the event goes on untouched (the terminal always consumes a
  // wheel: no native scroll, so no chaining to the strip when it reaches its top or bottom). Anywhere else on the
  // canvas it is held back and handed to the locked terminal. The work is a few property reads and one dispatch.
  viewport.addEventListener("wheel", (e) => {
    const locked = cx.inputLock.state;
    if (!locked) return;
    const host = locked.win.card.body.querySelector<HTMLElement>(".terminal-host, .aw-stage");
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
  // ---- who a vertical wheel gesture belongs to: the content under the pointer, or the canvas (D275) ------------------
  // The rule, per gesture (a run of wheel events less than 150 ms apart; momentum is part of its
  // gesture), decided by the gesture's first event:
  // - the content under the pointer can scroll the way the wheel goes (a docs page, a list, a log, the focused
  //   terminal's scrollback or its running program): the whole gesture is the content's. It scrolls natively and the
  //   canvas never moves. When it reaches its end the rest of the gesture, momentum included, is swallowed: it never
  //   carries over to the canvas.
  // - otherwise (the pointer is over nothing that scrolls that way, an unfocused terminal, a window with nothing to
  //   scroll, or content already at its end when the gesture began): the canvas has it, as before. So at a page's end
  //   a *new* gesture moves on to the neighbouring window, and the input lock is how a person prevents that handoff.
  // Horizontal-dominant gestures (Shift+wheel arrives as one) and Ctrl/Cmd (zoom) are always the canvas's. Zoomed out to thumbnails there is
  // no content to scroll, so the canvas has everything.
  let lastWheel = 0, lastSign = 0, contentGesture = false;
  /**
   * Whether the content under `target` can scroll the way the wheel goes. While the canvas is locked to windows the column
   * (or group) is the canvas's own scroller, moved by steps, so the walk stops there; a free canvas lets the column scroll.
   */
  const scrolls = (target: Element, dy: number): boolean => {
    for (let el: Element | null = target; el && el !== viewport; el = el.parentElement) {
      if (state.canvasLock && el.matches(".cl-col, .cl-group")) return false;
      if (el.classList.contains("terminal-host")) {
        // Only the focused terminal takes the wheel; an unfocused one is like any window with nothing to scroll.
        const w = state.activeWin;
        return !!(w?.card.body.contains(el) && w.binding?.wheelUse?.(dy));
      }
      // Cheap test first: most elements do not overflow, and the style read is for those that do.
      if (el.scrollHeight > el.clientHeight + 1 && /auto|scroll/.test(getComputedStyle(el).overflowY)) return dy < 0 ? el.scrollTop > 0 : el.scrollTop + el.clientHeight < el.scrollHeight - 1;
    }
    return false;
  };
  /** Routes one wheel event. False: it belongs to the content under the pointer and goes on untouched. */
  const routeWheel = (e: WheelEvent): boolean => {
    const now = performance.now(), sign = Math.sign(e.deltaY);
    const can = camera.lod === "live" && !(e.ctrlKey || e.metaKey) && scrolls(e.target as Element, e.deltaY);
    if (now - lastWheel > 150 || sign * lastSign < 0) contentGesture = can && Math.abs(e.deltaY) > Math.abs(e.deltaX);
    lastWheel = now;
    lastSign = sign || lastSign;
    if (!contentGesture) { canvasWheel(e); return true; }
    if (!can) e.preventDefault(); // the content's gesture has reached its end: the rest of it, momentum included, goes nowhere
    return !can;
  };
  const canvasWheel = (e: WheelEvent): void => {
    if (state.canvasLock) { if (cx.inputLock.state) { e.preventDefault(); return; } snapWheel(e); return; }
    if (free) free.wheel(e); else e.preventDefault(); // the free-canvas code is fetched when the lock first turns off
  };
  // Panning, pinching and zooming a free canvas are not part of the first interaction: the canvas starts locked to windows
  // (D177), and everything below is fetched the first time the lock turns off (D188). A person cannot reach the free
  // canvas without that toggle, so the code is there before the first free gesture.
  let free: { wheel(e: WheelEvent): void } | undefined;
  const loadFree = (): void => {
    if (!free) void onDemand(() => import("./gestures-free.on-demand")).then((m) => { if (!signal.aborted) free ??= m.installFreeGestures(cx); });
  };
  if (!state.canvasLock) loadFree();
  signal.addEventListener("abort", cx.nav.onLockChange(() => { if (!state.canvasLock) loadFree(); }), { once: true });
  viewport.addEventListener("wheel", (e) => { routeWheel(e); }, { passive: false, signal });
  // The terminal's own wheel handler always consumes the event (scrollback, or the running program) and stops it, so a
  // swipe that starts over a terminal never reaches the bubble listener above: the canvas moved only when the pointer
  // happened to be over something else, which looked like swipes that "stop working". So terminals are routed here, in
  // the capture phase, before the terminal sees the event (input locked to a terminal is handled above). The focused
  // terminal keeps the gestures it can use (its scrollback, or its program, D275); everything else over a terminal
  // (unfocused, nothing to scroll, already at its end) is the canvas's and goes no further.
  viewport.addEventListener("wheel", (e) => {
    if (cx.inputLock.state || !(e.target as Element).closest?.(".terminal-host")) return;
    if (routeWheel(e)) e.stopPropagation();
  }, { passive: false, capture: true, signal });
}
