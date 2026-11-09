// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The row menu and row swipes (D309, #242): one component for every list of rows (sessions, hosts, Mesh nodes,
 * windows). A list says which element is a row and what its row can do (`RowMenuSource`); this module owns the
 * gestures and the one menu, so every list behaves the same way.
 *
 * - Pointer: a right-click on a row opens our menu at the pointer (the page's own menu would offer Look Up, Print and
 *   the like, none of which concern a row). The row's text is never selected by the press (`.ui-swipe-row` is
 *   `user-select: none`). Shift + right-click is the one way to the browser's own menu, for a developer who wants
 *   Inspect: it is not drawn or mentioned anywhere.
 * - Keyboard: the context-menu key and Shift+F10 open the same menu under the focused row, with focus on its first
 *   row and no motion (keyboard-opened overlays stay instant, TASTE). `actionsFor` feeds the palette, so each action
 *   is also a palette row for the focused row.
 * - Touch: a long press opens the menu at the finger.
 * - Swipe (touch, trackpad two-finger scroll, Magic Mouse): the row follows the gesture 1:1 and the action of that
 *   direction is revealed behind it. A short swipe leaves the button revealed (a tap on it performs the action); a
 *   long one performs it. An action that asks first (ending a session) asks in the row itself (row-confirm.ts) instead
 *   of acting. Every frame writes only transforms; they are cleared at rest, so text stays crisp.
 * - A swipe is one continuous motion (TASTE "A swipe that creates is continuous"): the row never jumps when the drag is
 *   recognised (the few pixels of slop are caught up over about 100 ms), the button's fill and icon build towards the
 *   threshold, and a release hands the finger's velocity to the spring. An action whose row stays (`swipeKeeps`: opening
 *   a session beside) acts at once and the row settles back from where the finger left it; only a row the list removes
 *   slides out.
 *
 * An action says its direction (`swipe: "left" | "right"`); a row without an action in the gesture's direction gives
 * a little and comes back. Nothing here knows what a row is: the list's code runs the action.
 */
import { Spring, type SpringConfig } from "./spring";
import { mountRowAsk } from "./row-confirm";

export interface RowAction {
  id: string;
  label: string;
  /** Inner SVG markup on the 24 px grid (the shared icons). */
  icon: string;
  run(row: HTMLElement): void;
  /** Drawn in the danger colour after a hairline; the menu's last row. */
  danger?: boolean;
  /**
   * Asks before running, in the row itself: `run` happens only once the person confirms. `question` is what the row
   * says ("End session?"), `confirmLabel` the answer that does it ("End"); `title` names the group for assistive
   * technology and `effect` (never drawn) is read out with it.
   */
  confirm?: { title: string; question: string; shortQuestion?: string; effect?: string; confirmLabel: string; cancelLabel?: string };
  /** The row is still in its list after the swipe action ran (it opens something else): it settles back instead of leaving. */
  swipeKeeps?: boolean;
  /** Revealed by a swipe in this direction (a left swipe moves the row left and shows what is on its right). */
  swipe?: "left" | "right";
  /** The words on the revealed button when they are shorter than the menu's ("End" for "End session…"). */
  swipeLabel?: string;
  /** The palette's words when they differ from the menu's (it names the row: "Rename 'deploy'"). */
  paletteLabel?: string;
}

export interface RowMenuSource {
  /** The element the menus and confirmations float over (the screen). */
  stage: HTMLElement;
  /** The row a press or key landed on, or nothing when the target is not a row of this list. */
  rowAt(target: Element): HTMLElement | undefined;
  /** What this row can do, in menu order. An empty list opens nothing. */
  actions(row: HTMLElement): RowAction[];
  /** What takes the focus back when the menu closes, and anchors a confirmation. Default: the row itself. */
  anchorOf?(row: HTMLElement): HTMLElement;
  /** The row's own label, where an in-row question starts. */
  labelOf?(row: HTMLElement): Element | null;
}

export interface RowMenu {
  /** Opens the menu for a row (the palette and tests use it too). */
  open(row: HTMLElement, how: "keyboard" | "pointer", at?: { x: number; y: number }): void;
  /** Runs one action, asking first (in the row) when it says so. The palette passes "keyboard": the question then opens instantly, focused. */
  perform(row: HTMLElement, action: RowAction, how?: "keyboard" | "pointer"): void;
  /** Closes an open menu and any revealed row. */
  close(): void;
  dispose(): void;
}

// A tap settles on the ease-out curve and a release flings from the finger, critically damped: never past the target
// (TASTE: no overshoot, ever; the row settles, it does not bounce). Both at most 300 ms (#471).
const OPEN: SpringConfig = { visualDuration: 0.24 };
const SHUT: SpringConfig = { visualDuration: 0.24 };
/** A swipe moves at most this far past the revealed button before the row stops following (never past its own width). */
const MIN_REVEAL = 72;
const LONG_PRESS = 480;
const WHEEL_GAP = 110;
const reduced = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;

interface Layer { side: "left" | "right"; action: RowAction; node: HTMLElement; inner: HTMLElement; icon: HTMLElement; width: number; arm: number }

/** One row being swiped: its leaf and the layers behind it. Built when a gesture starts, torn down once it rests closed. */
class Swipe {
  readonly leaf: HTMLElement;
  readonly layers: Layer[] = [];
  readonly spring: Spring;
  /** Where the row rests: 0 closed, otherwise minus or plus the revealed button's width. */
  rest = 0;
  /** While the row settles shut: the side it came from (-1 left, 1 right). It must not cross to the other side, which would flash that side's button. */
  private closing = 0;
  x = 0;
  rowWidth = 0;
  private armed: Layer | undefined;
  /** Runs once when the row has slid fully out for a long swipe. */
  private arrive: (() => void) | undefined;
  /** A finger is moving the row: crossing the threshold also ticks the device's haptic motor where it has one. */
  haptic = false;

  constructor(readonly row: HTMLElement, actions: RowAction[]) {
    this.leaf = row.firstElementChild as HTMLElement;
    row.classList.add("ui-swipe-row");
    // A leaf eases its own transform (the press scale, 140 ms): left on, it would trail the finger by that long and the row
    // would never be under it. While the swipe lives, the swipe owns the transform; only the fade of the in-row question stays.
    this.leaf.style.transition = "opacity 150ms var(--ease-out, ease-out)";
    for (const action of actions) {
      if (!action.swipe) continue;
      const node = document.createElement("div");
      node.className = "ui-row-swipe-act";
      node.dataset.side = action.swipe;
      node.dataset.action = action.id;
      if (action.danger) node.dataset.tone = "danger";
      node.setAttribute("aria-hidden", "true");
      const inner = document.createElement("span");
      inner.className = "ui-row-swipe-in";
      const icon = document.createElement("span");
      icon.className = "ui-row-swipe-icon";
      icon.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${action.icon}</svg>`;
      const label = document.createElement("span");
      label.textContent = action.swipeLabel ?? action.label.replace(/…$/, "");
      inner.append(icon, label);
      node.append(inner);
      row.append(node);
      this.layers.push({ side: action.swipe, action, node, inner, icon, width: 0, arm: 0 });
    }
    // One layout read for every layer, after all are in.
    this.rowWidth = row.offsetWidth;
    for (const layer of this.layers) {
      layer.width = Math.max(MIN_REVEAL, layer.inner.offsetWidth);
      layer.inner.style.width = `${layer.width}px`;
    }
    this.spring = new Spring(0, (value) => this.paint(this.closing > 0 ? Math.max(0, value) : this.closing < 0 ? Math.min(0, value) : value), OPEN);
  }

  layer(side: "left" | "right"): Layer | undefined { return this.layers.find((l) => l.side === side); }
  /** The distance past which the swipe performs instead of revealing. */
  longAt(layer: Layer): number { return Math.min(this.rowWidth * 0.8, Math.max(layer.width + 56, this.rowWidth * 0.5)); }

  paint(value: number): void {
    this.x = value;
    const t = value ? `translate3d(${value}px,0,0)` : "";
    this.leaf.style.transform = t;
    for (const layer of this.layers) {
      const active = layer.side === "left" ? value < 0 : value > 0;
      // The layer's box travels with the row and clips; its button stays pinned to the row's own edge, so the label is
      // never squeezed or shifted, only uncovered (and faded in over the first stretch). Transform and opacity only.
      layer.node.style.transform = active ? t : "";
      const behind = active ? Math.max(0, layer.width - Math.abs(value)) : layer.width;
      layer.inner.style.transform = behind ? `translate3d(${layer.side === "left" ? -behind : behind}px,0,0)` : "";
      layer.inner.style.opacity = active ? String(Math.min(1, Math.abs(value) / (layer.width * 0.7))) : "0";
    }
    const side = value < 0 ? "left" : value > 0 ? "right" : undefined;
    const layer = side && this.layer(side);
    // The cue builds from the revealed button's width up to the threshold, so it is felt before it is crossed (--arm, 0 to 1).
    for (const l of this.layers) {
      const arm = l === layer ? Math.min(1, Math.max(0, (Math.abs(value) - l.width) / Math.max(1, this.longAt(l) - l.width))) : 0;
      if (Math.abs(arm - l.arm) > 0.004 || (arm === 0) !== (l.arm === 0)) { l.arm = arm; l.node.style.setProperty("--arm", arm ? arm.toFixed(3) : "0"); }
    }
    const armed = layer && Math.abs(value) >= this.longAt(layer) ? layer : undefined;
    if (armed !== this.armed) {
      this.armed?.node.toggleAttribute("data-armed", false);
      armed?.node.toggleAttribute("data-armed", true);
      if (armed && this.haptic && "vibrate" in navigator) navigator.vibrate(8);
      this.armed = armed;
    }
    if (this.arrive && Math.abs(value) >= this.rowWidth - 1) { const run = this.arrive; this.arrive = undefined; run(); }
  }

  /** Follows the gesture 1:1 inside the row; a direction with no action gives a little (a fifth, up to 24 px). */
  follow(target: number): void {
    this.closing = 0;
    const layer = this.layer(target < 0 ? "left" : "right");
    const bound = this.rowWidth;
    const value = layer ? Math.max(-bound, Math.min(bound, target)) : Math.sign(target) * Math.min(24, Math.abs(target) * 0.2);
    this.spring.value = value;
    this.paint(value);
    this.spring.set(value, true);
  }

  /** Springs to `value`; `velocity` (px/s) is the finger's, so the motion goes on from where the release left it. */
  to(value: number, then?: () => void, velocity = 0): void {
    this.arrive = then && Math.abs(value) >= this.rowWidth - 1 ? then : undefined;
    // Shutting: critically damped and held to its own side. 
    this.closing = value === 0 ? Math.sign(this.x) : 0;
    this.spring.configure(value === 0 ? SHUT : OPEN);
    if (velocity) this.spring.fling(value, velocity); else this.spring.set(value);
  }

  /** The layer to settle on for a release at the current position, or undefined to close. */
  settle(flick: number): { layer: Layer; perform: boolean } | undefined {
    const layer = this.layer(this.x < 0 ? "left" : "right");
    if (!layer || !this.x) return undefined;
    const distance = Math.abs(this.x);
    if (distance >= this.longAt(layer)) return { layer, perform: true };
    // A flick towards the layer reveals it from a shorter pull.
    const toward = Math.sign(flick) === Math.sign(this.x);
    if (distance >= layer.width / 2 || (toward && Math.abs(flick) > 0.5 && distance > 14)) return { layer, perform: false };
    return undefined;
  }

  restoreAt(value: number): void { this.rest = value; this.row.toggleAttribute("data-swiped", value !== 0); if (value) this.row.dataset.swiped = value < 0 ? "left" : "right"; }

  dispose(): void {
    this.spring.set(0, true);
    for (const layer of this.layers) layer.node.remove();
    this.leaf.style.transition = "";
    this.row.removeAttribute("data-swiped");
  }
}

export function attachRowMenu(host: HTMLElement, source: RowMenuSource): RowMenu {
  const anchorOf = (row: HTMLElement): HTMLElement => source.anchorOf?.(row) ?? row;
  const events = new AbortController();
  const { signal } = events;
  let swipe: Swipe | undefined;
  let menu: { close(how: "keyboard" | "pointer"): void } | undefined;
  let menuRow: HTMLElement | undefined;
  let confirm: { close(restore?: boolean): void } | undefined;
  /** A drag, a long press or a wheel gesture that just ended must not become a click on the row. */
  let swallowClickUntil = 0;
  const swallow = (): void => { swallowClickUntil = performance.now() + 350; };

  // The menu's code loads once the first list that can use it is built, when the page is idle (D188).
  const warm = (): void => { void import("./window-menu.on-demand"); };
  const idle = (window as unknown as { requestIdleCallback?: (cb: () => void) => void }).requestIdleCallback;
  if (idle) idle.call(window, warm); else window.setTimeout(warm, 600);

  const closeSwipe = (animate = true, velocity = 0): void => {
    const s = swipe;
    if (!s) return;
    swipe = undefined;
    if (!animate || reduced()) { s.dispose(); return; }
    s.rest = 0;
    s.to(0, undefined, velocity);
    // Torn down once it has come to rest (the spring has settled within a few frames of its duration).
    window.setTimeout(() => { if (swipe !== s) s.dispose(); }, 520);
  };

  const perform = (row: HTMLElement, action: RowAction, how: "keyboard" | "pointer" = "pointer"): void => {
    if (!action.confirm) { action.run(row); return; }
    confirm?.close(false);
    const c = action.confirm;
    // The row settles shut while the question fades in over it; Cancel and Escape leave it shut.
    closeSwipe();
    confirm = mountRowAsk(row, anchorOf(row), {
      label: c.title, question: c.question, alignTo: source.labelOf?.(row) ?? null, ...(c.shortQuestion ? { shortQuestion: c.shortQuestion } : {}), ...(c.effect ? { effect: c.effect } : {}),
      confirmLabel: c.confirmLabel, cancelLabel: c.cancelLabel ?? "Cancel", keyboard: how === "keyboard",
      onConfirm: () => { confirm = undefined; action.run(row); },
      onCancel: () => { confirm = undefined; },
    });
  };

  const closeMenu = (how: "keyboard" | "pointer" = "pointer"): void => { menu?.close(how); };

  const open = (row: HTMLElement, how: "keyboard" | "pointer", at?: { x: number; y: number }): void => {
    const actions = source.actions(row);
    if (!actions.length) return;
    closeMenu("keyboard");
    closeSwipe(false);
    const anchor = anchorOf(row);
    const box = row.getBoundingClientRect();
    const point = at ?? { x: box.left + Math.min(40, box.width / 2), y: box.bottom - 2 };
    void import("./window-menu.on-demand").then((m) => {
      const popover = m.openWindowMenu(source.stage, anchor, actions.map((a) => ({
        id: a.id, label: a.label, icon: a.icon, ...(a.danger ? { danger: true } : {}),
        run: (event) => perform(row, a, event?.detail === 0 ? "keyboard" : how),
      })), how, () => { if (menuRow === row) { menu = undefined; menuRow = undefined; } },
      { label: "Row actions", hug: true, align: "start", maxWidth: 260, at: point });
      menu = popover;
      menuRow = row;
    });
  };

  // ---- pointer and keyboard menus -----------------------------------------------------------------------------
  host.addEventListener("contextmenu", (event) => {
    const row = event.target instanceof Element ? source.rowAt(event.target) : undefined;
    if (!row || event.shiftKey) return; // Shift + right-click: the browser's own menu, for developers.
    event.preventDefault();
    if (performance.now() < longPressOpenedUntil) return; // the long press already opened it
    open(row, "pointer", { x: event.clientX, y: event.clientY });
  }, { signal });
  host.addEventListener("keydown", (event) => {
    if (!(event.key === "ContextMenu" || (event.key === "F10" && event.shiftKey)) || !(event.target instanceof Element)) return;
    const row = source.rowAt(event.target);
    if (!row) return;
    event.preventDefault();
    event.stopPropagation();
    open(row, "keyboard");
  }, { signal });
  // A press that goes to a row text must not select it, whatever the button.
  host.addEventListener("mousedown", (event) => {
    if (event.button === 2 && event.target instanceof Element && source.rowAt(event.target) && !event.shiftKey) event.preventDefault();
  }, { signal });

  // ---- swipe: shared driver -----------------------------------------------------------------------------------
  const startSwipe = (row: HTMLElement): Swipe | undefined => {
    if (swipe?.row === row) return swipe;
    closeSwipe(false);
    const actions = source.actions(row);
    if (!actions.some((a) => a.swipe)) return undefined;
    swipe = new Swipe(row, actions);
    return swipe;
  };
  /** `flick` is the finger's velocity in px/ms at release (0 for a wheel gesture). */
  const release = (flick: number): void => {
    const s = swipe;
    if (!s) return;
    const velocity = flick * 1000;
    const choice = s.settle(flick);
    if (!choice) { closeSwipe(true, velocity); return; }
    const sign = choice.layer.side === "left" ? -1 : 1;
    if (!choice.perform) { s.rest = sign * choice.layer.width; s.restoreAt(s.rest); s.to(s.rest, undefined, velocity); return; }
    const action = choice.layer.action;
    swallow();
    // Asks first: the question fades in over the row while the row settles shut.
    if (action.confirm) { perform(s.row, action); return; }
    if (action.swipeKeeps) {
      // The row stays in its list, so it never leaves the screen: the action runs now and the row settles back from where
      // the finger let go, carrying the finger's speed (a row thrown off the screen and snapped back read as a glitch).
      action.run(s.row);
      closeSwipe(true, velocity);
      return;
    }
    s.to(sign * s.rowWidth, () => { action.run(s.row); closeSwipe(false); }, velocity);
    // A row that stays (the action opens something else) comes back; one the list removes is gone with its DOM.
    window.setTimeout(() => { if (swipe === s) closeSwipe(); }, 400);
  };

  // ---- touch and pen ------------------------------------------------------------------------------------------
  let longPressOpenedUntil = 0;
  /** The pointer whose long press opened the menu: the click its release makes must not open the row. */
  let pressed: number | undefined;
  let touch: { id: number; row: HTMLElement; x: number; y: number; base: number; dragging: boolean; samples: { t: number; x: number }[]; timer: number; dx: number; lag: number; frame: number; at: number } | undefined;
  /**
   * A drag is recognised after a few pixels of slop. The row must not jump by them in one frame, and it must stay 1:1 with
   * the finger afterwards, so the row starts at the finger's position minus the slop and catches up with it over about
   * 100 ms (`lag` decays to 0); from then on it is exactly under the finger.
   */
  const CATCH_UP = 70;
  const catchUp = (t: NonNullable<typeof touch>, now: number): void => {
    t.frame = 0;
    if (touch !== t || !t.dragging) return;
    t.lag *= Math.exp(-Math.max(0, Math.min(48, now - t.at)) / CATCH_UP);
    t.at = now;
    if (Math.abs(t.lag) < 0.25) t.lag = 0;
    swipe?.follow(t.base + t.dx - t.lag);
    if (t.lag) t.frame = requestAnimationFrame((next) => catchUp(t, next));
  };
  host.addEventListener("pointerdown", (event) => {
    if (event.pointerType === "mouse" || !event.isPrimary || !(event.target instanceof Element)) return;
    const row = source.rowAt(event.target);
    if (!row) return;
    if (event.target.closest(".ui-row-swipe-act")) return;
    if (swipe && swipe.row !== row) closeSwipe();
    const base = swipe?.row === row ? swipe.rest : 0;
    const t = { id: event.pointerId, row, x: event.clientX, y: event.clientY, base, dragging: false, samples: [{ t: event.timeStamp, x: event.clientX }], timer: 0, dx: 0, lag: 0, frame: 0, at: 0 };
    t.timer = window.setTimeout(() => {
      if (touch !== t || t.dragging) return;
      touch = undefined;
      pressed = t.id;
      longPressOpenedUntil = performance.now() + 700;
      open(row, "pointer", { x: t.x, y: t.y });
    }, LONG_PRESS);
    touch = t;
  }, { signal });
  host.addEventListener("pointermove", (event) => {
    const t = touch;
    if (!t || event.pointerId !== t.id) return;
    const dx = event.clientX - t.x, dy = event.clientY - t.y;
    if (!t.dragging) {
      if (Math.abs(dy) > 10 && Math.abs(dy) > Math.abs(dx)) { window.clearTimeout(t.timer); touch = undefined; return; }
      if (Math.abs(dx) < 8 || Math.abs(dx) < Math.abs(dy) * 1.4) return;
      window.clearTimeout(t.timer);
      const s = startSwipe(t.row);
      if (!s) { touch = undefined; return; }
      t.dragging = true;
      s.haptic = true;
      t.lag = reduced() ? 0 : Math.sign(dx) * Math.min(Math.abs(dx), 24);
      t.at = event.timeStamp;
      try { host.setPointerCapture(event.pointerId); } catch { /* A pointer that ended in between has nothing to capture. */ }
    }
    t.samples.push({ t: event.timeStamp, x: event.clientX });
    if (t.samples.length > 6) t.samples.shift();
    t.dx = dx;
    swipe?.follow(t.base + dx - t.lag);
    if (t.lag && !t.frame) { t.at = performance.now(); t.frame = requestAnimationFrame((now) => catchUp(t, now)); }
  }, { signal });
  const end = (event: PointerEvent): void => {
    if (event.pointerId === pressed) { pressed = undefined; swallow(); return; }
    const t = touch;
    if (!t || event.pointerId !== t.id) return;
    window.clearTimeout(t.timer);
    cancelAnimationFrame(t.frame);
    touch = undefined;
    if (!t.dragging) return;
    swallow();
    const first = t.samples[0]!, last = t.samples.at(-1)!;
    const flick = last.t > first.t ? (last.x - first.x) / (last.t - first.t) : 0;
    if (event.type === "pointercancel") closeSwipe(); else release(flick);
  };
  host.addEventListener("pointerup", end, { signal });
  host.addEventListener("pointercancel", end, { signal });

  // ---- trackpad two-finger scroll and Magic Mouse swipe ------------------------------------------------------
  // A swipe is a run of wheel events: a ramp while the fingers move, then (on some devices) a decaying tail of
  // momentum events. The row follows the ramp; the first decaying events are the fingers lifting, so the gesture
  // is released there and the tail is swallowed (it would otherwise carry a short swipe past the long threshold).
  let wheel: { row: HTMLElement; sum: number; base: number; last: number; peak: number; falling: number; released: boolean; timer: number } | undefined;
  host.addEventListener("wheel", (event) => {
    if (event.ctrlKey || !(event.target instanceof Element)) return;
    const unit = event.deltaMode === 1 ? 16 : 1;
    const dx = event.deltaX * unit, dy = event.deltaY * unit;
    if (!wheel) {
      const row = source.rowAt(event.target);
      if (!row || Math.abs(dx) < 2 || Math.abs(dx) < Math.abs(dy) * 1.2) return; // vertical scrolling stays the list's own
      const s = startSwipe(row);
      if (!s) return;
      wheel = { row, sum: 0, base: s.rest, last: 0, peak: 0, falling: 0, released: false, timer: 0 };
      closeMenu("keyboard");
    }
    event.preventDefault();
    const w = wheel;
    window.clearTimeout(w.timer);
    w.timer = window.setTimeout(() => { if (wheel === w) { if (!w.released) release(0); wheel = undefined; } }, WHEEL_GAP);
    if (w.released) return;
    const magnitude = Math.abs(dx);
    w.falling = magnitude < w.last ? w.falling + 1 : 0;
    w.peak = Math.max(w.peak, magnitude);
    w.last = magnitude;
    if (w.peak >= 6 && w.falling >= 3) { w.released = true; swallow(); release(0); return; }
    // Fingers moving left bring the content in from the right: a positive deltaX moves the row left.
    w.sum -= dx;
    swipe?.follow(w.base + w.sum);
  }, { signal, passive: false });

  // ---- taps on a revealed button, taps that close, outside presses ------------------------------------------
  host.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) return;
    const layerNode = event.target.closest<HTMLElement>(".ui-row-swipe-act");
    if (layerNode && swipe) {
      event.preventDefault();
      event.stopPropagation();
      const layer = swipe.layers.find((l) => l.node === layerNode);
      const row = swipe.row;
      if (layer) { if (layer.action.confirm) perform(row, layer.action, event instanceof MouseEvent && event.detail === 0 ? "keyboard" : "pointer"); else { closeSwipe(); layer.action.run(row); } }
      return;
    }
    if (performance.now() < swallowClickUntil) { event.preventDefault(); event.stopPropagation(); return; }
    if (swipe?.rest) { event.preventDefault(); event.stopPropagation(); closeSwipe(); }
  }, { signal, capture: true });
  document.addEventListener("pointerdown", (event) => {
    if (swipe?.rest && event.target instanceof Node && !swipe.row.contains(event.target) && !(event.target instanceof Element && event.target.closest(".ui-confirm-tip"))) closeSwipe();
  }, { signal, capture: true });
  // Escape closes a revealed row first and goes no further (the sidebar stays open). On the window, in capture, so it runs
  // before the sidebar's own Escape handler.
  window.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || !swipe?.rest || document.querySelector(".ui-confirm-tip, .ui-window-menu, .ui-row-ask")) return;
    event.stopPropagation();
    closeSwipe();
  }, { signal, capture: true });

  return {
    open, perform,
    close() { closeMenu("keyboard"); closeSwipe(false); confirm?.close(false); },
    dispose() { events.abort(); closeMenu("keyboard"); closeSwipe(false); confirm?.close(false); },
  };
}
