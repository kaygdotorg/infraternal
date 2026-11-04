/**
 * What an app window or a screen window shows inside its card (D200 V7, D207, D208): the machine's picture, the honest
 * state of the stream, and the person's hands on the machine.
 *
 * The window is a `SessionBinding`, like a terminal, so the canvas treats it the same way: the visibility module
 * tells it when it is on screen (`setVisible`), activation tells it when it is the one (`setActive`), the lifecycle
 * refits and disposes it. Everything about the stream is in `stream.ts`; this file is the DOM and the input.
 *
 * Control (D208 A3). Looking never moves anything on the machine. The first click, key or scroll that is meant for the
 * machine takes control (an explicit handover on the server) and shows it as a small icon in the window's pill (D342),
 * mirroring the indicator on the machine. Resizing the card, or moving it into a column, is layout and not input: the
 * real window still follows (D208 A2), but that never shows control (see `AppStream.resize`). Input reaches the machine
 * only when
 * - the window is the active one, and the press that activated it is not forwarded (the second press acts, as in a
 *   terminal), and
 * - the keys: the window has typing focus (a click, or the input lock); the wheel: the input lock holds this window
 *   (as for terminals, D177, so a swipe across the canvas never scrolls an app by accident).
 * Canvas shortcuts are bound on the capture phase of the page and win before any of this runs; under the input lock they
 * decline, so the machine receives those keys.
 *
 * Costs: pointer moves are coalesced to one per animation frame, a window that is not the active one has no input
 * listeners doing work, and the resize observer only fires when the box changes.
 */
import { ICONS, icon } from "../../../../../packages/ui/src/icons";
import { createSpinner } from "../../../../../packages/ui/src/spinner";
import type { VideoInput } from "../../../../../packages/protocol/src/desktop";
import type { Ctx, WinRec } from "../context";
import type { SessionBinding } from "../sessions/adapter";
import { coarse, el } from "../dom";
import { peekTip, refreshTip } from "../../../../../packages/ui/src/tooltip";
import { DesktopKeyboard } from "../../../../../packages/protocol/src/desktop-input";
import { containedRect, framePoint, modifierBits, movedEnough, scrollDelta, wireButton } from "./input";
import { controlLine, describe, type ControlState, type StateView, type StreamState } from "./status";
import { AppStream } from "./stream";
import { shapeStreamWindow } from "./shape";
import type { AppTarget } from "./inventory";
import type { StreamConnection } from "./adapter";

export interface AppBodyOptions {
  connection: StreamConnection;
  hostId: string;
  target: AppTarget;
  /** The machine's name, for the words a state uses. */
  machine: string;
  app: string;
  /** The machine's window shape (width / height) as listed: the window takes it before the stream starts. */
  aspect?: number;
}

/** A box change this soon after the window took the machine's shape came from that, not from the person's hand. */
const SHAPE_SETTLE_MS = 600;

/** Icons of the state cards, from the shared set. */
const CARD_ICON: Record<NonNullable<StateView["card"]>["mark"], string | undefined> = {
  spinner: undefined,
  alert: ICONS.warning,
  lock: ICONS.lock,
  window: '<rect x="3.5" y="5" width="17" height="14" rx="2.5"/><path d="M3.5 9.5h17M7 7.2h.01"/>',
  unsupported: ICONS.warning,
  offline: '<path d="M3 3l18 18M8.5 8.6A7 7 0 0 0 5 14.5M12 7a6.5 6.5 0 0 1 5.8 3.5A4.5 4.5 0 0 1 17.5 19H9M6.5 19a4 4 0 0 1-1.3-7.2"/>',
};
const CONTROL_ICON = '<path d="M5 4l5 15 2.4-6.2L19 10.4z"/>';
const VIEW_ICON = '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.8"/>';
const PAUSE_ICON = '<path d="M9 6v12M15 6v12"/>';

export class AppBinding implements SessionBinding {
  private stream: AppStream;
  private stage!: HTMLElement;
  private card!: HTMLElement;
  private root!: HTMLElement;
  private surface: HTMLCanvasElement | undefined;
  private observer: ResizeObserver | undefined;
  private visible = true;
  private activeNow = false;
  private typing = false;
  private lastState: StreamState = { kind: "idle" };
  private lastControl: ControlState = { kind: "none" };
  private picture = { width: 0, height: 0 };
  /** The machine's own window or screen shape (width / height), once it has reported one. */
  private remoteShape: number | undefined;
  private shapedAt = -Infinity;
  private listedShapeTried = false;
  private resizeTimer = 0;
  private opened = false;
  private disposed = false;
  /** Set while the press that activated this window is still being dispatched: that press is not forwarded. */
  private justActivated = false;
  /** Input waiting for control to be approved (bounded); discarded if it is refused. */
  private queued: VideoInput[] = [];
  private move: { x: number; y: number } | undefined;
  private lastSent: { x: number; y: number } | undefined;
  private moveFrame = 0;
  private buttons = 0;
  private readonly keyboard = new DesktopKeyboard();
  private touch: { id: number; x: number; y: number; t: number; mode: "tap" | "scroll" | "drag"; timer: number } | undefined;
  private removers: Array<() => void> = [];
  /** The small icon in the pill (control, view only, paused); absent while there is nothing to say. */
  private pillMark: HTMLElement | undefined;
  /** The press on the mark was a touch: its tap peeks the tooltip instead of opening the pill's popover. */
  private markTouch = false;

  constructor(private readonly cx: Ctx, private readonly rec: WinRec, private readonly o: AppBodyOptions) {
    this.stream = new AppStream({
      connection: o.connection, hostId: o.hostId, target: o.target, coarse: coarse.matches,
      events: {
        state: (s) => this.paintState(s),
        control: (c) => this.paintControl(c),
        picture: (size) => { this.picture = size; },
        shape: (aspect) => { this.remoteShape = aspect; this.applyShape(aspect, true); },
        surface: (canvas) => this.setSurface(canvas),
      },
    });
  }

  get connected(): boolean { return this.lastState.kind === "live" || this.lastState.kind === "paused"; }

  // ---- DOM ------------------------------------------------------------------------------------------------------

  mount(body: HTMLElement): void {
    this.root = el("div", "aw");
    this.stage = el("div", "aw-stage");
    this.stage.tabIndex = -1;
    this.stage.setAttribute("aria-label", this.o.target.type === "screen" ? `${this.o.machine} screen` : `${this.o.app} on ${this.o.machine}`);
    this.card = el("div", "cl-noaccess aw-card");
    this.card.setAttribute("role", "status");
    this.root.append(this.stage, this.card);
    body.append(this.root);
    this.wireInput();
    // The box the machine's window follows (A2): layout size, not the camera's zoom. The first size starts the stream.
    this.observer = new ResizeObserver(() => this.measure(false));
    this.observer.observe(this.stage);
    this.paintState({ kind: "idle" });
    this.measure(true);
  }

  private css(): { width: number; height: number; density: number } {
    return { width: this.stage.clientWidth, height: this.stage.clientHeight, density: window.devicePixelRatio || 1 };
  }

  /** Starts the stream on the first real size, then follows the box (a trailing debounce, so a drag-resize asks once it settles). */
  private measure(first: boolean): void {
    if (this.disposed) return;
    const size = this.css();
    if (size.width < 2 || size.height < 2) return;
    if (!this.opened) {
      // Open in the shape the machine listed: the first size the stream asks for is then already the right one. Tried
      // once; later shapes come only from the machine's own reports while it streams.
      const tried = this.listedShapeTried;
      this.listedShapeTried = true;
      if (!tried && this.applyShape(this.o.aspect, true)) return;
      this.opened = true;
      this.stream.setVisible(this.visible);
      void this.stream.open(size);
      return;
    }
    window.clearTimeout(this.resizeTimer);
    // A resize by hand makes the machine's window follow, quietly (no control shown). Taking the machine's shape is
    // looking, which never moves anything (D208 A3), so that one sends nothing.
    this.resizeTimer = window.setTimeout(() => this.stream.resize(this.css(), performance.now() - this.shapedAt > SHAPE_SETTLE_MS), first ? 0 : 120);
  }

  private setSurface(canvas: HTMLCanvasElement | undefined): void {
    this.surface?.remove();
    this.surface = canvas;
    if (canvas) { this.stage.prepend(canvas); this.applyPicture(); }
  }

  /** Hides the picture when the state has nothing true to show; dims it when it is only a memory. */
  private applyPicture(view?: StateView): void {
    const v = view ?? describe(this.lastState, this.words());
    this.stage.dataset.picture = !v.keepPicture ? "none" : v.dim ? "dim" : "live";
  }

  private words(): { machine: string; app: string; screen: boolean } { return { machine: this.o.machine, app: this.o.app, screen: this.o.target.type === "screen" }; }

  // ---- state ----------------------------------------------------------------------------------------------------

  private paintState(state: StreamState): void {
    if (this.disposed) return;
    this.lastState = state;
    const view = describe(state, this.words());
    this.rec.card.setStatus(view.dot);
    this.applyPicture(view);
    this.paintCard(view, state);
    this.paintPillMark();
    this.cx.sessionUi?.paint(this.rec);
    if (state.kind !== "live") this.stopInput();
  }

  private paintCard(view: StateView, state: StreamState): void {
    const card = this.card;
    const spec = view.card;
    card.dataset.shown = String(Boolean(spec));
    card.toggleAttribute("inert", !spec);
    if (!spec) return;
    // Rebuilt only when the words change, so a repaint never resets a press on its button.
    const signature = `${state.kind}:${spec.title}:${spec.hint ?? ""}:${spec.action?.id ?? ""}`;
    if (card.dataset.signature === signature) return;
    card.dataset.signature = signature;
    const mark = el("span", "aw-mark");
    if (spec.mark === "spinner") mark.append(createSpinner());
    else mark.innerHTML = icon(CARD_ICON[spec.mark] ?? ICONS.warning);
    const nodes: HTMLElement[] = [mark, el("p", "cl-noaccess-title", spec.title)];
    if (spec.hint) nodes.push(el("p", "cl-noaccess-hint", spec.hint));
    if (spec.action) {
      const act = el("button", "cl-sx-again aw-action");
      act.type = "button";
      act.innerHTML = `<span>${spec.action.label}</span>`;
      const id = spec.action.id;
      act.addEventListener("click", () => { if (id === "close") this.cx.win.close(this.rec); else this.stream.retry(this.css()); });
      nodes.push(act);
    }
    card.replaceChildren(...nodes);
  }

  /**
   * The pill's small mark, beside the status dot: the one icon that says what the dot cannot. A paused stream shows
   * the pause icon; a live picture shows who is driving (cursor: controlled, eye: view only, pause: remote input
   * waiting). Nothing is ever drawn over the picture (D342, TASTE: status is an icon, not a text box), and no mark is
   * made at all until there is something to say. The words are the mark's warm tooltip and its accessible name.
   */
  private paintPillMark(): void {
    const stateMark = describe(this.lastState, this.words()).mark;
    const line = !stateMark && this.lastState.kind === "live" ? controlLine(this.lastControl, this.o.machine) : undefined;
    const spec = stateMark ? { glyph: PAUSE_ICON, kind: "paused", tip: stateMark.tip }
      : line ? { glyph: line.mark === "view" ? VIEW_ICON : line.mark === "paused" ? PAUSE_ICON : CONTROL_ICON, kind: line.mark, tip: line.text }
      : undefined;
    let mark = this.pillMark;
    if (!spec) { mark?.remove(); this.pillMark = undefined; return; }
    if (!mark) {
      mark = el("span", "aw-pillmark");
      mark.setAttribute("role", "img");
      // A tap on a touch screen shows the sentence and does nothing else, as the connection dot beside it does.
      mark.addEventListener("pointerdown", (e) => { this.markTouch = e.pointerType === "touch"; }, true);
      mark.addEventListener("click", (e) => { if (!this.markTouch) return; this.markTouch = false; e.stopPropagation(); e.preventDefault(); peekTip(mark!); });
      this.rec.card.pill.querySelector(".ui-window-conn")?.before(mark);
      this.pillMark = mark;
    }
    if (mark.dataset.kind === spec.kind && mark.dataset.tip === spec.tip) return;
    mark.dataset.kind = spec.kind;
    mark.dataset.tip = spec.tip;
    mark.setAttribute("aria-label", spec.tip);
    mark.innerHTML = icon(spec.glyph);
    refreshTip(mark);
  }

  private paintControl(control: ControlState): void {
    if (this.disposed) return;
    this.lastControl = control;
    if (control.kind === "none" || control.kind === "view-only" || control.kind === "paused") this.queued.length = 0;
    // Automatic reacquisition also owns pending input. Defer only this drain so
    // takeControl can send the current Size before Input; ordinary input stays synchronous.
    if (control.kind === "controlled" && this.queued.length) queueMicrotask(() => {
      if (this.disposed || !this.armed() || this.stream.controlState.kind !== "controlled") return;
      const pending = this.queued.splice(0);
      for (const input of pending) this.stream.sendInput(input);
    });
    this.paintPillMark();
  }

  // ---- input ----------------------------------------------------------------------------------------------------

  /** Whether input may reach the machine now (the window is the active, live one and its first press is over). */
  private armed(): boolean {
    return this.activeNow && this.lastState.kind === "live" && !this.justActivated;
  }

  /** Sends `input`, taking control first when it is not held. Input meant for the machine while control is pending waits. */
  private send(input: VideoInput): void {
    if (this.stream.sendInput(input)) return;
    const c = this.stream.controlState;
    if (c.kind === "view-only" || c.kind === "paused") return;
    if (c.kind === "none") void this.stream.takeControl();
    // A cooldown or detached stream can decline before announcing requesting.
    // Such input must not survive for an unrelated later lease.
    if (this.stream.controlState.kind === "requesting" && this.queued.length < 32) this.queued.push(input);
  }

  /** Held buttons and keys are released on the machine whenever the window can no longer be trusted to send their ups. */
  private stopInput(): void {
    window.cancelAnimationFrame(this.moveFrame);
    this.moveFrame = 0;
    this.move = undefined;
    this.buttons = 0;
    this.keyboard.release();
    this.queued.length = 0;
    window.clearTimeout(this.touch?.timer);
    this.touch = undefined;
  }

  private point(e: { clientX: number; clientY: number }): { x: number; y: number; inside: boolean } {
    const r = this.stage.getBoundingClientRect();
    // The box is laid out at its natural size and scaled by the camera: dividing by the scale gives layout pixels.
    const k = r.width / (this.stage.clientWidth || 1) || 1;
    const picture = containedRect({ width: this.stage.clientWidth, height: this.stage.clientHeight }, this.picture);
    return framePoint((e.clientX - r.left) / k, (e.clientY - r.top) / k, picture);
  }

  private flushMove(): void {
    this.moveFrame = 0;
    const m = this.move;
    this.move = undefined;
    if (!m || !this.armed() || !movedEnough(this.lastSent, m)) return;
    this.lastSent = m;
    this.send({ kind: "mouse", x: m.x, y: m.y, button: 0, state: 0, modifiers: 0 });
  }

  private releasePoint(point: { x: number; y: number; inside: boolean }): { x: number; y: number } | undefined {
    // Consume the newest inside move while the remote button is still held.
    // Cancel its callback so no stale movement can follow the button-up.
    if (this.moveFrame) cancelAnimationFrame(this.moveFrame);
    this.flushMove();
    const release = point.inside ? point : this.lastSent;
    if (release) this.lastSent = release;
    return release;
  }

  private wireInput(): void {
    const s = this.stage;
    const on = <E extends keyof HTMLElementEventMap>(type: E, handler: (e: HTMLElementEventMap[E]) => void, options?: AddEventListenerOptions): void => {
      s.addEventListener(type, handler as EventListener, options);
      this.removers.push(() => s.removeEventListener(type, handler as EventListener, options));
    };
    on("pointerdown", (e) => {
      if (e.pointerType === "touch") { this.touchDown(e); return; }
      const button = wireButton(e.button);
      if (button === undefined || !this.armed()) return;
      const p = this.point(e);
      if (!p.inside) return;
      e.preventDefault();
      this.typing = true;
      s.focus({ preventScroll: true });
      s.setPointerCapture(e.pointerId);
      this.buttons |= 1 << button;
      this.lastSent = p;
      this.send({ kind: "mouse", x: p.x, y: p.y, button, state: 1, modifiers: modifierBits(e) });
    });
    on("pointermove", (e) => {
      if (e.pointerType === "touch") { this.touchMove(e); return; }
      // Looking never moves anything on the machine: a hover is sent only once control is held.
      if (!this.armed() || this.stream.controlState.kind !== "controlled") return;
      const p = this.point(e);
      if (!p.inside) return;
      this.move = p;
      if (!this.moveFrame) this.moveFrame = requestAnimationFrame(() => this.flushMove());
    });
    const up = (e: PointerEvent): void => {
      if (e.pointerType === "touch") { this.touchUp(e); return; }
      const button = wireButton(e.button);
      if (button === undefined || !(this.buttons & (1 << button))) return;
      this.buttons &= ~(1 << button);
      // A captured pointer can leave the picture before its up. Consume any
      // pending inside move before releasing at that last valid position.
      const p = this.releasePoint(this.point(e));
      if (p) this.send({ kind: "mouse", x: p.x, y: p.y, button, state: 2, modifiers: modifierBits(e) });
      else this.send({ kind: "release" });
    };
    on("pointerup", up);
    on("pointercancel", (e) => { if (e.pointerType === "touch") this.touchUp(e); else up(e); });
    // A right click is the machine's, not the browser's, while the window is in use.
    on("contextmenu", (e) => { if (this.armed()) e.preventDefault(); });
    on("wheel", (e) => {
      // The wheel reaches the machine only under the input lock; elsewhere it belongs to the canvas (D177).
      if (this.cx.inputLock.state?.win !== this.rec || !this.armed() || e.ctrlKey) return;
      const p = this.point(e);
      if (!p.inside) return;
      e.preventDefault();
      e.stopPropagation();
      const d = scrollDelta(e);
      if (d.dx || d.dy) this.send({ kind: "scroll", x: p.x, y: p.y, dx: d.dx, dy: d.dy, modifiers: modifierBits(e) });
    }, { passive: false });
    const key = (down: boolean) => (e: KeyboardEvent): void => {
      if (!this.armed() || e.isComposing) return;
      const input = this.keyboard.input(e, down);
      if (!input) return;
      // Escape, Tab and the arrows are the machine's while the window has the keys; the canvas's own handlers see them defaultPrevented.
      e.preventDefault();
      e.stopPropagation();
      this.send(input);
    };
    on("keydown", key(true));
    on("keyup", key(false));
    on("blur", () => { this.typing = false; if (this.stream.controlState.kind === "controlled") this.stream.releaseControl(); this.stopInput(); });
  }

  // Touch: a tap clicks, a drag scrolls, a press and hold then drag is a mouse drag. (Trackpad mode, D200 V4, is a later round.)
  private touchDown(e: PointerEvent): void {
    if (!this.armed() || this.touch || !this.point(e).inside) return;
    e.preventDefault();
    this.stage.setPointerCapture(e.pointerId);
    const t = { id: e.pointerId, x: e.clientX, y: e.clientY, t: performance.now(), mode: "tap" as "tap" | "scroll" | "drag", timer: 0 };
    t.timer = window.setTimeout(() => {
      if (this.touch !== t || t.mode !== "tap") return;
      const p = this.point(e);
      if (!p.inside) return;
      t.mode = "drag";
      this.lastSent = p;
      this.send({ kind: "mouse", x: p.x, y: p.y, button: 0, state: 1, modifiers: 0 });
    }, 380);
    this.touch = t;
  }

  private touchMove(e: PointerEvent): void {
    const t = this.touch;
    if (!t || t.id !== e.pointerId || !this.armed()) return;
    const dx = e.clientX - t.x, dy = e.clientY - t.y;
    if (t.mode === "tap" && Math.hypot(dx, dy) > 8) { t.mode = "scroll"; window.clearTimeout(t.timer); }
    const p = this.point(e);
    if (!p.inside) { t.x = e.clientX; t.y = e.clientY; return; }
    if (t.mode === "scroll") {
      // The finger moves the content: a finger going down moves the content down, which is scrolling up on the machine.
      this.send({ kind: "scroll", x: p.x, y: p.y, dx: Math.round(dx), dy: Math.round(dy), modifiers: 0 });
      t.x = e.clientX; t.y = e.clientY;
    } else if (t.mode === "drag") {
      this.move = p;
      if (!this.moveFrame) this.moveFrame = requestAnimationFrame(() => this.flushMove());
    }
  }

  private touchUp(e: PointerEvent): void {
    const t = this.touch;
    if (!t || t.id !== e.pointerId) return;
    window.clearTimeout(t.timer);
    this.touch = undefined;
    if (!this.armed()) return;
    const point = this.point(e);
    const p = t.mode === "drag" ? this.releasePoint(point) : point.inside ? point : undefined;
    if (!p) { if (t.mode === "drag") this.send({ kind: "release" }); return; }
    if (t.mode === "tap") {
      this.send({ kind: "mouse", x: p.x, y: p.y, button: 0, state: 1, modifiers: 0 });
      this.send({ kind: "mouse", x: p.x, y: p.y, button: 0, state: 2, modifiers: 0 });
    } else if (t.mode === "drag") this.send({ kind: "mouse", x: p.x, y: p.y, button: 0, state: 2, modifiers: 0 });
  }

  // ---- SessionBinding -------------------------------------------------------------------------------------------

  focus(): void {
    // Typing focus on a device with a hardware keyboard; a phone never summons its keyboard for an app window.
    if (coarse.matches || this.disposed) return;
    this.typing = true;
    this.stage.focus({ preventScroll: true });
  }

  setActive(active: boolean): void {
    if (active === this.activeNow) return;
    this.activeNow = active;
    if (active) {
      this.justActivated = true;
      window.setTimeout(() => { this.justActivated = false; }, 0);
      return;
    }
    // Leaving the window gives the machine back: held keys and buttons are released, the indicator goes quiet.
    this.typing = false;
    this.stopInput();
    this.stream.releaseControl();
    this.stream.clearViewOnly();
    if (document.activeElement === this.stage) this.stage.blur();
  }

  setVisible(visible: boolean): void {
    if (visible === this.visible) return;
    this.visible = visible;
    if (this.opened) this.stream.setVisible(visible);
    if (!visible) this.stopInput();
  }

  /** The canvas window takes the machine's shape (TASTE "A remote window takes its own shape"); a no-op once it has it. */
  /** `looking` marks the change as the window following the machine, so the size it causes never takes control. */
  private applyShape(aspect: number | undefined, looking: boolean): boolean {
    if (aspect === undefined || this.disposed || !shapeStreamWindow(this.cx, this.rec, this.stage, aspect)) return false;
    if (looking) this.shapedAt = performance.now();
    return true;
  }

  // A resize by hand ends here too: the window settles back into the machine's shape, keeping the height it was given.
  refit(): void { this.applyShape(this.remoteShape, false); this.measure(false); }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    window.clearTimeout(this.resizeTimer);
    this.stopInput();
    this.observer?.disconnect();
    for (const remove of this.removers) remove();
    this.removers.length = 0;
    this.stream.dispose();
    this.pillMark?.remove();
    this.root?.remove();
  }

  /** Counters of the decode worker (measurement). */
  stats(): ReturnType<AppStream["stats"]> { return this.stream.stats(); }
  get streamState(): StreamState { return this.lastState; }
  get streamControl(): ControlState { return this.lastControl; }
}
