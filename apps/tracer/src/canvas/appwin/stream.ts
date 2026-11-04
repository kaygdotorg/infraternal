/**
 * One app-window or screen stream, from the page's side (D200, D208, D232, D254, D266).
 *
 * It starts the stream on the machine (`desktop.session.start`), attaches a viewer on one stream of the page's single
 * WebSocket, hands every encoded access unit to a decode worker that owns the visible canvas, and keeps the honest
 * state of all of that (`status.ts`). It is DOM-free except for the surface it makes (a canvas) and the worker.
 *
 * Costs, because several windows may stream at once:
 * - The main thread only copies each access unit into a transferred buffer; decoding and drawing are in the worker.
 * - A stream that is not visible detaches its viewer and resets its worker: no bytes arrive and nothing decodes. After
 *   a while (at once on a phone) the worker and its surface are released too. The session stays on the machine, so
 *   coming back attaches again and the server sends a keyframe first.
 * - Input is sent only after control was approved, moves are coalesced to one per animation frame by the caller.
 *   Control lost to a dropped connection is asked for again on the next welcome; control the person gave back, or a
 *   window that went out of sight, waits for the person.
 *
 * The machine's own words about what is happening to a stream (the app quit, a permission was withdrawn, local input
 * pauses remote input) reach the page through `desktop.session.clock`, polled only while control is in use; the shape
 * it parses is documented at `parseStatus`. Everything else is derived from what the wire already says: the stream
 * closing, an action refusing, the socket dropping.
 */
import type { MuxConnection, StreamHandler } from "../../connection";
import type { VideoInput } from "../../../../../packages/protocol/src/desktop";
import type { WireFrame } from "../../../../../packages/protocol/src/codec";
import { parseInventory, type AppTarget } from "./inventory";
import { chooseSize, densityMilli, sizeChanged, type StreamSize } from "./size";
import { onConnection, type ControlState, type StreamState } from "./status";
import { traceClock, traceEnabled, recordFrame } from "./frame-trace";
import type { FromWorker, ToWorker, WorkerStats } from "./worker-protocol";

/** `no-preference` lets the browser pick hardware decoding where it has it (the choice is the browser's, not ours). */
const HARDWARE: HardwareAcceleration = "no-preference";
/** How many times a start waits for a lost connection and goes again. */
const MAX_START_TRIES = 6;
/** A desktop window releases its worker and surface after this long off screen. A phone does it at once (memory). */
const RELEASE_AFTER_MS = 30_000;
/** After control is refused, ask again no sooner than this. */
const CONTROL_RETRY_MS = 15_000;
/** The status poll while control is in use, and how long after the last input it keeps asking (an idle window asks nothing). */
const STATUS_EVERY_MS = 500;
/** How long after the last input the status poll keeps asking (see `STATUS_EVERY_MS`). */
const STATUS_WHILE_MS = 4000;
/**
 * How often a live, visible window asks the machine for its window's shape when nobody is typing (the status poll above
 * reports it too while control is in use). The machine's own window follower runs once a second; this matches it.
 */
const SHAPE_EVERY_MS = 1000;
/** A shape change smaller than this (relative) is rounding, not a new shape. */
const SHAPE_EPSILON = 0.005;

/** The callbacks a stream uses to tell its window what happened. They run on the main thread, in the order things occurred. */
export interface StreamEvents {
  state(state: StreamState): void;
  control(control: ControlState): void;
  /** The decoded picture's size, in pixels (for mapping pointer positions and for the letterbox). */
  picture(size: { width: number; height: number }): void;
  /** The surface to show: made when the stream starts and when it comes back after being released; `undefined` when released. */
  surface(canvas: HTMLCanvasElement | undefined): void;
  /** The machine's window (or screen) shape, width / height of what it captures: on the first report and on each change. */
  shape(aspect: number): void;
}

/** What a stream needs: the connection, which machine and target to stream, and the callbacks. `makeWorker` is a test seam. */
export interface StreamOptions {
  connection: Pick<MuxConnection, "call" | "openStream" | "closeStream" | "send" | "isWelcomed" | "onWelcome">;
  hostId: string;
  target: AppTarget;
  /** True on a touch device: memory is tight, so a hidden stream releases its worker at once. */
  coarse: boolean;
  events: StreamEvents;
  /** Test seam: makes the decode worker. */
  makeWorker?: () => Worker;
}

/** What `desktop.session.clock` says, reduced. All fields are optional; absent means "nothing to report". */
export interface MachineStatus {
  /** The window is gone, or the machine stopped sharing it. */
  gone?: boolean;
  /** The machine withdrew a permission. */
  permission?: "Screen Recording" | "Accessibility";
  /** Remote input waits this long because someone is using the machine. */
  inputPausedMs?: number;
  /**
   * Width / height of what the machine captures (its window with its menus, or the screen), from `capture_rect`, when
   * that shape is the machine's own: a screen, or a window that does not follow the canvas window's size.
   */
  shape?: number;
}

/**
 * Reads the status the machine reports. Proposed shape (nothing here is guessed to exist in the current reply; an
 * unknown or missing field changes nothing):
 * `{ "state": "capturing" | "gone" | "permission_missing", "permission"?: "screen_recording" | "accessibility",
 *    "input"?: { "pause_remaining_ms": number } }`
 */
export function parseStatus(value: unknown): MachineStatus {
  const v = value && typeof value === "object" ? value as Record<string, unknown> : {};
  const out: MachineStatus = {};
  if (v.state === "gone") out.gone = true;
  if (v.state === "permission_missing") out.permission = v.permission === "accessibility" ? "Accessibility" : "Screen Recording";
  const input = v.input && typeof v.input === "object" ? v.input as Record<string, unknown> : undefined;
  const wait = input?.pause_remaining_ms;
  if (typeof wait === "number" && Number.isFinite(wait) && wait > 0 && wait <= 60_000) out.inputPausedMs = wait;
  const rect = v.capture_rect && typeof v.capture_rect === "object" ? v.capture_rect as Record<string, unknown> : undefined;
  const w = rect?.width, h = rect?.height;
  // A window that follows the canvas window's size (reason "following") takes the canvas shape, so it reports none:
  // shaping the canvas window to it would undo the person's own resize before the machine catches up.
  const follows = v.reason === "following";
  if (!follows && typeof w === "number" && typeof h === "number" && Number.isFinite(w) && Number.isFinite(h) && w > 0 && h > 0) out.shape = w / h;
  return out;
}

/** A UUID string as its 16 bytes, or `undefined` when it is not a valid UUID. */
const uuidBytes = (id: string): Uint8Array | undefined => {
  const hex = id.replaceAll("-", "");
  return /^[0-9a-f]{32}$/i.test(hex) ? new Uint8Array(hex.match(/../g)!.map((b) => parseInt(b, 16))) : undefined;
};

/** Whether this browser can show a stream at all: it needs WebCodecs and a canvas it can hand to a worker. */
export function streamingSupport(): "ok" | "decoder" | "canvas" {
  if (typeof VideoDecoder === "undefined" || typeof EncodedVideoChunk === "undefined" || typeof Worker === "undefined") return "decoder";
  if (typeof OffscreenCanvas === "undefined" || typeof HTMLCanvasElement === "undefined" || !("transferControlToOffscreen" in HTMLCanvasElement.prototype)) return "canvas";
  return "ok";
}

/**
 * One app-window or screen stream, from the page's side. Call `open` to start, `setVisible` as the window comes and goes from view, `resize`
 * when its body changes size, `takeControl` and `sendInput` for input, and `dispose` when the window closes (which also stops the stream on
 * the machine). Read `current`, `controlState` and `hasSession` for the present state; changes also arrive through `StreamOptions.events`.
 */
export class AppStream {
  private state: StreamState = { kind: "idle" };
  private control: ControlState = { kind: "none" };
  private session: { id: string; bytes: Uint8Array } | undefined;
  private streamId: number | undefined;
  private attached = false;
  private worker: Worker | undefined;
  private canvas: HTMLCanvasElement | undefined;
  private size: StreamSize | undefined;
  private visible = false;
  private started = false;
  private disposed = false;
  private hadPicture = false;
  private generation = 0;
  private releaseTimer = 0;
  private statusTimer = 0;
  private statusBusy = false;
  private controlRefusedAt = -Infinity;
  /**
   * The person holds control and has not given it back. A dropped connection or a retired viewer clears the lease on
   * the server; this remembers the intent so the next welcome asks again by itself (no click needed).
   */
  private keepControl = false;
  private shapeTimer = 0;
  private shapeBusy = false;
  private lastShape: number | undefined;
  private lastInputAt = -Infinity;
  private pausedTimer = 0;
  private statsWaiters: Array<(stats: WorkerStats) => void> = [];
  /** Native sessions to release on Retry/disposal, including retired viewers and disconnected Stops. */
  private pendingStops: Set<string> | undefined;
  private stopTask: Promise<boolean> | undefined;
  private stopWelcomeOff: (() => void) | undefined;

  constructor(private readonly o: StreamOptions) {}

  /** The stream's present state. */
  get current(): StreamState { return this.state; }
  /** The present control state. */
  get controlState(): ControlState { return this.control; }
  /** True once the machine has started a session for this stream and it has not been stopped. */
  get hasSession(): boolean { return this.session !== undefined; }

  private setState(next: StreamState): void {
    if (this.state.kind === next.kind && JSON.stringify(this.state) === JSON.stringify(next)) return;
    this.state = next;
    this.o.events.state(next);
  }
  private setControl(next: ControlState): void {
    if (this.control.kind === next.kind && JSON.stringify(this.control) === JSON.stringify(next)) return;
    this.control = next;
    this.o.events.control(next);
  }

  /** Starts the stream at `css` size. Safe to call again after a final state (Try again). */
  async open(css: { width: number; height: number; density: number }): Promise<void> {
    const generation = ++this.generation;
    this.started = true;
    this.hadPicture = false;
    this.size = chooseSize(css.width, css.height, css.density);
    const support = streamingSupport();
    if (support !== "ok") { this.setState({ kind: "unsupported", reason: support }); return; }
    this.setState({ kind: "connecting" });
    // A call made while the socket is down would wait for ever (nothing is sent), and one in flight when the socket drops is
    // rejected: either way the start waits for the connection and goes again, a few times, before it explains itself.
    let attempts = 0;
    while (attempts < MAX_START_TRIES) {
      await this.welcomed();
      if (generation !== this.generation || this.disposed) return;
      // A disconnected retry retains the old session ID until Stop is acknowledged (or refused). Starting first
      // would leave both native captures alive when the socket comes back.
      if (this.pendingStops?.size) {
        if (!(await this.flushStops())) continue;
        if (!this.o.connection.isWelcomed) continue;
      }
      if (await this.start(generation, attempts === MAX_START_TRIES - 1)) return;
      attempts++;
    }
  }

  /** Resolves once the connection is welcomed (now, when it already is). */
  private welcomed(): Promise<void> {
    return new Promise((resolve) => {
      if (this.o.connection.isWelcomed) { resolve(); return; }
      const off = this.o.connection.onWelcome(() => { off(); resolve(); });
    });
  }

  /** One try at starting the session. True when it is settled (started, or explained); false when the connection was lost and another try is due. */
  private async start(generation: number, last: boolean): Promise<boolean> {
    try {
      if (!this.size) return true;
      const start = {
        host_id: this.o.hostId,
        start: {
          target: this.o.target.type === "window"
            ? { type: "window", window_id: this.o.target.windowId, owner_pid: this.o.target.ownerPid }
            : { type: "screen", display_id: this.o.target.displayId },
          size: { width: this.size.width, height: this.size.height, canvas_width: this.size.canvasWidth, canvas_height: this.size.canvasHeight, backing_scale: this.size.backingScale },
        },
        delivery: "reliable",
      };
      const reply = await this.o.connection.call("desktop.session.start", start);
      if (generation !== this.generation || this.disposed) { void this.stopSession(typeof reply.session_id === "string" ? reply.session_id : undefined); return true; }
      const id = typeof reply.session_id === "string" ? reply.session_id : "";
      const bytes = uuidBytes(id);
      if (!bytes) { this.setState({ kind: "failed", reason: "refused" }); return true; }
      this.session = { id, bytes };
      // Not on screen yet: the session waits on the machine and the viewer attaches when the window is shown.
      if (this.visible) this.attach();
      return true;
    } catch (error) {
      if (generation !== this.generation || this.disposed) return true;
      if (error instanceof Error && error.message === "connection lost" && !last) return false;
      await this.diagnose(generation, error);
      return true;
    }
  }

  /**
   * A refused or failed start is explained from the machine's own inventory, the one honest source: no longer listed
   * means the window is gone; a permission it reports as missing is named; a connection that dropped is retried by the
   * reconnect; anything else is a plain refusal.
   */
  private async diagnose(generation: number, error: unknown): Promise<void> {
    if (error instanceof Error && error.message === "connection lost") { this.setState({ kind: "failed", reason: "unreachable" }); return; }
    try {
      await this.welcomed();
      const inventory = parseInventory(await this.o.connection.call("desktop.windows", { host_id: this.o.hostId }));
      if (generation !== this.generation || this.disposed) return;
      const t = this.o.target;
      if (inventory.permissions.screenRecording === false) { this.setState({ kind: "permission", what: "Screen Recording" }); return; }
      const listed = t.type === "screen" ? inventory.screens.some((s) => s.target.displayId === t.displayId) : inventory.windows.some((w) => w.target.windowId === t.windowId && w.target.ownerPid === t.ownerPid);
      this.setState(listed ? { kind: "failed", reason: "refused" } : { kind: "closed" });
    } catch {
      if (generation === this.generation && !this.disposed) this.setState({ kind: "failed", reason: "unreachable" });
    }
  }

  // ---- the viewer on the socket -----------------------------------------------------------------------------------

  private attach(): void {
    if (this.streamId !== undefined || !this.session || this.disposed) return;
    this.ensureSurface();
    this.worker?.postMessage({ t: "reset" } satisfies ToWorker);
    const handler: StreamHandler = {
      onSocketOpen: () => undefined,
      onWelcome: () => {
        if (!this.session || this.streamId === undefined) return;
        this.attached = true;
        this.o.connection.send(this.streamId, { type: "Desktop", message: { kind: "attach", sessionId: this.session.bytes, delivery: 0 } });
        // Attached again: a window that was live shows "reconnecting" until its first new picture; a paused one stays paused
        // until then; a window that never had a picture is still connecting.
        if (this.state.kind === "live" && this.hadPicture) this.setState({ kind: "reconnecting" });
        if (this.keepControl) void this.takeControl();
      },
      onFrame: (frame) => this.frame(frame),
      onDisconnected: () => {
        this.attached = false;
        this.setControl({ kind: "none" });
        this.setState(onConnection(this.state, false, this.hadPicture));
        this.worker?.postMessage({ t: "reset" } satisfies ToWorker);
      },
      hasSession: () => false,
      onStatus: () => undefined,
    };
    this.streamId = this.o.connection.openStream(handler);
  }

  private detach(): void {
    if (this.streamId === undefined) return;
    const id = this.streamId;
    this.streamId = undefined;
    this.attached = false;
    this.o.connection.closeStream(id);
    this.worker?.postMessage({ t: "reset" } satisfies ToWorker);
    window.clearTimeout(this.statusTimer);
    this.statusTimer = 0;
    window.clearTimeout(this.pausedTimer);
    window.clearTimeout(this.shapeTimer);
    this.shapeTimer = 0;
  }

  private frame(frame: WireFrame): void {
    if (frame.type === "Close") {
      // Close retires this viewer; the server may still retain native capture.
      // Keep its identity for Retry/disposal without stopping sibling viewers
      // merely because this attachment ended. The local handler retires now.
      const retired = this.session?.id;
      this.detach();
      if (retired) (this.pendingStops ??= new Set()).add(retired);
      this.session = undefined;
      this.setControl({ kind: "none" });
      void this.diagnose(this.generation, new Error("closed"));
      return;
    }
    if (frame.type !== "Desktop" || frame.message.kind !== "video") return;
    const m = frame.message;
    const receivedAt = this.measuring ? traceClock() : 0;
    // The access unit is a view into the socket's receive buffer, which the next message reuses: copy it into a buffer
    // the worker takes over (one memcpy of the unit, nothing else on this thread).
    const copy = m.bytes.slice();
    const packet: ToWorker = { t: "chunk", sequence: Number(m.sequence), keyframe: m.keyframe, bytes: copy.buffer };
    if (this.measuring) packet.trace = { captureNs: m.captureNs.toString(), bytes: copy.byteLength, receivedAt, copyFinishedAt: traceClock() };
    this.worker?.postMessage(packet, [copy.buffer]);
  }

  // ---- the worker and its surface ---------------------------------------------------------------------------------

  private readonly measuring = traceEnabled();

  private ensureSurface(): void {
    window.clearTimeout(this.releaseTimer);
    if (this.worker) return;
    const canvas = document.createElement("canvas");
    canvas.className = "aw-surface";
    canvas.width = 2; canvas.height = 2;
    const offscreen = canvas.transferControlToOffscreen();
    const worker = this.o.makeWorker ? this.o.makeWorker() : new Worker(new URL("./decode.worker.on-demand.js", document.baseURI), { type: "module" });
    worker.onmessage = (event: MessageEvent<FromWorker>) => this.fromWorker(event.data);
    worker.onerror = () => { this.setState({ kind: "failed", reason: "decode" }); };
    worker.postMessage({ t: "init", canvas: offscreen, hardware: HARDWARE, ...(this.measuring ? { measure: true } : {}) } satisfies ToWorker, [offscreen]);
    this.worker = worker;
    this.canvas = canvas;
    this.o.events.surface(canvas);
  }

  private releaseSurface(): void {
    if (!this.worker) return;
    this.worker.postMessage({ t: "close" } satisfies ToWorker);
    this.worker.terminate();
    this.worker = undefined;
    this.canvas = undefined;
    this.hadPicture = false;
    this.o.events.surface(undefined);
  }

  private fromWorker(m: FromWorker): void {
    switch (m.t) {
      case "first":
        this.hadPicture = true;
        this.o.events.picture({ width: m.width, height: m.height });
        if (this.visible) this.setState({ kind: "live" });
        this.pollShape();
        return;
      case "size": this.o.events.picture({ width: m.width, height: m.height }); return;
      case "repair":
        if (this.streamId !== undefined && this.attached) this.o.connection.send(this.streamId, { type: "Desktop", message: { kind: "repair", lastSequence: BigInt(m.lastSequence) } });
        return;
      case "error":
        if (m.reason === "decode") this.setState(this.hadPicture ? this.state : { kind: "failed", reason: "decode" });
        else this.setState({ kind: "unsupported", reason: m.reason === "unsupported-canvas" ? "canvas" : "codec" });
        return;
      case "trace": recordFrame(m.frame); return;
      case "stats": for (const w of this.statsWaiters.splice(0)) w(m.stats); return;
    }
  }

  /** The worker's counters (measurement). */
  stats(): Promise<WorkerStats | undefined> {
    if (!this.worker) return Promise.resolve(undefined);
    return new Promise((resolve) => { this.statsWaiters.push(resolve); this.worker?.postMessage({ t: "stats" } satisfies ToWorker); });
  }

  // ---- visibility, size, input --------------------------------------------------------------------------------------

  /** The window is on screen and live (true), or off screen, in another view or the page is hidden (false). */
  setVisible(visible: boolean): void {
    if (visible === this.visible) return;
    this.visible = visible;
    if (this.disposed || !this.started) return;
    if (!visible) {
      // Only a window with a picture to remember is "paused"; one still connecting stays connecting.
      if (this.hadPicture && (this.state.kind === "live" || this.state.kind === "reconnecting")) this.setState({ kind: "paused" });
      // Out of sight is not a transient loss: control comes back only from the person.
      this.keepControl = false;
      this.setControl({ kind: "none" });
      this.detach();
      window.clearTimeout(this.releaseTimer);
      if (this.o.coarse) this.releaseSurface();
      else this.releaseTimer = window.setTimeout(() => this.releaseSurface(), RELEASE_AFTER_MS);
      return;
    }
    window.clearTimeout(this.releaseTimer);
    if (this.session && this.streamId === undefined && (this.state.kind === "paused" || this.state.kind === "connecting" || this.state.kind === "reconnecting")) this.attach();
  }

  /**
   * The window body's layout size changed: the machine's window follows it (A2). `byHand` is a resize by the person,
   * an explicit control action; a change that only took the machine's own shape sends its size if control is already
   * held and otherwise waits for it.
   */
  resize(css: { width: number; height: number; density: number }, byHand = true): void {
    const next = chooseSize(css.width, css.height, css.density);
    if (!sizeChanged(this.size, next)) return;
    this.size = next;
    // Merely attaching uses Start's size; taking control sends the latest size.
    if (this.control.kind === "controlled" || this.control.kind === "paused") this.pushSize();
    else if (byHand) void this.takeControl();
  }

  private pushSize(): void {
    if (!this.size || this.streamId === undefined || !this.attached || (this.control.kind !== "controlled" && this.control.kind !== "paused")) return;
    this.o.connection.send(this.streamId, { type: "Desktop", message: { kind: "size", width: this.size.width, height: this.size.height, densityMilli: densityMilli(this.size) } });
  }

  /** Sends one input event. The caller has checked that this window may control; this checks that control is held. */
  sendInput(input: VideoInput): boolean {
    if (this.streamId === undefined || !this.attached || this.control.kind !== "controlled") return false;
    this.o.connection.send(this.streamId, { type: "Desktop", message: { kind: "input", input } });
    this.lastInputAt = performance.now();
    // The machine's words about this stream are asked only while the person is using it.
    if (!this.statusTimer) this.pollStatus();
    return true;
  }

  /** Asks to control the machine through this stream (an explicit handover on the server). */
  async takeControl(): Promise<boolean> {
    if (this.control.kind === "controlled") return true;
    if (this.control.kind === "requesting" || this.streamId === undefined || !this.attached || !this.o.connection.isWelcomed) return false;
    if (performance.now() - this.controlRefusedAt < CONTROL_RETRY_MS) return false;
    const id = this.streamId;
    this.setControl({ kind: "requesting" });
    try {
      await this.o.connection.call("desktop.session.control", { stream_id: id });
      if (this.streamId !== id) return false;
      this.keepControl = true;
      this.setControl({ kind: "controlled" });
      this.pushSize();
      this.pollStatus();
      return true;
    } catch {
      if (this.streamId === id) {
        this.controlRefusedAt = performance.now();
        this.keepControl = false;
        this.setControl({ kind: "view-only", why: "rights" });
      }
      return false;
    }
  }

  /** The window lost focus: held keys and buttons are released on the machine, and the indicator goes quiet. */
  releaseControl(): void {
    const held = this.control.kind === "controlled" || this.control.kind === "paused" || this.control.kind === "requesting";
    this.keepControl = false;
    this.setControl({ kind: "none" });
    window.clearTimeout(this.statusTimer);
    window.clearTimeout(this.pausedTimer);
    this.statusTimer = 0;
    if (held) {
      // Input::Release clears held keys but intentionally retains the native lease.
      // Retire this viewer to withdraw the lease, then view the existing session
      // under a new stream id so a late acquisition cannot regain control.
      this.detach();
      if (this.visible && this.session && !this.disposed) this.attach();
    }
  }

  /** Whether the person may try to control again (the view-only state shows until the retry window passes). */
  clearViewOnly(): void { if (this.control.kind === "view-only") this.setControl({ kind: "none" }); }

  private noteShape(shape: number | undefined): void {
    if (shape === undefined || this.disposed) return;
    if (this.lastShape !== undefined && Math.abs(shape / this.lastShape - 1) < SHAPE_EPSILON) return;
    this.lastShape = shape;
    this.o.events.shape(shape);
  }

  /**
   * Follows the machine's window shape while the picture is live and on screen, so the canvas window can take that shape
   * (TASTE "A remote window takes its own shape"). One small call a second per visible window; none while hidden.
   */
  private pollShape(): void {
    window.clearTimeout(this.shapeTimer);
    this.shapeTimer = 0;
    const session = this.session;
    if (!session || !this.visible || !this.attached || this.disposed || this.shapeBusy) return;
    const streamId = this.streamId;
    const current = (): boolean => !this.disposed && this.session === session && this.streamId === streamId && this.visible;
    const again = (): void => { if (current()) this.shapeTimer = window.setTimeout(() => this.pollShape(), SHAPE_EVERY_MS); };
    // While the person is typing, the status poll already asks twice a second and reports the shape.
    if (this.statusTimer) { again(); return; }
    this.shapeBusy = true;
    this.o.connection.call("desktop.session.clock", { session_id: session.id }).then((reply) => {
      this.shapeBusy = false;
      if (!current()) return;
      this.noteShape(parseStatus(reply).shape);
      again();
    }, () => { this.shapeBusy = false; again(); });
  }

  private pollStatus(): void {
    window.clearTimeout(this.statusTimer);
    this.statusTimer = 0;
    if (this.control.kind !== "controlled" && this.control.kind !== "paused") return;
    if (performance.now() - this.lastInputAt > STATUS_WHILE_MS) return;
    const session = this.session;
    if (!session || !this.visible || this.statusBusy) return;
    this.statusBusy = true;
    const streamId = this.streamId;
    const current = (): boolean => !this.disposed && this.session === session && this.streamId === streamId && (this.control.kind === "controlled" || this.control.kind === "paused");
    this.o.connection.call("desktop.session.clock", { session_id: session.id }).then((reply) => {
      this.statusBusy = false;
      if (!current()) return;
      const status = parseStatus(reply);
      this.noteShape(status.shape);
      if (status.gone) { this.setState({ kind: "closed" }); return; }
      if (status.permission) { this.setState({ kind: "permission", what: status.permission }); return; }
      window.clearTimeout(this.pausedTimer);
      if (status.inputPausedMs) {
        this.setControl({ kind: "paused", untilMs: performance.now() + status.inputPausedMs });
        // The 2 s of D208 A3: the indication clears by itself when the pause ends.
        this.pausedTimer = window.setTimeout(() => { if (this.control.kind === "paused") this.setControl({ kind: "controlled" }); }, status.inputPausedMs);
      } else if (this.control.kind === "paused") this.setControl({ kind: "controlled" });
      this.statusTimer = window.setTimeout(() => this.pollStatus(), STATUS_EVERY_MS);
    }, () => { this.statusBusy = false; if (current()) this.statusTimer = window.setTimeout(() => this.pollStatus(), STATUS_EVERY_MS * 4); });
  }

  /** Try again after a failure or a missing permission. */
  retry(css: { width: number; height: number; density: number }): void {
    const previousSession = this.session?.id;
    // Invalidate an in-flight Start before it can publish a session over this retry. Viewer Close only detaches;
    // the server retains its capture, so request Stop while the old session identity is still available.
    this.generation++;
    this.detach();
    this.session = undefined;
    void this.stopSession(previousSession);
    void this.open(css);
  }

  private stopSession(id: string | undefined): void {
    if (id) (this.pendingStops ??= new Set()).add(id);
    if (!this.pendingStops?.size) return;
    if (!this.stopWelcomeOff) this.stopWelcomeOff = this.o.connection.onWelcome(() => { void this.flushStops(); });
    void this.flushStops();
  }

  /** Drain native Stop requests serially and retain them across a lost socket. */
  private flushStops(): Promise<boolean> {
    if (this.stopTask) return this.stopTask;
    const pendingStops = this.pendingStops;
    if (!pendingStops || pendingStops.size === 0) {
      this.stopWelcomeOff?.();
      this.stopWelcomeOff = undefined;
      return Promise.resolve(true);
    }
    if (!this.o.connection.isWelcomed) return Promise.resolve(false);

    const task = (async (): Promise<boolean> => {
      while (pendingStops.size > 0 && this.o.connection.isWelcomed) {
        const id = pendingStops.values().next().value as string;
        try {
          await this.o.connection.call("desktop.session.stop", { session_id: id });
          pendingStops.delete(id);
        } catch (error) {
          if (error instanceof Error && error.message === "connection lost") return false;
          // A refusal or unreadable result is a completed response; retry only when the transport itself was lost.
          pendingStops.delete(id);
        }
      }
      return pendingStops.size === 0;
    })();
    this.stopTask = task;
    void task.then(() => {
      if (this.stopTask !== task) return;
      this.stopTask = undefined;
      if (pendingStops.size === 0) {
        if (this.pendingStops === pendingStops) this.pendingStops = undefined;
        this.stopWelcomeOff?.();
        this.stopWelcomeOff = undefined;
      } else if (this.o.connection.isWelcomed) {
        // A reconnect may welcome while the previous socket's rejected call is settling, or another Stop may arrive as the queue drains.
        queueMicrotask(() => { void this.flushStops(); });
      }
    }, () => {
      if (this.stopTask === task) this.stopTask = undefined;
    });
    return task;
  }

  /** The window closed: the viewer detaches, the worker ends and the machine stops the stream (its window goes back to its own size). */
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.generation++;
    window.clearTimeout(this.releaseTimer);
    window.clearTimeout(this.statusTimer);
    window.clearTimeout(this.pausedTimer);
    this.detach();
    this.releaseSurface();
    const id = this.session?.id;
    this.session = undefined;
    void this.stopSession(id);
  }
}
