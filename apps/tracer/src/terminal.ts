/** Owns Ghostty rendering, leg-A mux frames, bounded stream queues, and resumable input. */
import { keysIn } from "./input-keys";
import { mountToast, type ToastController } from "../../../packages/ui/src/toast";
import { ICONS } from "../../../packages/ui/src/icons";
import { bindingLabel } from "../../../packages/ui/src/shortcuts";
import { TerminalQueries } from "./terminal-queries";
import { terminalRefusal } from "./terminal-refusal";
import { isCanonicalUuid } from "./identifiers";
import { reattachReason, recoveringReason } from "./close-reasons";
import { init, Terminal, type ITheme } from "../vendor/ghostty-web";
import { mountTerminalCursorLayer, type TerminalCursorLayer } from "../../../packages/ui/src/terminal-cursor-layer";
import { mountTerminalNote, type TerminalNote } from "../../../packages/ui/src/terminal-note";
import { replayedSize, StaleScreenWatch, staleWaitMs, type ScreenSize } from "./stale-screen";
import { DEFAULT_FONT_ID, fontById, fontStack, loadFont, type MonoFont } from "../../../packages/ui/src/fonts";
import { terminalTouch } from "./terminal-touch";
import { pulseActivity } from "./perf-activity";
import { PredictiveEcho, type PredictionPosition, type PredictiveEchoState } from "./predictive-echo";
import { CLOSE_SESSION_GONE, type WireFrame } from "../../../packages/protocol/src/codec";
import { MuxConnection, reconnectDelay, STABLE_CONNECTION_MS, type StreamHandler } from "./connection";
import { onDemand } from "./on-demand";
import { captureFocusIntent } from "../../../packages/ui/src/focus-intent";
import type { TerminalLink, TerminalLinkController, TerminalLinkRow } from "./terminal-links.on-demand";
import { SynchronizedOutput } from "./synchronized-output";

const INITIAL_CREDIT = 1024 * 1024;
const INPUT_QUEUE_LIMIT = 1024 * 1024;
const INPUT_RESUME_GUARD = 16 * 1024;
const INPUT_FRAME_LIMIT = 16 * 1024;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const RENDER_IDLE_MS = 700;
/** Shown while the host link is doubted but kept (`terminal.link_doubt`, D300); recovery clears only this text. */
const LINK_DOUBT_STATUS = "Reconnecting…";
const TERMINAL_FONT_SIZE_DESKTOP = 14;
const TERMINAL_FONT_SIZE_TOUCH = 13;
/** The font sizes a keyboard step or a pinch may reach (terminal-touch.ts uses the same range). */
const TERMINAL_FONT_SIZE_MIN = 9;
const TERMINAL_FONT_SIZE_MAX = 24;
const THEME_HISTORY_PROBE_ROWS = 10_000;
const THEME_HISTORY_INDEXED_COLUMN = "theme-history-00000 | ".length;
const THEME_HISTORY_TRUECOLOR_COLUMN = THEME_HISTORY_INDEXED_COLUMN + 4;
const ANSI_THEME_KEYS = [
  "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
  "brightBlack", "brightRed", "brightGreen", "brightYellow", "brightBlue", "brightMagenta", "brightCyan", "brightWhite",
] as const;
const THEME_COLOR_KEYS: readonly (keyof ITheme)[] = [
  "background", "foreground", "cursor", "cursorAccent", "selectionBackground", "selectionForeground", ...ANSI_THEME_KEYS,
];
const encoder = new TextEncoder();
/** Never append to this shared sentinel: the first answer gets a private collector. */
const EMPTY_PARSER_REPLIES: string[] = [];

/** Private hooks on the pinned Ghostty build, kept at the renderer boundary for idle parking. */
interface GhosttyActivityControls {
  startRenderLoop(): void;
  cancelRenderLoop(): void;
  scrollbarOpacity: number;
  renderer?: {
    remeasureFont(): void;
    resize(cols: number, rows: number): void;
    getMetrics(): { width: number; height: number; baseline: number };
    setCursorBlink(enabled: boolean): void;
    setTheme(theme: ITheme): void;
    renderLine(line: unknown[], y: number, cols: number, lineOffset?: number, backgroundAlreadyPainted?: boolean): void;
    renderCursor(x: number, y: number, line: unknown[] | null): void;
    setHoveredLinkRanges(ranges: readonly { startX: number; startY: number; endX: number; endY: number }[] | null): void;
    naturalCellWidth?: number;
    ctx?: CanvasRenderingContext2D;
    devicePixelRatio?: number;
    theme?: { background?: string; foreground?: string; cursor?: string };
    render(buffer: unknown, forceAll?: boolean, viewportY?: number, scrollbackProvider?: unknown, scrollbarOpacity?: number): void;
  };
}

export interface TerminalHooks {
  /** Return true when a product surface presents the refusal and its session-list action. */
  onOpenRefused?: (message: string, sessionList: boolean) => boolean;
  /** Only a public session id; writer/resume capabilities remain in memory. */
  onSessionCreated?: (sessionId: string) => void;
  onAttached?: (resumed: boolean, terminal: TerminalClient) => void;
  onDisconnected?: (forced: boolean) => void;
  /**
   * The host link missed a reply but is kept (`terminal.link_doubt`, D300, #234), or answered again
   * (`terminal.link_recovered`). A product surface shows its connection indicator in the reconnecting
   * state meanwhile; the terminal's own status text is not shown on the canvas.
   */
  onLinkDoubt?: (doubted: boolean) => void;
  /**
   * The screen came back rebuilt from the latest state, so some scrollback may be approximate (`terminal.snapshot` with
   * `approximate`). A product surface shows its connection indicator's "approximate" mark for a moment.
   */
  onApproximate?: () => void;
  /**
   * How many keys typed while the link could not carry them are being kept to be sent (0 once they were sent). Only the
   * count is reported, never what was typed: a password typed into a hidden prompt must not be shown anywhere.
   */
  onInputHeld?: (keys: number) => void;
  /** Final output has painted; clean exits may close their window. */
  onExited?: (status: number) => void;
  /**
   * The host no longer has this terminal's session (the server's final Close 4404). The terminal has stopped
   * attaching; the window shows the ended state. Every other close stays transient and retries.
   */
  onSessionGone?: (status?: number) => void;
  onInput?: (data: string, at: number, sequence: bigint) => boolean | void;
  onTrace?: (keyId: string, hop: TerminalTraceHop, at: number) => void;
  onPaintedOutput?: (bytes: Uint8Array, at: number, sequence: bigint) => void;
}

export type InputModifierState = "off" | "armed" | "locked";

/** Modifier states shared by the key tray and Ghostty's input encoder. */
export interface InputModifiers {
  ctrl: InputModifierState;
  alt: InputModifierState;
}

function applyInputModifiers(data: string, ctrl: boolean, alt: boolean): string {
  if (!ctrl && !alt) return data;

  // Ghostty emits CSI or SS3 arrows before the key tray modifier is applied.
  // CSI's parameter follows xterm's bit values: Alt=2, Ctrl=4, plus the base 1.
  const arrow = /^\x1b(?:\[|O)(?:1;)?([ABCD])$/.exec(data);
  if (arrow) {
    const parameter = 1 + (alt ? 2 : 0) + (ctrl ? 4 : 0);
    return `\x1b[1;${parameter}${arrow[1]!}`;
  }

  if (ctrl && data.length === 1) {
    const code = data.toUpperCase().charCodeAt(0);
    if (code >= 64 && code <= 95) data = String.fromCharCode(code - 64);
  }
  return alt ? `\x1b${data}` : data;
}

export type TerminalTraceHop =
  | "encode"
  | "wsSend"
  | "wsMessage"
  | "decode"
  | "termWrite"
  | "writeCallback"
  | "paint"
  | "prediction";

export interface TerminalConfig {
  /** The owning window still wants initial desktop focus when initialization finishes. */
  shouldFocusOnOpen?: () => boolean;
  /** Readable label for refusal guidance; hostId remains the routing authority. */
  hostName?: string;
  host: HTMLElement;
  /** Stage that follows the visual viewport when iOS opens its on-screen keyboard. */
  screen?: HTMLElement;
  status: HTMLElement;
  hooks?: TerminalHooks;
  /** Curated theme shared by the floating controls and Ghostty. */
  theme?: ITheme;
  /** The chosen font (registry); the default family when absent. */
  font?: MonoFont;
  onRoundTrip?: (milliseconds: number | undefined) => void;
  onConnectionChange?: (connected: boolean) => void;
  onScroll?: (scrolled: boolean) => void;
  onInputActivity?: () => void;
  onRecoveryPending?: (readyAt: number | undefined) => void;
  traceMockServer?: boolean;
  /**
   * The connection this terminal's stream rides on. Terminals of one page share one (D183); without it the
   * client makes and owns a private connection, which is how the single-terminal screen works.
   */
  connection?: MuxConnection;
  /** Attach to a session that already exists on the server (a window reopened from the sidebar). */
  attachSessionId?: string;
  /** The host to open the new session on (a lowercase UUID); the embedded host when absent. */
  hostId?: string;
  /** Reattach this tab's owned session using a new writer after a page reload. */
  initialSessionId?: string;
  /** Recheck liveness before opening the stream so a snapshot racing font load cannot attach a retired ID. */
  getEndedSession?: () => { status?: number } | undefined;
  /** Test-only cap override; normal tracer sessions retain the 10,000-row default. */
  scrollbackLimit?: number;
  /** Enables the explicit `?predict=1` opt-in; the production default remains off. */
  predictiveEcho?: boolean;
}

interface PendingSnapshot {
  outSeq: bigint;
  bytes: Uint8Array;
}

/** A fixed-size byte ring; callers decide what a full queue means. */
class ByteQueue {
  private readonly bytes: Uint8Array;
  private head = 0;
  private used = 0;

  constructor(readonly capacity: number) {
    this.bytes = new Uint8Array(capacity);
  }

  get length(): number { return this.used; }
  get free(): number { return this.capacity - this.used; }

  push(source: Uint8Array): boolean {
    if (source.byteLength > this.free) return false;
    const tail = (this.head + this.used) % this.capacity;
    const first = Math.min(source.byteLength, this.capacity - tail);
    this.bytes.set(source.subarray(0, first), tail);
    this.bytes.set(source.subarray(first), 0);
    this.used += source.byteLength;
    return true;
  }

  /** Returns the next contiguous region for a renderer write. */
  peek(): Uint8Array {
    return this.bytes.subarray(this.head, this.head + Math.min(this.used, this.capacity - this.head));
  }

  /** Returns one of the at most two contiguous views that make up the queued bytes. */
  peekAt(offset: number): Uint8Array {
    if (offset < 0 || offset >= this.used) return this.bytes.subarray(0, 0);
    const start = (this.head + offset) % this.capacity;
    return this.bytes.subarray(start, start + Math.min(this.used - offset, this.capacity - start));
  }

  consume(length: number): void {
    if (length < 0 || length > this.used) throw new Error("queue consume exceeds queued bytes");
    this.fillRange(this.head, length);
    this.head = (this.head + length) % this.capacity;
    this.used -= length;
  }

  /** Keeps only an active prefix and releases the queued tail. */
  discardAfter(keep: number): number {
    if (keep < 0 || keep > this.used) throw new Error("queue discard exceeds queued bytes");
    const dropped = this.used - keep;
    this.fillRange((this.head + keep) % this.capacity, dropped);
    this.used = keep;
    return dropped;
  }

  copyOut(offset: number, target: Uint8Array): number {
    if (offset < 0 || offset >= this.used) return 0;
    const start = (this.head + offset) % this.capacity;
    const length = Math.min(target.byteLength, this.used - offset, this.capacity - start);
    target.set(this.bytes.subarray(start, start + length), 0);
    return length;
  }

  clear(): void {
    this.bytes.fill(0);
    this.head = 0;
    this.used = 0;
  }

  private fillRange(start: number, length: number): void {
    const first = Math.min(length, this.capacity - start);
    this.bytes.fill(0, start, start + first);
    if (length > first) this.bytes.fill(0, 0, length - first);
  }
}

/** The sole terminal session in the tracer; all network and renderer buffers are bounded. */
export class TerminalClient {
  private static rendererPreparation: Promise<void> | undefined;
  private static readonly rendererWarmups = new Map<string, Promise<void>>();
  private readonly terminal: Terminal;
  private readonly ghostty: GhosttyActivityControls;
  private readonly synchronizedOutput: SynchronizedOutput;
  private synchronizedOutputBatchPending = false;
  private readonly inputQueue = new ByteQueue(INPUT_QUEUE_LIMIT);
  /** Keys typed since the stream last lost its shim and not yet sent (the connection indicator's kept-keys mark). */
  private heldKeys = 0;
  /** Uncertain bytes from an old writer stay separate from input typed into the live fresh writer. */
  private retainedInput: Uint8Array | undefined;
  /** A fresh writer cannot deduplicate old input; the saved bytes wait for an explicit choice. */
  private inputNeedsResend = false;
  private inputResendNoticeVisible = false;
  private inputResendNotice: ToastController | undefined;
  private readonly outputQueue = new ByteQueue(INITIAL_CREDIT);
  private readonly inputScratch = new Uint8Array(INPUT_FRAME_LIMIT);
  private readonly resizeObserver: ResizeObserver;
  private readonly screen: HTMLElement;
  private readonly conn: MuxConnection;
  private readonly ownsConnection: boolean;
  private streamId = 0;
  private readonly offRoundTrip: () => void;
  private sessionId: Uint8Array | undefined;
  private symbolFaceRequested = false;
  /** The font in use and the two canvas weights drawn from it (see installFontWeights). */
  private font: MonoFont;
  private readonly canvasWeights = { regular: 400, bold: 700 };
  private readonly weightMemo = new Map<string, string>();
  private outputWriteInFlight = false;
  private outputWriteLength = 0;
  /** Parser writes are compared with the latest successful renderer pass on a synchronized release. */
  private parsedOutputVersion = 0;
  private renderedOutputVersion = 0;
  /** A release-frame render may complete Ghostty's queued callback after drawing it in that same frame. */
  private pendingWriteCompletion: (() => void) | undefined;
  /** Identifies the pending callback for the one atomic mode-2026 write held behind earlier output. */
  private pendingWriteSynchronizedBatch = false;
  /** Synchronous segment writes cannot expose a partial mode-2026 batch through a renderer callback. */
  private synchronizedBatchWriting = false;
  /** Monotonic timestamps expose the actual release and paint callbacks to the marked test surface. */
  private synchronizedTimeoutReleasedAt = 0;
  private lastPaintedOutputAt = 0;
  private snapshotWriteInFlight = false;
  private pendingSnapshot: PendingSnapshot | undefined;
  private receivedOutSeq = 0n;
  private lastOutSeq = 0n;
  private nextInSeq = 0n;
  private ackedInSeq = 0n;
  private creditAvailable = 0;
  private attached = false;
  /** A sent AttachTerm is only a request; the ordered, painted replay fence proves recovery. */
  private attachmentConfirmed = false;
  private attachRequested = false;
  private openCallSent = false;
  private fitQueued = false;
  private hasAttached = false;
  /** Bumped when the cursors restart, so a write that was in flight does not account for bytes that are gone. */
  private cursorEpoch = 0;
  /** Off screen: no drawing and no canvas backing store (see `setSuspended`). */
  private suspended = false;
  private closed = false;
  /** Saved status survives reconnect until the final Close; a live exit still owns its paint barrier. */
  private pendingExit: { status: number; finalSeq: bigint; retired?: boolean } | undefined;
  private exitReported = false;
  /** The server's final answer that the session is gone: no attach is ever sent for it again. */
  private sessionGone = false;
  /** A later full census can add a saved exit code after this stream is already final. */
  private sessionGoneStatus: number | undefined;
  /** Armed only after a transient shared-stream Close; live idle terminals have no retry timer. */
  private streamRetryTimer = 0;
  private streamRetryAttempt = 0;
  private attachedAt = 0;
  private inputPaused = false;
  private inputAtCapacityMessageShown = false;
  private connectionIsResume = false;
  /** Existing-session restores suppress parser replies until the server's replay fence has painted. */
  private suppressReplayResponses = false;
  private replayResponseFence: bigint | undefined;
  /** The size the replay was captured at, from the same fence; absent from an older server. */
  private replayCapturedSize: ScreenSize | undefined;
  /** Scoped only around synchronous renderer writes; keyboard input arrives in later event tasks. */
  private suppressTerminalResponses = false;
  // Allocate only when output is scanned; a reset before the first write has no query state.
  private terminalQueries: TerminalQueries | undefined;
  private parserReplies: string[] | undefined;
  private parserReplyLength = 0;
  private renderIdleTimer = 0;
  /** Set by writes and consumed by the next renderer pass; link parsing itself waits for an idle callback. */
  private linkRowsArmed = false;
  private linkBufferType: string | undefined;
  private linkController: TerminalLinkController | undefined;
  private linkControllerLoading: Promise<void> | undefined;
  private readonly pendingLinkRows = new Set<number>();
  private readonly forcedLinkRows = new Set<number>();
  /** D249: the live cursor, a layer of its own that the compositor blinks; the renderer never draws it while this shows. */
  private cursorLayer: TerminalCursorLayer | undefined;
  /** D309: after a reattach, silence from the program means its screen may be out of date; see stale-screen.ts. */
  private staleNote: TerminalNote | undefined;
  private staleWatch: StaleScreenWatch | undefined;
  private roundTripMs: number | undefined;
  private rendererCursorHidden = false;
  /**
   * Whether typing would reach this terminal now. A desktop terminal focuses itself, so it is always ready. On a
   * phone the keyboard needs a tap: until the terminal's input has focus the cursor waits (steady, an underline) and
   * after the keyboard goes away it waits again; a blinking cursor never promises a keyboard that will not come (D191).
   */
  private typingReady = !matchMedia("(pointer: coarse)").matches;
  private predictionCursorHidden = false;
  private lastThemeColorsMs = 0;
  private lastThemeRenderMs = 0;
  private inputModifiers: InputModifiers = { ctrl: "off", alt: "off" };
  private readonly prediction: PredictiveEcho | undefined;
  private lastSize = { cols: 80, rows: 24, pxW: 0, pxH: 0 };
  private readonly onViewportChange = (): void => this.syncVisualViewport();
  private readonly onTerminalActivity = (): void => this.wakeTerminal();
  private readonly onBlinkInput = (): void => this.restartCursorBlink();
  private readonly onBlinkEnvironment = (): void => this.restartCursorBlink();
  private readonly disposeTouch: () => void;

  private constructor(private readonly config: TerminalConfig, terminal: Terminal, font: MonoFont) {
    this.terminal = terminal;
    this.font = font;
    this.ghostty = terminal as unknown as GhosttyActivityControls;
    this.synchronizedOutput = new SynchronizedOutput(
      () => {
        this.synchronizedTimeoutReleasedAt = performance.now();
        this.synchronizedOutputBatchPending = this.synchronizedOutput.requiresAtomicPaint;
        this.wakeTerminal();
        this.drainOutput();
      },
      () => this.paintSynchronizedRelease(),
    );
    this.screen = config.screen ?? config.host.parentElement ?? config.host;
    // Opening a renderer must never choose the page's input destination. Its
    // default focus also schedules another focus task, after user input can run.
    // Suppress both at their source; open() below applies the owner's intent.
    const rendererFocus = terminal.focus;
    terminal.focus = () => {};
    try { terminal.open(config.host); } finally { terminal.focus = rendererFocus; }
    // Keep Ghostty's scrollbar drag handler, but let the on-demand controller own link scanning and activation.
    (terminal as unknown as { linkDetector?: unknown }).linkDetector = undefined;
    const write = terminal.write.bind(terminal);
    terminal.write = (data, callback) => {
      this.linkRowsArmed = true;
      write(data, callback);
    };
    // Phones wait for a real tap before opening the keyboard (D191).
    this.disposeTouch = terminalTouch(config.host, terminal, () => this.cellMetrics(), () => this.scheduleFit(), () => this.wakeTerminal());
    this.pauseTerminal(); // Ghostty opens with one live loop; the client owns its activity window.
    this.terminal.options.scrollback = config.scrollbackLimit ?? 10_000;
    this.prediction = config.predictiveEcho === true
      ? new PredictiveEcho({
        host: config.host,
        optedIn: true,
        getPosition: () => this.predictionPosition(),
        onVisible: (sequence, at) => config.hooks?.onTrace?.(sequence, "prediction", at),
        setHostCursorHidden: (hidden) => this.setPredictionCursorHidden(hidden),
      })
      : undefined;
    this.cursorLayer = mountTerminalCursorLayer(config.host);
    this.staleNote = mountTerminalNote(config.host, "screen may be out of date");
    this.staleWatch = new StaleScreenWatch((shown) => {
      if (!shown) { this.staleNote?.hide(); return; }
      const cursorRow = this.terminal.wasmTerm?.getCursor().y ?? 0;
      this.staleNote?.show(cursorRow, this.terminal.rows);
    }, { after: (ms, run) => window.setTimeout(run, ms), cancel: (handle) => window.clearTimeout(handle as number) });
    config.host.addEventListener("pointerdown", this.onTerminalActivity, { passive: true });
    config.host.addEventListener("pointerdown", this.onBlinkInput, { passive: true });
    document.addEventListener("visibilitychange", this.onBlinkEnvironment);
    window.addEventListener("blur", this.onBlinkEnvironment);
    window.addEventListener("focus", this.onBlinkEnvironment);
    config.host.addEventListener("pointermove", this.onTerminalActivity, { passive: true });
    config.host.addEventListener("wheel", this.onTerminalActivity, { passive: true });
    this.resizeObserver = new ResizeObserver(() => {
      this.wakeTerminal();
      this.scheduleFit();
    });
    this.resizeObserver.observe(config.host);
    window.visualViewport?.addEventListener("resize", this.onViewportChange);
    window.visualViewport?.addEventListener("scroll", this.onViewportChange);
    this.terminal.onResize(({ cols, rows }) => {
      // The grid is readable from the page (specs, and anyone judging that a line did not rewrap).
      config.host.dataset.cols = String(cols); config.host.dataset.rows = String(rows);
      this.prediction?.layoutChanged();
      this.wakeTerminal();
      const rect = config.host.getBoundingClientRect();
      this.lastSize = { cols, rows, pxW: toU16(rect.width), pxH: toU16(rect.height) };
      if (this.attached) this.sendFrame(this.streamId, { type: "Resize", ...this.lastSize });
      this.linkController?.invalidateBuffer();
    });
    this.terminal.onData((data) => {
      // Replayed parser replies are not typing: they neither reach the shell nor restart the blink.
      if (this.suppressTerminalResponses) {
        this.wakeTerminal();
        return;
      }
      if (this.parserReplies) {
        this.parserReplyLength += data.length;
        if (this.parserReplyLength <= 1024) {
          if (this.parserReplies === EMPTY_PARSER_REPLIES) this.parserReplies = [data];
          else this.parserReplies.push(data);
        }
        this.wakeTerminal();
        return;
      }
      // Starting the render loop may run a frame synchronously, so send typed bytes first.
      this.handleInput(data);
      this.restartCursorBlink();
      this.wakeTerminal();
    });
    this.terminal.onScroll((offset) => {
      this.wakeTerminal();
      if (offset !== 0) this.prediction?.unsafeScreen();
      else this.prediction?.returnToLiveViewport();
      config.host.dataset.scrolled = String(offset !== 0);
      config.onScroll?.(offset !== 0);
      this.queueVisibleLinkRows();
    });
    const known = config.attachSessionId ?? config.initialSessionId;
    if (known && isCanonicalUuid(known)) {
      // A page reload has no pending-input buffer or writer capability. Start
      // a fresh writer at zero. The renderer restores the old screen silently
      // through the replay fence; server-owned session authorization validates
      // this nonsecret convenience identifier.
      this.sessionId = uuidBytes(known);
      this.suppressReplayResponses = true;
    }
    const ended = config.getEndedSession?.();
    if (ended) {
      this.sessionGone = true;
      this.sessionGoneStatus = ended.status;
    }
    this.scheduleFit();
    this.ownsConnection = config.connection === undefined;
    this.conn = config.connection ?? new MuxConnection({
      ...(config.traceMockServer ? { traceMockServer: true } : {}),
      ...(config.onRecoveryPending ? { onRecoveryPending: config.onRecoveryPending } : {}),
      ...(config.onConnectionChange ? { onConnectionChange: config.onConnectionChange } : {}),
    });
    // The round trip is the connection's; every terminal on it reads it (prediction needs it, the pill shows it).
    this.offRoundTrip = this.conn.onRoundTrip((ms) => {
      this.roundTripMs = ms;
      this.prediction?.setRoundTrip(ms);
      config.onRoundTrip?.(ms);
    });
    this.streamId = this.conn.openStream(this.streamHandler());
    if (ended) {
      if (config.hooks?.onSessionGone) config.hooks.onSessionGone(ended.status);
      else this.setStatus("This session has ended. Open a new shell to continue.");
    }
    config.host.addEventListener("focusin", () => { this.setTypingReady(true); this.restartCursorBlink(); });
    config.host.addEventListener("focusout", (event) => {
      if (!config.host.contains(event.relatedTarget as Node | null)) this.cursorLayer?.stopBlink();
      // Focus moving between the host's own elements (its input and the host) keeps the terminal ready.
      if (!config.host.contains(event.relatedTarget as Node | null) && matchMedia("(pointer: coarse)").matches) this.setTypingReady(false);
    });
    this.paintTypingState();
  }

  /**
   * Loads the chosen font's upright faces and the WASM terminal once, then opens the
   * one-session client. Only the upright faces gate the first paint, because the cell
   * grid is measured from them; italic and Nerd Font faces load afterwards.
   */
  static async open(config: TerminalConfig): Promise<TerminalClient> {
    // Initialization yields to input. Any focus or input activity during that
    // wait supersedes automatic focus, even if focus later returns to the body.
    const focusIntent = captureFocusIntent(document);
    try {
      const font = config.font ?? fontById(DEFAULT_FONT_ID)!;
      await TerminalClient.prepareResources(font);
      // Restored windows share the resource promise. Give each renderer its own
      // task so dozens of initializations cannot hold queued socket replies in
      // one microtask batch (#245); the first window pays only one task turn.
      await new Promise<void>((resolve) => window.setTimeout(resolve, 0));
      const terminal = TerminalClient.createRenderer(font, config);
      const client = new TerminalClient(config, terminal, font);
      // Weights go in before the first measurement so the grid is measured from the face it draws.
      client.installFontWeights();
      client.remeasureFont();
      client.keepLigaturesOff();
      client.installCursorLayerHook();
      client.loadStyledFaces();
      // An already opened terminal has paid the same first-renderer cost. Also
      // supersede an optional warm-up still waiting for resources on this font.
      TerminalClient.rendererWarmups.set(font.id, Promise.resolve());
      if (focusIntent.isCurrent() && (config.shouldFocusOnOpen?.() ?? true) && !matchMedia("(pointer: coarse)").matches) {
        // Automatic focus is immediate, with no deferred renderer callback that
        // could take focus back after the person has moved to another surface.
        (terminal.textarea ?? config.host).focus();
      }
      return client;
    } finally {
      focusIntent.dispose();
    }
  }

  private static createRenderer(font: MonoFont, config: Pick<TerminalConfig, "scrollbackLimit" | "theme">): Terminal {
    return new Terminal({
      fontFamily: fontStack(font),
      fontSize: matchMedia("(pointer: coarse)").matches ? TERMINAL_FONT_SIZE_TOUCH : TERMINAL_FONT_SIZE_DESKTOP,
      cursorBlink: false,
      cursorStyle: "bar",
      scrollback: config.scrollbackLimit ?? 10_000,
      theme: config.theme ?? {
        background: "#101113",
        foreground: "#e6e7e9",
        cursor: "#c8ceff",
        cursorAccent: "#101113",
        selectionBackground: "#44485c",
      },
    });
  }

  /** Warm font, parser and canvas setup during sign-in; no session or socket is opened. */
  static async prepare(font: MonoFont = fontById(DEFAULT_FONT_ID)!): Promise<void> {
    let warmup = TerminalClient.rendererWarmups.get(font.id);
    if (!warmup) {
      warmup = TerminalClient.prepareResources(font).then(() => {
        if (TerminalClient.rendererWarmups.get(font.id) !== warmup) return;
        // First canvas/font setup can block long enough to expire a healthy
        // socket. Exercise it before publication, with no input or live loop
        // left behind. Inert, hidden content cannot steal sign-in focus.
        const host = document.createElement("div");
        host.inert = true;
        host.style.cssText = "position:fixed;left:-10000px;top:0;width:800px;height:480px;visibility:hidden;pointer-events:none";
        const renderer = TerminalClient.createRenderer(font, {});
        try {
          document.body.append(host);
          renderer.open(host);
        } finally {
          try { renderer.dispose(); } finally { host.remove(); }
        }
      });
      TerminalClient.rendererWarmups.set(font.id, warmup);
      const pending = warmup;
      void warmup.catch(() => {
        if (TerminalClient.rendererWarmups.get(font.id) === pending) TerminalClient.rendererWarmups.delete(font.id);
      });
    }
    await warmup;
  }

  private static async prepareResources(font: MonoFont): Promise<void> {
    let renderer = TerminalClient.rendererPreparation;
    if (!renderer) {
      renderer = init();
      TerminalClient.rendererPreparation = renderer;
      // Concurrent opens/preparation must share one instance. A failed optional
      // warm-up must not poison the later session's ordinary initialization.
      void renderer.catch(() => {
        if (TerminalClient.rendererPreparation === renderer) TerminalClient.rendererPreparation = undefined;
      });
    }
    await Promise.all([loadFont(font), renderer]);
  }

  get isConnected(): boolean { return this.attachmentConfirmed; }
  get outputSequence(): bigint { return this.lastOutSeq; }
  get inputSequence(): bigint { return this.nextInSeq; }
  get inputAcknowledged(): bigint { return this.ackedInSeq; }
  get predictiveEchoState(): PredictiveEchoState {
    return this.prediction?.state ?? {
      optedIn: false,
      enabled: false,
      roundTripMs: undefined,
      pendingText: "",
      muted: false,
      mispredictions: 0,
      fallbacks: {},
      inputCostMs: [],
      overlay: undefined,
      reason: "flag-off",
    };
  }

  /** Available only through the mock-page hook for paired on/off measurements. */
  setPredictiveEchoForTest(enabled: boolean): void {
    this.prediction?.setOptedIn(enabled);
  }

  /** Exposes renderer allocation counters only through the explicit test-double hook. */
  get rendererMetrics(): {
    cols: number;
    rows: number;
    cellWidth: number;
    cellHeight: number;
    naturalCellWidth: number;
    configuredScrollback: number;
    cursorX: number;
    cursorY: number;
    renderCursorX: number;
    renderCursorY: number;
    renderCursorVisible: boolean;
    rendererAccentColor: string;
    themeColorsMs: number;
    themeRenderMs: number;
    synchronizedOutputHoldsPaint: boolean;
    synchronizedTimeoutReleasedAt: number;
    lastPaintedOutputAt: number;
    terminalColors?: { background: { r: number; g: number; b: number }; foreground: { r: number; g: number; b: number } };
    receivedSequence: string;
    outputSequence: string;
    scrollbackRows: number;
    viewportY: number;
    cursorVisible: boolean;
    fontSize: number;
    fontFamily: string;
    fontId: string;
    wasmMemoryBytes: number;
  } {
    const wasmTerm = this.terminal.wasmTerm;
    const memory = (wasmTerm as unknown as { memory?: WebAssembly.Memory } | undefined)?.memory;
    const renderer = this.ghostty.renderer as unknown as { naturalCellWidth?: number } | undefined;
    const colors = wasmTerm?.getColors();
    const cell = this.cellMetrics();
    const cursor = wasmTerm?.getCursor();
    return {
      cols: this.terminal.cols,
      rows: this.terminal.rows,
      cellWidth: cell.width,
      cellHeight: cell.height,
      naturalCellWidth: renderer?.naturalCellWidth ?? cell.width,
      configuredScrollback: this.terminal.options.scrollback ?? 10_000,
      cursorX: cursor?.x ?? 0,
      cursorY: cursor?.y ?? 0,
      renderCursorX: cursor?.x ?? 0,
      renderCursorY: cursor?.y ?? 0,
      renderCursorVisible: Boolean(cursor?.visible),
      rendererAccentColor: this.ghostty.renderer?.theme?.cursor ?? "",
      themeColorsMs: this.lastThemeColorsMs,
      themeRenderMs: this.lastThemeRenderMs,
      synchronizedOutputHoldsPaint: this.synchronizedOutput.holdsPaint,
      synchronizedTimeoutReleasedAt: this.synchronizedTimeoutReleasedAt,
      lastPaintedOutputAt: this.lastPaintedOutputAt,
      ...(colors ? { terminalColors: { background: colors.background, foreground: colors.foreground } } : {}),
      receivedSequence: this.receivedOutSeq.toString(),
      outputSequence: this.lastOutSeq.toString(),
      scrollbackRows: wasmTerm?.getScrollbackLength() ?? 0,
      viewportY: this.terminal.viewportY,
      cursorVisible: Boolean(cursor?.visible),
      fontSize: this.terminal.options.fontSize,
      fontFamily: this.terminal.options.fontFamily ?? "",
      fontId: this.font.id,
      wasmMemoryBytes: memory?.buffer.byteLength ?? 0,
    };
  }

  /** Returns bounded renderer text for the explicitly marked test-double page. */
  readScreenText(): string {
    const maxRows = Math.max(10_000, this.terminal.options.scrollback ?? 10_000);
    return terminalBufferText(this.terminal, maxRows);
  }

  /** Replays test-double output in a second Ghostty instance for differential checks. */
  async baselineScreenText(bytes: Uint8Array): Promise<string> {
    if (bytes.byteLength > 64 * 1024) throw new Error("differential replay exceeds its test bound");
    const rect = this.config.host.getBoundingClientRect();
    const holder = document.createElement("div");
    Object.assign(holder.style, {
      position: "fixed",
      left: `${-Math.ceil(rect.width) - 100}px`,
      top: "0",
      width: `${rect.width}px`,
      height: `${rect.height}px`,
      visibility: "hidden",
      pointerEvents: "none",
    });
    document.body.append(holder);
    const baseline = new Terminal({
      fontFamily: this.terminal.options.fontFamily,
      fontSize: this.terminal.options.fontSize,
      cursorBlink: false,
      cursorStyle: this.terminal.options.cursorStyle,
      scrollback: this.terminal.options.scrollback,
      theme: this.terminal.options.theme,
    });
    try {
      baseline.open(holder);
      baseline.resize(this.terminal.cols, this.terminal.rows);
      await new Promise<void>((resolve) => baseline.write(bytes, resolve));
      return terminalBufferText(baseline, Math.max(10_000, baseline.options.scrollback ?? 10_000));
    } finally {
      baseline.dispose();
      holder.remove();
    }
  }

  /** Reads indexed and literal RGB probe cells on the browser fixture's history rows. */
  readThemeHistoryColors(): { rows: number; indexed: number[]; truecolor: number[] } {
    const buffer = this.terminal.buffer.active;
    const scrollbackRows = this.terminal.getScrollbackLength();
    const indexed: number[] = [];
    const truecolor: number[] = [];
    const historyPrefix = "theme-history-";
    for (let row = 0; row < scrollbackRows && indexed.length < THEME_HISTORY_PROBE_ROWS; row += 1) {
      const line = buffer.getLine(row);
      if (!line || line.translateToString(false, 0, historyPrefix.length) !== historyPrefix) continue;
      const indexedCell = line.getCell(THEME_HISTORY_INDEXED_COLUMN);
      const truecolorCell = line.getCell(THEME_HISTORY_TRUECOLOR_COLUMN);
      if (!indexedCell || !truecolorCell) continue;
      indexed.push(indexedCell.getFgColor());
      truecolor.push(truecolorCell.getFgColor());
    }
    return { rows: indexed.length, indexed, truecolor };
  }

  /** Reads renderer graphemes from the test-only tail, including ZWJ and modifier codepoints. */
  readGraphemeText(): string {
    const buffer = this.terminal.buffer.active;
    const first = Math.max(0, buffer.length - this.terminal.rows - 256);
    const wasmTerm = this.terminal.wasmTerm;
    const scrollbackRows = wasmTerm?.getScrollbackLength() ?? 0;
    const lines: string[] = [];
    for (let row = first; row < buffer.length; row += 1) {
      const line = buffer.getLine(row);
      if (!line) continue;
      let text = "";
      for (let col = 0; col < line.length; col += 1) {
        const cell = line.getCell(col);
        if (!cell || cell.getWidth() === 0) continue;
        if (cell.getCodepoint() === 0) {
          text += " ";
        } else if (wasmTerm && row < scrollbackRows) {
          text += wasmTerm.getScrollbackGraphemeString(row, col);
        } else if (wasmTerm) {
          text += wasmTerm.getGraphemeString(row - scrollbackRows, col);
        } else {
          text += cell.getChars();
        }
      }
      lines.push(text.trimEnd());
    }
    return lines.join("\n");
  }

  /** Injects probe input through Ghostty's normal input event path. */
  injectInput(data: string): void {
    if (this.closed || this.pendingExit || this.inputPaused) throw new Error("terminal input is paused");
    this.terminal.input(data, true);
  }

  /** Seeds a visible shell prompt in the mock page without advancing wire sequences. */
  async seedPromptForTest(): Promise<void> {
    if (this.closed) throw new Error("terminal is closed");
    await new Promise<void>((resolve) => this.terminal.write("$ ", resolve));
    this.prediction?.refresh();
  }

  /** Writes text onto the screen without the wire (mock pages only): a mockup prints what a shell would show. */
  async writeTextForTest(text: string): Promise<void> {
    if (this.closed) throw new Error("terminal is closed");
    this.wakeTerminal(); // the render loop idles between outputs; a local write must be painted too
    await new Promise<void>((resolve) => this.terminal.write(text, resolve));
    this.prediction?.refresh();
  }

  /**
   * Parks the terminal while its window is off screen, in another view or a thumbnail. Output keeps flowing
   * into the terminal state (cheap, and credit keeps returning), but nothing is drawn and the canvas gives its
   * backing store back: a phone must hold about one screen of pixels, not one per window (iOS ends a page that
   * holds more). Resuming restores the canvas at the current grid and repaints once.
   */
  setSuspended(suspended: boolean): void {
    if (suspended === this.suspended || this.closed) return;
    this.suspended = suspended;
    if (suspended) {
      window.clearTimeout(this.renderIdleTimer);
      this.pauseTerminal();
      this.releaseSurface();
      this.cursorLayer?.hide();
      return;
    }
    this.restoreSurface();
    this.scheduleFit();
    this.wakeTerminal();
    this.linkController?.updateVisibleRows();
  }

  /** Links already recognized in the active terminal's visible viewport, for the keyboard palette. */
  linksOnScreen(): readonly TerminalLink[] { return this.linkController?.linksOnScreen() ?? []; }

  /** Opens a target only while a matching, openable link is still visible in this terminal. */
  openLinkFromPalette(target: string): boolean { return this.linkController?.openTarget(target) ?? false; }

  /** Recomputes the grid from the host's box (the window was resized). */
  refit(): void {
    this.scheduleFit();
  }

  /**
   * Keyboard font size (D222): one point up or down, or back to this device's default. The size stays in the range a
   * terminal reads at (the pinch range of terminal-touch.ts), and the grid refits once. Only this window changes; the
   * others keep theirs.
   */
  adjustFontSize(step: number | "reset"): void {
    if (this.closed) return;
    const base = matchMedia("(pointer: coarse)").matches ? TERMINAL_FONT_SIZE_TOUCH : TERMINAL_FONT_SIZE_DESKTOP;
    const current = this.terminal.options.fontSize ?? base;
    const next = step === "reset" ? base : Math.min(TERMINAL_FONT_SIZE_MAX, Math.max(TERMINAL_FONT_SIZE_MIN, current + step));
    if (next === current) return;
    this.terminal.options.fontSize = next;
    // The size is also on the host, where a test (and a person inspecting the page) can read it.
    this.config.host.dataset.fontSize = String(next);
    this.wakeTerminal();
    this.scheduleFit();
  }

  private setTypingReady(ready: boolean): void {
    if (ready === this.typingReady || this.closed) return;
    this.typingReady = ready;
    this.paintTypingState();
    this.wakeTerminal();
  }

  /** The cursor tells the truth: a bar that blinks when typing will land, a steady underline while it waits for a tap. */
  private paintTypingState(): void {
    this.config.host.dataset.typing = this.typingReady ? "ready" : "waiting";
    this.terminal.options.cursorStyle = this.typingReady ? "bar" : "underline";
    this.syncCursorLayer();
    this.restartCursorBlink();
  }

  /**
   * Focuses the element that receives typing so the mobile keyboard can stay open. That is the renderer's text input, as
   * when a pointer lands on the canvas: committed text (a phone keyboard, an IME commit, dictation) arrives as
   * `beforeinput` on it only, while the container merely sees physical keys. The renderer's own `focus()` targets the
   * container and re-focuses it on the next task, so it is the fallback before the input exists.
   */
  focus(): void {
    const input = this.config.host.querySelector("textarea");
    if (input) input.focus({ preventScroll: true });
    else this.terminal.focus();
  }

  /** Sets one modifier; the one-argument form keeps the earlier keybar API compatible. */
  setInputModifier(modifier: "ctrl" | "alt" | null): void;
  setInputModifier(modifier: "ctrl" | "alt", state: InputModifierState): void;
  setInputModifier(modifier: "ctrl" | "alt" | null, state?: InputModifierState): void {
    if (modifier && state) {
      this.inputModifiers[modifier] = state;
      return;
    }
    this.inputModifiers = {
      ctrl: modifier === "ctrl" ? "armed" : "off",
      alt: modifier === "alt" ? "armed" : "off",
    };
  }

  /** Updates both Ghostty's option record and renderer palette without rebuilding the session. */
  setTheme(theme: ITheme): void {
    if (sameTheme(this.config.theme, theme)) return;
    const optionsTheme = this.terminal.options.theme;
    const themeColors = localThemeColorValues(theme, optionsTheme);
    this.config.theme = theme;
    // The options root is proxied; mutate its nested theme to avoid the pinned
    // runtime warning while keeping terminal resets aligned with the active look.
    Object.assign(optionsTheme, theme);
    const renderer = this.ghostty.renderer;
    renderer?.setTheme(theme);
    const buffer = this.terminal.wasmTerm;
    if (!buffer) return;

    // Palette-backed cells stay indexed in libghostty-vt. Updating its palette
    // locally recolors retained rows; literal RGB cells remain untouched.
    let startedAt = performance.now();
    for (const [index, color] of themeColors.entries()) buffer.setThemeColor(index, color);
    this.lastThemeColorsMs = performance.now() - startedAt;
    startedAt = performance.now();
    renderer?.render(buffer, true, this.terminal.viewportY, this.terminal, this.ghostty.scrollbarOpacity);
    this.lastThemeRenderMs = performance.now() - startedAt;
    this.prediction?.rendererPainted();
    this.prediction?.refresh();
  }

  /** Forces a WebSocket close for the opt-in resume probe. */
  forceDrop(): void {
    this.conn.forceDrop();
  }

  dispose(): void {
    if (this.closed) return;
    this.closed = true;
    this.cursorEpoch += 1;
    this.terminalQueries?.reset();
    this.terminalQueries = undefined;
    this.synchronizedOutput.dispose();
    this.cancelStreamRetry();
    this.linkController?.dispose();
    this.linkController = undefined;
    this.pendingLinkRows.clear();
    this.forcedLinkRows.clear();
    this.disposeTouch();
    this.pauseTerminal();
    this.config.host.removeEventListener("pointerdown", this.onTerminalActivity);
    this.config.host.removeEventListener("pointerdown", this.onBlinkInput);
    document.removeEventListener("visibilitychange", this.onBlinkEnvironment);
    window.removeEventListener("blur", this.onBlinkEnvironment);
    window.removeEventListener("focus", this.onBlinkEnvironment);
    this.cursorLayer?.dispose();
    this.cursorLayer = undefined;
    this.staleWatch?.reset();
    this.staleWatch = undefined;
    this.staleNote?.dispose();
    this.staleNote = undefined;
    this.config.host.removeEventListener("pointermove", this.onTerminalActivity);
    this.config.host.removeEventListener("wheel", this.onTerminalActivity);
    if (this.attachmentConfirmed) this.conn.streamAttached(false);
    this.offRoundTrip();
    this.prediction?.dispose();
    this.resizeObserver.disconnect();
    window.visualViewport?.removeEventListener("resize", this.onViewportChange);
    window.visualViewport?.removeEventListener("scroll", this.onViewportChange);
    this.inputResendNotice?.dispose();
    this.inputQueue.clear();
    this.retainedInput?.fill(0);
    this.retainedInput = undefined;
    this.inputNeedsResend = false;
    this.inputResendNoticeVisible = false;
    this.outputQueue.clear();
    this.pendingSnapshot?.bytes.fill(0);
    // A shared connection only detaches this stream: the session keeps running (D178).
    if (this.ownsConnection) this.conn.dispose(); else this.conn.closeStream(this.streamId);
    this.terminal.dispose();
  }

  /** What the connection needs from this terminal's stream. */
  private streamHandler(): StreamHandler {
    return {
      onSocketOpen: (resuming) => {
        if (this.closed || (this.pendingExit && !this.pendingExit.retired) || this.sessionGone) return;
        this.cancelStreamRetry();
        this.connectionIsResume = this.sessionId !== undefined;
        if (this.sessionId && resuming) {
          this.attachRequested = true;
          this.tryAttach();
        } else if (this.sessionId) {
          this.attachRequested = true;
        }
      },
      onWelcome: (resumed) => {
        if (this.closed || (this.pendingExit && !this.pendingExit.retired) || this.sessionGone) return;
        this.cancelStreamRetry();
        // A restored renderer may join an already-open shared socket and miss
        // onSocketOpen. Session identity, not callback order, determines resume.
        this.connectionIsResume = this.sessionId !== undefined;
        // A connection the server does not know starts every writer at zero, like a page reload.
        if (!resumed && this.hasAttached) this.restartCursors(true);
        if (!this.sessionId) this.openSession();
        else {
          this.attachRequested = true;
          this.tryAttach();
        }
      },
      onFrame: (frame, message, receivedAt) => this.handleTerminalFrame(frame, message, receivedAt),
      onDisconnected: (forced) => {
        this.cancelStreamRetry();
        if (this.closed || this.exitReported || this.sessionGone) return;
        this.attached = false;
        this.attachmentConfirmed = false;
        this.attachRequested = false;
        this.openCallSent = false;
        this.staleWatch?.reset();
        this.config.hooks?.onDisconnected?.(forced);
        this.setStatus("Connection lost. Reconnecting…");
      },
      hasSession: () => this.sessionId !== undefined,
      onStatus: (message) => this.setStatus(message),
    };
  }

  private handleTerminalFrame(frame: WireFrame, message: Uint8Array, receivedAt: number): void {
    if (!this.attached) {
      this.protocolFailure("server sent terminal data before AttachTerm");
      return;
    }
    switch (frame.type) {
      case "Ack":
        this.acknowledgeInput(frame.inSeqAcked);
        return;
      case "Output":
        this.traceRange(frame.outSeq, frame.bytes.byteLength, "wsMessage", receivedAt);
        this.traceRange(frame.outSeq, frame.bytes.byteLength, "decode", performance.now());
        this.acceptOutput(frame.outSeq, frame.bytes, message);
        return;
      case "Snapshot":
        this.traceRange(frame.outSeq, frame.bytes.byteLength, "wsMessage", receivedAt);
        this.traceRange(frame.outSeq, frame.bytes.byteLength, "decode", performance.now());
        this.acceptSnapshot(frame.outSeq, frame.bytes);
        return;
      case "Event": {
        if (frame.subId !== 0 || frame.eventJson.byteLength > 1024) {
          this.protocolFailure("invalid terminal notice");
          return;
        }
        try {
          const notice = asRecord(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(frame.eventJson)));
          const session = uuidBytes(requireString(notice.session_id));
          if (!this.sessionId || session.some((byte, index) => byte !== this.sessionId?.[index])) throw new Error("session mismatch");
          // Notices describe recovery; only the subsequent wire Snapshot advances the cursor.
          if (notice.type === "terminal.query_replies_unavailable") {
            this.setStatus("Open a new shell to enable terminal query replies after this update.");
          } else if (notice.type === "terminal.reconnecting") {
            // The supervisor retains this writer and replays it on the new host link.
            // Keep new input locally until the replacement's replay fence is painted.
            if (this.attachmentConfirmed) {
              this.conn.streamAttached(false);
              this.config.hooks?.onDisconnected?.(false);
            }
            this.attachmentConfirmed = false;
            this.staleWatch?.reset();
            this.connectionIsResume = true;
            this.replayResponseFence = undefined;
            this.replayCapturedSize = undefined;
            this.suppressReplayResponses = true;
            this.setStatus(recoveringReason(typeof notice.reason === "string" ? notice.reason : undefined));
          } else if (notice.type === "terminal.link_doubt") {
            // The host link missed one reply but is kept: this is live output,
            // not replay. Only say so; replies to the program and typing go on.
            const shown = this.config.status.textContent ?? "";
            if (shown === "" || shown === LINK_DOUBT_STATUS) this.setStatus(LINK_DOUBT_STATUS);
            this.config.hooks?.onLinkDoubt?.(true);
          } else if (notice.type === "terminal.link_recovered") {
            // Clears only its own indicator; it is never a replay fence.
            if (this.config.status.textContent === LINK_DOUBT_STATUS) this.setStatus("");
            this.config.hooks?.onLinkDoubt?.(false);
          } else if (notice.type === "terminal.snapshot" && notice.approximate === true) {
            this.setStatus("Reconnected. The screen may be slightly out of date.");
            this.config.hooks?.onApproximate?.();
          } else if (notice.type === "terminal.snapshot_unavailable") {
            this.setStatus("Waiting for the screen to catch up.");
          } else if (notice.type === "terminal.replay_complete") {
            const sequence = requireString(notice.out_seq);
            if (!/^(0|[1-9][0-9]*)$/.test(sequence)) throw new Error("invalid replay cursor");
            const fence = BigInt(sequence);
            // The ordered event follows every replay frame and any Snapshot
            // repaint, so its cursor must equal the received PTY boundary.
            if (fence !== this.receivedOutSeq) throw new Error("replay cursor mismatch");
            this.replayResponseFence = fence;
            this.replayCapturedSize = replayedSize(notice);
            this.releaseReplayResponsesAfterPaint();
          } else if (notice.type === "terminal.exited") {
            if (!Number.isSafeInteger(notice.status) || !Number.isSafeInteger(notice.final_seq) || (notice.final_seq as number) < 0) throw new Error("invalid exit");
            const status = notice.status as number;
            if (status < -2147483648 || status > 2147483647) throw new Error("invalid status");
            const finalSeq = BigInt(notice.final_seq as number);
            // Live exits follow all final bytes; a saved exit proves status without a repaint.
            if (notice.retired !== undefined && typeof notice.retired !== "boolean") throw new Error("invalid retirement");
            const retired = notice.retired === true;
            if (retired ? finalSeq < this.receivedOutSeq : finalSeq !== this.receivedOutSeq) throw new Error("exit cursor mismatch");
            if (this.pendingExit && (this.pendingExit.status !== status || this.pendingExit.finalSeq !== finalSeq || (this.pendingExit.retired === true) !== retired)) throw new Error("changed exit");
            this.pendingExit = { status, finalSeq, retired };
            this.finishExit();
          }
          // Any other notice type comes from a newer server: it is additive, so ignore it.
        } catch {
          this.protocolFailure("invalid terminal notice");
        }
        return;
      }
      case "Ping":
        this.sendFrame(this.streamId, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs });
        return;
      case "Pong":
        this.conn.acceptPong(frame.nonce, frame.sentUs);
        return;
      case "Close":
        if (frame.code === CLOSE_SESSION_GONE) { this.endSession(); return; }
        // Every other stream close reattaches by itself, so its status never reads as an ending.
        this.setStatus(reattachReason(frame.reason));
        if (this.ownsConnection) this.conn.forceClose(frame.code, frame.reason);
        else this.retryStream();
        return;
      default:
        this.protocolFailure("server sent an invalid terminal-stream frame");
    }
  }

  /** Retain this stream's writer/cursors while siblings continue on the healthy shared socket. */
  private retryStream(): void {
    const wasConfirmed = this.attachmentConfirmed;
    if (this.attachmentConfirmed) this.conn.streamAttached(false);
    this.attached = false;
    this.attachmentConfirmed = false;
    this.attachRequested = false;
    if (this.closed || (this.pendingExit && !this.pendingExit.retired) || this.sessionGone || this.streamRetryTimer !== 0) return;
    if (performance.now() - this.attachedAt >= STABLE_CONNECTION_MS) this.streamRetryAttempt = 0;
    this.config.hooks?.onDisconnected?.(false);
    // A proven route gets one prompt reattach; repeated unconfirmed failures retain the bounded backoff.
    const delay = wasConfirmed ? 5 + Math.random() * 5 : reconnectDelay(this.streamRetryAttempt);
    this.streamRetryAttempt++;
    this.streamRetryTimer = window.setTimeout(() => {
      this.streamRetryTimer = 0;
      if (this.closed || (this.pendingExit && !this.pendingExit.retired) || this.sessionGone || !this.conn.isWelcomed) return;
      // Reuse the stream id: the server's durable writer owns the acknowledged
      // input cursor. A new stream would start a different writer at zero.
      this.connectionIsResume = true;
      this.attachRequested = true;
      this.tryAttach();
    }, delay);
  }

  private cancelStreamRetry(): void {
    window.clearTimeout(this.streamRetryTimer);
    this.streamRetryTimer = 0;
  }

  private openSession(): void {
    if (this.openCallSent || this.closed) return;
    const hostId = this.config.hostId ?? new URLSearchParams(location.search).get("host");
    if (hostId && !isCanonicalUuid(hostId)) {
      this.setStatus("That host address is not valid.");
      return;
    }
    this.openCallSent = true;
    this.conn.call("ssh.session.open", hostId ? { host_id: hostId } : {}).then((result) => {
      if (this.closed || this.sessionId) return;
      try {
        const sessionId = requireString(result.session_id);
        this.sessionId = uuidBytes(sessionId);
        this.config.hooks?.onSessionCreated?.(sessionId);
        this.attachRequested = true;
        this.tryAttach();
      } catch {
        this.protocolFailure("terminal.open returned an invalid session id");
      }
    }, (error: unknown) => {
      this.openCallSent = false;
      if (!this.closed && this.conn.isOpen) {
        const refusal = terminalRefusal(error, this.config.hostName);
        if (!this.config.hooks?.onOpenRefused?.(refusal.message, refusal.sessionList)) this.setStatus(refusal.message);
      }
    });
  }

  private tryAttach(): void {
    if (!this.attachRequested || !this.sessionId || this.attached || this.closed || this.exitReported || this.sessionGone || !this.conn.isOpen) return;
    if (this.outputWriteInFlight || this.snapshotWriteInFlight || this.pendingSnapshot || this.outputQueue.length > 0) return;
    this.attachRequested = false;
    this.attached = true;
    this.attachedAt = performance.now();
    this.sendFrame(this.streamId, {
      type: "AttachTerm",
      sessionId: this.sessionId,
      lastOutSeq: this.lastOutSeq,
      // Only server-confirmed bytes belong in Resume; retained input replays separately.
      lastInSeq: this.ackedInSeq,
    });
    this.creditAvailable = INITIAL_CREDIT;
    this.sendFrame(this.streamId, { type: "Credit", bytes: INITIAL_CREDIT });
    this.sendFrame(this.streamId, { type: "Resize", ...this.lastSize });
    this.setStatus("Catching up…");
    this.hasAttached = true;
    this.wakeTerminal();
  }

  /** The session this terminal shows, as a lowercase UUID. */
  get sessionUuid(): string | undefined {
    const b = this.sessionId;
    if (!b) return undefined;
    const hex = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  /** A full host inventory retired this session; stop stream retries and retain any saved exit status. */
  markSessionGone(status?: number): void {
    this.endSession(status);
  }

  /** The renderer's canvas, for a caller that keeps a picture of the last screen (the switch's ghost). */
  get canvas(): HTMLCanvasElement | undefined {
    return this.config.host.querySelector<HTMLCanvasElement>("canvas:not(.cl-ghost)") ?? undefined;
  }

  /**
   * Shows another session in this same terminal, without tearing the renderer down (#128): the old stream detaches
   * (its session keeps running), the screen starts over, and a new stream attaches to `sessionId` from the
   * beginning, as after a reload. Nothing waits on the network: the attach goes out now and the snapshot paints when
   * it arrives. Font, glyph atlas, canvas and layout stay.
   */
  retarget(sessionId: string): void {
    if (this.closed || !isCanonicalUuid(sessionId)) return;
    this.restartOn(uuidBytes(sessionId));
  }

  /**
   * Starts a new shell on the same host in this same terminal (the ended state's one action): like `retarget`, but
   * the new stream opens a session instead of attaching to one. The window, renderer and layout stay.
   */
  openNewSession(): void {
    if (this.closed) return;
    this.restartOn(undefined);
  }

  /** Moves this terminal to a fresh stream for `sessionId`, or for a new session when there is none. */
  private restartOn(sessionId: Uint8Array | undefined): void {
    this.cancelStreamRetry();
    this.streamRetryAttempt = 0;
    if (this.attachmentConfirmed) this.conn.streamAttached(false);
    this.conn.closeStream(this.streamId);
    this.attached = false;
    this.attachmentConfirmed = false;
    this.attachRequested = false;
    this.openCallSent = false;
    this.hasAttached = false;
    this.pendingExit = undefined;
    this.exitReported = false;
    this.sessionGone = false;
    this.sessionGoneStatus = undefined;
    this.snapshotWriteInFlight = false;
    this.outputWriteInFlight = false;
    this.sessionId = sessionId;
    this.restartCursors();
    this.connectionIsResume = sessionId !== undefined;
    this.setStatus("");
    this.streamId = this.conn.openStream(this.streamHandler());
    // Choosing a session is the person's own act in this window, so on a desktop the keys go to it, as for a new terminal.
    if (!matchMedia("(pointer: coarse)").matches) this.terminal.focus();
  }

  /**
   * The server's final answer: the host no longer has this session. Stop for good (no reattach on this or any later
   * socket), release the stream, and let the window say so. Typing goes nowhere until a new session starts.
   */
  private endSession(status?: number): void {
    if (this.sessionGone || this.closed) {
      if (this.sessionGone && status !== undefined && this.sessionGoneStatus !== status) {
        this.sessionGoneStatus = status;
        this.config.hooks?.onSessionGone?.(status);
      }
      return;
    }
    this.sessionGone = true;
    this.sessionGoneStatus = this.pendingExit?.status ?? status;
    this.cancelStreamRetry();
    if (this.attachmentConfirmed) this.conn.streamAttached(false);
    this.attached = false;
    this.attachmentConfirmed = false;
    this.attachRequested = false;
    this.staleWatch?.reset();
    // The server keeps absorbing this stream's in-flight frames until this Close (contracts/wire.md §4).
    this.conn.closeStream(this.streamId);
    if (this.config.hooks?.onSessionGone) { this.setStatus(""); this.config.hooks.onSessionGone(this.sessionGoneStatus); }
    else this.setStatus("This session has ended. Open a new shell to continue.");
  }

  /** Fresh writers start at zero; retained typing requires explicit consent before its rebased bytes can replay. */
  private restartCursors(retainInput = false): void {
    this.cursorEpoch += 1;
    this.receivedOutSeq = 0n;
    this.lastOutSeq = 0n;
    this.parsedOutputVersion += 1;

    // A fresh writer has its own sequence space. Keep uncertain earlier bytes aside, so keys typed after this reset
    // can start at sequence zero and flow to the live shell while the person decides what to do with the old bytes.
    const previousLength = retainInput ? this.retainedInput?.byteLength ?? 0 : 0;
    const currentLength = retainInput ? this.inputQueue.length : 0;
    const retainedLength = previousLength + currentLength;
    if (retainedLength > INPUT_QUEUE_LIMIT) {
      this.protocolFailure("input resume queue exceeded its bound");
      return;
    }
    let nextRetained: Uint8Array | undefined;
    if (retainedLength > 0) {
      nextRetained = new Uint8Array(retainedLength);
      if (this.retainedInput && retainInput) nextRetained.set(this.retainedInput);
      let copied = 0;
      while (copied < currentLength) {
        const count = this.inputQueue.copyOut(copied, nextRetained.subarray(previousLength + copied));
        if (count === 0) {
          nextRetained.fill(0);
          this.protocolFailure("input resume queue is inconsistent");
          return;
        }
        copied += count;
      }
    }
    this.retainedInput?.fill(0);
    this.retainedInput = nextRetained;
    this.inputNeedsResend = nextRetained !== undefined;
    this.inputQueue.clear();
    this.nextInSeq = 0n;
    this.ackedInSeq = 0n;
    if (!this.inputNeedsResend) {
      this.inputResendNotice?.dismiss();
      this.inputResendNoticeVisible = false;
    }
    this.outputQueue.clear();
    this.staleWatch?.reset();
    this.replayResponseFence = undefined;
    this.replayCapturedSize = undefined;
    this.suppressReplayResponses = this.sessionId !== undefined;
    this.pendingSnapshot?.bytes.fill(0);
    this.pendingSnapshot = undefined;
    this.pendingWriteCompletion = undefined;
    this.pendingWriteSynchronizedBatch = false;
    this.prediction?.resetForSnapshot();
    this.terminalQueries?.reset();
    this.synchronizedOutput.reset();
    this.synchronizedOutputBatchPending = false;
    this.terminal.reset();
    this.resumeInputIfRoom();
  }

  /** Input capacity is shared by the live writer queue and bytes awaiting a resend decision. */
  private availableInputSpace(): number {
    return this.inputQueue.free - (this.retainedInput?.byteLength ?? 0);
  }

  private resumeInputIfRoom(): void {
    if (!this.inputPaused || this.availableInputSpace() < INPUT_RESUME_GUARD) return;
    this.inputPaused = false;
    this.terminal.options.disableStdin = false;
    if (this.inputAtCapacityMessageShown) this.setStatus("");
    this.inputAtCapacityMessageShown = false;
  }

  private resendUnacknowledgedInput(): void {
    let offset = 0;
    let sequence = this.ackedInSeq;
    while (offset < this.inputQueue.length) {
      const length = this.inputQueue.copyOut(offset, this.inputScratch.subarray(0, INPUT_FRAME_LIMIT));
      if (length === 0) {
        this.protocolFailure("input resume queue is inconsistent");
        return;
      }
      this.sendFrame(this.streamId, {
        type: "Input",
        inSeq: sequence,
        bytes: this.inputScratch.subarray(0, length),
      });
      offset += length;
      sequence += BigInt(length);
    }
  }

  private handleInput(data: string): void {
    pulseActivity("typing", 400);
    if (this.closed || this.pendingExit || this.sessionGone || !data) return;
    const ctrl = this.inputModifiers.ctrl !== "off";
    const alt = this.inputModifiers.alt !== "off";
    if (this.inputModifiers.ctrl === "armed") this.inputModifiers.ctrl = "off";
    if (this.inputModifiers.alt === "armed") this.inputModifiers.alt = "off";
    this.config.onInputActivity?.();
    this.sampleRoundTrip();
    data = applyInputModifiers(data, ctrl, alt);
    const at = performance.now();
    const traceInput = this.config.hooks?.onInput?.(data, at, this.nextInSeq) === true;
    let encoded = this.encoderIntoScratch(data);
    if (encoded === undefined) {
      // Large paste events take the slow path; ordinary key events reuse inputScratch.
      encoded = encoder.encode(data);
    }
    if (encoded.byteLength > this.availableInputSpace()) {
      this.pauseInput("Typing is paused until the connection catches up.");
      return;
    }
    if (this.nextInSeq > MAX_U64 - BigInt(encoded.byteLength) || !this.inputQueue.push(encoded)) {
      this.protocolFailure("input resume sequence or queue exceeded its bound");
      return;
    }
    const firstSequence = this.nextInSeq;
    this.nextInSeq += BigInt(encoded.byteLength);
    // Typed while the stream cannot carry it: kept in the queue and sent once the shim is confirmed. Only the count is told.
    if (!this.attachmentConfirmed && this.config.hooks?.onInputHeld) {
      this.heldKeys += keysIn(data);
      this.config.hooks.onInputHeld(this.heldKeys);
    }
    // An Attach request is not a ready shim: per-key frames would fill its
    // bounded handshake queue. Retain them locally until replay confirms it.
    if (this.attachmentConfirmed) {
      for (let offset = 0; offset < encoded.byteLength;) {
        const length = Math.min(INPUT_FRAME_LIMIT, encoded.byteLength - offset);
        this.sendFrame(this.streamId, {
          type: "Input",
          inSeq: firstSequence + BigInt(offset),
          bytes: encoded.subarray(offset, offset + length),
        }, traceInput ? firstSequence + BigInt(offset) : undefined, traceInput ? length : 0);
        offset += length;
      }
    }
    // Predict after retaining input and sending when ready: prediction never delays delivery. The overlay is still
    // drawn in this same task, so no host echo can be processed (and painted) before the prediction is.
    // `encoded` may alias inputScratch, which the queue has already copied; prediction copies what it keeps.
    this.prediction?.input(data, firstSequence, encoded, this.predictionSafe());
    if (this.availableInputSpace() < INPUT_RESUME_GUARD) {
      this.pauseInput("Typing is paused because too much is waiting to be sent. It resumes when the connection is back.");
    }
  }

  /** Explicit consent applies once, only after the fresh writer's replay has painted. */
  resendRetainedInput(): void {
    if (!this.inputNeedsResend || this.closed) return;
    if (!this.attachmentConfirmed) { this.showInputResendNotice(); return; }
    const retained = this.retainedInput;
    if (!retained || this.nextInSeq > MAX_U64 - BigInt(retained.byteLength)) {
      this.protocolFailure("input resume sequence exceeded its bound");
      return;
    }
    if (!this.inputQueue.push(retained)) {
      this.protocolFailure("input resume queue exceeded its bound");
      return;
    }
    this.nextInSeq += BigInt(retained.byteLength);
    retained.fill(0);
    this.retainedInput = undefined;
    this.inputNeedsResend = false;
    this.inputResendNoticeVisible = false;
    this.inputResendNotice?.dismiss();
    this.resendUnacknowledgedInput();
  }

  /** Discard only the uncertain bytes from the earlier writer; live fresh-shell input stays queued normally. */
  discardRetainedInput(): void {
    if (!this.inputNeedsResend || this.closed) return;
    this.retainedInput?.fill(0);
    this.retainedInput = undefined;
    this.inputNeedsResend = false;
    this.inputResendNoticeVisible = false;
    this.inputResendNotice?.dismiss();
    this.resumeInputIfRoom();
  }

  /** Reports only a visible resend choice, so the focus shortcut stays inert at other times. */
  hasPendingInputResend(): boolean {
    return this.inputNeedsResend && this.inputResendNoticeVisible && !this.closed;
  }

  /** The keyboard shortcut hands focus to the existing notice; normal Tab remains a terminal key. */
  focusInputResendActions(): boolean {
    if (!this.hasPendingInputResend()) return false;
    return this.inputResendNotice?.focusAction() ?? false;
  }

  private showInputResendNotice(): void {
    this.inputResendNotice ??= mountToast(this.config.host.parentElement ?? this.config.host, { placement: "parent" });
    const focusShortcut = bindingLabel("focus-resend-actions") || "Ctrl+Shift+Space";
    this.inputResendNotice.show({
      // Retained bytes were sent but never acknowledged (or never sent), so the page cannot know whether the old shell
      // saw them: say "may not have arrived", and name the duplicate risk by calling the action "Send again".
      message: "New shell. Offline typing may not have arrived.",
      icon: ICONS.terminal,
      duration: 0,
      actionGroupLabel: `Saved typing actions. Press ${focusShortcut} to focus these actions.`,
      action: { label: "Send again", onSelect: () => this.resendRetainedInput() },
      secondaryAction: { label: "Discard", onSelect: () => this.discardRetainedInput() },
    });
    this.inputResendNoticeVisible = true;
  }

  private encoderIntoScratch(data: string): Uint8Array | undefined {
    const result = encoder.encodeInto(data, this.inputScratch);
    if (result.read !== data.length) return undefined;
    return this.inputScratch.subarray(0, result.written);
  }

  private acknowledgeInput(sequence: bigint): void {
    if (sequence < this.ackedInSeq || sequence > this.nextInSeq) {
      this.protocolFailure("server acknowledged an invalid input sequence");
      return;
    }
    const acknowledged = Number(sequence - this.ackedInSeq);
    if (acknowledged > this.inputQueue.length) {
      this.protocolFailure("server acknowledgement exceeds retained input");
      return;
    }
    this.inputQueue.consume(acknowledged);
    this.ackedInSeq = sequence;
    this.resumeInputIfRoom();
  }

  private acceptOutput(sequence: bigint, bytes: Uint8Array, message: Uint8Array): void {
    if (sequence !== this.receivedOutSeq || sequence > MAX_U64 - BigInt(bytes.byteLength)) {
      this.protocolFailure("server output sequence is discontinuous");
      return;
    }
    if (bytes.byteLength > this.creditAvailable || !this.outputQueue.push(bytes)) {
      this.protocolFailure("server exceeded the bounded output credit window");
      return;
    }
    this.creditAvailable -= bytes.byteLength;
    this.receivedOutSeq += BigInt(bytes.byteLength);
    this.staleWatch?.output(this.receivedOutSeq);
    this.synchronizedOutput.feed(bytes);
    if (this.synchronizedOutput.requiresAtomicPaint) this.synchronizedOutputBatchPending = true;
    // `message` keeps an unfragmented decoder view alive; fragment scratch is copied by the ring.
    void message;
    this.drainOutput();
  }

  private acceptSnapshot(sequence: bigint, bytes: Uint8Array): void {
    performance.mark(`sw:snapshot:${this.streamId}`);
    performance.mark(`sw:snapshot:${this.streamId}`);
    if (sequence < this.receivedOutSeq || bytes.byteLength > this.creditAvailable) {
      this.protocolFailure("server sent a stale snapshot or exceeded output credit");
      return;
    }
    this.creditAvailable -= bytes.byteLength;
    this.receivedOutSeq = sequence;
    this.staleWatch?.reset();

    // A snapshot replaces the parser's prior mode state before later live bytes are scanned.
    this.synchronizedOutput.reset();
    this.synchronizedOutputBatchPending = false;

    if (this.pendingSnapshot) this.returnCredit(this.pendingSnapshot.bytes.byteLength);
    this.pendingSnapshot?.bytes.fill(0);
    this.pendingSnapshot = { outSeq: sequence, bytes: bytes.slice() };

    // Drop queued raw bytes that this repaint supersedes. Output received after
    // this point starts at `sequence` and must survive older write callbacks.
    const keep = this.outputWriteInFlight ? this.outputWriteLength : 0;
    const dropped = this.outputQueue.discardAfter(keep);
    if (dropped > 0) this.returnCredit(dropped);
    this.drainOutput();
  }

  private drainOutput(): void {
    this.wakeTerminal();
    if (this.synchronizedOutput.holdsPaint) return;
    // Received bytes remain owned after disconnect. Finish painting them before Attach
    // advertises lastOutSeq; returnCredit sends nothing on a detached transport.
    if (this.outputWriteInFlight || this.snapshotWriteInFlight || this.closed) return;
    if (this.pendingSnapshot) {
      const snapshot = this.pendingSnapshot;
      this.pendingSnapshot = undefined;
      this.snapshotWriteInFlight = true;
      this.prediction?.resetForSnapshot();
      this.parsedOutputVersion += 1;
      this.terminal.reset();
      this.requestSymbolsIfNeeded(snapshot.bytes);
      this.traceRange(snapshot.outSeq, snapshot.bytes.byteLength, "termWrite", performance.now());
      const epoch = this.cursorEpoch;
      this.terminalQueries?.reset();
      let completed = false;
      const onSnapshotWritten = (): void => {
        if (completed) return;
        completed = true;
        if (this.pendingWriteCompletion === onSnapshotWritten) {
          this.pendingWriteCompletion = undefined;
          this.pendingWriteSynchronizedBatch = false;
        }
        if (epoch !== this.cursorEpoch) {
          this.snapshotWriteInFlight = false;
          this.drainOutput();
          this.tryAttach();
          return;
        }
        const callbackAt = performance.now();
        this.traceRange(snapshot.outSeq, snapshot.bytes.byteLength, "writeCallback", callbackAt);
        // Ghostty calls this from the rAF after its render loop draws the write; another rAF adds a full frame.
        const paintedAt = performance.now();
        this.lastPaintedOutputAt = paintedAt;
        this.lastOutSeq = snapshot.outSeq;
        this.releaseReplayResponsesAfterPaint();
        this.snapshotWriteInFlight = false;
        this.traceRange(snapshot.outSeq, snapshot.bytes.byteLength, "paint", paintedAt);
        this.config.hooks?.onPaintedOutput?.(snapshot.bytes, paintedAt, snapshot.outSeq);
        snapshot.bytes.fill(0);
        this.returnCredit(snapshot.bytes.byteLength);
        this.drainOutput();
        this.tryAttach();
      };
      this.pendingWriteCompletion = onSnapshotWritten;
      this.pendingWriteSynchronizedBatch = false;
      this.writeSuppressingTerminalResponses(snapshot.bytes, onSnapshotWritten);
      return;
    }

    if (this.outputQueue.length > 0) {
      const synchronizedBatch = this.synchronizedOutputBatchPending;
      let region: Uint8Array | undefined;
      let regions: Uint8Array[] | undefined;
      let writeLength: number;
      if (synchronizedBatch) {
        regions = [];
        let offset = 0;
        const queuedLength = this.outputQueue.length;
        while (offset < queuedLength) {
          const next = this.outputQueue.peekAt(offset);
          if (next.byteLength === 0) {
            this.protocolFailure("synchronized output queue is inconsistent");
            return;
          }
          regions.push(next);
          offset += next.byteLength;
        }
        writeLength = queuedLength;
      } else {
        region = this.outputQueue.peek();
        if (region.byteLength === 0) {
          this.protocolFailure("output queue has no contiguous data");
          return;
        }
        if (this.suppressReplayResponses && this.replayResponseFence !== undefined) {
          // The ring can coalesce replay and live frames while a write awaits paint.
          // Paint exactly to the fence before parsing live bytes with replies enabled.
          const remaining = this.replayResponseFence - this.lastOutSeq;
          if (remaining > 0n && remaining < BigInt(region.byteLength)) region = region.subarray(0, Number(remaining));
        }
        writeLength = region.byteLength;
      }
      pulseActivity("output", 300);
      this.outputWriteInFlight = true;
      this.outputWriteLength = writeLength;
      const writeSequence = this.lastOutSeq;
      this.traceRange(writeSequence, writeLength, "termWrite", performance.now());
      const epoch = this.cursorEpoch;
      this.parsedOutputVersion += 1;
      if (synchronizedBatch) {
        this.synchronizedOutputBatchPending = false;
        this.synchronizedOutput.finishAtomicPaint();
      }
      let completed = false;
      const onWritten = (): void => {
        if (completed) return;
        completed = true;
        if (this.pendingWriteCompletion === onWritten) {
          this.pendingWriteCompletion = undefined;
          this.pendingWriteSynchronizedBatch = false;
        }
        if (epoch !== this.cursorEpoch) {
          this.outputWriteLength = 0;
          this.outputWriteInFlight = false;
          this.drainOutput();
          this.tryAttach();
          return;
        }
        const callbackAt = performance.now();
        this.traceRange(writeSequence, this.outputWriteLength, "writeCallback", callbackAt);
        // The callback is ordered after Ghostty's render-loop callback in the same animation frame.
        const paintedAt = performance.now();
        const consumed = this.outputWriteLength;
        this.lastPaintedOutputAt = paintedAt;
        this.lastOutSeq += BigInt(consumed);
        this.releaseReplayResponsesAfterPaint();
        this.traceRange(writeSequence, consumed, "paint", paintedAt);
        if (this.predictionScreenUnsafe()) this.prediction?.unsafeScreen();
        else {
          this.prediction?.rendererPainted();
          this.prediction?.paintedOutput();
        }
        if (synchronizedBatch) {
          let hookOffset = 0;
          for (const segment of regions!) {
            const length = Math.min(segment.byteLength, consumed - hookOffset);
            if (length <= 0) break;
            this.config.hooks?.onPaintedOutput?.(segment.subarray(0, length), paintedAt, writeSequence + BigInt(hookOffset));
            hookOffset += length;
          }
        } else {
          this.config.hooks?.onPaintedOutput?.(region!.subarray(0, consumed), paintedAt, writeSequence);
        }
        this.outputQueue.consume(consumed);
        this.outputWriteLength = 0;
        this.outputWriteInFlight = false;
        this.returnCredit(consumed);
        this.drainOutput();
        this.tryAttach();
      };
      this.pendingWriteCompletion = onWritten;
      this.pendingWriteSynchronizedBatch = synchronizedBatch;
      if (synchronizedBatch) {
        const segments = regions!;
        // Feed every ring segment in this task; only the final callback crosses the shared paint barrier.
        let batchOffset = 0;
        this.synchronizedBatchWriting = true;
        try {
          for (let index = 0; index < segments.length; index += 1) {
            const segment = segments[index]!;
            let segmentOffset = 0;
            while (segmentOffset < segment.byteLength) {
              const sequence = writeSequence + BigInt(batchOffset);
              let fragment = segment.subarray(segmentOffset);
              if (this.suppressReplayResponses && this.replayResponseFence !== undefined) {
                const bytesToFence = this.replayResponseFence - sequence;
                if (bytesToFence <= 0n) this.suppressReplayResponses = false;
                else if (bytesToFence < BigInt(fragment.byteLength)) fragment = fragment.subarray(0, Number(bytesToFence));
              }
              this.requestSymbolsIfNeeded(fragment);
              const callback = batchOffset + fragment.byteLength === writeLength ? onWritten : undefined;
              if (this.suppressReplayResponses) this.writeSuppressingTerminalResponses(fragment, callback, sequence);
              else this.writeQueryResponses(fragment, sequence, callback);
              // The parser consumes this region synchronously. Reconcile prediction before the next animation frame.
              if (this.predictionUnsafe()) this.prediction?.unsafeScreen();
              else this.prediction?.hostWritten(fragment);
              segmentOffset += fragment.byteLength;
              batchOffset += fragment.byteLength;
              if (
                this.suppressReplayResponses
                && this.replayResponseFence !== undefined
                && sequence + BigInt(fragment.byteLength) >= this.replayResponseFence
              ) {
                // Parser replies switch at the replay fence; attachment still waits for the batch paint callback.
                this.suppressReplayResponses = false;
              }
            }
          }
        } finally {
          this.synchronizedBatchWriting = false;
        }
      } else {
        this.requestSymbolsIfNeeded(region!);
        if (this.suppressReplayResponses) this.writeSuppressingTerminalResponses(region!, onWritten, writeSequence);
        else this.writeQueryResponses(region!, writeSequence, onWritten);
        // The terminal state includes these bytes now; only their paint is a frame away. Reconcile prediction.
        if (this.predictionUnsafe()) this.prediction?.unsafeScreen();
        else this.prediction?.hostWritten(region!);
      }
      return;
    }
    this.finishExit();
    this.tryAttach();
  }

  /** Write through generic control boundaries and mark every synchronous renderer answer.
   * Keyboard callbacks run in later tasks and always use the unchanged typing path.
   */
  private writeQueryResponses(bytes: Uint8Array, offset: bigint, callback?: () => void): void {
    if (!this.conn.terminalQueryReplies) { this.terminal.write(bytes, callback); return; }
    this.linkRowsArmed = true;
    this.terminal.writeSlices(bytes, (writeSlice) => {
      let start = 0;
      const write = (end: number, replyTo: bigint): void => {
        this.parserReplies = EMPTY_PARSER_REPLIES;
        this.parserReplyLength = 0;
        try {
          writeSlice(end);
          const response = this.parserReplies.join("");
          if (response && this.parserReplyLength <= 1024) {
            const encoded = encoder.encode(response);
            if (encoded.length <= 1024) this.sendFrame(this.streamId, { type: "Input", inSeq: 0n, replyTo, bytes: encoded });
          }
        } finally { this.parserReplies = undefined; }
        start = end;
      };
      (this.terminalQueries ??= new TerminalQueries()).scan(bytes, offset, (end, sequence) => write(end, sequence));
      if (start < bytes.length) write(bytes.length, offset + BigInt(start));
    }, callback);
  }

  /**
   * Ghostty emits all parser replies synchronously from write() through the same
   * onData event used for keyboard input. This scoped gate drops only those
   * write-time replies; real key events run in a later task and remain enabled.
   */
  private writeSuppressingTerminalResponses(bytes: Uint8Array, callback?: () => void, queryOffset?: bigint): void {
    const previous = this.suppressTerminalResponses;
    this.suppressTerminalResponses = true;
    if (queryOffset !== undefined) (this.terminalQueries ??= new TerminalQueries()).scan(bytes, queryOffset, () => undefined);
    try {
      this.terminal.write(bytes, callback);
    } finally {
      this.suppressTerminalResponses = previous;
    }
  }

  /** A replay fence takes effect only after the renderer has parsed and painted every byte before it. */
  private releaseReplayResponsesAfterPaint(): void {
    if (this.replayResponseFence !== undefined && this.lastOutSeq >= this.replayResponseFence) {
      const fence = this.replayResponseFence;
      const captured = this.replayCapturedSize;
      this.suppressReplayResponses = false;
      this.replayResponseFence = undefined;
      this.replayCapturedSize = undefined;
      if (this.attached && !this.attachmentConfirmed) {
        // A reattached session is waiting for its program to repaint, but only if the attach resized it
        // (the repaint is the program's answer to the new size); a new shell has nothing to be out of date.
        // `lastSize` is what the attach sent, or the latest size sent since, which is the size the program now has.
        if (this.connectionIsResume) this.staleWatch?.begin(fence, this.receivedOutSeq, staleWaitMs(this.roundTripMs), captured, this.lastSize);
        this.attachmentConfirmed = true;
        this.resendUnacknowledgedInput();
        if (this.heldKeys > 0) { this.heldKeys = 0; this.config.hooks?.onInputHeld?.(0); }
        if (this.inputNeedsResend) this.showInputResendNotice();
        // Completing replay clears its wait, not an approximation or input-pressure warning.
        if (this.config.status.textContent === "Catching up…") this.setStatus("");
        this.conn.streamAttached(true, this.streamId);
        this.startPings();
        this.config.hooks?.onAttached?.(this.connectionIsResume, this);
      }
    }
  }

  /** Wait for paint callbacks so a clean exit never discards its final bytes. */
  private finishExit(): void {
    const exit = this.pendingExit;
    if (!exit || exit.retired || this.exitReported || this.lastOutSeq < exit.finalSeq || this.outputWriteInFlight || this.snapshotWriteInFlight || this.pendingSnapshot || this.outputQueue.length > 0) return;
    this.exitReported = true;
    this.cancelStreamRetry();
    this.setStatus(exit.status === 0 ? "Shell exited." : `Shell exited with status ${exit.status}. Open a new shell to continue.`);
    this.config.hooks?.onExited?.(exit.status);
  }

  private returnCredit(bytes: number): void {
    if (bytes === 0) return;
    if (this.creditAvailable > INITIAL_CREDIT - bytes) {
      this.protocolFailure("output credit accounting exceeded the initial window");
      return;
    }
    this.creditAvailable += bytes;
    if (this.attached) this.sendFrame(this.streamId, { type: "Credit", bytes });
  }

  private pauseInput(message: string): void {
    this.inputPaused = true;
    this.inputAtCapacityMessageShown = true;
    this.terminal.options.disableStdin = true;
    this.setStatus(message);
  }

  private scheduleFit(): void {
    if (this.fitQueued || this.closed || this.suspended || this.frozen) return;
    this.fitQueued = true;
    requestAnimationFrame(() => {
      this.fitQueued = false;
      // A layout update can retire or park this renderer after the frame was queued.
      if (this.closed || this.suspended || this.frozen) return;
      const style = getComputedStyle(this.config.host);
      const width = this.config.host.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
      const height = this.config.host.clientHeight - parseFloat(style.paddingTop) - parseFloat(style.paddingBottom);
      const metrics = this.cellMetrics();
      const cols = clamp(Math.floor(width / metrics.width), 20, 0xffff);
      const rows = clamp(Math.floor(height / metrics.height), 6, 0xffff);
      if (this.terminal.cols !== cols || this.terminal.rows !== rows) {
        this.wakeTerminal();
        this.terminal.resize(cols, rows);
      }
    });
  }

  private cellMetrics(): { width: number; height: number; naturalWidth: number; baseline: number } {
    const metrics = this.ghostty.renderer?.getMetrics();
    if (!metrics || metrics.width <= 0 || metrics.height <= 0) {
      throw new Error("terminal renderer cell metrics are unavailable");
    }
    return {
      width: metrics.width,
      height: metrics.height,
      naturalWidth: this.ghostty.renderer?.naturalCellWidth ?? metrics.width,
      baseline: metrics.baseline,
    };
  }

  /**
   * Terminal ligatures stay off, on purpose (D175, measured in test/font-maple.spec.ts).
   *
   * The renderer draws a run of plain ASCII cells with one fillText and a canvas
   * letterSpacing that stretches the font's natural advance onto the device-pixel cell
   * (cell = round(advance x dpr) / dpr). Chromium turns Maple Mono's contextual
   * ligatures off whenever letterSpacing is non-zero, and the spacing is zero only when
   * the natural advance already equals the cell. So with the default `auto` text
   * rendering the same text would show ligatures on one display and not on another,
   * and a colour or style change would split them mid-sequence. Rather than ship that,
   * choose "optimizeSpeed", which disables ligatures and kerning in every case and
   * leaves every glyph exactly on its cell.
   *
   * A canvas resize resets the context's state, so the mode is applied at the start of
   * every render instead of once.
   */
  private keepLigaturesOff(): void {
    const renderer = this.ghostty.renderer;
    const context = renderer?.ctx;
    if (!renderer || !context) return;
    const render = renderer.render.bind(renderer);
    renderer.render = (...args) => {
      context.textRendering = "optimizeSpeed";
      render(...args);
    };
  }

  /**
   * The renderer asks the canvas for plain, bold and italic text with the keywords `bold` and
   * `italic` only, so every font would draw at weight 400 and 700 whatever its registry
   * weights say. A canvas has no weight setting apart from that string, so the font property
   * of this one context rewrites the weight keyword on its way in: plain text takes the
   * font's terminal weight, bold takes its bold weight. Everything else in the string,
   * including the family list and the size, passes through untouched, so the renderer's own
   * measurement (cell width and font box) is made from the very face it will draw with.
   *
   * The rewrite is memoised per distinct string because the renderer sets the property for
   * every run it draws; the redraw benchmark shows the cost.
   */
  private installFontWeights(): void {
    const context = this.ghostty.renderer?.ctx;
    if (!context) return;
    const native = Object.getOwnPropertyDescriptor(CanvasRenderingContext2D.prototype, "font");
    if (!native?.get || !native.set) return;
    const get = native.get, set = native.set;
    const memo = this.weightMemo;
    this.canvasWeights.regular = this.font.terminalWeight;
    this.canvasWeights.bold = this.font.boldWeight;
    this.applyGlyphPlacement();
    Object.defineProperty(context, "font", {
      configurable: true,
      get: () => get.call(context) as string,
      set: (value: string) => {
        let rewritten = memo.get(value);
        if (rewritten === undefined) {
          const parts = /^(italic )?(bold )?(.*)$/.exec(value)!;
          rewritten = `${parts[1] ?? ""}${parts[2] ? this.canvasWeights.bold : this.canvasWeights.regular} ${parts[3]}`;
          memo.set(value, rewritten);
        }
        set.call(context, rewritten);
      },
    });
  }

  /**
   * Switches the terminal to another font without reopening the session: the whole font
   * changes (family and weights) and the grid is measured again from the new font box.
   * The caller loads the font's faces first (`loadFont`), because canvas text never waits for a
   * face and would draw the fallback.
   *
   * Setting the family makes the renderer re-measure its cells (device-pixel advance and the
   * font's ascent plus descent) and resize its canvas; `scheduleFit` then recomputes columns
   * and rows for the new cell size, which also tells the host. The cursor, drawn from those
   * cells, moves with them: no stored pixel position survives the change.
   */
  setFont(font: MonoFont): void {
    if (font === this.font || this.closed) return;
    this.font = font;
    this.canvasWeights.regular = font.terminalWeight;
    this.canvasWeights.bold = font.boldWeight;
    this.weightMemo.clear();
    this.applyGlyphPlacement();
    this.terminal.options.fontFamily = fontStack(font);
    this.scheduleFit();
    this.wakeTerminal();
    this.loadStyledFaces();
  }

  /**
   * Chooses between the renderer's two ways of putting text on the grid (see `placeGlyphs` in
   * the registry). The renderer stretches a run with canvas letter spacing when the context
   * has it, and otherwise draws one glyph per cell. Hiding the property on this context for
   * the fonts that need exact placement selects the second way without touching the renderer.
   */
  private applyGlyphPlacement(): void {
    const context = this.ghostty.renderer?.ctx;
    if (!context) return;
    if (this.font.placeGlyphs) Object.defineProperty(context, "letterSpacing", { value: undefined, writable: true, configurable: true });
    else delete (context as { letterSpacing?: string }).letterSpacing;
  }

  /**
   * Canvas text never waits for a web font: a face that is not loaded yet is drawn with
   * the fallback and is not repainted by the browser. So the italic faces are loaded here,
   * and the whole screen is repainted once they arrive. The upright faces already carry
   * every weight (one variable face, or the regular and bold static faces), so bold needs
   * no request of its own. Italic and bold cells are drawn one cell at a time, so they stay
   * on the grid.
   */
  private loadStyledFaces(): void {
    const font = this.font;
    const load = (): void => {
      void loadFont(font, true).then(() => { if (this.font === font) this.repaintAll(); }, () => undefined);
    };
    // Off the critical path: the first prompt must not wait behind these downloads.
    // Safari has no requestIdleCallback; the lib types claim it always exists, so widen it.
    const idle = (window as { requestIdleCallback?: Window["requestIdleCallback"] }).requestIdleCallback;
    if (idle) idle.call(window, load, { timeout: 3000 });
    else window.setTimeout(load, 1000);
  }

  /**
   * Fetches the Nerd Font symbol face the first time output holds a private-use code
   * point. In UTF-8 the private-use area U+E000..U+F8FF starts with 0xEE or 0xEF, and
   * Uint8Array.indexOf scans natively, so a screen without prompt icons never pays the
   * download and the check costs next to nothing per chunk.
   */
  private requestSymbolsIfNeeded(bytes: Uint8Array): void {
    if (this.symbolFaceRequested) return;
    if (bytes.indexOf(0xee) < 0 && bytes.indexOf(0xef) < 0) return;
    this.symbolFaceRequested = true;
    const size = this.terminal.options.fontSize ?? TERMINAL_FONT_SIZE_DESKTOP;
    void document.fonts.load(`${size}px "Nerd Symbols"`, "\ue0b0\uf015\ue718")
      .then(() => this.repaintAll(), () => undefined);
  }

  /**
   * Frees the canvas's backing store while the terminal cannot be seen (a hidden page, a locked phone, a
   * view far from the screen): a 0 x 0 canvas holds no pixels. The terminal's state is untouched, so
   * `restoreSurface` re-renders everything from it.
   */
  releaseSurface(): void {
    const canvas = this.config.host.querySelector<HTMLCanvasElement>("canvas");
    if (!canvas || this.surfaceReleased) return;
    this.surfaceReleased = true;
    // The renderer would size the canvas again on its next frame (a blinking cursor is enough), so its drawing
    // calls are silenced until the surface is restored.
    this.silenceRenderer();
    canvas.width = 0;
    canvas.height = 0;
  }

  /** Gives the canvas its size back and draws the whole screen again from the terminal state. */
  restoreSurface(): void {
    const renderer = this.ghostty.renderer;
    if (!renderer || !this.surfaceReleased || this.closed) return;
    this.surfaceReleased = false;
    // Frozen (the camera is moving): the picture comes back when the camera rests, in `setFrozen(false)`.
    if (this.frozen) { this.restorePending = true; return; }
    this.unsilenceRenderer();
    renderer.resize(this.terminal.cols, this.terminal.rows);
    this.repaintAll();
  }

  private surfaceReleased = false;
  private silenced: Record<string, unknown> | undefined;
  private frozen = false;
  private restorePending = false;

  /** Replaces the renderer's drawing calls with no-ops (the canvas keeps what it shows). */
  private silenceRenderer(): void {
    const renderer = this.ghostty.renderer as unknown as Record<string, unknown> | undefined;
    if (!renderer || this.silenced) return;
    this.silenced = {};
    for (const name of ["render", "renderLine", "renderCursor", "resize"]) {
      const original = renderer[name];
      if (typeof original !== "function") continue;
      this.silenced[name] = original;
      renderer[name] = () => undefined;
    }
  }

  private unsilenceRenderer(): void {
    const target = this.ghostty.renderer as unknown as Record<string, unknown> | undefined;
    if (target) for (const [name, original] of Object.entries(this.silenced ?? {})) target[name] = original;
    this.silenced = undefined;
  }

  /**
   * Holds the drawing while the camera moves across a canvas of many terminals (#121): at a small scale the zoom or the
   * flight redrew every visible terminal's canvas again and again (with the draw calls made no-ops, a zoom with 54 real
   * terminals on a GPU went from 83 ms to 34 ms at p95 and the GPU process from 418 to 255 ms/s). The canvas keeps the
   * pixels it shows, so there is nothing to copy and nothing to swap: no extra memory, and the picture is the same one when
   * the camera rests. Output keeps flowing into the terminal's state (credit returns as usual); what arrived is drawn once
   * when the freeze ends. The active terminal is never frozen by the caller.
   */
  setFrozen(frozen: boolean): void {
    if (frozen === this.frozen || this.closed) return;
    this.frozen = frozen;
    if (this.suspended) return; // already not drawing, and its surface is restored by `setSuspended`
    if (frozen) {
      window.clearTimeout(this.renderIdleTimer);
      this.pauseTerminal();
      this.silenceRenderer();
      return;
    }
    if (!this.surfaceReleased) this.unsilenceRenderer();
    if (this.restorePending) { this.restorePending = false; this.surfaceReleased = true; this.restoreSurface(); } else this.repaintAll();
    this.scheduleFit();
    this.wakeTerminal();
  }

  private repaintAll(): void {
    const renderer = this.ghostty.renderer;
    const buffer = this.terminal.wasmTerm;
    if (!renderer || !buffer || this.closed) return;
    renderer.render(buffer, true, this.terminal.viewportY, this.terminal, this.ghostty.scrollbarOpacity);
  }

  /** Draws released VT state in its first available frame, then completes callbacks for what that frame painted. */
  private paintSynchronizedRelease(): void {
    if (this.closed || this.suspended || this.surfaceReleased || this.frozen || this.synchronizedOutput.holdsPaint) return;
    this.wakeTerminal();
    // A pre-hold write can occupy the callback slot and prevent the queued atomic batch from parsing until this frame.
    for (let completionCount = 0; completionCount < 2; completionCount += 1) {
      if (this.renderedOutputVersion !== this.parsedOutputVersion) this.repaintAll();
      // A hidden or released surface cannot prove a paint; leave its normal callback as the eventual fence.
      if (this.renderedOutputVersion !== this.parsedOutputVersion) return;
      const complete = this.pendingWriteCompletion;
      if (!complete) return;
      const isSynchronizedBatch = this.pendingWriteSynchronizedBatch;
      complete();
      // Completion can drain the held batch from behind one earlier write. Further writes use the regular frame path.
      if (isSynchronizedBatch) return;
    }
  }

  /** Rebuilds backing dimensions from the loaded web font before the first frame. */
  private remeasureFont(): void {
    const renderer = this.ghostty.renderer;
    if (!renderer) throw new Error("terminal renderer is unavailable after font load");
    renderer.remeasureFont();
    renderer.resize(this.terminal.cols, this.terminal.rows);
    this.scheduleFit();
  }

  /** Times synchronous full-screen redraws for the test-double performance probe. */
  benchmarkFullRedraw(iterations: number): number[] {
    const renderer = this.ghostty.renderer;
    const buffer = this.terminal.wasmTerm;
    if (!renderer || !buffer) throw new Error("terminal renderer is unavailable for redraw benchmark");
    if (!Number.isInteger(iterations) || iterations < 1 || iterations > 100) {
      throw new RangeError("redraw benchmark iterations must be from 1 to 100");
    }
    const samples: number[] = [];
    for (let iteration = 0; iteration < iterations; iteration += 1) {
      const startedAt = performance.now();
      renderer.render(buffer, true, this.terminal.viewportY, this.terminal, this.ghostty.scrollbarOpacity);
      samples.push(performance.now() - startedAt);
    }
    return samples;
  }

  /** Stops cursor blinking and paints one stable frame for canvas pixel tests. */
  freezeCursorForTest(): void {
    const renderer = this.ghostty.renderer;
    const buffer = this.terminal.wasmTerm;
    if (!renderer || !buffer) throw new Error("terminal renderer is unavailable for cursor pixel test");
    this.cursorLayerOffForTest = true;
    this.syncCursorLayer();
    renderer.setCursorBlink(false);
    renderer.render(buffer, true, this.terminal.viewportY, this.terminal, this.ghostty.scrollbarOpacity);
  }

  /** Feeds a paced 10 MB/s text stream through Ghostty and waits for its last paint. */
  async benchmarkOutputAt10MBps(): Promise<{
    bytes: number;
    elapsedMs: number;
    writeCpuMs: number;
    p95FrameMs: number;
    maxFrameMs: number;
    wasmMemoryBytes: number;
  }> {
    const bytesPerChunk = 100_000;
    const chunkCount = 100;
    const totalBytes = bytesPerChunk * chunkCount;
    const chunk = new Uint8Array(bytesPerChunk).fill(0x78);
    await new Promise<void>((resolve) => {
      this.terminal.write(new TextEncoder().encode("\x1b[?1049h\x1b[2J\x1b[H"), resolve);
    });
    const startedAt = performance.now();
    const frameIntervals: number[] = [];
    let previousFrameAt = startedAt;
    let writingDone = false;
    const sampleFrame = (at: number): void => {
      frameIntervals.push(at - previousFrameAt);
      previousFrameAt = at;
      if (!writingDone || frameIntervals.length < 2) requestAnimationFrame(sampleFrame);
    };
    requestAnimationFrame(sampleFrame);

    let writeCpuMs = 0;
    let lastPaint: Promise<void> | undefined;
    for (let index = 0; index < chunkCount; index += 1) {
      const dueAt = startedAt + index * 10;
      const delay = dueAt - performance.now();
      if (delay > 0) await new Promise<void>((resolve) => window.setTimeout(resolve, delay));
      const writeStartedAt = performance.now();
      if (index + 1 === chunkCount) {
        lastPaint = new Promise<void>((resolve) => this.terminal.write(chunk, resolve));
      } else {
        this.terminal.write(chunk);
      }
      writeCpuMs += performance.now() - writeStartedAt;
    }
    writingDone = true;
    await lastPaint;
    await new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve())));
    const elapsedMs = performance.now() - startedAt;
    const sortedFrames = frameIntervals.slice().sort((left, right) => left - right);
    return {
      bytes: totalBytes,
      elapsedMs,
      writeCpuMs,
      p95FrameMs: sortedFrames[Math.floor((sortedFrames.length - 1) * 0.95)] ?? 0,
      maxFrameMs: sortedFrames[sortedFrames.length - 1] ?? 0,
      wasmMemoryBytes: this.rendererMetrics.wasmMemoryBytes,
    };
  }

  private predictionPosition(): PredictionPosition | undefined {
    const buffer = this.terminal.wasmTerm;
    const renderer = this.terminal.renderer;
    if (!buffer || !renderer) return undefined;
    const cursor = buffer.getCursor();
    const metrics = this.cellMetrics();
    return {
      canvas: renderer.getCanvas(),
      x: cursor.x,
      y: cursor.y,
      visible: cursor.visible,
      alternate: buffer.isAlternateScreen(),
      viewportY: this.terminal.viewportY,
      columns: this.terminal.cols,
      rows: this.terminal.rows,
      cellWidth: metrics.width,
      cellHeight: metrics.height,
      naturalCellWidth: metrics.naturalWidth,
      baseline: metrics.baseline,
      fontFamily: this.terminal.options.fontFamily,
      fontSize: this.terminal.options.fontSize,
      devicePixelRatio: this.ghostty.renderer?.devicePixelRatio,
      background: this.ghostty.renderer?.theme?.background ?? (this.terminal.options.theme as ITheme | undefined)?.background,
      foreground: this.ghostty.renderer?.theme?.foreground ?? (this.terminal.options.theme as ITheme | undefined)?.foreground,
      cursorStyle: this.terminal.options.cursorStyle,
      cursorColor: this.ghostty.renderer?.theme?.cursor ?? (this.terminal.options.theme as ITheme | undefined)?.cursor ?? "#c8ceff",
    };
  }

  /**
   * Hides or restores the renderer's own cursor while a prediction is pending.
   *
   * There must be exactly one visible cursor: the predicted one. Repainting the
   * row once is not enough, because Ghostty redraws its cursor on every render
   * pass, so the renderer's renderCursor is wrapped once (installCursorLayerHook)
   * and skips drawing while hidden. Toggling only repaints the single cursor row.
   */
  private setPredictionCursorHidden(hidden: boolean): void {
    if (hidden === this.predictionCursorHidden) return;
    this.predictionCursorHidden = hidden;
    this.syncCursorLayer();
    // A prediction without the layer (the host cursor was drawn by the renderer) still needs the one-row repaint.
    this.setRendererCursorHidden(this.predictionCursorHidden || this.cursorLayerShown);
  }

  /**
   * Whether the live cursor layer owns the cursor now (D249): typing can reach the terminal, the program shows its
   * cursor, the view is at the live screen, and no prediction draws the cursor instead.
   */
  private cursorLayerWanted(): boolean {
    const buffer = this.terminal.wasmTerm;
    return !this.closed && !this.suspended && !this.surfaceReleased && !this.cursorLayerOffForTest && this.typingReady && !this.predictionCursorHidden
      && this.terminal.viewportY === 0 && Boolean(buffer?.getCursor().visible);
  }

  private cursorLayerShown = false;
  /** Pixel tests read the renderer's own cursor; they switch the layer off so the canvas draws it. */
  private cursorLayerOffForTest = false;
  private renderPasses = 0;

  /** The cursor layer and the renderer's passes, for the browser specs (D249). */
  get cursorLayerState(): { layer: ReturnType<TerminalCursorLayer["snapshot"]> | undefined; renderPasses: number; rendererCursorHidden: boolean; typing: string | undefined } {
    return { layer: this.cursorLayer?.snapshot(), renderPasses: this.renderPasses, rendererCursorHidden: this.rendererCursorHidden, typing: this.config.host.dataset.typing };
  }

  /**
   * Puts the cursor layer on the cursor cell (or hides it) and keeps exactly one visible cursor: while the layer shows,
   * the renderer's own cursor draw is skipped and its row repainted once. Called after every renderer pass, so the
   * layer follows cursor moves, scrolling, resizes and font changes with no frame of its own.
   */
  private syncCursorLayer(): void {
    if (this.synchronizedOutput.holdsPaint) return;
    const layer = this.cursorLayer;
    const renderer = this.ghostty.renderer;
    const buffer = this.terminal.wasmTerm;
    const canvas = this.terminal.renderer?.getCanvas();
    if (!layer || !renderer || !buffer || !canvas) return;
    const shown = this.cursorLayerWanted();
    if (shown) {
      const cursor = buffer.getCursor();
      const metrics = this.cellMetrics();
      layer.place({
        canvas,
        column: cursor.x,
        row: cursor.y,
        cellWidth: metrics.width,
        cellHeight: metrics.height,
        style: this.terminal.options.cursorStyle ?? "bar",
        color: renderer.theme?.cursor ?? (this.terminal.options.theme as ITheme | undefined)?.cursor ?? "#c8ceff",
      });
      if (!this.cursorLayerShown) this.restartCursorBlink();
    } else {
      layer.hide();
    }
    this.cursorLayerShown = shown;
    this.setRendererCursorHidden(this.predictionCursorHidden || shown);
  }

  /** Any input, focus or visibility change: blinks again from the visible phase, only while the page is live and focused. */
  private restartCursorBlink(): void {
    const layer = this.cursorLayer;
    if (!layer) return;
    const focused = document.visibilityState === "visible" && document.hasFocus() && this.config.host.contains(document.activeElement);
    if (focused) layer.restart(); else layer.stopBlink();
  }

  /** Skips the renderer's cursor draw, and repaints the cursor row once so the cursor it drew is gone (or back). */
  private setRendererCursorHidden(hidden: boolean): void {
    if (this.synchronizedOutput.holdsPaint || hidden === this.rendererCursorHidden) return;
    this.rendererCursorHidden = hidden;
    const renderer = this.ghostty.renderer;
    const buffer = this.terminal.wasmTerm;
    if (!renderer || !buffer) return;
    const cursor = buffer.getCursor();
    const line = this.cursorLine(cursor.y);
    if (!line) return;
    renderer.renderLine(line, cursor.y, this.terminal.cols);
    if (!hidden && cursor.visible && this.terminal.viewportY === 0) renderer.renderCursor(cursor.x, cursor.y, line);
  }

  /** Wraps the renderer once: the cursor draw honours the hidden flag, and the cursor layer follows every pass. */
  private installCursorLayerHook(): void {
    const renderer = this.ghostty.renderer;
    if (!renderer) return;
    const draw = renderer.renderCursor.bind(renderer);
    renderer.renderCursor = (x, y, line) => {
      if (!this.synchronizedOutput.holdsPaint && !this.rendererCursorHidden) draw(x, y, line);
    };
    const render = renderer.render.bind(renderer);
    renderer.render = (...args) => {
      if (this.synchronizedOutput.holdsPaint || this.synchronizedBatchWriting) return;
      const changedRows = this.takeChangedLinkRows(args[0], args[1] === true);
      render(...args);
      this.renderedOutputVersion = this.parsedOutputVersion;
      if (changedRows) this.queueLinkRows(changedRows.rows, changedRows.force);
      this.renderPasses += 1;
      this.syncCursorLayer();
    };
  }

  /** Reads the renderer's dirty rows before its pass clears them; no detection runs on the write or input path. */
  private takeChangedLinkRows(value: unknown, forceAll: boolean): { rows: number[]; force: boolean } | undefined {
    if (!this.linkRowsArmed || this.suspended) return undefined;
    this.linkRowsArmed = false;
    const active = this.terminal.buffer.active;
    const bufferChanged = this.linkBufferType !== undefined && this.linkBufferType !== active.type;
    this.linkBufferType = active.type;
    if (bufferChanged) this.linkController?.invalidateBuffer();
    // Dirty indices describe the live screen; compare the visible scrollback fingerprints after output in that view.
    if (this.terminal.viewportY !== 0 && !bufferChanged) {
      const visible = this.visibleLinkRange();
      const rows: number[] = [];
      for (let y = visible.first; y <= visible.last; y += 1) rows.push(y);
      return { rows, force: false };
    }
    const buffer = value as {
      isDirty?: () => boolean;
      needsFullRedraw?: () => boolean;
      isRowDirty?: (y: number) => boolean;
    } | undefined;
    if (!buffer?.isRowDirty) return undefined;
    const visible = this.visibleLinkRange();
    const full = bufferChanged || forceAll || buffer.needsFullRedraw?.() === true;
    if (full) {
      const all: number[] = [];
      for (let y = visible.first; y <= visible.last; y += 1) all.push(y);
      return { rows: all, force: true };
    }
    buffer.isDirty?.(); // Updates Ghostty's dirty snapshot once before the row checks.
    const scrollback = active.type === "alternate" ? 0 : Math.max(0, active.length - this.terminal.rows);
    const changed: number[] = [];
    for (let row = 0; row < this.terminal.rows; row += 1) {
      if (!buffer.isRowDirty(row)) continue;
      const absolute = scrollback + row;
      if (absolute >= visible.first && absolute <= visible.last) changed.push(absolute);
    }
    return { rows: changed, force: true };
  }

  /** Makes only the named rows available to the deferred detector. */
  private queueLinkRows(rows: readonly number[], force = true): void {
    if (this.closed || this.suspended || rows.length === 0) return;
    for (const row of rows) {
      this.pendingLinkRows.add(row);
      if (force) this.forcedLinkRows.add(row);
    }
    if (this.linkController) this.flushLinkRows();
    else this.loadLinkController();
  }

  /** A scroll exposes existing rows, so the deferred detector may inspect that viewport once. */
  private queueVisibleLinkRows(): void {
    if (this.closed || this.suspended) return;
    const visible = this.visibleLinkRange();
    const rows: number[] = [];
    for (let row = visible.first; row <= visible.last; row += 1) rows.push(row);
    this.queueLinkRows(rows, true);
  }

  private loadLinkController(): void {
    if (this.linkController || this.linkControllerLoading || this.pendingLinkRows.size === 0) return;
    this.linkControllerLoading = onDemand(() => import("./terminal-links.on-demand")).then(({ createTerminalLinkController }) => {
      if (this.closed) return;
      if (this.suspended) { this.linkControllerLoading = undefined; return; }
      const canvas = this.terminal.renderer?.getCanvas();
      if (!canvas) { this.linkControllerLoading = undefined; return; }
      this.linkController = createTerminalLinkController({
        host: this.config.host,
        canvas,
        getBufferLength: () => this.terminal.buffer.active.length,
        getVisibleRange: () => this.visibleLinkRange(),
        getRow: (y) => this.readLinkRow(y),
        getCellMetrics: () => this.cellMetrics(),
        paint: (ranges) => {
          const renderer = this.ghostty.renderer;
          const buffer = this.terminal.wasmTerm;
          if (!renderer || !buffer || this.suspended || this.closed) return;
          renderer.setHoveredLinkRanges(ranges);
          renderer.render(buffer, false, this.terminal.viewportY, this.terminal, this.ghostty.scrollbarOpacity);
          this.wakeTerminal();
        },
        open: (link) => {
          if (link.openable) window.open(link.target, "_blank", "noopener,noreferrer");
        },
      });
      this.flushLinkRows();
      this.linkControllerLoading = undefined;
    }).catch(() => { this.linkControllerLoading = undefined; });
  }

  private flushLinkRows(): void {
    const controller = this.linkController;
    if (!controller || this.pendingLinkRows.size === 0 || this.suspended) return;
    const rows = [...this.pendingLinkRows];
    const forced = rows.filter((row) => this.forcedLinkRows.has(row));
    const candidates = rows.filter((row) => !this.forcedLinkRows.has(row));
    this.pendingLinkRows.clear();
    this.forcedLinkRows.clear();
    controller.updateRows(forced, true);
    controller.updateRows(candidates, false);
  }

  private visibleLinkRange(): { first: number; last: number } {
    const active = this.terminal.buffer.active;
    const first = active.type === "alternate"
      ? 0
      : Math.max(0, active.length - this.terminal.rows - Math.floor(this.terminal.viewportY));
    return { first, last: Math.min(active.length - 1, first + this.terminal.rows - 1) };
  }

  private readLinkRow(y: number): TerminalLinkRow | undefined {
    const active = this.terminal.buffer.active;
    const line = active.getLine(y);
    if (!line) return undefined;
    const scrollback = active.type === "alternate" ? 0 : Math.max(0, active.length - this.terminal.rows);
    const wasm = this.terminal.wasmTerm;
    const cells: TerminalLinkRow["cells"] = [];
    for (let x = 0; x < line.length; x += 1) {
      const cell = line.getCell(x);
      if (!cell) { cells.push({ text: " " }); continue; }
      const text = cell.getWidth() === 0 ? "" : cell.getChars() || (cell.getCodepoint() === 0 ? " " : "");
      const target = cell.getHyperlinkId() === 0 || !wasm
        ? null
        : y < scrollback
          ? wasm.getScrollbackHyperlinkUri(y, x)
          : wasm.getHyperlinkUri(active.type === "alternate" ? y : y - scrollback, x);
      cells.push({ text, ...(target === null ? {} : { target }) });
    }
    return { y, bufferType: active.type, wrapped: line.isWrapped, wrapKnown: active.type === "alternate" || y >= scrollback, cells };
  }

  /** Uses the same viewport slice the renderer uses for its cursor row. */
  private cursorLine(y: number): unknown[] | null {
    const buffer = this.terminal.wasmTerm;
    if (!buffer) return null;
    const viewport = buffer.getViewport?.();
    return viewport
      ? viewport.slice(y * this.terminal.cols, (y + 1) * this.terminal.cols)
      : buffer.getLine(y);
  }

  private predictionUnsafe(): boolean {
    const buffer = this.terminal.wasmTerm;
    return !this.attached || this.inputPaused || !buffer || buffer.isAlternateScreen() || this.terminal.viewportY !== 0;
  }

  private predictionScreenUnsafe(): boolean {
    const buffer = this.terminal.wasmTerm;
    return !buffer || buffer.isAlternateScreen() || this.terminal.viewportY !== 0;
  }

  private predictionSafe(): boolean {
    if (this.predictionUnsafe()) return false;
    const position = this.predictionPosition();
    return position !== undefined && position.visible && !position.alternate && position.viewportY === 0;
  }

  private syncVisualViewport(): void {
    const viewport = window.visualViewport;
    if (!viewport) return;
    this.wakeTerminal();
    const keyboardOpen = viewport.height < window.innerHeight - 120;
    this.screen.style.height = keyboardOpen ? `${viewport.height}px` : "";
    this.screen.style.transform = keyboardOpen ? `translateY(${viewport.offsetTop}px)` : "";
    this.scheduleFit();
  }

  private sendFrame(streamId: number, frame: WireFrame, traceStart?: bigint, traceLength = 0): void {
    if (traceStart === undefined) { this.conn.send(streamId, frame); return; }
    this.conn.send(streamId, frame, (at) => this.traceRange(traceStart, traceLength, "encode", at), () => this.traceRange(traceStart, traceLength, "wsSend", performance.now()));
  }

  /** Maps byte-stream sequence numbers to probe key IDs without changing wire frames. */
  private traceRange(start: bigint, length: number, hop: TerminalTraceHop, at: number): void {
    const onTrace = this.config.hooks?.onTrace;
    if (!onTrace) return;
    for (let offset = 0; offset < length; offset += 1) {
      onTrace((start + BigInt(offset)).toString(), hop, at);
    }
  }

  private protocolFailure(message: string): void {
    this.conn.fail(message);
  }

  private setStatus(message: string): void {
    this.config.status.textContent = message;
    this.config.status.hidden = message.length === 0;
  }

  /** Attachment and typing refresh the latency sample; connection liveness continues at idle [D265]. */
  private startPings(): void {
    this.prediction?.setRoundTrip(undefined);
    this.config.onRoundTrip?.(undefined);
    this.conn.sampleRoundTrip();
  }

  private sampleRoundTrip(): void {
    if (this.attached && !this.closed) this.conn.sampleRoundTrip();
  }

  /** Keeps Ghostty drawing only through active input/output and its settling window. */
  private wakeTerminal(): void {
    if (this.closed || this.suspended || this.frozen) return;
    window.clearTimeout(this.renderIdleTimer);
    this.renderIdleTimer = window.setTimeout(() => this.pauseTerminal(), RENDER_IDLE_MS);
    this.ghostty.startRenderLoop();
  }

  /** Parks Ghostty's private render loop and steady cursor after the settling window. */
  private pauseTerminal(): void {
    window.clearTimeout(this.renderIdleTimer);
    this.renderIdleTimer = 0;
    this.ghostty.cancelRenderLoop();
    this.ghostty.renderer?.setCursorBlink(false);
    this.syncCursorLayer();
  }
}

function toU16(value: number): number {
  return clamp(Math.round(value), 0, 0xffff);
}

function terminalBufferText(terminal: Terminal, maxRows: number): string {
  const buffer = terminal.buffer.active;
  const first = Math.max(0, buffer.length - terminal.rows - maxRows);
  const lines: string[] = [];
  for (let row = first; row < buffer.length; row += 1) {
    const line = buffer.getLine(row);
    if (line) lines.push(line.translateToString(true));
  }
  return lines.join("\n");
}

/** Packs palette and default colors for the terminal's local theme API. */
function localThemeColorValues(theme: ITheme, fallback: ITheme): number[] {
  const palette = ANSI_THEME_KEYS.map((key) => themeHex(theme[key] ?? fallback[key], key, fallback[key]));
  const foreground = themeHex(theme.foreground ?? fallback.foreground, "foreground", fallback.foreground);
  const background = themeHex(theme.background ?? fallback.background, "background", fallback.background);
  const cursor = themeHex(theme.cursor ?? fallback.cursor, "cursor", fallback.cursor);
  return [...palette, foreground, background, cursor].map((color) => Number.parseInt(color.slice(1), 16));
}

/** Normalizes transparent mesh backgrounds to zero RGB and rejects OSC injection. */
function themeHex(value: string | undefined, name: keyof ITheme, fallback: string | undefined): string {
  const color = value ?? fallback;
  if (name === "background" && color === "rgba(0,0,0,0)") return "#000000";
  if (!color || !/^#[0-9a-f]{6}$/i.test(color)) throw new Error(`invalid terminal theme color for ${name}`);
  return color.toLowerCase();
}

/** Avoids sending duplicate local OSC writes when UI and terminal state already agree. */
function sameTheme(left: ITheme | undefined, right: ITheme): boolean {
  return left !== undefined && THEME_COLOR_KEYS.every((key) => left[key] === right[key]);
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, Number.isFinite(value) ? value : min));
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("result is not an object");
  return value as Record<string, unknown>;
}

function requireString(value: unknown): string {
  if (typeof value !== "string") throw new Error("result string is missing");
  return value;
}

function uuidBytes(value: string): Uint8Array {
  if (!isCanonicalUuid(value)) throw new Error("session id is not a canonical UUID");
  const hex = value.replace(/-/g, "");
  const output = new Uint8Array(16);
  for (let index = 0; index < output.byteLength; index += 1) {
    output[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}
