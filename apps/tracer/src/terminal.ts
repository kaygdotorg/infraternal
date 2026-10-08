/** Owns Ghostty rendering, leg-A mux frames, bounded stream queues, and resumable input. */
import { init, Terminal, type ITheme } from "../vendor/ghostty-web";
import { DEFAULT_FONT_ID, fontById, fontStack, loadFont, type MonoFont } from "../../../packages/ui/src/fonts";
import { terminalTouch } from "./terminal-touch";
import { PredictiveEcho, type PredictionPosition, type PredictiveEchoState } from "./predictive-echo";
import type { WireFrame } from "../../../packages/protocol/src/codec";
import { MuxConnection, type StreamHandler } from "./connection";

const INITIAL_CREDIT = 1024 * 1024;
const INPUT_QUEUE_LIMIT = 1024 * 1024;
const INPUT_RESUME_GUARD = 16 * 1024;
const INPUT_FRAME_LIMIT = 16 * 1024;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const RENDER_IDLE_MS = 700;
const TERMINAL_FONT_SIZE_DESKTOP = 14;
const TERMINAL_FONT_SIZE_TOUCH = 13;
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
    naturalCellWidth?: number;
    ctx?: CanvasRenderingContext2D;
    devicePixelRatio?: number;
    theme?: { background?: string; foreground?: string; cursor?: string };
    render(buffer: unknown, forceAll?: boolean, viewportY?: number, scrollbackProvider?: unknown, scrollbarOpacity?: number): void;
  };
}

export interface TerminalHooks {
  /** Only a public session id; writer/resume capabilities remain in memory. */
  onSessionCreated?: (sessionId: string) => void;
  onAttached?: (resumed: boolean, terminal: TerminalClient) => void;
  onDisconnected?: (forced: boolean) => void;
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
  private readonly terminal: Terminal;
  private readonly ghostty: GhosttyActivityControls;
  private readonly inputQueue = new ByteQueue(INPUT_QUEUE_LIMIT);
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
  private snapshotWriteInFlight = false;
  private pendingSnapshot: PendingSnapshot | undefined;
  private receivedOutSeq = 0n;
  private lastOutSeq = 0n;
  private nextInSeq = 0n;
  private ackedInSeq = 0n;
  private creditAvailable = 0;
  private attached = false;
  private attachRequested = false;
  private openCallSent = false;
  private fitQueued = false;
  private hasAttached = false;
  /** Bumped when the cursors restart, so a write that was in flight does not account for bytes that are gone. */
  private cursorEpoch = 0;
  /** Off screen: no drawing and no canvas backing store (see `setSuspended`). */
  private suspended = false;
  private closed = false;
  private inputPaused = false;
  private inputAtCapacityMessageShown = false;
  private connectionIsResume = false;
  private renderIdleTimer = 0;
  private rendererCursorBlinking = false;
  private predictionCursorHidden = false;
  private lastThemeColorsMs = 0;
  private lastThemeRenderMs = 0;
  private inputModifiers: InputModifiers = { ctrl: "off", alt: "off" };
  private readonly prediction: PredictiveEcho | undefined;
  private lastSize = { cols: 80, rows: 24, pxW: 0, pxH: 0 };
  private readonly onViewportChange = (): void => this.syncVisualViewport();
  private readonly onTerminalActivity = (): void => this.wakeTerminal();
  private readonly disposeTouch: () => void;

  private constructor(private readonly config: TerminalConfig, terminal: Terminal, font: MonoFont) {
    this.terminal = terminal;
    this.font = font;
    this.ghostty = terminal as unknown as GhosttyActivityControls;
    this.screen = config.screen ?? config.host.parentElement ?? config.host;
    this.terminal.open(config.host);
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
    config.host.addEventListener("pointerdown", this.onTerminalActivity, { passive: true });
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
      this.prediction?.layoutChanged();
      this.wakeTerminal();
      const rect = config.host.getBoundingClientRect();
      this.lastSize = { cols, rows, pxW: toU16(rect.width), pxH: toU16(rect.height) };
      if (this.attached) this.sendFrame(this.streamId, { type: "Resize", ...this.lastSize });
    });
    this.terminal.onData((data) => { this.wakeTerminal(); this.handleInput(data); });
    this.terminal.onScroll((offset) => {
      this.wakeTerminal();
      if (offset !== 0) this.prediction?.unsafeScreen();
      else this.prediction?.returnToLiveViewport();
      config.host.dataset.scrolled = String(offset !== 0);
      config.onScroll?.(offset !== 0);
    });
    const known = config.attachSessionId ?? config.initialSessionId;
    if (known && isCanonicalUuid(known)) {
      // A page reload has no pending-input buffer or writer capability. Start
      // a fresh writer at zero, replay output from zero, and let server-owned
      // session authorization validate this nonsecret convenience identifier.
      this.sessionId = uuidBytes(known);
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
      this.prediction?.setRoundTrip(ms);
      config.onRoundTrip?.(ms);
    });
    this.streamId = this.conn.openStream(this.streamHandler());
    if (!matchMedia("(pointer: coarse)").matches) this.terminal.focus();
  }

  /**
   * Loads the chosen font's upright faces and the WASM terminal once, then opens the
   * one-session client. Only the upright faces gate the first paint, because the cell
   * grid is measured from them; italic and Nerd Font faces load afterwards.
   */
  static async open(config: TerminalConfig): Promise<TerminalClient> {
    const font = config.font ?? fontById(DEFAULT_FONT_ID)!;
    await loadFont(font);
    await init();
    const terminal = new Terminal({
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
    const client = new TerminalClient(config, terminal, font);
    // Weights go in before the first measurement so the grid is measured from the face it draws.
    client.installFontWeights();
    client.remeasureFont();
    client.keepLigaturesOff();
    client.loadStyledFaces();
    return client;
  }

  get isConnected(): boolean { return this.attached; }
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
    themeColorsMs: number;
    themeRenderMs: number;
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
      themeColorsMs: this.lastThemeColorsMs,
      themeRenderMs: this.lastThemeRenderMs,
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
    if (this.closed || this.inputPaused) throw new Error("terminal input is paused");
    this.terminal.input(data, true);
  }

  /** Seeds a visible shell prompt in the mock page without advancing wire sequences. */
  async seedPromptForTest(): Promise<void> {
    if (this.closed) throw new Error("terminal is closed");
    await new Promise<void>((resolve) => this.terminal.write("$ ", resolve));
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
      return;
    }
    this.restoreSurface();
    this.scheduleFit();
    this.wakeTerminal();
  }

  /** Recomputes the grid from the host's box (the window was resized). */
  refit(): void {
    this.scheduleFit();
  }

  /** Focuses Ghostty's actual input host so the mobile keyboard can stay open. */
  focus(): void {
    this.terminal.focus();
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
    this.disposeTouch();
    this.pauseTerminal();
    this.config.host.removeEventListener("pointerdown", this.onTerminalActivity);
    this.config.host.removeEventListener("pointermove", this.onTerminalActivity);
    this.config.host.removeEventListener("wheel", this.onTerminalActivity);
    if (this.attached) this.conn.streamAttached(false);
    this.offRoundTrip();
    this.prediction?.dispose();
    this.resizeObserver.disconnect();
    window.visualViewport?.removeEventListener("resize", this.onViewportChange);
    window.visualViewport?.removeEventListener("scroll", this.onViewportChange);
    this.inputQueue.clear();
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
        this.connectionIsResume = this.sessionId !== undefined;
        if (this.sessionId && resuming) {
          this.attachRequested = true;
          this.tryAttach();
        } else if (this.sessionId) {
          this.attachRequested = true;
        }
      },
      onWelcome: (resumed) => {
        // A connection the server does not know starts every writer at zero, like a page reload.
        if (!resumed && this.hasAttached) this.restartCursors();
        if (!this.sessionId) this.openSession();
        else {
          this.attachRequested = true;
          this.tryAttach();
        }
      },
      onFrame: (frame, message, receivedAt) => this.handleTerminalFrame(frame, message, receivedAt),
      onDisconnected: (forced) => {
        if (this.closed) return;
        this.attached = false;
        this.attachRequested = false;
        this.openCallSent = false;
        this.config.hooks?.onDisconnected?.(forced);
        this.setStatus("Connection lost; resuming…");
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
          if (notice.type === "terminal.snapshot" && notice.approximate === true) {
            this.setStatus("Reconnected with an approximate screen.");
          } else if (notice.type === "terminal.snapshot_unavailable") {
            this.setStatus("Output paused; waiting for screen recovery.");
          } else if (notice.type !== "terminal.exited") {
            throw new Error("unknown terminal notice");
          }
        } catch {
          this.protocolFailure("invalid terminal notice");
        }
        return;
      }
      case "Ping":
        this.sendFrame(this.streamId, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs });
        return;
      case "Pong":
        this.conn.acceptPong(frame.nonce);
        return;
      case "Close":
        this.setStatus(frame.reason || "The terminal stream closed.");
        // On a connection of its own a closed stream restarts it; on a shared one the others keep running.
        if (this.ownsConnection) this.conn.forceClose();
        return;
      default:
        this.protocolFailure("server sent an invalid terminal-stream frame");
    }
  }

  private openSession(): void {
    if (this.openCallSent || this.closed) return;
    const hostId = this.config.hostId ?? new URLSearchParams(location.search).get("host");
    if (hostId && !isCanonicalUuid(hostId)) {
      this.setStatus("The host query parameter must be a lowercase UUID.");
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
    }, () => {
      this.openCallSent = false;
      if (!this.closed && this.conn.isOpen) this.setStatus("The server could not open this terminal.");
    });
  }

  private tryAttach(): void {
    if (!this.attachRequested || !this.sessionId || this.attached || this.closed || !this.conn.isOpen) return;
    if (this.outputWriteInFlight || this.snapshotWriteInFlight || this.pendingSnapshot || this.outputQueue.length > 0) return;
    this.attachRequested = false;
    this.attached = true;
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
    this.resendUnacknowledgedInput();
    this.setStatus("");
    this.hasAttached = true;
    this.conn.streamAttached(true, this.streamId);
    this.startPings();
    this.wakeTerminal();
    this.config.hooks?.onAttached?.(this.connectionIsResume, this);
  }

  /** Starts the stream's cursors over: its session is attached again from the beginning, as after a reload. */
  private restartCursors(): void {
    this.cursorEpoch += 1;
    this.receivedOutSeq = 0n;
    this.lastOutSeq = 0n;
    this.nextInSeq = 0n;
    this.ackedInSeq = 0n;
    this.inputQueue.clear();
    this.outputQueue.clear();
    this.pendingSnapshot?.bytes.fill(0);
    this.pendingSnapshot = undefined;
    this.prediction?.resetForSnapshot();
    this.terminal.reset();
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
    if (this.closed || !data) return;
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
    if (encoded.byteLength > this.inputQueue.free) {
      this.pauseInput("Input is paused until the server acknowledges buffered keystrokes.");
      return;
    }
    if (this.nextInSeq > MAX_U64 - BigInt(encoded.byteLength) || !this.inputQueue.push(encoded)) {
      this.protocolFailure("input resume sequence or queue exceeded its bound");
      return;
    }
    const firstSequence = this.nextInSeq;
    this.nextInSeq += BigInt(encoded.byteLength);
    if (this.attached) {
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
    // Predict after the bytes are on the socket: prediction never delays the send. The overlay is still
    // drawn in this same task, so no host echo can be processed (and painted) before the prediction is.
    // `encoded` may alias inputScratch, which the queue has already copied; prediction copies what it keeps.
    this.prediction?.input(data, firstSequence, encoded, this.predictionSafe());
    if (this.inputQueue.free < INPUT_RESUME_GUARD) {
      this.pauseInput("Input paused: the bounded reconnect buffer is nearly full.");
    }
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
    if (this.inputPaused && this.inputQueue.free >= INPUT_RESUME_GUARD) {
      this.inputPaused = false;
      this.terminal.options.disableStdin = false;
      if (this.inputAtCapacityMessageShown) this.setStatus("");
      this.inputAtCapacityMessageShown = false;
    }
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
    // `message` keeps an unfragmented decoder view alive; fragment scratch is copied by the ring.
    void message;
    this.drainOutput();
  }

  private acceptSnapshot(sequence: bigint, bytes: Uint8Array): void {
    if (sequence < this.receivedOutSeq || bytes.byteLength > this.creditAvailable) {
      this.protocolFailure("server sent a stale snapshot or exceeded output credit");
      return;
    }
    this.creditAvailable -= bytes.byteLength;
    this.receivedOutSeq = sequence;

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
    // Received bytes remain owned after disconnect. Finish painting them before Attach
    // advertises lastOutSeq; returnCredit sends nothing on a detached transport.
    if (this.outputWriteInFlight || this.snapshotWriteInFlight || this.closed) return;
    if (this.pendingSnapshot) {
      const snapshot = this.pendingSnapshot;
      this.pendingSnapshot = undefined;
      this.snapshotWriteInFlight = true;
      this.prediction?.resetForSnapshot();
      this.terminal.reset();
      this.requestSymbolsIfNeeded(snapshot.bytes);
      this.traceRange(snapshot.outSeq, snapshot.bytes.byteLength, "termWrite", performance.now());
      const epoch = this.cursorEpoch;
      this.terminal.write(snapshot.bytes, () => {
        if (epoch !== this.cursorEpoch) { this.snapshotWriteInFlight = false; this.drainOutput(); this.tryAttach(); return; }
        const callbackAt = performance.now();
        this.traceRange(snapshot.outSeq, snapshot.bytes.byteLength, "writeCallback", callbackAt);
        // Ghostty calls this from the rAF after its render loop draws the write; another rAF adds a full frame.
        const paintedAt = performance.now();
        this.lastOutSeq = snapshot.outSeq;
        this.snapshotWriteInFlight = false;
        this.traceRange(snapshot.outSeq, snapshot.bytes.byteLength, "paint", paintedAt);
        this.config.hooks?.onPaintedOutput?.(snapshot.bytes, paintedAt, snapshot.outSeq);
        snapshot.bytes.fill(0);
        this.returnCredit(snapshot.bytes.byteLength);
        this.drainOutput();
        this.tryAttach();
      });
      return;
    }

    if (this.outputQueue.length > 0) {
      const region = this.outputQueue.peek();
      if (region.byteLength === 0) {
        this.protocolFailure("output queue has no contiguous data");
        return;
      }
      this.outputWriteInFlight = true;
      this.outputWriteLength = region.byteLength;
      this.requestSymbolsIfNeeded(region);
      const writeSequence = this.lastOutSeq;
      this.traceRange(writeSequence, region.byteLength, "termWrite", performance.now());
      const epoch = this.cursorEpoch;
      this.terminal.write(region, () => {
        if (epoch !== this.cursorEpoch) { this.outputWriteLength = 0; this.outputWriteInFlight = false; this.drainOutput(); this.tryAttach(); return; }
        const callbackAt = performance.now();
        this.traceRange(writeSequence, this.outputWriteLength, "writeCallback", callbackAt);
        // The callback is ordered after Ghostty's render-loop callback in the same animation frame.
        const paintedAt = performance.now();
        const consumed = this.outputWriteLength;
        this.lastOutSeq += BigInt(consumed);
        this.traceRange(writeSequence, consumed, "paint", paintedAt);
        if (this.predictionScreenUnsafe()) this.prediction?.unsafeScreen();
        else {
          this.prediction?.rendererPainted();
          this.prediction?.paintedOutput();
        }
        this.config.hooks?.onPaintedOutput?.(region.subarray(0, consumed), paintedAt, writeSequence);
        this.outputQueue.consume(consumed);
        this.outputWriteLength = 0;
        this.outputWriteInFlight = false;
        this.returnCredit(consumed);
        this.drainOutput();
        this.tryAttach();
      });
      // The terminal state includes these bytes now; only their paint is a frame away. Reconcile the
      // prediction against them at once, so a key typed in that frame is placed from a consistent cursor.
      if (this.predictionUnsafe()) this.prediction?.unsafeScreen();
      else this.prediction?.hostWritten(region.subarray(0, region.byteLength));
      return;
    }
    this.tryAttach();
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
    if (this.fitQueued || this.closed || this.suspended) return;
    this.fitQueued = true;
    requestAnimationFrame(() => {
      this.fitQueued = false;
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
    const renderer = this.ghostty.renderer as unknown as Record<string, unknown> | undefined;
    if (renderer) {
      this.silenced = {};
      for (const name of ["render", "renderLine", "renderCursor", "resize"]) {
        const original = renderer[name];
        if (typeof original !== "function") continue;
        this.silenced[name] = original;
        renderer[name] = () => undefined;
      }
    }
    canvas.width = 0;
    canvas.height = 0;
  }

  /** Gives the canvas its size back and draws the whole screen again from the terminal state. */
  restoreSurface(): void {
    const renderer = this.ghostty.renderer;
    if (!renderer || !this.surfaceReleased || this.closed) return;
    this.surfaceReleased = false;
    const target = renderer as unknown as Record<string, unknown>;
    for (const [name, original] of Object.entries(this.silenced ?? {})) target[name] = original;
    this.silenced = undefined;
    renderer.resize(this.terminal.cols, this.terminal.rows);
    this.repaintAll();
  }

  private surfaceReleased = false;
  private silenced: Record<string, unknown> | undefined;

  private repaintAll(): void {
    const renderer = this.ghostty.renderer;
    const buffer = this.terminal.wasmTerm;
    if (!renderer || !buffer || this.closed) return;
    renderer.render(buffer, true, this.terminal.viewportY, this.terminal, this.ghostty.scrollbarOpacity);
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
   * pass, so the renderer's renderCursor is wrapped once (installCursorGuard)
   * and skips drawing while hidden. Toggling only repaints the single cursor row.
   */
  private setPredictionCursorHidden(hidden: boolean): void {
    if (hidden === this.predictionCursorHidden) return;
    this.installCursorGuard();
    this.predictionCursorHidden = hidden;
    const renderer = this.ghostty.renderer;
    const buffer = this.terminal.wasmTerm;
    if (!renderer || !buffer) return;
    const cursor = buffer.getCursor();
    const line = this.cursorLine(cursor.y);
    if (!line) return;
    renderer.renderLine(line, cursor.y, this.terminal.cols);
    if (!hidden && cursor.visible && this.terminal.viewportY === 0) renderer.renderCursor(cursor.x, cursor.y, line);
  }

  private cursorGuardInstalled = false;

  /** Wraps the pinned renderer's cursor draw once so a pending prediction suppresses it on every pass. */
  private installCursorGuard(): void {
    const renderer = this.ghostty.renderer;
    if (this.cursorGuardInstalled || !renderer) return;
    const draw = renderer.renderCursor.bind(renderer);
    renderer.renderCursor = (x, y, line) => {
      if (!this.predictionCursorHidden) draw(x, y, line);
    };
    this.cursorGuardInstalled = true;
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

  /** Samples RTT on attachment and typing; an idle terminal schedules no wakeups [81]. */
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
    if (this.closed || this.suspended) return;
    window.clearTimeout(this.renderIdleTimer);
    this.renderIdleTimer = window.setTimeout(() => this.pauseTerminal(), RENDER_IDLE_MS);
    this.rendererCursorBlinking = true;
    this.ghostty.renderer?.setCursorBlink(true);
    this.ghostty.startRenderLoop();
  }

  /** Parks Ghostty's private render loop and steady cursor after the settling window. */
  private pauseTerminal(): void {
    window.clearTimeout(this.renderIdleTimer);
    this.renderIdleTimer = 0;
    this.ghostty.cancelRenderLoop();
    this.rendererCursorBlinking = false;
    this.ghostty.renderer?.setCursorBlink(false);
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

function isCanonicalUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
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
