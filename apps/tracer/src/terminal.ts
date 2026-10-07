/** Owns Ghostty rendering, leg-A mux frames, bounded stream queues, and resumable input. */
import { init, Terminal, type ITheme } from "../vendor/ghostty-web";
import {
  WebSocketFrameDecoder,
  encodeMuxedFrameInto,
  type WireFrame,
} from "../../../packages/protocol/src/codec";

const CONTROL_STREAM = 0;
const TERMINAL_STREAM = 1;
const VERSION = 1;
const INITIAL_CREDIT = 1024 * 1024;
const INPUT_QUEUE_LIMIT = 1024 * 1024;
const INPUT_RESUME_GUARD = 16 * 1024;
const INPUT_FRAME_LIMIT = 16 * 1024;
const SEND_BUFFER_SIZE = 32 * 1024;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const encoder = new TextEncoder();

export interface TerminalHooks {
  /** Only a public session id; writer/resume capabilities remain in memory. */
  onSessionCreated?: (sessionId: string) => void;
  onAttached?: (resumed: boolean, terminal: TerminalClient) => void;
  onDisconnected?: (forced: boolean) => void;
  onInput?: (data: string, at: number, sequence: bigint) => boolean | void;
  onTrace?: (keyId: string, hop: TerminalTraceHop, at: number) => void;
  onPaintedOutput?: (bytes: Uint8Array, at: number, sequence: bigint) => void;
}

export type TerminalTraceHop =
  | "encode"
  | "wsSend"
  | "wsMessage"
  | "decode"
  | "termWrite"
  | "writeCallback"
  | "paint";

export interface TerminalConfig {
  host: HTMLElement;
  /** Stage that follows the visual viewport when iOS opens its on-screen keyboard. */
  screen?: HTMLElement;
  status: HTMLElement;
  hooks?: TerminalHooks;
  /** Curated theme shared by the floating controls and Ghostty. */
  theme?: ITheme;
  onRoundTrip?: (milliseconds: number | undefined) => void;
  onConnectionChange?: (connected: boolean) => void;
  onScroll?: (scrolled: boolean) => void;
  onInputActivity?: () => void;
  traceMockServer?: boolean;
  /** Reattach this tab's owned session using a new writer after a page reload. */
  initialSessionId?: string;
  /** Test-only cap override; normal tracer sessions retain the 10,000-row default. */
  scrollbackLimit?: number;
}

interface ResumeCredentials {
  connectionId: Uint8Array;
  resumeToken: Uint8Array;
  deadline: number;
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
  private readonly inputQueue = new ByteQueue(INPUT_QUEUE_LIMIT);
  private readonly outputQueue = new ByteQueue(INITIAL_CREDIT);
  private readonly inputScratch = new Uint8Array(INPUT_FRAME_LIMIT);
  private readonly sendScratch = new Uint8Array(SEND_BUFFER_SIZE);
  private readonly resizeObserver: ResizeObserver;
  private readonly screen: HTMLElement;
  private socket: WebSocket | undefined;
  private decoder: WebSocketFrameDecoder | undefined;
  private resumeCredentials: ResumeCredentials | undefined;
  private sessionId: Uint8Array | undefined;
  private retryTimer = 0;
  private retryAttempt = 0;
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
  private closed = false;
  private forcedDrop = false;
  private inputPaused = false;
  private inputAtCapacityMessageShown = false;
  private connectionIsResume = false;
  private lastPingAt = -Infinity;
  private nextPingNonce = 0n;
  private readonly pendingPings = new Map<bigint, number>();
  private inputModifier: "ctrl" | "alt" | undefined;
  private lastSize = { cols: 80, rows: 24, pxW: 0, pxH: 0 };
  private readonly onViewportChange = (): void => this.syncVisualViewport();

  private constructor(private readonly config: TerminalConfig, terminal: Terminal) {
    this.terminal = terminal;
    this.screen = config.screen ?? config.host.parentElement ?? config.host;
    this.terminal.open(config.host);
    this.terminal.options.scrollback = config.scrollbackLimit ?? 10_000;
    this.resizeObserver = new ResizeObserver(() => this.scheduleFit());
    this.resizeObserver.observe(config.host);
    window.visualViewport?.addEventListener("resize", this.onViewportChange);
    window.visualViewport?.addEventListener("scroll", this.onViewportChange);
    this.terminal.onResize(({ cols, rows }) => {
      const rect = config.host.getBoundingClientRect();
      this.lastSize = { cols, rows, pxW: toU16(rect.width), pxH: toU16(rect.height) };
      if (this.attached) this.sendFrame(TERMINAL_STREAM, { type: "Resize", ...this.lastSize });
    });
    this.terminal.onData((data) => this.handleInput(data));
    this.terminal.onScroll((offset) => {
      config.host.dataset.scrolled = String(offset !== 0);
      config.onScroll?.(offset !== 0);
    });
    if (config.initialSessionId && isCanonicalUuid(config.initialSessionId)) {
      // A page reload has no pending-input buffer or writer capability. Start
      // a fresh writer at zero, replay output from zero, and let server-owned
      // session authorization validate this nonsecret convenience identifier.
      this.sessionId = uuidBytes(config.initialSessionId);
    }
    this.scheduleFit();
    this.connect();
    if (!matchMedia("(pointer: coarse)").matches) this.terminal.focus();
  }

  /** Loads Geist and the WASM terminal once, then opens the one-session client. */
  static async open(config: TerminalConfig): Promise<TerminalClient> {
    await document.fonts.load('400 14px "Geist Mono"');
    await init();
    return new TerminalClient(config, new Terminal({
      fontFamily: '"Geist Mono", ui-monospace, monospace',
      fontSize: matchMedia("(pointer: coarse)").matches ? 13 : 14,
      cursorBlink: true,
      cursorStyle: "bar",
      scrollback: config.scrollbackLimit ?? 10_000,
      theme: config.theme ?? {
        background: "#101113",
        foreground: "#e6e7e9",
        cursor: "#c8ceff",
        cursorAccent: "#101113",
        selectionBackground: "#44485c",
      },
    }));
  }

  get isConnected(): boolean { return this.attached; }
  get outputSequence(): bigint { return this.lastOutSeq; }
  get inputSequence(): bigint { return this.nextInSeq; }
  get inputAcknowledged(): bigint { return this.ackedInSeq; }

  /** Exposes renderer allocation counters only through the explicit test-double hook. */
  get rendererMetrics(): {
    cols: number;
    rows: number;
    cellWidth: number;
    cellHeight: number;
    configuredScrollback: number;
    receivedSequence: string;
    outputSequence: string;
    scrollbackRows: number;
    wasmMemoryBytes: number;
  } {
    const wasmTerm = this.terminal.wasmTerm;
    const memory = (wasmTerm as unknown as { memory?: WebAssembly.Memory } | undefined)?.memory;
    const cell = this.cellMetrics();
    return {
      cols: this.terminal.cols,
      rows: this.terminal.rows,
      cellWidth: cell.width,
      cellHeight: cell.height,
      configuredScrollback: this.terminal.options.scrollback ?? 10_000,
      receivedSequence: this.receivedOutSeq.toString(),
      outputSequence: this.lastOutSeq.toString(),
      scrollbackRows: wasmTerm?.getScrollbackLength() ?? 0,
      wasmMemoryBytes: memory?.buffer.byteLength ?? 0,
    };
  }

  /** Returns bounded renderer text for the explicitly marked test-double page. */
  readScreenText(): string {
    const buffer = this.terminal.buffer.active;
    const first = Math.max(0, buffer.length - this.terminal.rows - 10_000);
    const lines: string[] = [];
    for (let row = first; row < buffer.length; row += 1) {
      const line = buffer.getLine(row);
      if (line) lines.push(line.translateToString(true));
    }
    return lines.join("\n");
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

  /** Applies one sticky mobile modifier to the next terminal input event. */
  setInputModifier(modifier: "ctrl" | "alt" | null): void {
    this.inputModifier = modifier ?? undefined;
  }

  /** Updates both Ghostty's option record and renderer palette without rebuilding the session. */
  setTheme(theme: ITheme): void {
    this.config.theme = theme;
    this.terminal.options.theme = theme;
    const renderer = (this.terminal as unknown as { renderer?: { setTheme: (next: ITheme) => void } }).renderer;
    renderer?.setTheme(theme);
  }

  /** Forces a WebSocket close for the opt-in resume probe. */
  forceDrop(): void {
    this.forcedDrop = true;
    this.socket?.close(4000, "tracer resume probe");
  }

  dispose(): void {
    if (this.closed) return;
    this.closed = true;
    this.config.onConnectionChange?.(false);
    window.clearTimeout(this.retryTimer);
    this.stopPings();
    this.resizeObserver.disconnect();
    window.visualViewport?.removeEventListener("resize", this.onViewportChange);
    window.visualViewport?.removeEventListener("scroll", this.onViewportChange);
    this.inputQueue.clear();
    this.outputQueue.clear();
    this.resumeCredentials?.connectionId.fill(0);
    this.resumeCredentials?.resumeToken.fill(0);
    this.pendingSnapshot?.bytes.fill(0);
    this.socket?.close(1000, "terminal closed");
    this.terminal.dispose();
  }

  private connect(): void {
    if (this.closed) return;
    this.setStatus(this.sessionId ? "Connection lost; resuming…" : "Connecting…");
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const traceQuery = this.config.traceMockServer ? "?trace=1" : "";
    const socket = new WebSocket(`${protocol}//${location.host}/v1/ws${traceQuery}`);
    socket.binaryType = "arraybuffer";
    this.socket = socket;
    this.decoder = new WebSocketFrameDecoder();
    this.attached = false;
    this.attachRequested = false;

    socket.onopen = () => {
      const resumable = this.sessionId !== undefined && this.resumeCredentials !== undefined && Date.now() < this.resumeCredentials.deadline;
      // RESUME_NEXT tells the server to wait for the adjacent Resume before issuing Welcome.
      const hello: WireFrame = { type: "Hello", version: VERSION, caps: resumable ? 1n : 0n, clientInfo: "infraternal-tracer/0.1" };
      let length = encodeMuxedFrameInto(CONTROL_STREAM, hello, this.sendScratch);
      this.connectionIsResume = this.sessionId !== undefined;
      if (resumable && this.resumeCredentials) {
        length += encodeMuxedFrameInto(CONTROL_STREAM, {
          type: "Resume",
          connectionId: this.resumeCredentials.connectionId,
          resumeToken: this.resumeCredentials.resumeToken,
        }, this.sendScratch, length);
      }
      socket.send(this.sendScratch.subarray(0, length));
      if (this.sessionId && resumable) {
        this.attachRequested = true;
        this.tryAttach();
      } else if (this.sessionId) {
        this.attachRequested = true;
      }
    };
    socket.onmessage = (event: MessageEvent<ArrayBuffer>) => {
      const receivedAt = performance.now();
      if (!(event.data instanceof ArrayBuffer)) {
        this.protocolFailure("server sent a non-binary frame");
        return;
      }
      try {
        const message = new Uint8Array(event.data);
        this.decoder?.feed(message, (streamId, frame) => this.handleFrame(streamId, frame, message, receivedAt));
      } catch {
        this.protocolFailure("server sent an invalid wire frame");
      }
    };
    socket.onerror = () => this.setStatus("Connection interrupted; reconnecting…");
    socket.onclose = () => {
      if (this.socket !== socket || this.closed) return;
      this.socket = undefined;
      this.decoder = undefined;
      this.attached = false;
      this.attachRequested = false;
      this.config.onConnectionChange?.(false);
      this.stopPings();
      const forced = this.forcedDrop;
      this.forcedDrop = false;
      this.config.hooks?.onDisconnected?.(forced);
      this.setStatus("Connection lost; resuming…");
      this.scheduleReconnect();
    };
  }

  private handleFrame(streamId: number, frame: WireFrame, message: Uint8Array, receivedAt: number): void {
    if (streamId !== CONTROL_STREAM && streamId !== TERMINAL_STREAM) {
      this.protocolFailure("server used an unexpected stream id");
      return;
    }
    if (streamId === CONTROL_STREAM) {
      this.handleControlFrame(frame);
    } else {
      this.handleTerminalFrame(frame, message, receivedAt);
    }
  }

  private handleControlFrame(frame: WireFrame): void {
    switch (frame.type) {
      case "Hello":
        if (frame.version !== VERSION) this.protocolFailure("server uses an unsupported wire version");
        return;
      case "Welcome":
        this.resumeCredentials?.connectionId.fill(0);
        this.resumeCredentials?.resumeToken.fill(0);
        this.resumeCredentials = {
          connectionId: frame.connectionId.slice(),
          resumeToken: frame.resumeToken.slice(),
          deadline: Date.now() + frame.resumeWindowSeconds * 1000,
        };
        if (!this.sessionId) this.openSession();
        else {
          this.attachRequested = true;
          this.tryAttach();
        }
        return;
      case "Result":
        if (frame.callId !== 1 || !this.openCallSent || this.sessionId) {
          this.protocolFailure("server returned an unexpected action result");
          return;
        }
        if (!frame.ok) {
          this.setStatus("The server could not open this terminal.");
          return;
        }
        try {
          const result = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(frame.json)) as unknown;
          const record = asRecord(result);
          const sessionId = requireString(record.session_id);
          this.sessionId = uuidBytes(sessionId);
          this.config.hooks?.onSessionCreated?.(sessionId);
          this.attachRequested = true;
          this.tryAttach();
        } catch {
          this.protocolFailure("terminal.open returned an invalid session id");
        }
        return;
      case "Ping":
        this.sendFrame(CONTROL_STREAM, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs });
        return;
      case "Pong":
        this.acceptPong(frame.nonce);
        return;
      case "Close":
        this.setStatus(frame.reason || "The server closed the connection.");
        this.socket?.close();
        return;
      default:
        this.protocolFailure("server sent a terminal frame on the control stream");
    }
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
        this.sendFrame(TERMINAL_STREAM, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs });
        return;
      case "Pong":
        this.acceptPong(frame.nonce);
        return;
      case "Close":
        this.setStatus(frame.reason || "The terminal stream closed.");
        this.socket?.close();
        return;
      default:
        this.protocolFailure("server sent an invalid terminal-stream frame");
    }
  }

  private openSession(): void {
    if (this.openCallSent || this.closed) return;
    const hostId = new URLSearchParams(location.search).get("host");
    if (hostId && !isCanonicalUuid(hostId)) {
      this.setStatus("The host query parameter must be a lowercase UUID.");
      return;
    }
    this.openCallSent = true;
    const input = hostId ? { host_id: hostId } : {};
    this.sendFrame(CONTROL_STREAM, {
      type: "Call",
      callId: 1,
      actionId: "ssh.session.open",
      inputJson: encoder.encode(JSON.stringify(input)),
    });
  }

  private tryAttach(): void {
    if (!this.attachRequested || !this.sessionId || this.attached || this.closed || !this.isSocketOpen()) return;
    if (this.outputWriteInFlight || this.snapshotWriteInFlight || this.pendingSnapshot || this.outputQueue.length > 0) return;
    this.attachRequested = false;
    this.attached = true;
    this.sendFrame(TERMINAL_STREAM, {
      type: "AttachTerm",
      sessionId: this.sessionId,
      lastOutSeq: this.lastOutSeq,
      // Only server-confirmed bytes belong in Resume; retained input replays separately.
      lastInSeq: this.ackedInSeq,
    });
    this.creditAvailable = INITIAL_CREDIT;
    this.sendFrame(TERMINAL_STREAM, { type: "Credit", bytes: INITIAL_CREDIT });
    this.sendFrame(TERMINAL_STREAM, { type: "Resize", ...this.lastSize });
    this.resendUnacknowledgedInput();
    this.setStatus("");
    this.retryAttempt = 0;
    this.config.onConnectionChange?.(true);
    this.startPings();
    this.config.hooks?.onAttached?.(this.connectionIsResume, this);
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
      this.sendFrame(TERMINAL_STREAM, {
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
    this.config.onInputActivity?.();
    this.sampleRoundTrip();
    const modifier = this.inputModifier;
    this.inputModifier = undefined;
    if (modifier === "ctrl" && data.length === 1) {
      const code = data.toUpperCase().charCodeAt(0);
      if (code >= 64 && code <= 95) data = String.fromCharCode(code - 64);
    } else if (modifier === "alt") {
      data = `\x1b${data}`;
    }
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
        this.sendFrame(TERMINAL_STREAM, {
          type: "Input",
          inSeq: firstSequence + BigInt(offset),
          bytes: encoded.subarray(offset, offset + length),
        }, traceInput ? firstSequence + BigInt(offset) : undefined, traceInput ? length : 0);
        offset += length;
      }
    }
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
    // Received bytes remain owned after disconnect. Finish painting them before Attach
    // advertises lastOutSeq; returnCredit sends nothing on a detached transport.
    if (this.outputWriteInFlight || this.snapshotWriteInFlight || this.closed) return;
    if (this.pendingSnapshot) {
      const snapshot = this.pendingSnapshot;
      this.pendingSnapshot = undefined;
      this.snapshotWriteInFlight = true;
      this.terminal.reset();
      this.traceRange(snapshot.outSeq, snapshot.bytes.byteLength, "termWrite", performance.now());
      this.terminal.write(snapshot.bytes, () => {
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
      const writeSequence = this.lastOutSeq;
      this.traceRange(writeSequence, region.byteLength, "termWrite", performance.now());
      this.terminal.write(region, () => {
        const callbackAt = performance.now();
        this.traceRange(writeSequence, this.outputWriteLength, "writeCallback", callbackAt);
        // The callback is ordered after Ghostty's render-loop callback in the same animation frame.
        const paintedAt = performance.now();
        const consumed = this.outputWriteLength;
        this.lastOutSeq += BigInt(consumed);
        this.traceRange(writeSequence, consumed, "paint", paintedAt);
        this.config.hooks?.onPaintedOutput?.(region.subarray(0, consumed), paintedAt, writeSequence);
        this.outputQueue.consume(consumed);
        this.outputWriteLength = 0;
        this.outputWriteInFlight = false;
        this.returnCredit(consumed);
        this.drainOutput();
        this.tryAttach();
      });
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
    if (this.attached) this.sendFrame(TERMINAL_STREAM, { type: "Credit", bytes });
  }

  private pauseInput(message: string): void {
    this.inputPaused = true;
    this.inputAtCapacityMessageShown = true;
    this.terminal.options.disableStdin = true;
    this.setStatus(message);
  }

  private scheduleFit(): void {
    if (this.fitQueued || this.closed) return;
    this.fitQueued = true;
    requestAnimationFrame(() => {
      this.fitQueued = false;
      const style = getComputedStyle(this.config.host);
      const width = this.config.host.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
      const height = this.config.host.clientHeight - parseFloat(style.paddingTop) - parseFloat(style.paddingBottom);
      const metrics = this.cellMetrics();
      const cols = clamp(Math.floor(width / metrics.width), 20, 0xffff);
      const rows = clamp(Math.floor(height / metrics.height), 6, 0xffff);
      if (this.terminal.cols !== cols || this.terminal.rows !== rows) this.terminal.resize(cols, rows);
    });
  }

  private cellMetrics(): { width: number; height: number } {
    const renderer = (this.terminal as unknown as { renderer?: { metrics?: { width: number; height: number } } }).renderer?.metrics;
    if (renderer && renderer.width > 0 && renderer.height > 0) return renderer;
    const context = document.createElement("canvas").getContext("2d");
    if (!context) return { width: 8, height: 18 };
    context.font = `400 ${this.terminal.options.fontSize}px ${this.terminal.options.fontFamily}`;
    const measured = context.measureText("W");
    return {
      width: measured.width || 8,
      height: (measured.fontBoundingBoxAscent ?? this.terminal.options.fontSize) + (measured.fontBoundingBoxDescent ?? 3),
    };
  }

  private syncVisualViewport(): void {
    const viewport = window.visualViewport;
    if (!viewport) return;
    const keyboardOpen = viewport.height < window.innerHeight - 120;
    this.screen.style.height = keyboardOpen ? `${viewport.height}px` : "";
    this.screen.style.transform = keyboardOpen ? `translateY(${viewport.offsetTop}px)` : "";
    this.scheduleFit();
  }

  private scheduleReconnect(): void {
    if (this.closed || this.retryTimer !== 0) return;
    const delay = Math.min(1000, 50 * 2 ** Math.min(this.retryAttempt, 4));
    this.retryAttempt += 1;
    this.retryTimer = window.setTimeout(() => {
      this.retryTimer = 0;
      this.connect();
    }, delay);
  }

  private sendFrame(streamId: number, frame: WireFrame, traceStart?: bigint, traceLength = 0): void {
    const socket = this.socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) return;
    try {
      const length = encodeMuxedFrameInto(streamId, frame, this.sendScratch);
      const encodedAt = performance.now();
      if (traceStart !== undefined) this.traceRange(traceStart, traceLength, "encode", encodedAt);
      socket.send(this.sendScratch.subarray(0, length));
      if (traceStart !== undefined) this.traceRange(traceStart, traceLength, "wsSend", performance.now());
    } catch {
      this.protocolFailure("could not encode an infraternal wire frame");
    }
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
    this.setStatus(`Terminal protocol error: ${message}.`);
    this.socket?.close(1002, "invalid tracer frame");
  }

  private isSocketOpen(): boolean {
    return this.socket?.readyState === WebSocket.OPEN;
  }

  private setStatus(message: string): void {
    this.config.status.textContent = message;
    this.config.status.hidden = message.length === 0;
  }

  /** Samples RTT on attachment and typing; an idle terminal schedules no wakeups [81]. */
  private startPings(): void {
    this.stopPings();
    this.sampleRoundTrip();
  }

  private sampleRoundTrip(): void {
    const startedAt = performance.now();
    if (!this.attached || this.closed || startedAt - this.lastPingAt < 2000) return;
    this.lastPingAt = startedAt;
    this.nextPingNonce = this.nextPingNonce >= MAX_U64 ? 1n : this.nextPingNonce + 1n;
    const nonce = this.nextPingNonce;
    if (this.pendingPings.size >= 8) {
      const oldest = this.pendingPings.keys().next().value as bigint | undefined;
      if (oldest !== undefined) this.pendingPings.delete(oldest);
    }
    this.pendingPings.set(nonce, startedAt);
    this.sendFrame(CONTROL_STREAM, { type: "Ping", nonce, sentUs: BigInt(Math.round(startedAt * 1000)) });
  }

  private stopPings(): void {
    this.lastPingAt = -Infinity;
    this.pendingPings.clear();
    this.config.onRoundTrip?.(undefined);
  }

  private acceptPong(nonce: bigint): void {
    const startedAt = this.pendingPings.get(nonce);
    if (startedAt === undefined) return;
    this.pendingPings.delete(nonce);
    this.config.onRoundTrip?.(Math.max(1, performance.now() - startedAt));
  }
}

function toU16(value: number): number {
  return clamp(Math.round(value), 0, 0xffff);
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
