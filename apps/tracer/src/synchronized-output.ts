/** Tracks DEC private mode 2026 across PTY fragments and bounds how long its paint hold can last. */
/** The ESC byte that starts every control sequence. */
const ESCAPE = 0x1b;
/** The DEC private mode number (`CSI ? 2026 h` to begin, `l` to end) with which a program asks for its output to be painted in one piece. */
const SYNCHRONIZED_OUTPUT_MODE = 2026;
/** The longest the paint may be held, in milliseconds, if the program never ends the mode. */
const PAINT_HOLD_MS = 150;
/** A control sequence longer than this is dropped, so a broken stream cannot keep the scanner busy or hold painting. */
const MAX_CSI_BYTES = 4096;

/** Clock and frame hooks keep release scheduling deterministic in tests. */
export interface SynchronizedOutputScheduler {
  /** Runs `callback` after `delayMs`; returns a handle for `clearTimeout`. */
  setTimeout(callback: () => void, delayMs: number): unknown;
  /** Cancels a timer from `setTimeout`. */
  clearTimeout(timer: unknown): void;
  /** Runs `callback` before the next paint; returns a handle for `cancelAnimationFrame`. */
  requestAnimationFrame(callback: () => void): number;
  /** Cancels a frame from `requestAnimationFrame`. */
  cancelAnimationFrame(frame: number): void;
}

/** The real timers, used unless a test passes its own. */
const browserScheduler: SynchronizedOutputScheduler = {
  setTimeout: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
  clearTimeout: (timer) => globalThis.clearTimeout(timer as ReturnType<typeof setTimeout>),
  requestAnimationFrame: (callback) => globalThis.requestAnimationFrame(callback),
  cancelAnimationFrame: (frame) => globalThis.cancelAnimationFrame(frame),
};

/** Where the scanner is inside a control sequence: plain text, after ESC, inside CSI, OSC, or another string (and the ESC that may end one). */
const enum SequenceState {
  Ground,
  Escape,
  Csi,
  Osc,
  OscEscape,
  ControlString,
  ControlStringEscape,
}

/** The byte scanner skips ordinary text in native `indexOf` and examines only VT control sequences. */
/**
 * Watches terminal output for the synchronized-output mode so the caller can hold painting while a program draws.
 * Feed every chunk to `feed` before it reaches the terminal parser.
 *
 * - While the mode is on, `holdsPaint` is true and the caller should write output but not paint.
 * - When the mode ends, or the hold has lasted `timeoutMs` (the program may have died mid-draw), the hold ends: the
 *   next animation frame calls `onReleaseFrame`, and a timeout also calls `onTimeout` first.
 * - `requiresAtomicPaint` stays true from the start of a hold until the caller calls `finishAtomicPaint`, so the
 *   output queued during the hold is painted together.
 * - A full reset (`ESC c`) turns the mode off.
 * `dispose()` cancels the timers.
 */
export class SynchronizedOutput {
  private state = SequenceState.Ground;
  /** The CSI began with `?`, so its parameters are private modes. */
  private privateCsi = false;
  /** The next byte is the first one after `CSI`, the only place a `?` counts. */
  private firstCsiByte = false;
  /** Cleared by any byte that makes the sequence something other than plain `CSI ? n;n h/l`. */
  private csiValid = false;
  /** Bytes of the current CSI seen so far, checked against {@link MAX_CSI_BYTES}. */
  private csiBytes = 0;
  /** The parameter being read; capped just above 2026 so a long number cannot overflow. */
  private modeParameter = 0;
  /** Whether the parameter being read has any digit. */
  private parameterHasDigits = false;
  /** Whether any parameter of this CSI was 2026. */
  private containsSynchronizedMode = false;
  /** Whether the program has the mode on. */
  private enabled = false;
  /** Whether painting is held right now: the mode is on and the timeout has not run out. */
  private paintHeld = false;
  /** Set when a hold starts; cleared by `finishAtomicPaint` or `reset`. */
  private atomicPaintPending = false;
  /** The pending hold timeout. */
  private holdTimer: unknown;
  /** The pending animation frame that calls `onReleaseFrame`. */
  private releaseFrame: number | undefined;

  /**
   * @param onTimeout called when the hold ran out before the program ended the mode
   * @param onReleaseFrame called on the animation frame after a hold ended, when painting may resume
   * @param timeoutMs the longest hold; defaults to 150 ms
   * @param scheduler timers and frames; tests pass a fake
   */
  constructor(
    private readonly onTimeout: () => void,
    private readonly onReleaseFrame: () => void,
    private readonly timeoutMs = PAINT_HOLD_MS,
    private readonly scheduler: SynchronizedOutputScheduler = browserScheduler,
  ) {}

  /** True while painting should wait. */
  get holdsPaint(): boolean {
    return this.paintHeld;
  }

  /** True from the start of a hold until `finishAtomicPaint` is called. */
  get requiresAtomicPaint(): boolean {
    return this.atomicPaintPending;
  }

  /** The caller has accumulated queued bytes through reset or timeout and will paint them together. */
  finishAtomicPaint(): void {
    this.atomicPaintPending = false;
  }

  /** Feed PTY bytes in delivery order before they enter the terminal parser. */
  feed(data: Uint8Array | string): void {
    let offset = 0;
    while (offset < data.length) {
      if (this.state === SequenceState.Ground) {
        const nextEscape = this.indexOf(data, ESCAPE, offset);
        if (nextEscape < 0) return;
        offset = nextEscape + 1;
        this.state = SequenceState.Escape;
        continue;
      }
      if (this.state === SequenceState.Osc) {
        const escape = this.indexOf(data, ESCAPE, offset);
        const bell = this.indexOf(data, 0x07, offset);
        if (escape < 0 && bell < 0) return;
        const terminator = escape < 0 ? bell : bell < 0 ? escape : Math.min(escape, bell);
        const byte = typeof data === "string" ? data.charCodeAt(terminator) : data[terminator]!;
        offset = terminator + 1;
        this.state = byte === ESCAPE ? SequenceState.OscEscape : SequenceState.Ground;
        continue;
      }
      if (this.state === SequenceState.ControlString) {
        const escape = this.indexOf(data, ESCAPE, offset);
        if (escape < 0) return;
        offset = escape + 1;
        this.state = SequenceState.ControlStringEscape;
        continue;
      }

      const byte = typeof data === "string" ? data.charCodeAt(offset) : data[offset]!;
      offset += 1;
      switch (this.state) {
        case SequenceState.Escape:
          if (byte === 0x5b) this.startCsi();
          else if (byte === 0x5d) this.state = SequenceState.Osc;
          else if (byte === 0x50 || byte === 0x58 || byte === 0x5e || byte === 0x5f) {
            this.state = SequenceState.ControlString;
          } else if (byte === 0x63) {
            this.state = SequenceState.Ground;
            this.setEnabled(false);
          } else if (byte !== ESCAPE) this.state = SequenceState.Ground;
          break;
        case SequenceState.Csi:
          this.consumeCsiByte(byte);
          break;
        case SequenceState.OscEscape:
          if (byte === 0x5c || byte === 0x07) this.state = SequenceState.Ground;
          else if (byte !== ESCAPE) this.state = SequenceState.Osc;
          break;
        case SequenceState.ControlStringEscape:
          if (byte === 0x5c) this.state = SequenceState.Ground;
          else if (byte !== ESCAPE) this.state = SequenceState.ControlString;
          break;
      }
    }
  }

  /** A replacement session starts with independent VT state and no outstanding timeout. */
  reset(): void {
    this.state = SequenceState.Ground;
    this.privateCsi = false;
    this.firstCsiByte = false;
    this.csiValid = false;
    this.csiBytes = 0;
    this.modeParameter = 0;
    this.parameterHasDigits = false;
    this.containsSynchronizedMode = false;
    this.atomicPaintPending = false;
    this.setEnabled(false);
  }

  /** Cancels the timer and the pending frame and returns to the idle state. */
  dispose(): void {
    if (this.holdTimer !== undefined) this.scheduler.clearTimeout(this.holdTimer);
    this.holdTimer = undefined;
    if (this.releaseFrame !== undefined) this.scheduler.cancelAnimationFrame(this.releaseFrame);
    this.releaseFrame = undefined;
    this.enabled = false;
    this.paintHeld = false;
    this.atomicPaintPending = false;
    this.state = SequenceState.Ground;
  }

  /** Begins reading a CSI sequence. */
  private startCsi(): void {
    this.state = SequenceState.Csi;
    this.privateCsi = false;
    this.firstCsiByte = true;
    this.csiValid = true;
    this.csiBytes = 0;
    this.modeParameter = 0;
    this.parameterHasDigits = false;
    this.containsSynchronizedMode = false;
  }

  /** Advances through one byte of a CSI. A final byte `h` or `l` of a private sequence that named 2026 turns the mode on or off. */
  private consumeCsiByte(byte: number): void {
    this.csiBytes += 1;
    if (this.csiBytes > MAX_CSI_BYTES) {
      // Oversized, unfinished control sequences cannot hold the paint loop or scanner work open.
      this.state = SequenceState.Ground;
      return;
    }
    if (byte === ESCAPE) {
      this.state = SequenceState.Escape;
      return;
    }
    if (byte === 0x18 || byte === 0x1a) {
      this.state = SequenceState.Ground;
      return;
    }
    if (byte >= 0x40 && byte <= 0x7e) {
      if (this.privateCsi && this.csiValid && (byte === 0x68 || byte === 0x6c)) {
        this.finishParameter();
        if (this.containsSynchronizedMode) this.setEnabled(byte === 0x68);
      }
      this.state = SequenceState.Ground;
      return;
    }
    if (byte === 0x3f && this.firstCsiByte) {
      this.privateCsi = true;
      this.firstCsiByte = false;
      return;
    }
    this.firstCsiByte = false;
    if (byte >= 0x30 && byte <= 0x39) {
      const digit = byte - 0x30;
      this.parameterHasDigits = true;
      this.modeParameter = this.modeParameter > SYNCHRONIZED_OUTPUT_MODE
        ? SYNCHRONIZED_OUTPUT_MODE + 1
        : Math.min(SYNCHRONIZED_OUTPUT_MODE + 1, this.modeParameter * 10 + digit);
    } else if (byte === 0x3b) {
      this.finishParameter();
      this.modeParameter = 0;
      this.parameterHasDigits = false;
    } else if (byte === 0x3a || (byte >= 0x20 && byte <= 0x2f)) {
      this.csiValid = false;
    } else {
      this.csiValid = false;
    }
  }

  /** Called at the end of a parameter; remembers whether it was 2026. */
  private finishParameter(): void {
    if (this.parameterHasDigits && this.modeParameter === SYNCHRONIZED_OUTPUT_MODE) {
      this.containsSynchronizedMode = true;
    }
  }

  /** Finds `byte` in a string or byte array from `offset`, or -1. */
  private indexOf(data: Uint8Array | string, byte: number, offset: number): number {
    return typeof data === "string"
      ? data.indexOf(String.fromCharCode(byte), offset)
      : data.indexOf(byte, offset);
  }

  /** Turns the mode on or off. Turning it on starts the hold and its timeout; turning it off releases a held paint through the release frame. */
  private setEnabled(enabled: boolean): void {
    if (enabled === this.enabled) return;
    this.enabled = enabled;
    if (!enabled) {
      if (this.holdTimer !== undefined) this.scheduler.clearTimeout(this.holdTimer);
      this.holdTimer = undefined;
      const released = this.paintHeld;
      this.paintHeld = false;
      if (released) this.scheduleReleaseFrame();
      return;
    }

    this.atomicPaintPending = true;
    this.paintHeld = true;
    this.holdTimer = this.scheduler.setTimeout(() => {
      this.holdTimer = undefined;
      if (!this.enabled || !this.paintHeld) return;
      this.paintHeld = false;
      this.scheduleReleaseFrame();
      this.onTimeout();
    }, this.timeoutMs);
  }

  /** Queue the paint after parser state is released, so the next frame sees the complete output. */
  private scheduleReleaseFrame(): void {
    if (this.releaseFrame !== undefined) return;
    this.releaseFrame = this.scheduler.requestAnimationFrame(() => {
      this.releaseFrame = undefined;
      if (!this.paintHeld) this.onReleaseFrame();
    });
  }
}
