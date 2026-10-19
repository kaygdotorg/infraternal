/** Tracks DEC private mode 2026 across PTY fragments and bounds how long its paint hold can last. */
const ESCAPE = 0x1b;
const SYNCHRONIZED_OUTPUT_MODE = 2026;
const PAINT_HOLD_MS = 150;
const MAX_CSI_BYTES = 4096;

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
export class SynchronizedOutput {
  private state = SequenceState.Ground;
  private privateCsi = false;
  private firstCsiByte = false;
  private csiValid = false;
  private csiBytes = 0;
  private modeParameter = 0;
  private parameterHasDigits = false;
  private containsSynchronizedMode = false;
  private enabled = false;
  private paintHeld = false;
  private atomicPaintPending = false;
  private holdTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(private readonly onTimeout: () => void, private readonly timeoutMs = PAINT_HOLD_MS) {}

  get holdsPaint(): boolean {
    return this.paintHeld;
  }

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

  dispose(): void {
    if (this.holdTimer !== undefined) clearTimeout(this.holdTimer);
    this.holdTimer = undefined;
    this.enabled = false;
    this.paintHeld = false;
    this.atomicPaintPending = false;
    this.state = SequenceState.Ground;
  }

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

  private finishParameter(): void {
    if (this.parameterHasDigits && this.modeParameter === SYNCHRONIZED_OUTPUT_MODE) {
      this.containsSynchronizedMode = true;
    }
  }

  private indexOf(data: Uint8Array | string, byte: number, offset: number): number {
    return typeof data === "string"
      ? data.indexOf(String.fromCharCode(byte), offset)
      : data.indexOf(byte, offset);
  }

  private setEnabled(enabled: boolean): void {
    if (enabled === this.enabled) return;
    this.enabled = enabled;
    if (!enabled) {
      if (this.holdTimer !== undefined) clearTimeout(this.holdTimer);
      this.holdTimer = undefined;
      this.paintHeld = false;
      return;
    }

    this.atomicPaintPending = true;
    this.paintHeld = true;
    this.holdTimer = setTimeout(() => {
      this.holdTimer = undefined;
      if (!this.enabled || !this.paintHeld) return;
      this.paintHeld = false;
      this.onTimeout();
    }, this.timeoutMs);
  }
}
