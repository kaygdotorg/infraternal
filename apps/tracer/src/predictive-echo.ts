/** Keeps opt-in local keystroke predictions in a removable overlay above the terminal renderer. */
import { mountTerminalTextOverlay, type TerminalTextOverlayPosition, type TerminalTextOverlay } from "../../../packages/ui/src/terminal-text-overlay";

const RTT_THRESHOLD_MS = 60;
const CONFIRMATION_FRAME_BUDGET_MS = 34;
// The high-latency browser profile varies burst RTT by ±30 ms from the ping sample.
const PROFILE_JITTER_GUARD_MS = 30;
const MAX_PENDING_GLYPHS = 128;
const MAX_PREDICTED_INPUT_BYTES = 8;
const MAX_VISIBLE_ECHO_BYTES = 512;
const graphemeSegmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });
const encoder = new TextEncoder();

interface PredictionGlyph {
  text: string;
  bytes: Uint8Array;
  sequence: string;
  cells: number;
  enteredAt: number;
  reportedVisible: boolean;
}

export type PredictionPosition = TerminalTextOverlayPosition;

export interface PredictiveEchoState {
  optedIn: boolean;
  enabled: boolean;
  roundTripMs: number | undefined;
  pendingText: string;
  muted: boolean;
  mispredictions: number;
  reason: string;
}

export interface PredictiveEchoOptions {
  host: HTMLElement;
  optedIn: boolean;
  getPosition: () => PredictionPosition | undefined;
  onVisible: (sequence: string, at: number) => void;
}

type VtParserState = "text" | "escape" | "csi" | "string" | "string-escape";

/** A single terminal session's bounded, client-only prediction state. */
export class PredictiveEcho {
  private readonly overlay: TerminalTextOverlay | undefined;
  private readonly measureCanvas: HTMLCanvasElement | undefined;
  private readonly measureContext: CanvasRenderingContext2D | null | undefined;
  private readonly pending: PredictionGlyph[] = [];
  private matchedPrefixLength = 0;
  private roundTripMs: number | undefined;
  private muted = false;
  private proof: Uint8Array | undefined;
  private mispredictions = 0;
  private waitingForOutput = false;
  private timeout = 0;
  private renderFrame = 0;
  private visibilityFrame = 0;
  private parserState: VtParserState = "text";
  private lastReason = "flag-off";

  constructor(private readonly options: PredictiveEchoOptions) {
    if (!options.optedIn) return;
    this.overlay = mountTerminalTextOverlay(options.host);

    const measureCanvas = document.createElement("canvas");
    measureCanvas.width = 1;
    measureCanvas.height = 1;
    this.measureCanvas = measureCanvas;
    this.measureContext = measureCanvas.getContext("2d");
  }

  get state(): PredictiveEchoState {
    const enabled = this.isEnabled();
    return {
      optedIn: this.options.optedIn,
      enabled,
      roundTripMs: this.roundTripMs,
      pendingText: this.pending.map((glyph) => glyph.text).join(""),
      muted: this.muted,
      mispredictions: this.mispredictions,
      reason: !this.options.optedIn ? "flag-off" : enabled ? "ready" : this.lastReason,
    };
  }

  /** Test-double-only switch for measuring the same terminal session with the overlay off. */
  setOptedIn(enabled: boolean): void {
    this.options.optedIn = enabled;
    if (!enabled) this.clearPending("flag-off");
    else this.scheduleRender();
  }

  setRoundTrip(milliseconds: number | undefined): void {
    this.roundTripMs = milliseconds;
    if (!this.isAboveThreshold()) this.clearPending("rtt-low");
    else this.scheduleRender();
  }

  /** Predicts bounded printable input; longer paste and editing keys wait for host output. */
  input(data: string, sequence: bigint, bytes: Uint8Array, terminalSafe: boolean): void {
    if (!this.options.optedIn) return;
    if (!terminalSafe) {
      this.clearPending("unsafe-screen");
      this.waitingForOutput = true;
      return;
    }

    const graphemes = printableGraphemes(data);
    if (!graphemes || bytes.byteLength > MAX_PREDICTED_INPUT_BYTES) {
      this.clearPending(graphemes ? "large-input" : "editing-key");
      this.waitingForOutput = true;
      this.proof = undefined;
      return;
    }
    if (this.waitingForOutput) {
      this.lastReason = "awaiting-output";
      return;
    }
    if (!this.isAboveThreshold()) {
      this.lastReason = this.roundTripMs === undefined ? "rtt-unmeasured" : "rtt-low";
      return;
    }
    if (this.muted || this.mispredictions >= 3) {
      this.offerEchoProof(bytes);
      this.lastReason = "echo-unverified";
      return;
    }

    const position = this.options.getPosition();
    const predicted = graphemes.map((text) => ({
      text,
      bytes: encoder.encode(text),
      cells: position ? this.cellWidth(text, position) : 0,
    }));
    const cells = predicted.reduce((total, glyph) => total + glyph.cells, 0);
    const usedCells = this.pending.reduce((total, glyph) => total + glyph.cells, 0);
    if (!position || predicted.some((glyph) => glyph.cells < 1) || this.pending.length + predicted.length > MAX_PENDING_GLYPHS || position.x + usedCells + cells >= position.columns) {
      this.clearPending("line-boundary");
      this.waitingForOutput = true;
      return;
    }

    let byteOffset = 0;
    const enteredAt = performance.now();
    for (const glyph of predicted) {
      this.pending.push({
        text: glyph.text,
        bytes: bytes.slice(byteOffset, byteOffset + glyph.bytes.byteLength),
        sequence: (sequence + BigInt(byteOffset)).toString(),
        cells: glyph.cells,
        enteredAt,
        reportedVisible: false,
      });
      byteOffset += glyph.bytes.byteLength;
    }
    this.lastReason = "ready";
    this.armTimeout();
    // Commit the bounded local glyph before sending its bytes; otherwise a loaded
    // renderer can paint the host echo before this queued animation frame runs.
    this.renderNow(performance.now());
  }

  /** Reconciles only the small leading echo region after Ghostty has painted host bytes. */
  paintedOutput(bytes: Uint8Array): void {
    if (!this.options.optedIn || bytes.byteLength === 0) return;
    if (this.waitingForOutput) this.waitingForOutput = false;
    if (!this.proof && this.pending.length === 0) return;
    const visible = this.visibleBytes(bytes);
    if (visible.byteLength === 0) return;

    if (this.proof) {
      if (startsWith(visible, this.proof)) {
        this.proof = undefined;
        this.muted = false;
        this.mispredictions = 0;
        this.lastReason = "ready";
      } else {
        this.proof = undefined;
      }
    }

    let offset = 0;
    let matched = false;
    while (offset < visible.byteLength && this.pending.length > 0) {
      const first = this.pending[0];
      if (!first) break;
      const expected = first.bytes.subarray(this.matchedPrefixLength);
      const available = visible.subarray(offset);
      const common = commonPrefixLength(available, expected);
      if (common === 0) {
        this.noteMisprediction();
        break;
      }
      offset += common;
      this.matchedPrefixLength += common;
      if (this.matchedPrefixLength < first.bytes.byteLength) {
        if (offset < visible.byteLength) this.noteMisprediction();
        break;
      }
      this.pending.shift();
      this.matchedPrefixLength = 0;
      matched = true;
      this.mispredictions = 0;
    }

    if (matched || this.pending.length === 0) this.armTimeout();
    this.renderNow(performance.now());
  }

  /** Clears speculative text before a snapshot replaces the renderer state. */
  resetForSnapshot(): void {
    this.parserState = "text";
    this.proof = undefined;
    this.waitingForOutput = false;
    this.clearPending("snapshot");
  }

  unsafeScreen(): void {
    this.proof = undefined;
    this.waitingForOutput = true;
    this.clearPending("unsafe-screen");
  }

  /** Drops stale overlay geometry while retaining waits caused by unconfirmed input. */
  layoutChanged(): void {
    if (this.pending.length > 0) {
      this.waitingForOutput = true;
      this.lastReason = "layout-change";
      this.hideOverlay();
      return;
    }
    const keepWaiting = this.waitingForOutput && this.lastReason !== "unsafe-screen";
    this.clearPending("layout-change");
    this.waitingForOutput = keepWaiting;
    if (!keepWaiting) this.lastReason = this.isAboveThreshold() ? "ready" : "rtt-low";
  }

  /** Resumes after returning to the live viewport when no other safety wait remains. */
  returnToLiveViewport(): void {
    if (this.waitingForOutput && this.lastReason === "unsafe-screen") {
      this.waitingForOutput = false;
      this.lastReason = this.isAboveThreshold() ? "ready" : "rtt-low";
    }
    this.scheduleRender();
  }

  refresh(): void {
    this.scheduleRender();
  }

  dispose(): void {
    window.clearTimeout(this.timeout);
    if (this.renderFrame) cancelAnimationFrame(this.renderFrame);
    this.clearPending("disposed");
    this.overlay?.dispose();
  }

  private isAboveThreshold(): boolean {
    return this.roundTripMs !== undefined && this.roundTripMs > RTT_THRESHOLD_MS;
  }

  private isEnabled(): boolean {
    return this.options.optedIn && this.isAboveThreshold() && !this.muted && this.mispredictions < 3 && !this.waitingForOutput;
  }

  private cellWidth(text: string, position: PredictionPosition): number {
    const context = this.measureContext;
    if (!context) return 1;
    if (!Number.isFinite(position.cellWidth) || position.cellWidth <= 0) return 0;
    context.font = `400 ${position.fontSize}px ${position.fontFamily}`;
    const measured = context.measureText(text).width;
    if (!Number.isFinite(measured) || measured < position.cellWidth * 0.25) return 0;
    return Math.max(1, Math.min(2, Math.round(measured / position.cellWidth)));
  }

  private offerEchoProof(bytes: Uint8Array): void {
    if (this.proof) return;
    this.proof = bytes.slice();
    this.armProofTimeout();
  }

  private armTimeout(): void {
    window.clearTimeout(this.timeout);
    this.timeout = 0;
    const first = this.pending[0];
    if (!first || this.roundTripMs === undefined) return;
    const deadline = first.enteredAt + this.roundTripMs + CONFIRMATION_FRAME_BUDGET_MS + PROFILE_JITTER_GUARD_MS;
    this.timeout = window.setTimeout(() => {
      this.timeout = 0;
    if (this.pending.length === 0) return;
      this.muted = true;
      this.lastReason = "echo-timeout";
      this.clearPending("echo-timeout");
    }, Math.max(0, deadline - performance.now()));
  }

  private armProofTimeout(): void {
    window.clearTimeout(this.timeout);
    const expectedDelay = (this.roundTripMs ?? CONFIRMATION_FRAME_BUDGET_MS) + CONFIRMATION_FRAME_BUDGET_MS + PROFILE_JITTER_GUARD_MS;
    this.timeout = window.setTimeout(() => {
      this.timeout = 0;
      this.proof = undefined;
    }, expectedDelay);
  }

  private noteMisprediction(): void {
    this.mispredictions += 1;
    this.lastReason = this.mispredictions >= 3 ? "repeated-mispredictions" : "misprediction";
    if (this.mispredictions >= 3) this.muted = true;
    this.clearPending(this.lastReason);
  }

  private clearPending(reason: string): void {
    window.clearTimeout(this.timeout);
    this.timeout = 0;
    this.pending.length = 0;
    this.matchedPrefixLength = 0;
    this.lastReason = reason;
    this.hideOverlay();
  }

  private hideOverlay(): void {
    if (this.renderFrame) cancelAnimationFrame(this.renderFrame);
    this.renderFrame = 0;
    this.cancelVisibilityFrame();
    this.overlay?.hide();
  }

  private scheduleRender(): void {
    if (!this.overlay || this.renderFrame) return;
    this.renderFrame = requestAnimationFrame((at) => {
      this.renderFrame = 0;
      this.render(at, true);
    });
  }

  private render(at: number, reportAtFrame = false): void {
    const overlay = this.overlay;
    if (!overlay) return;
    const position = this.options.getPosition();
    if (!position || position.alternate || position.viewportY !== 0 || !position.visible || this.pending.length === 0 || !this.isEnabled()) {
      this.hideOverlay();
      return;
    }

    const cells = this.pending.reduce((total, glyph) => total + glyph.cells, 0);
    if (position.x + cells >= position.columns || position.y < 0 || position.y >= position.rows) {
      this.clearPending("line-boundary");
      return;
    }

    const content = this.pending.map((glyph) => glyph.text).join("");
    if (!overlay.show(content, position)) {
      this.cancelVisibilityFrame();
      return;
    }
    if (!reportAtFrame) {
      this.scheduleVisibilityReport();
      return;
    }
    this.cancelVisibilityFrame();
    for (const glyph of this.pending) {
      if (glyph.reportedVisible) continue;
      glyph.reportedVisible = true;
      this.options.onVisible(glyph.sequence, at);
    }
  }

  private scheduleVisibilityReport(): void {
    if (this.visibilityFrame) return;
    // DOM insertion precedes display; measure visibility only at the next frame boundary.
    this.visibilityFrame = requestAnimationFrame((at) => {
      this.visibilityFrame = 0;
      this.render(at, true);
    });
  }

  private cancelVisibilityFrame(): void {
    if (this.visibilityFrame) cancelAnimationFrame(this.visibilityFrame);
    this.visibilityFrame = 0;
  }

  private renderNow(at: number): void {
    if (this.renderFrame) cancelAnimationFrame(this.renderFrame);
    this.renderFrame = 0;
    this.render(at, false);
  }

  private visibleBytes(bytes: Uint8Array): Uint8Array {
    const visible = new Uint8Array(Math.min(bytes.byteLength, MAX_VISIBLE_ECHO_BYTES));
    let length = 0;
    let scanned = 0;
    for (const byte of bytes) {
      scanned += 1;
      if (scanned > MAX_VISIBLE_ECHO_BYTES) break;
      if (this.parserState === "escape") {
        if (byte === 0x5b) this.parserState = "csi";
        else if (byte === 0x5d || byte === 0x50 || byte === 0x5e || byte === 0x5f || byte === 0x58) this.parserState = "string";
        else this.parserState = "text";
      } else if (this.parserState === "csi") {
        if (byte >= 0x40 && byte <= 0x7e) this.parserState = "text";
      } else if (this.parserState === "string") {
        if (byte === 0x07) this.parserState = "text";
        else if (byte === 0x1b) this.parserState = "string-escape";
      } else if (this.parserState === "string-escape") {
        this.parserState = byte === 0x5c ? "text" : "string";
      } else if (byte === 0x1b) {
        this.parserState = "escape";
      } else if (byte >= 0x20 && byte !== 0x7f) {
        if (length === visible.byteLength) break;
        visible[length] = byte;
        length += 1;
      }
    }
    return visible.subarray(0, length);
  }
}

function printableGraphemes(data: string): string[] | undefined {
  if (data.length === 0) return undefined;
  for (const scalar of data) {
    if (/[\p{Cc}\p{Cs}\p{Zl}\p{Zp}]/u.test(scalar)) return undefined;
    if (scalar !== "\u200d" && /\p{Cf}/u.test(scalar)) return undefined;
  }
  return Array.from(graphemeSegmenter.segment(data), ({ segment }) => segment);
}

function startsWith(haystack: Uint8Array, needle: Uint8Array): boolean {
  return needle.byteLength <= haystack.byteLength && commonPrefixLength(haystack, needle) === needle.byteLength;
}

function commonPrefixLength(left: Uint8Array, right: Uint8Array): number {
  const limit = Math.min(left.byteLength, right.byteLength);
  let index = 0;
  while (index < limit && left[index] === right[index]) index += 1;
  return index;
}
