/** Keeps opt-in local keystroke predictions in a removable overlay above the terminal renderer. */
import {
  mountTerminalTextOverlay,
  type TerminalTextOverlayCursor,
  type TerminalTextOverlayGlyph,
  type TerminalTextOverlayPosition,
  type TerminalTextOverlay,
} from "../../../packages/ui/src/terminal-text-overlay";

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
  x: number;
  y: number;
  cursorXAfter: number;
  cursorYAfter: number;
  wrapPendingAfter: boolean;
  enteredAt: number;
  reportedVisible: boolean;
}

interface PredictionGlyphInput {
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
  /** Printable inputs that were sent without a prediction, by reason (probe evidence for fallbacks). */
  fallbacks: Record<string, number>;
  /** Main-thread cost of prediction per printable key, most recent last (ms; bounded). */
  inputCostMs: number[];
  /** What the overlay currently draws, relative to the renderer canvas. */
  overlay: import("../../../packages/ui/src/terminal-text-overlay").TerminalTextOverlaySnapshot | undefined;
}

export interface PredictiveEchoOptions {
  host: HTMLElement;
  optedIn: boolean;
  getPosition: () => PredictionPosition | undefined;
  onVisible: (sequence: string, at: number) => void;
  setHostCursorHidden?: (hidden: boolean) => void;
  onRendererPainted?: () => void;
}

type VtParserState = "text" | "escape" | "csi" | "string" | "string-escape";
type VisibleOutput = { bytes: Uint8Array; backspaces: number };

/** A single terminal session's bounded, client-only prediction state. */
export class PredictiveEcho {
  private readonly overlay: TerminalTextOverlay | undefined;
  private readonly measureCanvas: HTMLCanvasElement | undefined;
  private readonly measureContext: CanvasRenderingContext2D | null | undefined;
  private readonly pending: PredictionGlyph[] = [];
  private matchedPrefixLength = 0;
  private roundTripMs: number | undefined;
  private muted = false;
  /** Echoes that would prove the host is echoing again: a timed-out run's late echo and the newest muted key. */
  private proofs: Uint8Array[] = [];
  private mispredictions = 0;
  private waitingForOutput = false;
  private pendingBackspaces = 0;
  private backspaceEnteredAt = 0;
  private backspaceEchoState: 0 | 1 | 2 = 0;
  private timeout = 0;
  private renderFrame = 0;
  private visibilityFrame = 0;
  private parserState: VtParserState = "text";
  private lastReason = "flag-off";
  private readonly fallbacks: Record<string, number> = {};
  private predictedLastInput = false;
  private readonly inputCosts: number[] = [];

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
      fallbacks: { ...this.fallbacks },
      inputCostMs: [...this.inputCosts],
      overlay: this.overlay?.snapshot(),
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

  /** Predicts bounded printable input and safe backspaces; paste and cursor moves await host output. */
  input(data: string, sequence: bigint, bytes: Uint8Array, terminalSafe: boolean): void {
    if (!this.options.optedIn) return;
    const startedAt = performance.now();
    this.predictedLastInput = false;
    this.predictInput(data, sequence, bytes, terminalSafe);
    this.inputCosts.push(performance.now() - startedAt);
    if (this.inputCosts.length > 256) this.inputCosts.shift();
    if (!this.predictedLastInput && printableGraphemes(data) && bytes.byteLength <= MAX_PREDICTED_INPUT_BYTES) {
      this.fallbacks[this.lastReason] = (this.fallbacks[this.lastReason] ?? 0) + 1;
    }
  }

  private predictInput(data: string, sequence: bigint, bytes: Uint8Array, terminalSafe: boolean): void {
    if (!terminalSafe) {
      this.clearPending("unsafe-screen");
      this.waitingForOutput = true;
      return;
    }

    if (data === "\u007f" || data === "\b") {
      const position = this.options.getPosition();
      if (!this.isAboveThreshold() || this.waitingForOutput || this.muted || this.mispredictions >= 3
        || !position || (!this.pending.length && position.x === position.columns - 1)
        || !this.layout(position, this.pending, [], this.pendingBackspaces + 1)) {
        this.clearPending("editing-key");
        this.waitingForOutput = true;
        this.proofs = [];
        return;
      }
      this.pendingBackspaces += 1;
      this.backspaceEnteredAt ||= performance.now();
      this.lastReason = "ready";
      this.armTimeout();
      this.renderNow(performance.now());
      return;
    }

    const graphemes = printableGraphemes(data);
    if (!graphemes || bytes.byteLength > MAX_PREDICTED_INPUT_BYTES) {
      this.clearPending(graphemes ? "large-input" : "editing-key");
      this.waitingForOutput = true;
      this.proofs = [];
      return;
    }
    if (this.waitingForOutput) {
      this.lastReason = "awaiting-output";
      return;
    }
    if (this.pendingBackspaces > 0) {
      this.lastReason = "awaiting-backspace-echo";
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
    if (!position || predicted.some((glyph) => glyph.cells < 1) || this.pending.length + predicted.length > MAX_PENDING_GLYPHS
      || (!this.pending.length && position.x === position.columns - 1)) {
      this.clearPending("line-boundary");
      this.waitingForOutput = true;
      return;
    }

    const enteredAt = performance.now();
    let byteOffset = 0;
    const additions: PredictionGlyphInput[] = predicted.map((glyph) => {
      const entry = {
        text: glyph.text,
        bytes: bytes.slice(byteOffset, byteOffset + glyph.bytes.byteLength),
        sequence: (sequence + BigInt(byteOffset)).toString(),
        cells: glyph.cells,
        enteredAt,
        reportedVisible: false,
      };
      byteOffset += glyph.bytes.byteLength;
      return entry;
    });
    const layout = this.layout(position, this.pending, additions, 0);
    if (!layout) {
      this.clearPending("line-boundary");
      this.waitingForOutput = true;
      return;
    }
    const newGlyphs = layout.pendingGlyphs.slice(this.pending.length);
    this.pending.push(...newGlyphs);
    this.predictedLastInput = true;
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
    if (this.proofs.length === 0 && this.pending.length === 0 && this.pendingBackspaces === 0) return;
    const visible = this.visibleBytes(bytes);
    if (visible.bytes.byteLength === 0 && visible.backspaces === 0) return;

    if (this.proofs.length > 0 && this.proofs.some((proof) => startsWith(visible.bytes, proof))) {
      // Unmatched proofs are not discarded here: other output (a prompt redraw) may precede the echo.
      // They expire with their timer instead.
      this.proofs = [];
      this.muted = false;
      this.mispredictions = 0;
      this.lastReason = "ready";
    }

    let offset = 0;
    let matched = false;
    while (offset < visible.bytes.byteLength && this.pending.length > 0) {
      const first = this.pending[0];
      if (!first) break;
      const expected = first.bytes.subarray(this.matchedPrefixLength);
      const available = visible.bytes.subarray(offset);
      const common = commonPrefixLength(available, expected);
      if (common === 0) {
        this.noteMisprediction();
        break;
      }
      offset += common;
      this.matchedPrefixLength += common;
      if (this.matchedPrefixLength < first.bytes.byteLength) {
        if (offset < visible.bytes.byteLength) this.noteMisprediction();
        break;
      }
      this.pending.shift();
      this.matchedPrefixLength = 0;
      matched = true;
      this.mispredictions = 0;
    }

    if (visible.backspaces > 0 && this.pendingBackspaces > 0) {
      this.pendingBackspaces = Math.max(0, this.pendingBackspaces - visible.backspaces);
      if (this.pendingBackspaces === 0) this.backspaceEnteredAt = 0;
    }

    if (matched || this.pending.length === 0 || visible.backspaces > 0) this.armTimeout();
    this.renderNow(performance.now());
  }

  /** Clears speculative text before a snapshot replaces the renderer state. */
  resetForSnapshot(): void {
    this.parserState = "text";
    this.proofs = [];
    this.waitingForOutput = false;
    this.clearPending("snapshot");
  }

  unsafeScreen(): void {
    this.proofs = [];
    this.waitingForOutput = true;
    this.clearPending("unsafe-screen");
  }

  /** Drops stale overlay geometry while retaining waits caused by unconfirmed input. */
  layoutChanged(): void {
    this.overlay?.invalidate();
    if (this.pending.length > 0 || this.pendingBackspaces > 0) {
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

  /** Marks the canvas cursor fresh after Ghostty paints an output frame. */
  rendererPainted(): void {
    this.options.onRendererPainted?.();
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

  /** Builds cell positions from Ghostty metrics; the final-column cursor remains there until the next glyph wraps. */
  private layout(
    position: PredictionPosition,
    existing: readonly PredictionGlyph[],
    additions: readonly PredictionGlyphInput[],
    backspaces: number,
  ): { glyphs: TerminalTextOverlayGlyph[]; pendingGlyphs: PredictionGlyph[]; cursor: TerminalTextOverlayCursor } | undefined {
    if (position.columns < 1 || position.rows < 1 || position.x < 0 || position.x >= position.columns
      || position.y < 0 || position.y >= position.rows) return undefined;

    let x = position.x;
    let y = position.y;
    let wrapPending = false;
    const glyphs: TerminalTextOverlayGlyph[] = [];
    const pendingGlyphs = [...existing];
    for (const glyph of existing) {
      glyphs.push({ text: glyph.text, x: glyph.x, y: glyph.y, cells: glyph.cells });
    }
    const last = existing[existing.length - 1];
    if (last) {
      x = last.cursorXAfter;
      y = last.cursorYAfter;
      wrapPending = last.wrapPendingAfter;
    }

    for (const glyph of additions) {
      if (wrapPending || x + glyph.cells > position.columns) {
        if (y + 1 >= position.rows) return undefined;
        x = 0;
        y += 1;
        wrapPending = false;
      }
      if (glyph.cells < 1 || x + glyph.cells > position.columns) return undefined;
      const cursorXAfter = x + glyph.cells === position.columns ? position.columns - 1 : x + glyph.cells;
      const wrapPendingAfter = x + glyph.cells === position.columns;
      glyphs.push({ text: glyph.text, x, y, cells: glyph.cells });
      const placed: PredictionGlyph = {
        ...glyph,
        x,
        y,
        cursorXAfter,
        cursorYAfter: y,
        wrapPendingAfter,
      };
      // Keep the chosen cell geometry on each pending glyph so a partial echo
      // at the right margin does not lose Ghostty's wrap-pending state.
      pendingGlyphs.push(placed);
      x = cursorXAfter;
      wrapPending = wrapPendingAfter;
    }

    for (let index = 0; index < backspaces; index += 1) {
      if (wrapPending) wrapPending = false;
      if (x === 0) return undefined;
      x -= 1;
    }
    return { glyphs, pendingGlyphs, cursor: { x, y } };
  }

  private offerEchoProof(bytes: Uint8Array): void {
    // The newest key while muted is the most direct proof; keep at most a few candidates.
    this.proofs.push(bytes.slice());
    if (this.proofs.length > 4) this.proofs.shift();
    this.armProofTimeout();
  }

  private armTimeout(): void {
    window.clearTimeout(this.timeout);
    this.timeout = 0;
    const first = this.pending[0];
    const enteredAt = first?.enteredAt ?? (this.pendingBackspaces > 0 ? this.backspaceEnteredAt : 0);
    if (!enteredAt || this.roundTripMs === undefined) return;
    // A host that is not echoing (a password prompt) never answers; a loaded network answers late. Allow a
    // whole extra round trip before muting, so ordinary jitter on a 300 ms link never mutes prediction.
    const deadline = enteredAt + 2 * this.roundTripMs + CONFIRMATION_FRAME_BUDGET_MS + PROFILE_JITTER_GUARD_MS;
    this.timeout = window.setTimeout(() => {
      this.timeout = 0;
      if (this.pending.length === 0 && this.pendingBackspaces === 0) return;
      // If the echo was merely late, its own bytes prove the host is echoing again, so the next key
      // is predicted instead of falling back once to fetch a fresh proof.
      const late = concatBytes(this.pending.map((glyph) => glyph.bytes));
      this.muted = true;
      this.lastReason = "echo-timeout";
      this.clearPending("echo-timeout");
      if (late.byteLength > 0) {
        this.proofs.push(late);
        this.armProofTimeout();
      }
    }, Math.max(0, deadline - performance.now()));
  }

  private armProofTimeout(): void {
    window.clearTimeout(this.timeout);
    const expectedDelay = 2 * (this.roundTripMs ?? CONFIRMATION_FRAME_BUDGET_MS) + CONFIRMATION_FRAME_BUDGET_MS + PROFILE_JITTER_GUARD_MS;
    this.timeout = window.setTimeout(() => {
      this.timeout = 0;
      this.proofs = [];
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
    this.pendingBackspaces = 0;
    this.backspaceEnteredAt = 0;
    this.backspaceEchoState = 0;
    this.lastReason = reason;
    this.hideOverlay();
  }

  private hideOverlay(): void {
    if (this.renderFrame) cancelAnimationFrame(this.renderFrame);
    this.renderFrame = 0;
    this.cancelVisibilityFrame();
    this.overlay?.hide();
    this.options.setHostCursorHidden?.(false);
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
    if (!position || position.alternate || position.viewportY !== 0 || !position.visible
      || (this.pending.length === 0 && this.pendingBackspaces === 0) || !this.isEnabled()) {
      this.hideOverlay();
      return;
    }

    const layout = this.layout(position, this.pending, [], this.pendingBackspaces);
    if (!layout) {
      this.clearPending("line-boundary");
      return;
    }

    if (!overlay.show(layout.glyphs, layout.cursor, position)) {
      this.cancelVisibilityFrame();
      return;
    }
    this.options.setHostCursorHidden?.(true);
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

  private visibleBytes(bytes: Uint8Array): VisibleOutput {
    const visible = new Uint8Array(Math.min(bytes.byteLength, MAX_VISIBLE_ECHO_BYTES));
    let length = 0;
    let scanned = 0;
    let backspaces = 0;
    const emit = (byte: number): void => {
      if (byte < 0x20 || byte === 0x7f || length === visible.byteLength) return;
      visible[length] = byte;
      length += 1;
    };
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
      } else if (this.backspaceEchoState === 0 && byte === 0x08) {
        this.backspaceEchoState = 1;
      } else if (this.backspaceEchoState === 1) {
        if (byte === 0x20) this.backspaceEchoState = 2;
        else {
          this.backspaceEchoState = 0;
          emit(byte);
        }
      } else if (this.backspaceEchoState === 2) {
        if (byte === 0x08) {
          this.backspaceEchoState = 0;
          backspaces += 1;
        } else {
          this.backspaceEchoState = 0;
          emit(0x20);
          emit(byte);
        }
      } else {
        emit(byte);
      }
    }
    return { bytes: visible.subarray(0, length), backspaces };
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

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.byteLength;
  const joined = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.byteLength;
  }
  return joined;
}
