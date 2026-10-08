/**
 * Keeps opt-in local keystroke predictions in a removable overlay above the terminal renderer.
 *
 * A prediction is an ordered queue of operations: a printable glyph, or an erase (the host's `\b \b` echo
 * of DEL). Invariants that keep the predicted cursor on the cell grid and on the host's cursor:
 *
 * - Every operation stores the integer cell (column, row) where it lands and where the cursor is afterwards,
 *   computed once when the key is typed from the previous operation (or, for the first one, from the host
 *   cursor). Nothing is counted relative to the live host cursor, so an echo that the renderer has already
 *   taken but that is not reconciled yet cannot be counted twice. The overlay turns a cell into pixels with
 *   `column * cellWidth` from the renderer's metrics only.
 * - Echoes are reconciled in order against the queue the moment their bytes are written to the renderer
 *   (`hostWritten`). Reconciled operations stay drawn until the renderer has painted them (`paintedOutput`),
 *   so no frame shows neither the prediction nor the host's glyph.
 * - Any disagreement, and any key that cannot be placed exactly, drops the whole queue. The overlay hides and
 *   the host cursor is the only cursor again.
 */
import {
  mountTerminalTextOverlay,
  type TerminalTextOverlayCell,
  type TerminalTextOverlayCursor,
  type TerminalTextOverlayGlyph,
  type TerminalTextOverlayPosition,
  type TerminalTextOverlay,
} from "../../../packages/ui/src/terminal-text-overlay";

const RTT_THRESHOLD_MS = 60;
const CONFIRMATION_FRAME_BUDGET_MS = 34;
// The high-latency browser profile varies burst RTT by ±30 ms from the ping sample.
const PROFILE_JITTER_GUARD_MS = 30;
const MAX_PENDING_OPS = 128;
const MAX_PREDICTED_INPUT_BYTES = 8;
const MAX_VISIBLE_ECHO_BYTES = 512;
const graphemeSegmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });
const encoder = new TextEncoder();
const WARM_TEXT = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";

/** One unconfirmed key: a glyph written to a cell, or an erase of the cell left of the cursor. */
interface PredictionOp {
  kind: "glyph" | "erase";
  /** The glyph text; empty for an erase. */
  text: string;
  /** The echo bytes expected from the host; empty for an erase, which is matched as `\b \b`. */
  bytes: Uint8Array;
  sequence: string;
  cells: number;
  /** The cell a glyph is drawn in, or the cell an erase clears. */
  x: number;
  y: number;
  cursorXAfter: number;
  cursorYAfter: number;
  wrapPendingAfter: boolean;
  enteredAt: number;
  reportedVisible: boolean;
}

type PredictionOpInput = Pick<PredictionOp, "kind" | "text" | "bytes" | "sequence" | "cells" | "enteredAt" | "reportedVisible">;

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
/** Visible echo bytes of one output chunk, and the offsets in `bytes` at which a complete `\b \b` erase occurred. */
type VisibleOutput = { bytes: Uint8Array; erases: number[] };

/** A single terminal session's bounded, client-only prediction state. */
export class PredictiveEcho {
  private readonly overlay: TerminalTextOverlay | undefined;
  private readonly measureCanvas: HTMLCanvasElement | undefined;
  private readonly measureContext: CanvasRenderingContext2D | null | undefined;
  /** Unconfirmed operations in typing order; the host has not echoed these yet. */
  private readonly pending: PredictionOp[] = [];
  /** Operations whose echo is written to the renderer but not painted yet; still drawn until the paint. */
  private awaitingPaint: PredictionOp[] = [];
  private matchedPrefixLength = 0;
  private roundTripMs: number | undefined;
  private muted = false;
  /** Echoes that would prove the host is echoing again: a timed-out run's late echo and the newest muted key. */
  private proofs: Uint8Array[] = [];
  private mispredictions = 0;
  private waitingForOutput = false;
  private backspaceEchoState: 0 | 1 | 2 = 0;
  private timeout = 0;
  private renderFrame = 0;
  private visibilityFrame = 0;
  private parserState: VtParserState = "text";
  private lastReason = "flag-off";
  private readonly fallbacks: Record<string, number> = {};
  private predictedLastInput = false;
  private readonly inputCosts: number[] = [];
  private warmHandle = 0;

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
      pendingText: this.awaitingPaint.concat(this.pending).map((op) => op.text).join(""),
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
    else {
      this.scheduleRender();
      this.scheduleWarm();
    }
  }

  /**
   * Runs the whole prediction path once at idle, so the first key after enabling or a resize does not pay
   * one-off costs on the keystroke: overlay canvas geometry and resize, font setup for measuring and drawing,
   * the host-cursor guard, and first-call compilation of the placement and drawing code.
   */
  private scheduleWarm(): void {
    if (!this.overlay || this.warmHandle) return;
    const idle = (window as { requestIdleCallback?: (callback: () => void, options?: { timeout: number }) => number }).requestIdleCallback;
    const run = (): void => {
      this.warmHandle = 0;
      this.warm();
    };
    this.warmHandle = idle ? idle.call(window, run, { timeout: 200 }) : window.setTimeout(run, 50);
  }

  /** A dry run of common glyphs and one erase through placement and drawing; nothing is sent or left on screen. */
  private warm(): void {
    // Intl.Segmenter and the Unicode property classes compile on first use; that is the largest one-off cost.
    printableGraphemes("a");
    encoder.encode("a").slice();
    if (!this.overlay || this.pending.length > 0 || this.awaitingPaint.length > 0 || !this.isEnabled()) return;
    const position = this.options.getPosition();
    if (!position || position.alternate || position.viewportY !== 0 || !position.visible) return;
    this.cellWidth("M", position);
    const enteredAt = performance.now();
    // Common ASCII glyphs, so the canvas rasterises them (and fills its glyph cache) now rather than on a key.
    const inputs: PredictionOpInput[] = Array.from(WARM_TEXT, (text) => ({
      kind: "glyph", text, bytes: encoder.encode(text), sequence: "0", cells: 1, enteredAt, reportedVisible: true,
    }));
    inputs.push({ kind: "erase", text: "", bytes: new Uint8Array(0), sequence: "0", cells: 1, enteredAt, reportedVisible: true });
    const placed = this.place(position, inputs);
    // The overlay is shown and hidden again inside this task, so no frame ever paints it.
    if (placed) {
      this.pending.push(...placed);
      this.render(enteredAt, false);
    }
    this.pending.length = 0;
    this.hideOverlay();
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
        || this.pending.length + 1 > MAX_PENDING_OPS) {
        this.clearPending("editing-key");
        this.waitingForOutput = true;
        this.proofs = [];
        return;
      }
      const erase = this.place(position, [{
        kind: "erase", text: "", bytes: new Uint8Array(0), sequence: sequence.toString(), cells: 1,
        enteredAt: performance.now(), reportedVisible: true,
      }]);
      if (!erase) {
        this.clearPending("editing-key");
        this.waitingForOutput = true;
        this.proofs = [];
        return;
      }
      this.pending.push(...erase);
      this.predictedLastInput = true;
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
    if (!position || predicted.some((glyph) => glyph.cells < 1) || this.pending.length + predicted.length > MAX_PENDING_OPS
      || (!this.pending.length && position.x === position.columns - 1)) {
      this.clearPending("line-boundary");
      this.waitingForOutput = true;
      return;
    }

    const enteredAt = performance.now();
    let byteOffset = 0;
    const additions: PredictionOpInput[] = predicted.map((glyph) => {
      const entry = {
        kind: "glyph" as const,
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
    const placed = this.place(position, additions);
    if (!placed) {
      this.clearPending("line-boundary");
      this.waitingForOutput = true;
      return;
    }
    this.pending.push(...placed);
    this.predictedLastInput = true;
    this.lastReason = "ready";
    this.armTimeout();
    // Commit the bounded local glyph before sending its bytes; otherwise a loaded
    // renderer can paint the host echo before this queued animation frame runs.
    this.renderNow(performance.now());
  }

  /**
   * Reconciles the small leading echo region the moment Ghostty has been handed host bytes.
   *
   * The renderer's cursor already includes these bytes (the terminal state is written synchronously; only the
   * paint is a frame later), so the queue must drop what they confirm now. Otherwise a key typed in that
   * frame would be placed from a cursor that includes echoes the queue still counts.
   */
  hostWritten(bytes: Uint8Array): void {
    if (!this.options.optedIn || bytes.byteLength === 0) return;
    if (this.waitingForOutput) this.waitingForOutput = false;
    if (this.proofs.length === 0 && this.pending.length === 0) return;
    const visible = this.visibleBytes(bytes);
    if (visible.bytes.byteLength === 0 && visible.erases.length === 0) return;

    if (this.proofs.length > 0 && this.proofs.some((proof) => startsWith(visible.bytes, proof))) {
      // Unmatched proofs are not discarded here: other output (a prompt redraw) may precede the echo.
      // They expire with their timer instead.
      this.proofs = [];
      this.muted = false;
      this.mispredictions = 0;
      this.lastReason = "ready";
    }

    const matched = this.reconcile(visible);
    if (matched || this.pending.length === 0) this.armTimeout();
    // Nothing is hidden here. Reconciled operations stay drawn until `paintedOutput`; only a misprediction,
    // which has already cleared the queue, removes them at once.
    if (this.pending.length > 0) this.renderNow(performance.now());
  }

  /** Matches echoed text and erases against the queue, in order. Returns whether anything was confirmed. */
  private reconcile(visible: VisibleOutput): boolean {
    let offset = 0;
    let matched = false;
    let erase = 0;
    const text = visible.bytes;
    const confirm = (): void => {
      const op = this.pending.shift();
      if (op) this.awaitingPaint.push(op);
      this.matchedPrefixLength = 0;
      matched = true;
      this.mispredictions = 0;
    };
    while (this.pending.length > 0) {
      // Text before the next erase belongs to glyphs; a glyph can be echoed across several chunks.
      const textEnd = erase < visible.erases.length ? visible.erases[erase]! : text.byteLength;
      while (offset < textEnd && this.pending.length > 0) {
        const first = this.pending[0]!;
        if (first.kind === "erase") {
          this.noteMisprediction();
          return matched;
        }
        const common = commonPrefixLength(text.subarray(offset, textEnd), first.bytes.subarray(this.matchedPrefixLength));
        if (common === 0) {
          this.noteMisprediction();
          return matched;
        }
        offset += common;
        this.matchedPrefixLength += common;
        if (this.matchedPrefixLength < first.bytes.byteLength) {
          if (offset < textEnd) this.noteMisprediction();
          return matched;
        }
        confirm();
      }
      offset = textEnd;
      if (erase >= visible.erases.length) break;
      erase += 1;
      const first = this.pending[0];
      if (!first) break;
      if (first.kind !== "erase" || this.matchedPrefixLength !== 0) {
        this.noteMisprediction();
        return matched;
      }
      confirm();
    }
    return matched;
  }

  /** The renderer has painted the bytes last given to `hostWritten`: drop the predictions they confirmed. */
  paintedOutput(): void {
    if (!this.options.optedIn || this.awaitingPaint.length === 0) return;
    this.awaitingPaint = [];
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
    if (this.isAboveThreshold()) this.scheduleWarm();
    if (this.pending.length > 0 || this.awaitingPaint.length > 0) {
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
    this.warmHandle = 0;
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

  /**
   * Places new operations on integer cells after the last queued one (or at the host cursor when the queue is
   * empty). The final-column cursor stays there, wrap pending, until the next glyph wraps. Returns undefined
   * when the exact cell cannot be known (row start for an erase, last row for a wrap).
   */
  private place(position: PredictionPosition, additions: readonly PredictionOpInput[]): PredictionOp[] | undefined {
    if (position.columns < 1 || position.rows < 1 || position.x < 0 || position.x >= position.columns
      || position.y < 0 || position.y >= position.rows) return undefined;

    let x = position.x;
    let y = position.y;
    let wrapPending = false;
    const last = this.pending[this.pending.length - 1];
    if (last) {
      x = last.cursorXAfter;
      y = last.cursorYAfter;
      wrapPending = last.wrapPendingAfter;
    }

    const placed: PredictionOp[] = [];
    for (const input of additions) {
      if (input.kind === "erase") {
        // The host erases the cell left of the cursor and ends on it. A row start would need the host's
        // wrap and margin rules, so it waits for the host instead of guessing.
        if (x === 0) return undefined;
        x -= 1;
        wrapPending = false;
        placed.push({ ...input, x, y, cursorXAfter: x, cursorYAfter: y, wrapPendingAfter: false });
        continue;
      }
      if (wrapPending || x + input.cells > position.columns) {
        if (y + 1 >= position.rows) return undefined;
        x = 0;
        y += 1;
        wrapPending = false;
      }
      if (input.cells < 1 || x + input.cells > position.columns) return undefined;
      const cursorXAfter = x + input.cells === position.columns ? position.columns - 1 : x + input.cells;
      const wrapPendingAfter = x + input.cells === position.columns;
      // Each operation keeps its own cell geometry so a partial echo at the right margin does not lose
      // Ghostty's wrap-pending state.
      placed.push({ ...input, x, y, cursorXAfter, cursorYAfter: y, wrapPendingAfter });
      x = cursorXAfter;
      wrapPending = wrapPendingAfter;
    }
    return placed;
  }

  /**
   * What the overlay draws for the queue: predicted glyphs that no later erase removed, and the cells a
   * pending erase clears out of text the host already confirmed (those need their old glyph covered).
   */
  private compose(): { glyphs: TerminalTextOverlayGlyph[]; erased: TerminalTextOverlayCell[] } {
    const glyphs: TerminalTextOverlayGlyph[] = [];
    const erased: TerminalTextOverlayCell[] = [];
    const apply = (op: PredictionOp): void => {
      if (op.kind === "glyph") {
        glyphs.push({ text: op.text, x: op.x, y: op.y, cells: op.cells });
        return;
      }
      for (let index = glyphs.length - 1; index >= 0; index -= 1) {
        const glyph = glyphs[index]!;
        if (glyph.y === op.y && op.x >= glyph.x && op.x < glyph.x + glyph.cells) {
          glyphs.splice(index, 1);
          return;
        }
      }
      erased.push({ x: op.x, y: op.y });
    };
    for (const op of this.awaitingPaint) apply(op);
    for (const op of this.pending) apply(op);
    return { glyphs, erased };
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
    const enteredAt = this.pending[0]?.enteredAt ?? 0;
    if (!enteredAt || this.roundTripMs === undefined) return;
    // A host that is not echoing (a password prompt) never answers; a loaded network answers late. Allow a
    // whole extra round trip before muting, so ordinary jitter on a 300 ms link never mutes prediction.
    const deadline = enteredAt + 2 * this.roundTripMs + CONFIRMATION_FRAME_BUDGET_MS + PROFILE_JITTER_GUARD_MS;
    this.timeout = window.setTimeout(() => {
      this.timeout = 0;
      if (this.pending.length === 0) return;
      // If the echo was merely late, its own bytes prove the host is echoing again, so the next key
      // is predicted instead of falling back once to fetch a fresh proof.
      const late = concatBytes(this.pending.map((op) => op.bytes));
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
    this.awaitingPaint = [];
    this.matchedPrefixLength = 0;
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
      || (this.pending.length === 0 && this.awaitingPaint.length === 0) || !this.isEnabled()) {
      this.hideOverlay();
      return;
    }

    // With nothing left to confirm the host's cursor is final; otherwise the last queued operation owns it.
    const last = this.pending[this.pending.length - 1];
    const cursor: TerminalTextOverlayCursor = last
      ? { x: last.cursorXAfter, y: last.cursorYAfter }
      : { x: position.x, y: position.y };
    const { glyphs, erased } = this.compose();
    if (!overlay.show(glyphs, cursor, position, erased)) {
      this.cancelVisibilityFrame();
      return;
    }
    this.options.setHostCursorHidden?.(true);
    if (!reportAtFrame) {
      this.scheduleVisibilityReport();
      return;
    }
    this.cancelVisibilityFrame();
    for (const op of this.pending) {
      if (op.reportedVisible) continue;
      op.reportedVisible = true;
      this.options.onVisible(op.sequence, at);
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
    const erases: number[] = [];
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
          erases.push(length);
        } else {
          this.backspaceEchoState = 0;
          emit(0x20);
          emit(byte);
        }
      } else {
        emit(byte);
      }
    }
    return { bytes: visible.subarray(0, length), erases };
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
