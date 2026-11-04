/**
 * The decode worker of one app window or screen window (D200, D204, D232, D254, D266).
 *
 * It owns the window's visible canvas (an `OffscreenCanvas` transferred from the page) and the WebCodecs decoder, so
 * decoding, drawing and the frame queue never touch the main thread. The page only forwards encoded access units.
 *
 * Bounded admission and frame ownership:
 * - a decoder holds at most two queued access units; up to eight continuous units, bounded together by one wire access-unit
 *   budget, can wait for dequeue. Transport bursts retain their required references without queueing decoded pictures;
 * - a gap in the sequence, a decoder error or a count/byte overflow asks the page for a repair keyframe, at most one request
 *   in flight;
 * - an IDR repairs the reference state inside the running decoder, which is only reconfigured when the profile or the
 *   level in its parameter sets changed; closing it on every IDR would cancel valid queued output;
 * - decoded pictures are drawn directly from the decoder output callback, without a second display-clock queue.
 *   If a newer unit is already accepted, its older decoded picture is closed without conversion. Only decoded pictures
 *   are skipped: the admitted coded units still establish codec references. Each picture is closed before the callback
 *   returns, so no presentation queue pins decoder memory or holds newer work behind obsolete conversion.
 *
 * Nothing is scheduled while no unit arrives and nothing is drawn without a new picture: a window whose machine shows
 * the same pixels costs no work at all (D254). The worker exists only while its window streams; the page ends it when
 * the window closes or has been off screen for long.
 */
import { traceClock, TRACE_LIMIT, type FrameTrace, type ReceiveTrace } from "./frame-trace";
import type { FromWorker, ToWorker, WorkerStats } from "./worker-protocol";
import { MAX_VIDEO_BYTES } from "../../../../../packages/protocol/src/desktop";

/** The few members of the worker's global scope used here (the project compiles against the page's types). */
interface WorkerScope {
  onmessage: ((event: MessageEvent<ToWorker>) => void) | null;
  postMessage(message: FromWorker): void;
  setTimeout(callback: () => void, ms: number): number;
  clearTimeout(handle: number): void;
  close(): void;
}
/** The worker's global scope, seen through the few members this file uses. */
const scope = self as unknown as WorkerScope;
/** Sends one message to the page. */
const post = (message: FromWorker): void => scope.postMessage(message);

/** The decoder's profile and level from the keyframe's SPS, as the codec string WebCodecs wants ("avc1.640028"). */
export function avcCodecString(bytes: Uint8Array): string | undefined {
  for (let i = 0; i + 6 < bytes.length; i++) {
    if (bytes[i] !== 0 || bytes[i + 1] !== 0) continue;
    const prefix = bytes[i + 2] === 1 ? 3 : bytes[i + 2] === 0 && bytes[i + 3] === 1 ? 4 : 0;
    if (prefix && i + prefix + 3 < bytes.length && (bytes[i + prefix]! & 31) === 7) {
      return "avc1." + Array.from(bytes.subarray(i + prefix + 1, i + prefix + 4), (b) => b.toString(16).padStart(2, "0")).join("");
    }
  }
  return undefined;
}

/** The visible surface handed over by `init`; its size follows the decoded picture. */
let canvas: OffscreenCanvas | undefined;
/** The surface's 2D drawing context. */
let context: OffscreenCanvasRenderingContext2D | null = null;
/** The page's hardware-decoding preference, passed to the decoder when it is configured. */
let hardware: HardwareAcceleration = "no-preference";
/** The running decoder, or `undefined` before the first keyframe and after it was retired. */
let decoder: VideoDecoder | undefined;
/** The codec string the decoder is configured for; a keyframe naming a different one reconfigures it. */
let codec: string | undefined;
/** The highest wire sequence accepted so far; a lower or equal one is a repeat and is ignored. */
let lastSequence = 0;
/** True while only a keyframe can be used: at the start and after a gap, an overflow or an error. */
let waitingKeyframe = true;
/** True while a repair request has been sent and its keyframe has not arrived. */
let repairPending = false;
/** The decoder timestamp of the newest accepted unit. An output older than this is superseded and not drawn. */
let timestamp = 0;
/** One encoded access unit waiting for the decoder. `stamp` is its decoder timestamp; `trace` is set only during measurement. */
interface CodedUnit { keyframe: boolean; bytes: Uint8Array; stamp: number; trace?: FrameTrace }
// The map exists only for measurement; decoder timestamps keep delayed outputs
// attached to their own wire sequence, including when a newer unit is queued.
let traces: Map<number, FrameTrace> | undefined;
/** Access units admitted but not yet given to the decoder, oldest first. At most `MAX_PENDING_UNITS`, and bounded in bytes. */
const pending: CodedUnit[] = [];
/** The most units that may wait in `pending`; going past it asks for a repair keyframe. */
const MAX_PENDING_UNITS = 8;
/** The total size in bytes of `pending`. */
let pendingBytes = 0;
/** Guards `pump` against running inside itself (an output can call it). */
let pumping = false;
/** True until the first picture of this attach has been drawn. */
let first = true;
/** The width and height of the last picture reported with a `size` message. */
let shownW = 0, shownH = 0;
/** The counters returned by a `stats` request. */
const stats: WorkerStats = { received: 0, decoded: 0, painted: 0, dropped: 0, superseded: 0, repairs: 0, pendingPeak: 0, pendingBytesPeak: 0 };

/** The least time between two requests for a keyframe. A decoder that cannot keep up asks again as soon as it is idle; each answer is a large
 *  picture that takes longest to decode, so unthrottled repairs feed the overload they answer (measured: 1,100 repairs in 12 s across ten streams). */
const REPAIR_MIN_MS = 300;
/** When the last repair request was sent, for the `REPAIR_MIN_MS` limit. */
let lastRepairAt = -Infinity;
/** The pending timer that will send a delayed repair request, if any. */
let repairTimer: number | undefined;

/** Asks the page for a keyframe now, if one is still needed. At most one request is in flight. */
function sendRepair(): void {
  repairTimer = undefined;
  if (!waitingKeyframe) return;
  repairPending = true;
  lastRepairAt = performance.now();
  stats.repairs++;
  post({ t: "repair", lastSequence });
}

/** Marks the stream as needing a keyframe and asks for one, no sooner than `REPAIR_MIN_MS` after the previous request. */
function repair(): void {
  waitingKeyframe = true;
  if (repairPending || repairTimer !== undefined) return;
  const wait = REPAIR_MIN_MS - (performance.now() - lastRepairAt);
  if (wait > 0) repairTimer = scope.setTimeout(sendRepair, wait); else sendRepair();
}

/** The decoder's output callback: draws the picture directly, unless a newer unit was already accepted, then closes it. Reports `first` and `size` messages and finishes the frame's trace. */
function output(frame: VideoFrame): void {
  stats.decoded++;
  const trace = traces?.get(frame.timestamp);
  if (trace) { traces!.delete(frame.timestamp); trace.decodedAt = traceClock(); }
  try {
    // Newer work is already accepted. Converting obsolete output would block its
    // callback and can overload the bounded decoder with avoidable canvas work.
    if (frame.timestamp < timestamp) { stats.superseded++; if (trace) trace.outcome = "superseded"; return; }
    if (!canvas || !context) return;
    if (canvas.width !== frame.displayWidth || canvas.height !== frame.displayHeight) {
      canvas.width = frame.displayWidth;
      canvas.height = frame.displayHeight;
    }
    if (trace) trace.drawStartedAt = traceClock();
    context.drawImage(frame, 0, 0);
    if (trace) { trace.drawFinishedAt = traceClock(); trace.width = frame.displayWidth; trace.height = frame.displayHeight; trace.outcome = "painted"; }
    stats.painted++;
    if (first) { first = false; post({ t: "first", width: frame.displayWidth, height: frame.displayHeight }); }
    if (frame.displayWidth !== shownW || frame.displayHeight !== shownH) {
      shownW = frame.displayWidth; shownH = frame.displayHeight;
      post({ t: "size", width: shownW, height: shownH });
    }
  } finally {
    frame.close();
    if (trace) post({ t: "trace", frame: trace });
    // Output proves codec progress even if its dequeue event is still pending.
    // No decoded picture waits here for that separate event or a display tick.
    pump();
  }
}

/** Forgets every waiting unit. */
function discardPending(): void { pending.length = 0; pendingBytes = 0; }

/** Closes the decoder and forgets its codec and traces. The waiting units are dropped too, unless `keepPending` (a keyframe is replacing the decoder and its followers belong to the new one). */
function retireDecoder(keepPending = false): void {
  if (!keepPending) discardPending();
  if (repairTimer !== undefined) { scope.clearTimeout(repairTimer); repairTimer = undefined; }
  if (decoder && decoder.state !== "closed") decoder.close();
  traces?.clear();
  decoder = undefined;
  codec = undefined;
}

/**
 * Gives one unit to the decoder. A keyframe may first (re)configure the decoder, when its parameter sets name a different codec. A
 * non-keyframe with no decoder asks for a repair. A decoder that is not supported at all reports `unsupported-codec`.
 */
function decodeUnit(keyframe: boolean, bytes: Uint8Array, stamp: number, trace?: FrameTrace): void {
  if (keyframe) {
    const wanted = avcCodecString(bytes) ?? codec;
    if (!wanted) { discardPending(); repair(); return; }
    if (!decoder || codec !== wanted) {
      // Units buffered after this IDR belong to its new codec, not the retired
      // decoder. Closing the old decoder must preserve that new reference chain.
      retireDecoder(true);
      codec = wanted;
      decoder = new VideoDecoder({
        output,
        error: (error) => {
          const unsupported = error.name === "NotSupportedError" && stats.decoded === 0;
          retireDecoder();
          if (unsupported) { post({ t: "error", reason: "unsupported-codec", detail: error.message }); return; }
          post({ t: "error", reason: "decode", detail: error.message });
          repair();
        },
      });
      decoder.ondequeue = () => { pump(); if (waitingKeyframe && (decoder?.decodeQueueSize ?? 2) < 2) repair(); };
      try { decoder.configure({ codec: wanted, optimizeForLatency: true, hardwareAcceleration: hardware }); }
      catch (error) { retireDecoder(); post({ t: "error", reason: "unsupported-codec", detail: String(error) }); return; }
    }
    waitingKeyframe = false;
    repairPending = false;
  }
  if (!decoder) { stats.dropped++; repair(); return; }
  if (trace) {
    if (traces!.size === TRACE_LIMIT) {
      const oldest = traces!.keys().next().value!;
      post({ t: "trace", frame: traces!.get(oldest)! });
      traces!.delete(oldest);
    }
    trace.submittedAt = traceClock(); traces!.set(stamp, trace);
  }
  try { decoder.decode(new EncodedVideoChunk({ type: keyframe ? "key" : "delta", timestamp: stamp, data: bytes })); }
  catch { retireDecoder(); post({ t: "error", reason: "decode" }); repair(); }
}

/** Moves waiting units to the decoder while it has fewer than two queued. */
function pump(): void {
  if (pumping) return;
  pumping = true;
  try {
    while (pending.length && (decoder?.decodeQueueSize ?? 0) < 2) {
      const unit = pending.shift()!;
      pendingBytes -= unit.bytes.byteLength;
      decodeUnit(unit.keyframe, unit.bytes, unit.stamp, unit.trace);
    }
  } finally { pumping = false; }
}

/**
 * Accepts one unit from the page. Repeats are ignored. A delta unit that follows a gap, or arrives while a keyframe is awaited, drops
 * the waiting units and asks for a repair. A keyframe replaces everything not yet submitted. Going over the unit or byte bound also asks
 * for a repair.
 */
function chunk(sequence: number, keyframe: boolean, buffer: ArrayBuffer, receipt?: ReceiveTrace): void {
  const receivedAt = traces ? traceClock() : 0;
  stats.received++;
  if (sequence <= lastSequence) return;
  const continuous = sequence === lastSequence + 1;
  lastSequence = sequence;
  if (!keyframe && (waitingKeyframe || !continuous)) {
    stats.dropped += pending.length + 1;
    discardPending(); repair(); return;
  }
  if (keyframe) {
    // A self-contained newer picture supersedes unsubmitted old references.
    stats.dropped += pending.length;
    discardPending();
  }
  // Consumption can precede the dequeue task. Drain any capacity already
  // available before applying the pending count/byte bounds to this arrival.
  if (pending.length) {
    pump();
    if (!keyframe && waitingKeyframe) { stats.dropped++; return; }
  }
  if (!buffer.byteLength || buffer.byteLength > MAX_VIDEO_BYTES || pending.length >= MAX_PENDING_UNITS || pendingBytes + buffer.byteLength > MAX_VIDEO_BYTES) {
    stats.dropped += pending.length + 1;
    discardPending();
    if (keyframe) repairPending = false;
    repair(); return;
  }
  if (keyframe) { waitingKeyframe = false; repairPending = false; }
  // Advance before decoder admission: even output from an admitted older unit
  // is obsolete while a newer accepted picture waits for its codec references.
  const bytes = new Uint8Array(buffer), stamp = ++timestamp;
  const trace: FrameTrace | undefined = traces && receipt ? { ...receipt, sequence, workerReceivedAt: receivedAt, outcome: "unpainted" } : undefined;
  // Ordinary delivery allocates no pending record. Only references waiting for
  // codec capacity need the extra bounded queue entry.
  if (!pending.length && (decoder?.decodeQueueSize ?? 0) < 2) {
    decodeUnit(keyframe, bytes, stamp, trace);
    return;
  }
  pending.push({ keyframe, bytes, stamp, ...(trace ? { trace } : {}) });
  pendingBytes += buffer.byteLength;
  stats.pendingPeak = Math.max(stats.pendingPeak, pending.length);
  stats.pendingBytesPeak = Math.max(stats.pendingBytesPeak, pendingBytes);
  pump();
}

scope.onmessage = (event: MessageEvent<ToWorker>) => {
  const m = event.data;
  switch (m.t) {
    case "init":
      traces = m.measure ? new Map() : undefined;
      canvas = m.canvas;
      hardware = m.hardware;
      // `alpha: false` lets the browser skip blending the picture with the page behind it. `desynchronized` (present without
      // waiting for the page's own frame) is left off: in the software-rendered runs on the perf VM it raised the page's long
      // tasks and halved the pictures drawn with five streams (docs on #146). It needs hardware evidence before it is chosen.
      context = canvas.getContext("2d", { alpha: false, desynchronized: false }) as OffscreenCanvasRenderingContext2D | null;
      if (!context || typeof VideoDecoder === "undefined" || typeof EncodedVideoChunk === "undefined") {
        post({ t: "error", reason: context ? "unsupported-codec" : "unsupported-canvas" });
      }
      return;
    case "chunk": chunk(m.sequence, m.keyframe, m.bytes, m.trace); return;
    case "reset":
      retireDecoder();
      lastSequence = 0; waitingKeyframe = true; repairPending = false; first = true;
      return;
    case "stats": post({ t: "stats", stats: { ...stats } }); return;
    case "close":
      retireDecoder();
      canvas = undefined; context = null;
      scope.close();
      return;
  }
};
