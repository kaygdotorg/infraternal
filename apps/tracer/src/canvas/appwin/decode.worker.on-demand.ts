/**
 * The decode worker of one app window or screen window (D200, D204, D232, D254, D266).
 *
 * It owns the window's visible canvas (an `OffscreenCanvas` transferred from the page) and the WebCodecs decoder, so
 * decoding, drawing and the frame queue never touch the main thread. The page only forwards encoded access units.
 *
 * Bounded admission and frame ownership:
 * - a decoder holds at most two queued access units; a unit arriving while it is full is dropped, and everything after
 *   it is dropped until the next keyframe (a delta frame without its reference would paint corruption);
 * - a gap in the sequence, a decoder error or a full queue asks the page for a repair keyframe, at most one request
 *   in flight;
 * - an IDR repairs the reference state inside the running decoder, which is only reconfigured when the profile or the
 *   level in its parameter sets changed; closing it on every IDR would cancel valid queued output;
 * - decoded pictures are drawn directly from the decoder output callback, without a second display-clock queue.
 *   The canvas always holds the newest completed picture; the compositor may skip earlier draws when output bursts.
 *   Each picture is closed before the callback returns so no presentation wait pins decoder memory.
 *
 * Nothing is scheduled while no unit arrives and nothing is drawn without a new picture: a window whose machine shows
 * the same pixels costs no work at all (D254). The worker exists only while its window streams; the page ends it when
 * the window closes or has been off screen for long.
 */
import type { FromWorker, ToWorker, WorkerStats } from "./worker-protocol";

/** The few members of the worker's global scope used here (the project compiles against the page's types). */
interface WorkerScope {
  onmessage: ((event: MessageEvent<ToWorker>) => void) | null;
  postMessage(message: FromWorker): void;
  setTimeout(callback: () => void, ms: number): number;
  clearTimeout(handle: number): void;
  close(): void;
}
const scope = self as unknown as WorkerScope;
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

let canvas: OffscreenCanvas | undefined;
let context: OffscreenCanvasRenderingContext2D | null = null;
let hardware: HardwareAcceleration = "no-preference";
let decoder: VideoDecoder | undefined;
let codec: string | undefined;
let lastSequence = 0;
let waitingKeyframe = true;
let repairPending = false;
let timestamp = 0;
let first = true;
let shownW = 0, shownH = 0;
const stats: WorkerStats = { received: 0, decoded: 0, painted: 0, dropped: 0, superseded: 0, repairs: 0 };

/** The least time between two requests for a keyframe. A decoder that cannot keep up asks again as soon as it is idle; each answer is a large
 *  picture that takes longest to decode, so unthrottled repairs feed the overload they answer (measured: 1,100 repairs in 12 s across ten streams). */
const REPAIR_MIN_MS = 300;
let lastRepairAt = -Infinity;
let repairTimer: number | undefined;

function sendRepair(): void {
  repairTimer = undefined;
  if (!waitingKeyframe) return;
  repairPending = true;
  lastRepairAt = performance.now();
  stats.repairs++;
  post({ t: "repair", lastSequence });
}

function repair(): void {
  waitingKeyframe = true;
  if (repairPending || repairTimer !== undefined) return;
  const wait = REPAIR_MIN_MS - (performance.now() - lastRepairAt);
  if (wait > 0) repairTimer = scope.setTimeout(sendRepair, wait); else sendRepair();
}

function output(frame: VideoFrame): void {
  stats.decoded++;
  if (!frame || !canvas || !context) { frame?.close(); return; }
  try {
    if (canvas.width !== frame.displayWidth || canvas.height !== frame.displayHeight) {
      canvas.width = frame.displayWidth;
      canvas.height = frame.displayHeight;
    }
    context.drawImage(frame, 0, 0);
    stats.painted++;
    if (first) { first = false; post({ t: "first", width: frame.displayWidth, height: frame.displayHeight }); }
    if (frame.displayWidth !== shownW || frame.displayHeight !== shownH) {
      shownW = frame.displayWidth; shownH = frame.displayHeight;
      post({ t: "size", width: shownW, height: shownH });
    }
  } finally { frame.close(); }
}

function retireDecoder(): void {
  if (repairTimer !== undefined) { scope.clearTimeout(repairTimer); repairTimer = undefined; }
  if (decoder && decoder.state !== "closed") decoder.close();
  decoder = undefined;
  codec = undefined;
}

function chunk(sequence: number, keyframe: boolean, buffer: ArrayBuffer): void {
  stats.received++;
  if (sequence <= lastSequence) return;
  const continuous = sequence === lastSequence + 1;
  lastSequence = sequence;
  if ((decoder?.decodeQueueSize ?? 0) >= 2) {
    // An IDR still takes a decode slot; admitting repairs while saturated would queue obsolete keyframes without bound.
    stats.dropped++;
    waitingKeyframe = true;
    if (keyframe) repairPending = false;
    return;
  }
  if (!keyframe && (waitingKeyframe || !continuous)) { stats.dropped++; repair(); return; }
  const bytes = new Uint8Array(buffer);
  if (keyframe) {
    const wanted = avcCodecString(bytes) ?? codec;
    if (!wanted) { repair(); return; }
    if (!decoder || codec !== wanted) {
      retireDecoder();
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
      decoder.ondequeue = () => { if (waitingKeyframe && (decoder?.decodeQueueSize ?? 2) < 2) repair(); };
      try { decoder.configure({ codec: wanted, optimizeForLatency: true, hardwareAcceleration: hardware }); }
      catch (error) { retireDecoder(); post({ t: "error", reason: "unsupported-codec", detail: String(error) }); return; }
    }
    waitingKeyframe = false;
    repairPending = false;
  }
  if (!decoder) { stats.dropped++; repair(); return; }
  const stamp = ++timestamp;
  try { decoder.decode(new EncodedVideoChunk({ type: keyframe ? "key" : "delta", timestamp: stamp, data: bytes })); }
  catch { retireDecoder(); post({ t: "error", reason: "decode" }); repair(); }
}

scope.onmessage = (event: MessageEvent<ToWorker>) => {
  const m = event.data;
  switch (m.t) {
    case "init":
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
    case "chunk": chunk(m.sequence, m.keyframe, m.bytes); return;
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
