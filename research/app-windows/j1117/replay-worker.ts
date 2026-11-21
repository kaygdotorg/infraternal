/**
 * Flicker-proof replay for the App Windows tile lane (#146 proposal C): the product's real decode worker, fed the packets
 * the product's real Mac pipeline sent (record.swift), with every painted picture compared to the source frame.
 *
 * This file runs as a module worker. It imports `decode.worker.on-demand.ts` unchanged, hands it an instrumented canvas
 * (the real worker draws on a real OffscreenCanvas through a thin proxy), and delivers the recorded access units with the
 * recorded timing, sped up, or with network-like jitter. After each painted unit, a whole video picture or a whole tile
 * update, it reads the canvas back and compares it with the source frame of that unit's capture stamp in 16x16 blocks:
 * - **match**: the block is within the tolerance of the expected source frame;
 * - **stale**: the block is not, but an older source frame matches it within the tolerance and better than the expected
 *   one: the window shows older content there. A flicker or a reverted rectangle shows up here;
 * - **lossy**: no frame in the look-back matches: video compression error (reported with its size, not a flicker).
 * It also checks that the expected source frame never goes back in time from one painted picture to the next.
 * Mode `swap` is the negative control: it delivers each tile that directly follows a video unit before that unit (with
 * the sequence numbers swapped), the way a viewer that ignored capture order would paint them. It must be flagged.
 * Mode `latency` takes no snapshots and draws on an ordinary (GPU) canvas, like the product, to time receive → paint per lane;
 * readback canvases slow video drawing, so the other modes' timings are not latency numbers.
 * Measurement only; nothing here ships.
 */
import type { FromWorker, ToWorker } from "../../../apps/tracer/src/canvas/appwin/worker-protocol";
import "../../../apps/tracer/src/canvas/appwin/decode.worker.on-demand";

/** A replay request from the page. */
interface Run { t: "run"; packets: ArrayBuffer; source: ArrayBuffer; mode: "realtime" | "fast" | "jitter" | "swap" | "latency"; seed: number; scenarios?: { name: string; first_ns: string; last_ns: string }[] }

const scope = self as unknown as { onmessage: ((event: MessageEvent<ToWorker | Run>) => void) | null; postMessage(message: unknown): void };
/** The real worker's message handler, installed by its import above. */
const deliver = scope.onmessage!;
/** The page's own postMessage; the real worker's messages are intercepted instead. */
const toPage = scope.postMessage.bind(scope);

const BLOCK = 16;
/** Mean absolute difference per channel (0-255) under which a block matches a source frame. */
const TOLERANCE = 8;
/** How many older source frames are searched for a better match of a bad block. */
const LOOKBACK = 24;

/** Source frames: capture stamp → offset and length of its raw-DEFLATE BGRA rows in source.bin. */
interface SourceIndex { width: number; height: number; stamps: bigint[]; offsets: number[]; lengths: number[]; byStamp: Map<bigint, number> }

/** Reads source.bin's index without inflating anything. */
function indexSource(buffer: ArrayBuffer): SourceIndex {
  const view = new DataView(buffer);
  const magic = new TextDecoder().decode(new Uint8Array(buffer, 0, 8));
  if (magic !== "J1117SRC") throw new Error("bad source magic");
  const width = view.getUint32(8), height = view.getUint32(12), count = view.getUint32(16);
  const index: SourceIndex = { width, height, stamps: [], offsets: [], lengths: [], byStamp: new Map() };
  let at = 20;
  for (let i = 0; i < count; i++) {
    const stamp = view.getBigUint64(at), length = view.getUint32(at + 8);
    index.byStamp.set(stamp, i); index.stamps.push(stamp); index.offsets.push(at + 12); index.lengths.push(length);
    at += 12 + length;
  }
  return index;
}

/** A small cache of inflated source frames (BGRA). */
const cache = new Map<number, Uint8Array>();
/** Inflates source frame `i`, keeping the 48 most recent. */
async function frame(buffer: ArrayBuffer, index: SourceIndex, i: number): Promise<Uint8Array> {
  const hit = cache.get(i);
  if (hit) { cache.delete(i); cache.set(i, hit); return hit; }
  const stream = new Blob([new Uint8Array(buffer, index.offsets[i], index.lengths[i])]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  const pixels = new Uint8Array(await new Response(stream).arrayBuffer());
  cache.set(i, pixels);
  if (cache.size > 48) cache.delete(cache.keys().next().value!);
  return pixels;
}

/** Mean absolute RGB difference of one block between a canvas snapshot (RGBA) and a source frame (BGRA). */
function blockError(snap: Uint8ClampedArray, src: Uint8Array, width: number, height: number, bx: number, by: number): number {
  let sum = 0, n = 0;
  const x1 = Math.min(width, bx + BLOCK), y1 = Math.min(height, by + BLOCK);
  for (let y = by; y < y1; y++) {
    let p = (y * width + bx) * 4;
    for (let x = bx; x < x1; x++, p += 4) {
      sum += Math.abs(snap[p]! - src[p + 2]!) + Math.abs(snap[p + 1]! - src[p + 1]!) + Math.abs(snap[p + 2]! - src[p]!);
      n += 3;
    }
  }
  return sum / n;
}

/** One painted unit's verdict. */
interface Verdict { kind: "video" | "tile"; captureNs: string; frame: number; at: number; stale: number; lossy: number; worst: number; regressed: boolean }

/** The canvas the real worker draws on, and the snapshots taken after each painted unit. */
const real = new OffscreenCanvas(1, 1);
/** The real canvas context; created per run, read-back friendly unless the mode only measures latency. */
let context!: OffscreenCanvasRenderingContext2D;
/** False in `latency` mode: draw only, never read back. */
let capture = true;
/** Snapshots waiting for comparison, in paint order. A video snapshot's capture stamp arrives with its trace a moment
 *  later in the same callback, after any tiles that waited for it, so it is queued unlabelled at draw time. */
const snapshots: { kind: "video" | "tile"; captureNs: string; image: ImageData; at: number }[] = [];
/** Video snapshots still waiting for their trace, oldest first. */
const unlabelled: { captureNs: string }[] = [];
const proxy = {
  drawImage(source: CanvasImageSource, x: number, y: number) {
    context.drawImage(source, x, y);
    if (!capture) return;
    const snap = { kind: "video" as const, captureNs: "", image: context.getImageData(0, 0, real.width, real.height), at: performance.now() };
    snapshots.push(snap); unlabelled.push(snap);
  },
  putImageData(image: ImageData, x: number, y: number) { context.putImageData(image, x, y); },
};
const canvas = {
  get width() { return real.width; }, set width(value: number) { real.width = value; },
  get height() { return real.height; }, set height(value: number) { real.height = value; },
  getContext: () => proxy,
} as unknown as OffscreenCanvas;

/** Counters of what the real worker reported. */
const reported = { repairs: 0, errors: [] as string[], traces: 0 };
/** Worker receive → paint finished, in milliseconds, per lane. */
const latency = { tile: [] as number[], video: [] as number[], tileInflate: [] as number[], videoDecode: [] as number[] };
/** Labels snapshots from the real worker's measurement traces. */
scope.postMessage = (message: unknown) => {
  const m = message as FromWorker;
  if (m.t === "repair") reported.repairs++;
  if (m.t === "error") reported.errors.push(`${m.reason}:${m.detail ?? ""}`);
  if (m.t !== "trace" || m.frame.outcome !== "painted") return;
  reported.traces++;
  if (m.frame.workerReceivedAt !== undefined && m.frame.drawFinishedAt !== undefined) {
    latency[m.frame.lane === "tile" ? "tile" : "video"].push(m.frame.drawFinishedAt - m.frame.workerReceivedAt);
    if (m.frame.decodedAt !== undefined) latency[m.frame.lane === "tile" ? "tileInflate" : "videoDecode"].push(m.frame.decodedAt - m.frame.workerReceivedAt);
  }
  if (!capture) return;
  if (m.frame.lane === "tile") {
    // The tile's last rectangle has just been drawn: this is the picture after the whole update.
    snapshots.push({ kind: "tile", captureNs: m.frame.captureNs, image: context.getImageData(0, 0, real.width, real.height), at: performance.now() });
  } else {
    const snap = unlabelled.shift();
    if (snap) snap.captureNs = m.frame.captureNs;
  }
};

/** A tiny deterministic random source for the jitter mode. */
function random(seed: number): () => number {
  let state = seed >>> 0 || 1;
  return () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return (state >>> 0) / 2 ** 32; };
}

/** Replays the packets into the real worker, then compares every snapshot and posts the report to the page. */
async function run(request: Run): Promise<void> {
  const view = new DataView(request.packets);
  const units: { t: number; sequence: number; capture: bigint; keyframe: boolean; bytes: ArrayBuffer }[] = [];
  for (let at = 0, sequence = 1; at < request.packets.byteLength; sequence++) {
    const t = Number(view.getBigUint64(at)) / 1e6, length = view.getUint32(at + 8);
    const body = new Uint8Array(request.packets, at + 12, length);
    units.push({ t, sequence, capture: new DataView(body.buffer, body.byteOffset).getBigUint64(0), keyframe: body[8] === 1, bytes: body.slice(9).buffer });
    at += 12 + length;
  }
  if (request.mode === "swap") {
    for (let i = 1; i < units.length; i++) {
      const before = units[i - 1]!, unit = units[i]!;
      if (new Uint8Array(unit.bytes)[0] === 0xf7 && new Uint8Array(before.bytes)[0] !== 0xf7) {
        [units[i - 1], units[i]] = [{ ...unit, sequence: before.sequence, t: before.t }, { ...before, sequence: unit.sequence, t: unit.t }];
        i++;
      }
    }
  }
  const index = indexSource(request.source);
  capture = request.mode !== "latency";
  context = real.getContext("2d", { alpha: false, willReadFrequently: capture })!;
  deliver({ data: { t: "init", canvas, hardware: "no-preference", measure: true } } as MessageEvent<ToWorker>);
  const speed = request.mode === "fast" ? 4 : 1;
  const next = random(request.seed);
  const origin = performance.now(), first = units[0]!.t;
  for (const unit of units) {
    // Jitter delays a unit by 0-30 ms without reordering it: later units bunch up behind it, like a congested link.
    const due = (unit.t - first) / speed + (request.mode === "jitter" ? next() * 30 : 0);
    const wait = origin + due - performance.now();
    if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
    const receivedAt = performance.timeOrigin + performance.now();
    deliver({ data: { t: "chunk", sequence: unit.sequence, keyframe: unit.keyframe, bytes: unit.bytes,
      trace: { captureNs: String(unit.capture), bytes: unit.bytes.byteLength, receivedAt, copyFinishedAt: receivedAt } } } as MessageEvent<ToWorker>);
  }
  // Let the last decodes and tile inflates finish.
  await new Promise((resolve) => setTimeout(resolve, 500));
  deliver({ data: { t: "stats" } } as MessageEvent<ToWorker>);
  const verdicts: Verdict[] = [];
  let lastFrame = -1, regressions = 0, missing = 0;
  const lossyErrors: number[] = [];
  for (const snap of snapshots) {
    const expected = snap.captureNs ? index.byStamp.get(BigInt(snap.captureNs)) : undefined;
    if (expected === undefined) { missing++; continue; }
    const pixels = snap.image.data, src = await frame(request.source, index, expected);
    let stale = 0, lossy = 0, worst = 0;
    for (let by = 0; by < index.height; by += BLOCK) for (let bx = 0; bx < index.width; bx += BLOCK) {
      const error = blockError(pixels, src, index.width, index.height, bx, by);
      worst = Math.max(worst, error);
      if (error <= TOLERANCE) continue;
      let older = Infinity;
      for (let i = expected - 1; i >= Math.max(0, expected - LOOKBACK); i--) {
        older = Math.min(older, blockError(pixels, await frame(request.source, index, i), index.width, index.height, bx, by));
        if (older <= TOLERANCE && older < error) break;
      }
      if (older <= TOLERANCE && older < error) stale++; else { lossy++; lossyErrors.push(error); }
    }
    const regressed = expected < lastFrame;
    if (regressed) regressions++;
    lastFrame = Math.max(lastFrame, expected);
    verdicts.push({ kind: snap.kind, captureNs: snap.captureNs, frame: expected, at: snap.at - origin, stale, lossy, worst, regressed });
  }
  lossyErrors.sort((a, b) => a - b);
  const percentile = (values: number[], q: number) => { const v = [...values].sort((a, b) => a - b); return v.length ? v[Math.min(v.length - 1, Math.floor(q * v.length))]! : 0; };
  const scenarios = (request.scenarios ?? []).map((scenario) => {
    const inside = verdicts.filter((v) => BigInt(v.captureNs) >= BigInt(scenario.first_ns) && BigInt(v.captureNs) <= BigInt(scenario.last_ns));
    return { name: scenario.name, snapshots: inside.length, tiles: inside.filter((v) => v.kind === "tile").length, video: inside.filter((v) => v.kind === "video").length,
      stale: inside.filter((v) => v.stale > 0).length, regressions: inside.filter((v) => v.regressed).length, lossy: inside.filter((v) => v.lossy > 0).length };
  });
  const summary = {
    mode: request.mode, units: units.length, videoUnits: units.filter((u) => !(new Uint8Array(u.bytes)[0] === 0xf7)).length,
    snapshots: verdicts.length, videoSnapshots: verdicts.filter((v) => v.kind === "video").length, tileSnapshots: verdicts.filter((v) => v.kind === "tile").length,
    staleSnapshots: verdicts.filter((v) => v.stale > 0).length, staleBlocks: verdicts.reduce((s, v) => s + v.stale, 0),
    regressions, missing, lossySnapshots: verdicts.filter((v) => v.lossy > 0).length, lossyBlocks: lossyErrors.length,
    lossyErrorP50: lossyErrors[Math.floor(lossyErrors.length / 2)] ?? 0, lossyErrorMax: lossyErrors.at(-1) ?? 0,
    tileWorstMax: Math.max(0, ...verdicts.filter((v) => v.kind === "tile").map((v) => v.worst)),
    repairs: reported.repairs, errors: reported.errors, tolerance: TOLERANCE, block: BLOCK, lookback: LOOKBACK,
    paintMs: { tileP50: percentile(latency.tile, 0.5), tileP95: percentile(latency.tile, 0.95), videoP50: percentile(latency.video, 0.5), videoP95: percentile(latency.video, 0.95),
      tiles: latency.tile.length, videos: latency.video.length,
      tileInflateP50: percentile(latency.tileInflate, 0.5), videoDecodeP50: percentile(latency.videoDecode, 0.5) },
    scenarios,
  };
  toPage({ t: "report", summary, verdicts, workerStats: lastStats });
}

/** The real worker's last stats reply. */
let lastStats: unknown;
const intercept = scope.postMessage;
scope.postMessage = (message: unknown) => {
  if ((message as FromWorker).t === "stats") lastStats = (message as { stats: unknown }).stats;
  intercept(message);
};

scope.onmessage = (event) => {
  const data = event.data as Run;
  if (data.t === "run") run(data).catch((error) => toPage({ t: "report", error: String(error) }));
};
