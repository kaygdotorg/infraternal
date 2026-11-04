/**
 * The messages between an app window and its decode worker (`decode.worker.on-demand.ts`). Types only, so the main
 * thread and the worker agree without sharing code: this file compiles to nothing.
 *
 * Why a worker: decoding and drawing a stream are the heavy part of a window. A window in the background must never
 * delay typing or scrolling on the main thread (D268 Q19 sets the same rule for terminal output), so the worker owns
 * the decoder and the visible canvas (transferred as an `OffscreenCanvas`) and the main thread only forwards the
 * encoded access units as they arrive from the one socket.
 */

import type { FrameTrace, ReceiveTrace } from "./frame-trace";

/** Main thread to worker. */
export type ToWorker =
  /** Hands over the visible surface. Sent once, with the canvas in the transfer list. */
  | { t: "init"; canvas: OffscreenCanvas; hardware: HardwareAcceleration; measure?: boolean }
  /** One access unit. `bytes` is transferred (the worker owns it). `sequence` is the wire's sequence (starts at 1). */
  | { t: "chunk"; sequence: number; keyframe: boolean; bytes: ArrayBuffer; trace?: ReceiveTrace }
  /** Drops the decoder and every queued frame (a pause, a re-attach). The picture on the surface stays. */
  | { t: "reset" }
  /** Asks for the counters (measurement only). */
  | { t: "stats" }
  | { t: "close" };

/** Worker to main thread. */
export type FromWorker =
  /** The first picture of an attach reached the surface. */
  | { t: "first"; width: number; height: number }
  /** The decoded picture changed size (the machine followed a resize, or the window letterboxed). */
  | { t: "size"; width: number; height: number }
  /** The decoder needs a fresh keyframe: a gap, an overflow or a decoder error. `lastSequence` is the last one received. */
  | { t: "repair"; lastSequence: number }
  /** The decoder cannot work at all. `unsupported-*` is final for this browser; `decode` may be tried again. */
  | { t: "error"; reason: "unsupported-codec" | "unsupported-canvas" | "decode"; detail?: string }
  | { t: "stats"; stats: WorkerStats }
  /** Emitted only by explicitly enabled, content-free stage measurements. */
  | { t: "trace"; frame: FrameTrace };

/** Counters of the decode worker's work, for measurement only. */
export interface WorkerStats {
  received: number;
  decoded: number;
  painted: number;
  dropped: number;
  /** Decoded pictures discarded because newer work was already accepted. */
  superseded: number;
  repairs: number;
  /** High-water marks for coded references awaiting decoder admission; decoded pictures are never queued here. */
  pendingPeak: number;
  pendingBytesPeak: number;
}
