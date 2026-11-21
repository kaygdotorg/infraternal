/**
 * Content-free, bounded receipts for explicitly requested app-window stage measurements [D208,D232,D262].
 * Each receipt times one access unit, video or tile (#146 proposal C), from the socket to the canvas; no pixels or titles.
 */

/** The stage times of one access unit, in `traceClock` milliseconds, and what became of it. */
export interface FrameTrace {
  sequence: number;
  captureNs: string;
  bytes: number;
  receivedAt: number;
  copyFinishedAt: number;
  workerReceivedAt?: number;
  submittedAt?: number;
  decodedAt?: number;
  drawStartedAt?: number;
  drawFinishedAt?: number;
  width?: number;
  height?: number;
  outcome: "painted" | "superseded" | "unpainted";
  /** Set to "tile" for a tile update (#146 proposal C); its `decodedAt` is when its pixels were inflated. Video leaves it unset. */
  lane?: "tile";
}
/** The part of a `FrameTrace` known when the frame arrives, before the decode worker has seen it. */
export type ReceiveTrace = Pick<FrameTrace, "captureNs" | "bytes" | "receivedAt" | "copyFinishedAt">;
/** Wall-clock time in milliseconds with sub-millisecond precision, comparable across the page and the worker. */
export const traceClock = (): number => performance.timeOrigin + performance.now();
/** True only when the page was opened with `?appwinMeasure=1`; otherwise no trace is kept or sent. */
export const traceEnabled = (): boolean => typeof location !== "undefined" && new URLSearchParams(location.search).get("appwinMeasure") === "1";
/** The most recent traces, oldest first. At most `TRACE_LIMIT` are kept. */
const frames: FrameTrace[] = [];
/** How many frame traces are kept before the oldest is dropped. */
export const TRACE_LIMIT = 512;
declare global {
  interface Window { __infraternalAppWindowTrace?: { take(): FrameTrace[] } }
}
/** A diagnostic reads and clears the bounded buffer; normal viewing exposes no global or extra messages. */
export function recordFrame(frame: FrameTrace): void {
  if (!traceEnabled()) return;
  if (frames.length === TRACE_LIMIT) frames.shift();
  frames.push(frame);
  window.__infraternalAppWindowTrace ??= { take: () => frames.splice(0) };
}
