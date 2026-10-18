/** Content-free, bounded receipts for explicitly requested app-window stage measurements [D208,D232,D262]. */
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
}
export type ReceiveTrace = Pick<FrameTrace, "captureNs" | "bytes" | "receivedAt" | "copyFinishedAt">;
export const traceClock = (): number => performance.timeOrigin + performance.now();
export const traceEnabled = (): boolean => typeof location !== "undefined" && new URLSearchParams(location.search).get("appwinMeasure") === "1";
const frames: FrameTrace[] = [];
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
