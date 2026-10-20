/** Observes content-free wire/worker receipts and owns a separate authenticated control socket for the real-window benchmark [D208,D232]. */
import { WebSocketFrameDecoder } from "../../../../packages/protocol/src/codec";
import { MuxConnection } from "../../src/connection";
import { plainCloseReason } from "../../src/close-reasons";

const now = (): number => performance.timeOrigin + performance.now();
const NativeSocket = WebSocket;
const NativeWorker = Worker;
const limit = <T>(rows: T[], row: T): void => { if (rows.length === 512) rows.shift(); rows.push(row); };
const inputs: Array<{ at: number; kind: string }> = [];
const domInputs: Array<{ at: number; eventAt: number }> = [];
window.addEventListener("keydown", (event) => limit(domInputs, { at: now(), eventAt: performance.timeOrigin + event.timeStamp }), true);
const videos: Array<{ at: number; captureNs: string; sequence: number; bytes: number }> = [];
const events: unknown[] = [];
const roundTrips: Array<{ at: number; ms: number }> = [];
let activeWorker: Worker | undefined;
let session: string | undefined;
let openedSockets = 0;
let closedSockets = 0;
let nextSocket = 0;
interface SocketEvent { at: number; socket: number; event: "open" | "close" | "client-close" | "server-close"; viewer: boolean; code?: number; reason?: string; clean?: boolean }
const socketEvents: SocketEvent[] = [];

if (!window.__benchResourcesOnly) globalThis.WebSocket = class extends NativeSocket {
  private readonly outgoing = new WebSocketFrameDecoder();
  private readonly identity = ++nextSocket;
  private viewer = false;
  private readonly probes = new Map<bigint, { at: number; sentUs: bigint }>();
  constructor(...args: ConstructorParameters<typeof WebSocket>) {
    super(...args);
    this.addEventListener("open", () => { openedSockets++; limit(socketEvents, { at: now(), socket: this.identity, event: "open", viewer: this.viewer }); });
    this.addEventListener("close", (event: CloseEvent) => { closedSockets++; limit(socketEvents, { at: now(), socket: this.identity, event: "close", viewer: this.viewer, code: event.code, reason: plainCloseReason(event.reason, "other"), clean: event.wasClean }); });
    const incoming = new WebSocketFrameDecoder();
    this.addEventListener("message", (event) => {
      if (!(event.data instanceof ArrayBuffer)) return;
      incoming.feed(new Uint8Array(event.data), (_stream, frame) => {
        if (frame.type === "Close" && _stream === 0) limit(socketEvents, { at: now(), socket: this.identity, event: "server-close", viewer: this.viewer, code: frame.code, reason: plainCloseReason(frame.reason, "other") });
        if (frame.type === "Pong") {
          const began = this.probes.get(frame.nonce);
          if (began !== undefined && began.sentUs === frame.sentUs) { limit(roundTrips, { at: now(), ms: now() - began.at }); this.probes.delete(frame.nonce); }
        }
        if (frame.type === "Desktop" && frame.message.kind === "video") {
          const v = frame.message;
          limit(videos, { at: now(), captureNs: v.captureNs.toString(), sequence: Number(v.sequence), bytes: v.bytes.length });
        }
      });
    });
  }
  override close(code?: number, reason?: string): void {
    // Peer text never enters receipts: reuse the application's fixed reason map.
    limit(socketEvents, { at: now(), socket: this.identity, event: "client-close", viewer: this.viewer, ...(code === undefined ? {} : { code }), reason: plainCloseReason(reason, "other") });
    super.close(code, reason);
  }
  override send(data: Parameters<WebSocket["send"]>[0]): void {
    if (data instanceof Uint8Array) this.outgoing.feed(data, (_stream, frame) => {
      if (frame.type === "Ping") {
        if (this.probes.size === 128) this.probes.delete(this.probes.keys().next().value!);
        this.probes.set(frame.nonce, { at: now(), sentUs: frame.sentUs });
      }
      if (frame.type !== "Desktop") return;
      const value = frame.message;
      if (value.kind === "input") limit(inputs, { at: now(), kind: value.input.kind });
      if (value.kind === "attach") {
        this.viewer = true;
        const hex = Array.from(value.sessionId, (byte) => byte.toString(16).padStart(2, "0")).join("");
        session = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
      }
    });
    super.send(data);
  }
};
globalThis.Worker = class extends NativeWorker {
  override postMessage(message: unknown, options?: Transferable[] | StructuredSerializeOptions): void {
    const value = message as { t?: string };
    const forwarded = value?.t === "init" && window.__benchHardwareHint ? { ...value, hardware: window.__benchHardwareHint } : message;
    if (Array.isArray(options)) super.postMessage(forwarded, options); else super.postMessage(forwarded, options);
  }
  constructor(...args: ConstructorParameters<typeof Worker>) {
    super(...args);
    this.addEventListener("message", (event: MessageEvent<{ t?: string }>) => {
      if (event.data?.t === "first") activeWorker = this;
      if (event.data?.t?.startsWith("bench-") || event.data?.t === "trace") limit(events, event.data);
    });
  }
};

let fixture: MuxConnection | undefined;
function connect(): Promise<void> {
  fixture ??= new MuxConnection({ desktop: () => true });
  if (fixture.isWelcomed) return Promise.resolve();
  return new Promise<void>((resolve, reject) => {
    let remove = (): void => {};
    const timer = setTimeout(() => { remove(); reject(new Error("fixture socket timeout")); }, 15_000);
    remove = fixture!.onWelcome(() => { clearTimeout(timer); remove(); resolve(); });
  });
}
async function call(action: string, input: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  await connect();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      fixture!.call(action, input),
      new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error("fixture action timeout")), 15_000); }),
    ]);
  } finally { clearTimeout(timer); }
}
function workerStats(): Promise<unknown> {
  const worker = activeWorker;
  if (!worker) return Promise.resolve(null);
  return new Promise((resolve, reject) => {
    const receive = (event: MessageEvent<{ t?: string; stats?: unknown }>): void => {
      if (event.data?.t !== "stats") return;
      clearTimeout(timer); worker.removeEventListener("message", receive); resolve(event.data.stats);
    };
    const timer = setTimeout(() => { worker.removeEventListener("message", receive); reject(new Error("worker counters unavailable")); }, 3000);
    worker.addEventListener("message", receive); worker.postMessage({ t: "stats" });
  });
}
let nextClock = 0;
function workerClock(): Promise<{ before: number; worker: number; after: number }> {
  const worker = activeWorker;
  if (!worker) return Promise.reject(new Error("worker clock unavailable"));
  return new Promise((resolve, reject) => {
    const id = ++nextClock;
    const before = now();
    const receive = (event: MessageEvent<{ t?: string; id?: number; at?: number }>): void => {
      if (event.data?.t !== "bench-clock" || event.data.id !== id || event.data.at === undefined) return;
      clearTimeout(timer); worker.removeEventListener("message", receive);
      resolve({ before, worker: event.data.at, after: now() });
    };
    const timer = setTimeout(() => { worker.removeEventListener("message", receive); reject(new Error("worker clock unavailable")); }, 3000);
    worker.addEventListener("message", receive); worker.postMessage({ t: "bench-clock", id });
  });
}
const probe = {
  call,
  stats: workerStats,
  workerClock,
  get session(): string | undefined { return session; },
  get sockets(): { opened: number; closed: number; history: SocketEvent[] } { return { opened: openedSockets, closed: closedSockets, history: socketEvents.slice() }; },
  take: () => ({ domInputs: domInputs.splice(0), inputs: inputs.splice(0), videos: videos.splice(0), events: events.splice(0), roundTrips: roundTrips.splice(0) }),
  arm: (id: number, crop: { colour: number; sequence: number }): void => { activeWorker?.postMessage({ t: "bench-arm", id, crop }); },
  close: (): void => { fixture?.dispose(); },
};
declare global { interface Window { __appWindowBench: typeof probe; __benchResourcesOnly?: boolean; __benchHardwareHint?: HardwareAcceleration } }
window.__appWindowBench = probe;
