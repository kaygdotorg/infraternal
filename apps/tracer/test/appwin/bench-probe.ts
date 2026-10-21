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
const videos: Array<{ at: number; captureNs: string; sequence: number; keyframe: boolean; bytes: number }> = [];
const events: unknown[] = [];
const roundTrips: Array<{ at: number; ms: number }> = [];
const errorNames = new Set(["Error", "TypeError", "ReferenceError", "SyntaxError", "RangeError", "DOMException"]);
const errorClasses = [
  ["data-clone", "DataCloneError"], ["not-supported", "NotSupportedError"], ["operation", "OperationError"],
  ["type", "TypeError"], ["reference", "ReferenceError"], ["syntax", "SyntaxError"], ["range", "RangeError"],
] as const;
const workerFunctions = new Set(["output", "pump", "chunk", "decodeUnit", "retireDecoder", "discardPending", "sendRepair", "repair"]);
// Browser error text can include machine paths; retain only bounded categories, static identifiers and coordinates.
function safeErrorReceipt(event: Event): { name: string; category: string; detail: string; function: string; source: string; line: number; column: number } {
  const value = event as ErrorEvent;
  const error = value.error as { name?: unknown; stack?: unknown } | null;
  const rawName = typeof error?.name === "string" ? error.name : "";
  const message = typeof value.message === "string" ? value.message : "";
  const match = errorClasses.find(([, candidate]) => rawName === candidate || message.includes(candidate));
  const read = message.match(/Cannot read properties of (undefined|null) \(reading '([A-Za-z_$][\w$]{0,39})'\)/);
  const write = message.match(/Cannot set properties of (undefined|null) \(setting '([A-Za-z_$][\w$]{0,39})'\)/);
  const detail = read ? `read-${read[1]}:${read[2]}` : write ? `write-${write[1]}:${write[2]}`
    : message.includes("is not a function") ? "not-callable" : message.includes("is not iterable") ? "not-iterable" : "other";
  const stack = typeof error?.stack === "string" ? error.stack : "";
  const functionName = [...stack.matchAll(/\bat ([A-Za-z_$][\w$]*)/g)].map((frame) => frame[1]!).find((name) => workerFunctions.has(name)) ?? "other";
  const source = value.filename.endsWith("decode.worker.on-demand.js") ? "decode-worker" : value.filename ? "other-script" : "unknown";
  return {
    name: errorNames.has(rawName) ? rawName : match?.[1] ?? "other",
    category: match?.[0] ?? (message === "Script error." ? "script" : "other"),
    detail,
    function: functionName,
    source,
    line: Number.isInteger(value.lineno) && value.lineno > 0 ? value.lineno : 0,
    column: Number.isInteger(value.colno) && value.colno > 0 ? value.colno : 0,
  };
}
window.addEventListener("error", (event) => limit(events, { t: "page-runtime-error", at: now(), ...safeErrorReceipt(event) }), true);
let activeWorker: Worker | undefined;
let session: string | undefined;
let openedSockets = 0;
let closedSockets = 0;
let nextSocket = 0;
let nextWorker = 0;
interface SocketEvent { at: number; socket: number; event: "open" | "close" | "client-close" | "server-close"; viewer: boolean; code?: number; reason?: string; clean?: boolean; probes?: { pending: Array<{ nonce: string; sentUs: string; ageMs: number }>; lastPongMs: number | null; lastInboundMs: number | null; bufferedBytes: number; hidden: boolean } }
const socketEvents: SocketEvent[] = [];

if (!window.__benchResourcesOnly) globalThis.WebSocket = class extends NativeSocket {
  private readonly outgoing = new WebSocketFrameDecoder();
  private readonly identity = ++nextSocket;
  private viewer = false;
  private readonly probes = new Map<bigint, { at: number; sentUs: bigint }>();
  private lastPong: number | undefined;
  private lastInbound: number | undefined;
  constructor(...args: ConstructorParameters<typeof WebSocket>) {
    super(...args);
    this.addEventListener("open", () => { openedSockets++; limit(socketEvents, { at: now(), socket: this.identity, event: "open", viewer: this.viewer }); });
    this.addEventListener("close", (event: CloseEvent) => { closedSockets++; limit(socketEvents, { at: now(), socket: this.identity, event: "close", viewer: this.viewer, code: event.code, reason: plainCloseReason(event.reason, "other"), clean: event.wasClean }); });
    const incoming = new WebSocketFrameDecoder();
    this.addEventListener("message", (event) => {
      if (!(event.data instanceof ArrayBuffer)) return;
      this.lastInbound = now();
      incoming.feed(new Uint8Array(event.data), (_stream, frame) => {
        if (frame.type === "Close" && _stream === 0) limit(socketEvents, { at: now(), socket: this.identity, event: "server-close", viewer: this.viewer, code: frame.code, reason: plainCloseReason(frame.reason, "other") });
        if (frame.type === "Pong") {
          const began = this.probes.get(frame.nonce);
          if (began !== undefined && began.sentUs === frame.sentUs) {
            this.lastPong = now();
            limit(roundTrips, { at: this.lastPong, ms: this.lastPong - began.at });
            // Match the connection's cumulative proof: a newer reply redeems
            // older unanswered probes too. Only actual outstanding waits count.
            for (const nonce of this.probes.keys()) if (nonce <= frame.nonce) this.probes.delete(nonce);
          }
        }
        if (frame.type === "Desktop" && frame.message.kind === "video") {
          const v = frame.message;
          limit(videos, { at: now(), captureNs: v.captureNs.toString(), sequence: Number(v.sequence), keyframe: v.keyframe, bytes: v.bytes.length });
        }
      });
    });
  }
  override close(code?: number, reason?: string): void {
    // Peer text never enters receipts: reuse the application's fixed reason map.
    const at = now();
    const probes = reason === "connection unresponsive" ? {
      pending: [...this.probes].map(([nonce, probe]) => ({ nonce: nonce.toString(), sentUs: probe.sentUs.toString(), ageMs: at - probe.at })),
      lastPongMs: this.lastPong === undefined ? null : at - this.lastPong,
      lastInboundMs: this.lastInbound === undefined ? null : at - this.lastInbound,
      bufferedBytes: this.bufferedAmount, hidden: document.hidden,
    } : undefined;
    limit(socketEvents, { at, socket: this.identity, event: "client-close", viewer: this.viewer, ...(code === undefined ? {} : { code }), reason: plainCloseReason(reason, "other"), ...(probes ? { probes } : {}) });
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
  private readonly identity = ++nextWorker;
  override postMessage(message: unknown, options?: Transferable[] | StructuredSerializeOptions): void {
    const value = message as { t?: string; sequence?: number; keyframe?: boolean; bytes?: ArrayBuffer; measure?: boolean };
    if (value?.t === "init" || value?.t === "reset" || value?.t === "close" || value?.t === "chunk") {
      limit(events, {
        t: "worker-send", worker: this.identity, message: value.t, at: now(),
        ...(value.t === "init" ? { measure: Boolean(value.measure) } : {}),
        ...(value.t === "chunk" ? { sequence: value.sequence, keyframe: Boolean(value.keyframe), bytes: value.bytes?.byteLength ?? 0 } : {}),
      });
    }
    const forwarded = value?.t === "init" && window.__benchHardwareHint ? { ...value, hardware: window.__benchHardwareHint } : message;
    if (Array.isArray(options)) super.postMessage(forwarded, options); else super.postMessage(forwarded, options);
  }
  constructor(...args: ConstructorParameters<typeof Worker>) {
    super(...args);
    limit(events, { t: "worker-create", worker: this.identity, at: now() });
    this.addEventListener("message", (event: MessageEvent<{ t?: string; width?: number; height?: number; reason?: string; frame?: unknown }>) => {
      const value = event.data;
      if (value?.t === "first") {
        activeWorker = this;
        limit(events, { t: "worker-first", worker: this.identity, at: now(), width: value.width, height: value.height });
      } else if (value?.t === "error") {
        const reasons = new Set(["decode", "unsupported-codec", "unsupported-canvas"]);
        limit(events, { t: "worker-error", worker: this.identity, at: now(), reason: reasons.has(value.reason ?? "") ? value.reason : "other" });
      } else if (value?.t === "trace") {
        limit(events, { ...value, worker: this.identity });
      } else if (value?.t?.startsWith("bench-") || value?.t === "size") {
        limit(events, { ...value, worker: this.identity });
      }
    });
    this.addEventListener("error", (event) => limit(events, { t: "worker-runtime-error", worker: this.identity, at: now(), ...safeErrorReceipt(event) }));
    this.addEventListener("messageerror", () => limit(events, { t: "worker-message-error", worker: this.identity, at: now() }));
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
  arm: (id: number, crop: { colour: number; sequence: number; projection?: { width: number; height: number; colourX: number; colourY: number; markerX: number; markerY: number; cell: number } }): void => { activeWorker?.postMessage({ t: "bench-arm", id, crop }); },
  close: (): void => { fixture?.dispose(); },
};
declare global { interface Window { __appWindowBench: typeof probe; __benchResourcesOnly?: boolean; __benchHardwareHint?: HardwareAcceleration } }
window.__appWindowBench = probe;
