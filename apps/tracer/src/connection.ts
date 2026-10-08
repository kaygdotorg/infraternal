/**
 * One WebSocket, many terminal streams (D11, D183): the multiplexed connection to the server.
 *
 * The connection owns everything that belongs to the socket and not to one terminal:
 * - the handshake (`Hello`, `Welcome`) and resume (`RESUME_NEXT` + `Resume` after a drop, within the window the
 *   server stated), with the credentials kept in memory only and wiped when replaced;
 * - the control stream (0): actions as `Call`/`Result`, the account's recovery notices, and pings;
 * - the stream table: odd stream ids are the client's, one per terminal, allocated by `openStream`; frames are
 *   dispatched to the stream's handler by id, so the hot path (decode, then hand the frame over) does not change;
 * - reconnecting with backoff, forced drops for the resume probe, and protocol failures.
 *
 * A terminal (`TerminalClient`) keeps its own cursors (output, input, acknowledged input) and re-attaches itself
 * with them on every welcome, so a reconnect restores every stream independently. Closing a stream detaches it
 * and never ends the session.
 *
 * Round trips: pings are sampled on attachment and on typing, at most one per 2 s, and only while a stream is
 * attached; an idle connection schedules no wakeups [81].
 */
import {
  WebSocketFrameDecoder,
  encodeMuxedFrameInto,
  type WireFrame,
} from "../../../packages/protocol/src/codec";

export const CONTROL_STREAM = 0;

/**
 * The server answered an action with a refusal: it does not exist here, the person may not run it, or it could not
 * be done. `reason` is the server's short, generic word for it (`forbidden`, `conflict`, `not found`, ...) when it
 * sent one; it never carries input or internal detail.
 */
export class ActionRefused extends Error {
  constructor(message = "the server refused the action", readonly reason?: string) { super(message); this.name = "ActionRefused"; }
}
/**
 * The server keeps a writer row for every stream that ever attached on a connection and allows 32. A closed window
 * frees no row, so a page that opens and closes windows for hours would hit the cap. Before that, the connection
 * starts a fresh one (see `openStream`); the open streams re-attach from the start, as a reload would.
 */
const WRITER_ROTATE_AT = 28;
const VERSION = 1;
const SEND_BUFFER_SIZE = 32 * 1024;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const RECOVERY_SUBSCRIPTION = 45;
/** Ids for subscriptions that features open through `subscribe` (the recovery notice keeps its own). */
const FIRST_FEATURE_SUBSCRIPTION = 64;

/** A feature's live subscription: the server pushes `Event` frames for `filter`; resent on every welcome. */
interface Subscription {
  filter: { topic: string };
  onEvent(event: Record<string, unknown>): void;
  /** The subscription is (re)established: the owner refetches its snapshot, since events may have been missed. */
  onOpen?: (() => void) | undefined;
}
const encoder = new TextEncoder();

/** What a stream gives the connection. All callbacks run on the socket's event task. */
export interface StreamHandler {
  /** The socket opened. `resuming` is true when a resume was sent: the stream may attach at once. */
  onSocketOpen(resuming: boolean): void;
  /**
   * The server welcomed this connection: attach, or open a session first. `resumed` is false for a connection the
   * server does not know yet, even when the stream attached before: its cursors are then stale and must restart.
   */
  onWelcome(resumed: boolean): void;
  /** A frame for this stream. `message` keeps the decoder's view alive for unfragmented frames. */
  onFrame(frame: WireFrame, message: Uint8Array, receivedAt: number): void;
  /** The socket closed. `forced` is true after `forceDrop`. */
  onDisconnected(forced: boolean): void;
  /** True when the stream owns a session that a resume should restore. */
  hasSession(): boolean;
  /** The connection failed in a way the person should see (a protocol error, a closed connection). */
  onStatus(message: string): void;
}

export interface ConnectionConfig {
  /** Asks the server to trace frames (mock server only). */
  traceMockServer?: boolean;
  /** The account's recovery notice changed (`undefined`: none pending). */
  onRecoveryPending?: (readyAt: number | undefined) => void;
  /** Connection state: true once a stream attached, false when the socket closes. */
  onConnectionChange?: (connected: boolean) => void;
}

interface ResumeCredentials { connectionId: Uint8Array; resumeToken: Uint8Array; deadline: number }

export class MuxConnection {
  private socket: WebSocket | undefined;
  private decoder: WebSocketFrameDecoder | undefined;
  private credentials: ResumeCredentials | undefined;
  private readonly streams = new Map<number, StreamHandler>();
  private readonly calls = new Map<number, { resolve(value: Record<string, unknown>): void; reject(error: Error): void }>();
  private readonly rttListeners = new Set<(ms: number | undefined) => void>();
  private readonly pendingPings = new Map<bigint, number>();
  private readonly subscriptions = new Map<number, Subscription>();
  private readonly welcomeListeners = new Set<() => void>();
  private nextSubscription = FIRST_FEATURE_SUBSCRIPTION;
  private readonly sendScratch = new Uint8Array(SEND_BUFFER_SIZE);
  private nextStream = 1;
  private nextCall = 1;
  private nextPingNonce = 0n;
  private lastPingAt = -Infinity;
  private retryTimer = 0;
  private retryAttempt = 0;
  private forcedDrop = false;
  private closed = false;
  private welcomed = false;
  private resumeSent = false;
  private attachedCount = 0;
  /** Streams that attached on this server-side connection: the server keeps a writer row for each, up to its cap. */
  private readonly writersUsed = new Set<number>();

  constructor(private readonly config: ConnectionConfig = {}) {}

  get isOpen(): boolean { return this.socket?.readyState === WebSocket.OPEN; }
  /** True once the server welcomed the current socket. */
  get isWelcomed(): boolean { return this.welcomed && this.isOpen; }
  get streamCount(): number { return this.streams.size; }

  /** Registers a stream and returns its id; the first stream starts the connection. */
  openStream(handler: StreamHandler): number {
    const id = this.nextStream;
    this.nextStream += 2;
    this.streams.set(id, handler);
    if (this.writersUsed.size >= WRITER_ROTATE_AT && this.socket) {
      // Forget the resume credentials so the next socket is a new connection with an empty writer table.
      this.credentials?.connectionId.fill(0);
      this.credentials?.resumeToken.fill(0);
      this.credentials = undefined;
      this.socket.close(4001, "tracer connection rotation");
      return id;
    }
    if (!this.socket && !this.closed) this.connect();
    else if (this.isWelcomed) handler.onWelcome(true);
    return id;
  }

  /** Detaches a stream (the session keeps running). The connection stays up for the others. */
  closeStream(id: number): void {
    if (!this.streams.delete(id)) return;
    this.send(id, { type: "Close", code: 1000, reason: "window closed" });
  }

  /** Sends one frame on a stream. Frames are dropped while the socket is not open (the stream resends on attach). */
  send(streamId: number, frame: WireFrame, onEncoded?: (at: number) => void, onSent?: (at: number) => void): void {
    const socket = this.socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) return;
    try {
      const length = encodeMuxedFrameInto(streamId, frame, this.sendScratch);
      onEncoded?.(performance.now());
      socket.send(this.sendScratch.subarray(0, length));
      onSent?.(performance.now());
    } catch {
      this.fail("could not encode an infraternal wire frame");
    }
  }

  /** Runs a control-stream action. Rejects when the server refuses or the socket drops first. */
  call(actionId: string, input: Record<string, unknown>): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      const callId = this.nextCall++;
      this.calls.set(callId, { resolve, reject });
      this.send(CONTROL_STREAM, { type: "Call", callId, actionId, inputJson: encoder.encode(JSON.stringify(input)) });
    });
  }

  /**
   * Subscribes to a topic of server events (contracts/plugin.md §5). The subscription is sent again after every
   * welcome (a new socket has none), and `onOpen` runs each time so the owner can resync: events sent while the
   * socket was down are not replayed. Returns the unsubscribe function.
   */
  subscribe(filter: { topic: string }, onEvent: (event: Record<string, unknown>) => void, onOpen?: () => void): () => void {
    const subId = this.nextSubscription++;
    this.subscriptions.set(subId, { filter, onEvent, onOpen });
    if (this.isWelcomed) this.openSubscription(subId);
    return () => { this.subscriptions.delete(subId); };
  }

  /**
   * Runs `listener` now if the socket is welcomed, and after every later welcome (a reconnect). A feature that must
   * not subscribe before it knows the server serves it (an unknown subscription closes the socket) starts here
   * with a plain call, and subscribes only once the call is answered.
   */
  onWelcome(listener: () => void): () => void {
    this.welcomeListeners.add(listener);
    if (this.isWelcomed) listener();
    return () => { this.welcomeListeners.delete(listener); };
  }

  /** Sends one subscription's filter (first connect and each reconnect) and lets its owner resync. */
  private openSubscription(subId: number): void {
    const sub = this.subscriptions.get(subId);
    if (!sub) return;
    this.send(CONTROL_STREAM, { type: "Subscribe", subId, filterJson: encoder.encode(JSON.stringify(sub.filter)) });
    sub.onOpen?.();
  }

  /** A stream attached (true) or detached (false): drives the connection indicator. */
  streamAttached(attached: boolean, streamId?: number): void {
    if (attached && streamId !== undefined) this.writersUsed.add(streamId);
    this.attachedCount = Math.max(0, this.attachedCount + (attached ? 1 : -1));
    if (attached) this.config.onConnectionChange?.(true);
  }

  onRoundTrip(listener: (ms: number | undefined) => void): () => void {
    this.rttListeners.add(listener);
    return () => { this.rttListeners.delete(listener); };
  }

  /** Samples the round trip: at most one ping per 2 s, only while something is attached. */
  sampleRoundTrip(): void {
    const startedAt = performance.now();
    if (this.attachedCount === 0 || this.closed || startedAt - this.lastPingAt < 2000) return;
    this.lastPingAt = startedAt;
    this.nextPingNonce = this.nextPingNonce >= MAX_U64 ? 1n : this.nextPingNonce + 1n;
    const nonce = this.nextPingNonce;
    if (this.pendingPings.size >= 8) {
      const oldest = this.pendingPings.keys().next().value as bigint | undefined;
      if (oldest !== undefined) this.pendingPings.delete(oldest);
    }
    this.pendingPings.set(nonce, startedAt);
    this.send(CONTROL_STREAM, { type: "Ping", nonce, sentUs: BigInt(Math.round(startedAt * 1000)) });
  }

  /** A pong arrived (on any stream). */
  acceptPong(nonce: bigint): void {
    const startedAt = this.pendingPings.get(nonce);
    if (startedAt === undefined) return;
    this.pendingPings.delete(nonce);
    const ms = Math.max(1, performance.now() - startedAt);
    for (const l of this.rttListeners) l(ms);
  }

  /** Forces a WebSocket close for the opt-in resume probe. */
  forceDrop(): void {
    this.forcedDrop = true;
    this.socket?.close(4000, "tracer resume probe");
  }

  /** Closes the socket so the connection restarts (every stream re-attaches on the next welcome). */
  forceClose(): void {
    this.socket?.close();
  }

  /** Reports a violation of the wire contract and closes the socket (the browser rejects 1002 from script, so 4002). */
  fail(message: string): void {
    for (const s of this.streams.values()) s.onStatus(`Terminal protocol error: ${message}.`);
    try { this.socket?.close(4002, "invalid tracer frame"); } catch { this.socket?.close(); }
  }

  dispose(): void {
    if (this.closed) return;
    this.closed = true;
    window.clearTimeout(this.retryTimer);
    this.resetPings();
    for (const call of this.calls.values()) call.reject(new Error("connection closed"));
    this.calls.clear();
    this.credentials?.connectionId.fill(0);
    this.credentials?.resumeToken.fill(0);
    this.config.onConnectionChange?.(false);
    this.socket?.close(1000, "terminal closed");
    this.streams.clear();
  }

  private status(message: string): void {
    for (const s of this.streams.values()) s.onStatus(message);
  }

  private connect(): void {
    if (this.closed) return;
    const resuming = [...this.streams.values()].some((s) => s.hasSession());
    this.status(resuming ? "Connection lost; resuming…" : "Connecting…");
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const traceQuery = this.config.traceMockServer ? "?trace=1" : "";
    const socket = new WebSocket(`${protocol}//${location.host}/v1/ws${traceQuery}`);
    socket.binaryType = "arraybuffer";
    this.socket = socket;
    this.decoder = new WebSocketFrameDecoder();
    this.welcomed = false;

    socket.onopen = () => {
      const credentials = this.credentials;
      const sessionsToResume = [...this.streams.values()].some((s) => s.hasSession());
      const resumable = sessionsToResume && credentials !== undefined && Date.now() < credentials.deadline;
      this.resumeSent = resumable;
      // RESUME_NEXT tells the server to wait for the adjacent Resume before issuing Welcome.
      const hello: WireFrame = { type: "Hello", version: VERSION, caps: resumable ? 1n : 0n, clientInfo: "infraternal-tracer/0.1" };
      let length = encodeMuxedFrameInto(CONTROL_STREAM, hello, this.sendScratch);
      if (resumable && credentials) {
        length += encodeMuxedFrameInto(CONTROL_STREAM, { type: "Resume", connectionId: credentials.connectionId, resumeToken: credentials.resumeToken }, this.sendScratch, length);
      }
      socket.send(this.sendScratch.subarray(0, length));
      for (const s of [...this.streams.values()]) s.onSocketOpen(resumable);
    };
    socket.onmessage = (event: MessageEvent<ArrayBuffer>) => {
      const receivedAt = performance.now();
      if (!(event.data instanceof ArrayBuffer)) { this.fail("server sent a non-binary frame"); return; }
      try {
        const message = new Uint8Array(event.data);
        this.decoder?.feed(message, (streamId, frame) => this.dispatch(streamId, frame, message, receivedAt));
      } catch {
        this.fail("server sent an invalid wire frame");
      }
    };
    socket.onerror = () => this.status("Connection interrupted; reconnecting…");
    socket.onclose = () => {
      if (this.socket !== socket || this.closed) return;
      this.socket = undefined;
      this.decoder = undefined;
      this.welcomed = false;
      this.attachedCount = 0;
      this.config.onConnectionChange?.(false);
      this.resetPings();
      for (const call of this.calls.values()) call.reject(new Error("connection lost"));
      this.calls.clear();
      const forced = this.forcedDrop;
      this.forcedDrop = false;
      for (const s of [...this.streams.values()]) s.onDisconnected(forced);
      this.status("Connection lost; resuming…");
      // With no stream left there is nothing to restore; the next `openStream` connects again.
      if (this.streams.size > 0) this.scheduleReconnect();
    };
  }

  private dispatch(streamId: number, frame: WireFrame, message: Uint8Array, receivedAt: number): void {
    if (streamId === CONTROL_STREAM) { this.control(frame); return; }
    const handler = this.streams.get(streamId);
    if (!handler) {
      // A frame for a stream that was just closed is expected once; anything else is a contract violation.
      if (streamId % 2 === 1 && streamId < this.nextStream) return;
      this.fail("server used an unexpected stream id");
      return;
    }
    handler.onFrame(frame, message, receivedAt);
  }

  private control(frame: WireFrame): void {
    switch (frame.type) {
      case "Hello":
        if (frame.version !== VERSION) this.fail("server uses an unsupported wire version");
        return;
      case "Welcome":
        this.send(CONTROL_STREAM, { type: "Subscribe", subId: RECOVERY_SUBSCRIPTION, filterJson: encoder.encode(JSON.stringify({ topic: "auth.recovery" })) });
        this.credentials?.connectionId.fill(0);
        this.credentials?.resumeToken.fill(0);
        this.credentials = {
          connectionId: frame.connectionId.slice(),
          resumeToken: frame.resumeToken.slice(),
          deadline: Date.now() + frame.resumeWindowSeconds * 1000,
        };
        this.welcomed = true;
        this.retryAttempt = 0;
        for (const subId of [...this.subscriptions.keys()]) this.openSubscription(subId);
        for (const l of [...this.welcomeListeners]) l();
        if (!this.resumeSent) this.writersUsed.clear();
        for (const s of [...this.streams.values()]) s.onWelcome(this.resumeSent);
        return;
      case "Result": {
        const pending = this.calls.get(frame.callId);
        if (!pending) { this.fail("server returned an unexpected action result"); return; }
        this.calls.delete(frame.callId);
        if (!frame.ok) { pending.reject(new ActionRefused(undefined, refusalReason(frame.json))); return; }
        try {
          pending.resolve(asRecord(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(frame.json)) as unknown));
        } catch { pending.reject(new Error("the server returned an unreadable result")); }
        return;
      }
      case "Event": {
        const feature = this.subscriptions.get(frame.subId);
        if (feature) {
          // A feature's events are its own to validate; a malformed one must not take the connection down.
          try { feature.onEvent(asRecord(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(frame.eventJson)) as unknown)); } catch { /* ignored: the owner resyncs on the next snapshot */ }
          return;
        }
        if (frame.subId !== RECOVERY_SUBSCRIPTION) return;
        try {
          const event = asRecord(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(frame.eventJson)) as unknown);
          if (event.topic !== "auth.recovery") throw new Error("unexpected recovery topic");
          const readyAt = event.pending === null ? undefined : asRecord(event.pending).ready_at;
          if (event.pending !== null && (typeof readyAt !== "number" || !Number.isSafeInteger(readyAt) || readyAt < 0)) throw new Error("invalid recovery deadline");
          this.config.onRecoveryPending?.(readyAt as number | undefined);
        } catch { this.fail("server returned invalid recovery state"); }
        return;
      }
      case "Ping":
        this.send(CONTROL_STREAM, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs });
        return;
      case "Pong":
        this.acceptPong(frame.nonce);
        return;
      case "Close":
        this.status(frame.reason || "The server closed the connection.");
        this.socket?.close();
        return;
      default:
        this.fail("server sent a terminal frame on the control stream");
    }
  }

  private scheduleReconnect(): void {
    if (this.closed || this.retryTimer !== 0) return;
    const delay = Math.min(1000, 50 * 2 ** Math.min(this.retryAttempt, 4));
    this.retryAttempt += 1;
    this.retryTimer = window.setTimeout(() => { this.retryTimer = 0; this.connect(); }, delay);
  }

  private resetPings(): void {
    this.lastPingAt = -Infinity;
    this.pendingPings.clear();
    for (const l of this.rttListeners) l(undefined);
  }
}

/** The `error` word of a refusal body (`{"error":"forbidden"}`), if the body is one. */
function refusalReason(body: Uint8Array): string | undefined {
  try {
    const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)) as unknown;
    const reason = typeof parsed === "object" && parsed !== null ? (parsed as { error?: unknown }).error : undefined;
    return typeof reason === "string" && reason.length <= 64 ? reason : undefined;
  } catch { return undefined; }
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("result is not an object");
  return value as Record<string, unknown>;
}
