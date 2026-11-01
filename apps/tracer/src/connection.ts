/**
 * One WebSocket, many terminal streams (D11, D183): the multiplexed connection to the server.
 *
 * The connection owns everything that belongs to the socket and not to one terminal:
 * - the handshake (`Hello`, `Welcome`) and resume (`RESUME_NEXT` + `Resume` after a drop, within the window the
 *   server stated), with the credentials kept in memory only and wiped when replaced;
 * - the control stream (0): actions as `Call`/`Result`, the account's recovery notices, and pings;
 * - the stream table: odd stream ids are the client's, one per terminal, allocated by `openStream`; frames are
 *   dispatched to the stream's handler by id, so the hot path (decode, then hand the frame over) does not change;
 * - reconnecting with a bounded, jittered exponential backoff, forced drops for the resume probe, and protocol
 *   failures. A previously attached session gets one quick retry; repeated short-lived resumes then use backoff
 *   until a socket stays up long enough to prove recovery. Local probe expiry records its reason before retiring
 *   the route, because its close event arrives after the socket has already been replaced.
 *
 * A terminal (`TerminalClient`) keeps its own cursors (output, input, acknowledged input) and re-attaches itself
 * with them on every welcome, so a reconnect restores every stream independently. Closing a stream detaches it
 * and never ends the session.
 *
 * Liveness [D265]: bounded probes expire an open but unusable route. Disconnect notification runs before
 * closing the socket: an intermediary may never deliver its close event. Streams retain unacknowledged input.
 */
import { noteWsMessage } from "./perf-activity";
import { CloseNotes, plainCloseReason } from "./close-reasons";
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
  constructor(message = "the server refused the action", readonly reason?: string, readonly memory?: { availableMiB: number; sessionCount: number }) { super(message); this.name = "ActionRefused"; }
}
/**
 * The server keeps a writer row for every stream that ever attached on a connection and allows 32. A closed window
 * frees no row, so a page that opens and closes windows for hours would hit the cap. Before that, the connection
 * starts a fresh one (see `openStream`); the open streams re-attach from the start, as a reload would.
 */
const WRITER_ROTATE_AT = 28;
/**
 * Terminals one socket carries. The server accepts 32 attachments per socket and refuses the rest, so a page with more
 * windows than that must not put them on one socket: with 54 windows on one, every connect attached 32 and failed the
 * rest, the connection rotated, and the page reconnected about once a second, re-attaching and re-painting every
 * window each time (165 sockets in three minutes, 270 ms of main-thread CPU per second at idle). Fewer than the cap
 * leaves room for the rotation above.
 */
export const STREAMS_PER_SOCKET = 28;
/** Reconnect pauses: the first retry is quick (a dropped mobile link), repeats double up to the ceiling. */
const RECONNECT_FIRST_MS = 50;
const RECONNECT_CEILING_MS = 5000;
/** A socket that stayed welcomed this long ended for a new reason; the next reconnect is quick again. */
export const STABLE_CONNECTION_MS = 10_000;

/** Socket and shared-stream retries use the same bounded steps and positive jitter (#158). */
export function reconnectDelay(attempt: number): number {
  const step = Math.min(RECONNECT_CEILING_MS, RECONNECT_FIRST_MS * 2 ** Math.min(attempt, 10));
  return step + Math.random() * (step / 2);
}
const LIVENESS_TICK_MS = 25;
// Idle waits for its correlated answer before sampling again. Ten milliseconds
// after that answer leaves forty of the RTT + 50ms budget for scheduling jitter.
const IDLE_PROBE_PAUSE_MS = 10;
const MAX_SOCKETS = 12;
const VERSION = 1;
/** Hello caps bit 0: a Resume follows this Hello. */
const RESUME_NEXT = 1n;
/** Hello caps bit 1: this viewer understands the kept-link doubt notices (contracts/wire.md, D300). */
const LINK_DOUBT_NOTICES = 2n;
/** Hello bit 2: control Event 0 reports page visibility (#244). */
const VIEWER_VISIBILITY = 4n;
/** Hello caps bit 4: request the layout session-incarnation Welcome suffix (contracts/wire.md, D312). */
export const LAYOUT_SESSION_INCARNATION = 1n << 4n;
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
/** Refresh keeps the subscription ID, so retries replace its bounded server slot. */
export type SubscriptionHandle = (() => void) & { resync(): void };
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
  /** Original authenticated lifetime, supplied before the first WebSocket handshake. */
  sessionIncarnation?: string;
  /** Asks the server to trace frames (mock server only). */
  traceMockServer?: boolean;
  /** The account's recovery notice changed (`undefined`: none pending). */
  onRecoveryPending?: (readyAt: number | undefined) => void;
  /** Connection state: true once a stream attached, false when the socket closes. */
  onConnectionChange?: (connected: boolean) => void;
}

interface ResumeCredentials { connectionId: Uint8Array; resumeToken: Uint8Array; deadline: number; windowMs: number }

export class MuxConnection {
  private socket: WebSocket | undefined;
  private decoder: WebSocketFrameDecoder | undefined;
  private credentials: ResumeCredentials | undefined;
  private readonly streams = new Map<number, StreamHandler>();
  private readonly calls = new Map<number, { resolve(value: Record<string, unknown>): void; reject(error: Error): void }>();
  private readonly rttListeners = new Set<(ms: number | undefined) => void>();
  private readonly pendingPings = new Map<bigint, number>();
  private livenessTimer = 0;
  /** Keep the socket-task confirmation alive while input or probe activity reschedules liveness. */
  private livenessConfirmationPending = false;
  /** Identify its arming route; a cleared timer may already be queued when a replacement route starts. */
  private livenessConfirmationToken = 0;
  /** A delayed browser task is local uncertainty, never evidence that the peer stopped answering (#245). */
  private livenessDueAt = Infinity;
  private lastLivenessStallAt = -Infinity;
  /** One local-stall grace per peer reply; callbacks alone cannot renew it (#245). */
  private stallGraceUsed = false;
  /** One post-stall miss interval, separate from D300's two-miss deadline. */
  private livenessStallGraceAt = -Infinity;
  private lastPongAt = 0;
  private fastProbeUntil = 0;
  private readonly unacknowledgedInput = new Map<number, bigint>();
  // Unknown startup RTT uses the same bounded two-second grace as native routes.
  // Once sampled, smoothed RTT and variation tolerate local scheduling stalls.
  private livenessRtt: number | undefined;
  // Keep the existing link-doubt signal independent of the response estimator,
  // so smoothing the deadline does not change healthy-idle probe frequency.
  private livenessSrtt: number | undefined;
  private livenessRttvar = 0;
  private lastRttReportAt = -Infinity;
  private readonly subscriptions = new Map<number, Subscription>();
  private readonly welcomeListeners = new Set<() => void>();
  private readonly attachListeners = new Set<() => void>();
  private nextSubscription = FIRST_FEATURE_SUBSCRIPTION;
  private readonly sendScratch = new Uint8Array(SEND_BUFFER_SIZE);
  private nextStream = 1;
  private nextCall = 1;
  private nextPingNonce = 0n;
  private lastPingAt = -Infinity;
  private retryTimer = 0;
  private retryAttempt = 0;
  /** Server refusals remain failures even when browser network hints lag. */
  private refusalBackoff = false;
  private readonly closeNotes = new CloseNotes();
  /** The console summary's timer. It runs on the global timer, apart from the reconnect schedule on `window`. */
  private closeNoteTimer: ReturnType<typeof setTimeout> | undefined;
  /** A confirmed terminal gets one quick retry; repeated short-lived resumes retain backoff [D259]. */
  private fastRecovery = false;
  /** When the current socket was welcomed (`performance.now()`), for the backoff's reset. */
  private welcomedAt = 0;
  /** Retry hints stay installed from a reconnect timer until the next Welcome. */
  private retryHintListeners = false;
  private readonly onNetworkAvailable = (): void => this.retryNow();
  private readonly onPageVisible = (): void => { if (document.visibilityState === "visible") this.retryNow(); };
  private forcedDrop = false;
  private closed = false;
  private welcomed = false;
  private resumeSent = false;
  private serverVisibility = false;
  private attachedCount = 0;
  /** Streams that attached on this server-side connection: the server keeps a writer row for each, up to its cap. */
  private readonly writersUsed = new Set<number>();
  /** Streams that sent AttachTerm on the current WebSocket; resume retains writers but replaces attachments. */
  private readonly attachedOnSocket = new Set<number>();

  private readonly onVisibility = (): void => this.pageVisibilityChanged();

  constructor(private readonly config: ConnectionConfig = {}) {
    this.sessionIncarnation = config.sessionIncarnation;
    if (typeof document !== "undefined" && typeof document.addEventListener === "function") document.addEventListener("visibilitychange", this.onVisibility);
  }

  /** Visibility is transport state, independent of terminal and authentication state. */
  private pageVisibilityChanged(): void {
    if (this.closed) return;
    // A retry armed before hiding must also park; its foreground hint stays installed.
    if (this.pageHidden()) this.clearRetryTimer();
    if (!this.isWelcomed) return;
    this.resetPings(true);
    this.livenessRtt = undefined;
    this.livenessSrtt = undefined;
    this.livenessRttvar = 0;
    if (this.serverVisibility) this.send(CONTROL_STREAM, { type: "Event", subId: 0, eventJson: encoder.encode(JSON.stringify({ topic: "connection.visibility", hidden: this.pageHidden() })) });
    this.scheduleLiveness();
  }

  private pageHidden(): boolean {
    return typeof document !== "undefined" && document.hidden === true;
  }

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
      this.retryAttempt = 0;
      this.socket.close(4001, "tracer connection rotation");
      return id;
    }
    if (!this.socket && !this.closed) this.connect();
    // The caller learns its stream id from the return value, so the handler must not run before it has it: a terminal
    // attached from inside this call sent AttachTerm on stream 0 (the control stream), and the server closed the
    // socket (#128). One microtask later the handler runs, still before anything is painted.
    else if (this.isWelcomed) queueMicrotask(() => { if (this.streams.get(id) === handler && this.isWelcomed) handler.onWelcome(true); });
    return id;
  }

  /** Detaches a stream (the session keeps running). The connection stays up for the others. */
  closeStream(id: number): void {
    if (!this.streams.delete(id)) return;
    this.unacknowledgedInput.delete(id);
    // A retained writer can belong to the resumed connection's old socket; Close requires a new AttachTerm first.
    if (this.attachedOnSocket.delete(id)) this.send(id, { type: "Close", code: 1000, reason: "window closed" });
  }

  /** Sends one frame on a stream. Frames are dropped while the socket is not open (the stream resends on attach). */
  send(streamId: number, frame: WireFrame, onEncoded?: (at: number) => void, onSent?: (at: number) => void): void {
    const socket = this.socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) return;
    try {
      const length = encodeMuxedFrameInto(streamId, frame, this.sendScratch);
      // Even an attachment closed before replay completes retains a server writer row.
      if (frame.type === "AttachTerm") this.writersUsed.add(streamId);
      if (frame.type === "Input" && frame.replyTo === undefined && this.streams.has(streamId)) {
        const end = frame.inSeq + BigInt(frame.bytes.byteLength);
        const previous = this.unacknowledgedInput.get(streamId) ?? 0n;
        // Replayed earlier bytes cannot lower the outstanding input watermark.
        this.unacknowledgedInput.set(streamId, end > previous ? end : previous);
        this.fastProbeUntil = performance.now() + 250;
        this.scheduleLiveness();
      }
      onEncoded?.(performance.now());
      socket.send(this.sendScratch.subarray(0, length));
      // Server writer identity survives resume, but the attached route is recreated on each WebSocket.
      if (frame.type === "AttachTerm") this.attachedOnSocket.add(streamId);
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
  subscribe(filter: { topic: string }, onEvent: (event: Record<string, unknown>) => void, onOpen?: () => void): SubscriptionHandle {
    const subId = this.nextSubscription++;
    this.subscriptions.set(subId, { filter, onEvent, onOpen });
    if (this.isWelcomed) this.openSubscription(subId);
    // Account state must load before any terminal window exists (D248).
    if (!this.socket && !this.closed) this.connect();
    return Object.assign(() => { this.subscriptions.delete(subId); }, {
      resync: () => { if (this.isWelcomed) this.openSubscription(subId); },
    });
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

  /**
   * Runs `listener` once a terminal stream is attached (now, if one is), and again after every reattach following a
   * reconnect. Work that is not the terminal's (the Mesh) starts here, so the terminal never waits for it: it is
   * the person's shell that must come up first, and a feature's failure never delays it.
   */
  onTerminalAttached(listener: () => void): () => void {
    this.attachListeners.add(listener);
    if (this.isWelcomed && this.attachedCount > 0) listener();
    return () => { this.attachListeners.delete(listener); };
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
    if (attached) { this.config.onConnectionChange?.(true); for (const l of [...this.attachListeners]) l(); }
  }

  onRoundTrip(listener: (ms: number | undefined) => void): () => void {
    this.rttListeners.add(listener);
    return () => { this.rttListeners.delete(listener); };
  }

  /** Probe at the existing cadence; correlated RTT and jitter bound silence [D265, #199]. */
  sampleRoundTrip(urgent = true): void {
    const startedAt = performance.now();
    if (!this.isWelcomed || this.closed || this.pageHidden()) return;
    this.accountLivenessDelay(startedAt);
    if (urgent) {
      this.fastProbeUntil = startedAt + 250;
      this.scheduleLiveness();
    }
    const dueAt = this.nextProbeAt();
    if (startedAt < dueAt) return;
    this.lastPingAt = startedAt;
    this.nextPingNonce = this.nextPingNonce >= MAX_U64 ? 1n : this.nextPingNonce + 1n;
    const nonce = this.nextPingNonce;
    // A delayed local timer cannot prove peer loss before there is a probe to answer.
    // Start a deadline only when the fully answered route issues its next probe.
    if (this.pendingPings.size === 0) {
      // Start the response allowance at actual issuance, including after a
      // delayed local callback. Further sends cannot move an outstanding lease.
      this.lastPongAt = startedAt;
    }
    if (this.pendingPings.size >= 128) {
      const oldest = this.pendingPings.keys().next().value as bigint | undefined;
      if (oldest !== undefined) this.pendingPings.delete(oldest);
    }
    this.pendingPings.set(nonce, startedAt);
    this.send(CONTROL_STREAM, { type: "Ping", nonce, sentUs: BigInt(Math.round(startedAt * 1000)) });
  }

  /** A pong arrived (on any stream). */
  acceptPong(nonce: bigint, sentUs: bigint): void {
    if (this.pageHidden()) return;
    const startedAt = this.pendingPings.get(nonce);
    if (startedAt === undefined || sentUs !== BigInt(Math.round(startedAt * 1000))) return;
    const now = performance.now();
    this.accountLivenessDelay(now);
    // Either task source can run first after a stall. A known local stall or
    // expired response deadline keeps the queued reply from training RTT.
    const delayed = startedAt <= this.lastLivenessStallAt || now >= this.responseDeadline();
    // A reply proves this direction works; discard older unanswered probes too.
    for (const key of this.pendingPings.keys()) { if (key <= nonce) this.pendingPings.delete(key); }
    this.lastPongAt = now;
    this.livenessStallGraceAt = -Infinity;
    this.stallGraceUsed = false;
    if (delayed) { this.scheduleLiveness(); return; }
    const ms = Math.max(1, now - startedAt);
    if (this.livenessRtt !== undefined && ms > this.livenessRtt + 5) this.fastProbeUntil = now + Math.max(250, ms * 2);
    // Variation uses the previous smoothed RTT; only correlated replies train it.
    this.livenessRttvar = this.livenessSrtt === undefined ? ms / 2 : this.livenessRttvar * 0.75 + Math.abs(this.livenessSrtt - ms) * 0.25;
    this.livenessSrtt = this.livenessSrtt === undefined ? ms : this.livenessSrtt * 0.875 + ms * 0.125;
    this.livenessRtt = Math.max(ms, this.livenessRtt === undefined ? ms : this.livenessRtt * 0.95);
    this.scheduleLiveness();
    // Probe frequency must not drive DOM/prediction updates more often than the former sampling cadence.
    if (this.lastPongAt - this.lastRttReportAt >= 2000) {
      this.lastRttReportAt = this.lastPongAt;
      for (const l of this.rttListeners) l(ms);
    }
  }

  /** Forces a WebSocket close for the opt-in resume probe. */
  forceDrop(): void {
    const socket = this.socket;
    if (!socket) return;
    this.forcedDrop = true;
    this.disconnect(socket);
    socket.close(4000, "tracer resume probe");
  }

  /** Closes the socket so the connection restarts (every stream re-attaches on the next welcome). */
  /** Closes the socket for a close the server named; `code` and `reason` are that close, for the console line. */
  forceClose(code?: number, reason?: string): void {
    const socket = this.socket;
    if (!socket) return;
    this.noteClose(code, reason, "the server");
    this.forgetRefusedResume(code, reason);
    this.disconnect(socket);
    socket.close();
  }

  /** Reports a violation of the wire contract and closes the socket (the browser rejects 1002 from script, so 4002). */
  fail(message: string): void {
    const socket = this.socket;
    if (socket) {
      this.noteClose(4002, "", "this page");
      this.disconnect(socket);
    }
    this.status("The connection sent something unexpected and was closed. Reconnecting…");
    try { socket?.close(4002, "invalid tracer frame"); } catch { socket?.close(); }
  }

  dispose(): void {
    if (this.closed) return;
    this.closed = true;
    this.clearRetryTimer();
    globalThis.clearTimeout(this.closeNoteTimer);
    this.closeNoteTimer = undefined;
    this.stopRetryHintListeners();
    if (typeof document !== "undefined" && typeof document.removeEventListener === "function") document.removeEventListener("visibilitychange", this.onVisibility);
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
    this.clearRetryTimer();
    const resuming = [...this.streams.values()].some((s) => s.hasSession());
    this.status(resuming ? "Connection lost. Reconnecting…" : "Connecting…");
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const traceQuery = this.config.traceMockServer ? "?trace=1" : "";
    const socket = new WebSocket(`${protocol}//${location.host}/v1/ws${traceQuery}`);
    socket.binaryType = "arraybuffer";
    this.socket = socket;
    this.decoder = new WebSocketFrameDecoder();
    this.attachedOnSocket.clear();
    this.serverVisibility = false;
    this.welcomed = false;

    socket.onopen = () => {
      if (this.socket !== socket || this.closed) return;
      const credentials = this.credentials;
      const sessionsToResume = [...this.streams.values()].some((s) => s.hasSession());
      const resumable = sessionsToResume && credentials !== undefined && Date.now() < credentials.deadline;
      this.resumeSent = resumable;
      // RESUME_NEXT tells the server to wait for the adjacent Resume before issuing Welcome.
      const hello: WireFrame = { type: "Hello", version: VERSION, caps: (resumable ? RESUME_NEXT : 0n) | LINK_DOUBT_NOTICES | VIEWER_VISIBILITY | LAYOUT_SESSION_INCARNATION, clientInfo: "infraternal-tracer/0.1" };
      let length = encodeMuxedFrameInto(CONTROL_STREAM, hello, this.sendScratch);
      if (resumable && credentials) {
        length += encodeMuxedFrameInto(CONTROL_STREAM, { type: "Resume", connectionId: credentials.connectionId, resumeToken: credentials.resumeToken }, this.sendScratch, length);
      }
      socket.send(this.sendScratch.subarray(0, length));
      for (const s of [...this.streams.values()]) s.onSocketOpen(resumable);
    };
    socket.onmessage = (event: MessageEvent<ArrayBuffer>) => {
      if (this.socket !== socket || this.closed) return;
      const receivedAt = performance.now();
      if (!(event.data instanceof ArrayBuffer)) { this.fail("server sent a non-binary frame"); return; }
      noteWsMessage(event.data.byteLength);
      try {
        const message = new Uint8Array(event.data);
        this.decoder?.feed(message, (streamId, frame) => {
          // A Close may retire this route midway through one message.
          if (this.socket === socket && !this.closed) this.dispatch(streamId, frame, message, receivedAt);
        });
      } catch {
        if (this.socket === socket && !this.closed) this.fail("server sent an invalid wire frame");
      }
    };
    socket.onerror = () => {
      if (this.socket !== socket || this.closed) return;
      // A browser reports a socket that failed at the network as `error` and then `close` 1006 with no reason. Retiring
      // the socket here makes the later close event ignored, so the console line must be written now (#227).
      this.noteClose(1006, "");
      this.disconnect(socket);
      socket.close();
    };
    socket.onclose = (event) => {
      if (this.socket !== socket || this.closed) return;
      const internalRotation = event?.code === 4001 && event.reason === "tracer connection rotation";
      if (!internalRotation) this.noteClose(event?.code, event?.reason);
      this.forgetRefusedResume(event?.code, event?.reason);
      this.disconnect(socket);
      if (!internalRotation) this.status(plainCloseReason(event?.reason || "connection ended"));
    };
  }

  /** Server refusals retain backoff; a refused resume also forgets its capability before fresh attach (#244). */
  private forgetRefusedResume(code: number | undefined, reason: string | undefined): void {
    if (this.welcomed || (code !== 1008 && reason !== "the server refused to resume the connection")) return;
    this.refusalBackoff = true;
    this.fastRecovery = false;
    if (!this.resumeSent) return;
    this.credentials?.connectionId.fill(0);
    this.credentials?.resumeToken.fill(0);
    this.credentials = undefined;
  }

  /**
   * One rate-limited console line per socket close, including a failed reconnect (#227). Call it before disconnect(),
   * which resets the welcome state and attempt count the line reports. Every path that retires a socket for a close
   * calls it: once the socket is retired, its later close event is ignored.
   */
  private noteClose(code: number | undefined, reason: string | undefined, by?: string): void {
    const line = this.closeNotes.note(Date.now(), code, reason, this.retryAttempt, this.welcomed, by);
    if (line) console.warn(line);
    const due = this.closeNotes.summaryDue();
    if (due === undefined || this.closeNoteTimer !== undefined) return;
    this.closeNoteTimer = globalThis.setTimeout(() => {
      this.closeNoteTimer = undefined;
      const summary = this.closeNotes.flush(Date.now());
      if (summary) console.warn(summary);
    }, Math.max(0, due - Date.now()));
  }

  /** Retire the route synchronously; closing a half-open socket need not produce an event. */
  private disconnect(socket: WebSocket): void {
    if (this.socket !== socket || this.closed) return;
    const wasWelcomed = this.welcomed;
    const lived = wasWelcomed && performance.now() - this.welcomedAt >= STABLE_CONNECTION_MS;
    const forced = this.forcedDrop;
    if (wasWelcomed) {
      this.fastRecovery = [...this.streams.values()].some((stream) => stream.hasSession());
      if (lived || forced) this.retryAttempt = 0;
    } else {
      // Preserve prompt network-outage checks, but an explicit server refusal
      // proves the offline hint stale. Its backoff survives until real success.
      if (!this.refusalBackoff && typeof navigator !== "undefined" && navigator.onLine === false) this.retryAttempt = 0;
      else this.fastRecovery = false;
    }
    // The server retains a live writer indefinitely; its grace starts on disconnect
    // (or startup recovery), not Welcome. Failed retries must never renew that grace.
    if (this.welcomed && this.credentials) this.credentials.deadline = Date.now() + this.credentials.windowMs;
    this.socket = undefined;
    this.decoder = undefined;
    this.welcomed = false;
    this.attachedOnSocket.clear();
    this.attachedCount = 0;
    this.config.onConnectionChange?.(false);
    this.resetPings();
    for (const call of this.calls.values()) call.reject(new Error("connection lost"));
    this.calls.clear();
    this.forcedDrop = false;
    for (const s of [...this.streams.values()]) s.onDisconnected(forced);
    this.status("Connection lost. Reconnecting…");
    // With no stream left there is nothing to restore; the next `openStream` connects again.
    if (this.streams.size > 0 || this.subscriptions.size > 0) this.scheduleReconnect();
  }

  /** One D300 miss interval; correlated RTT and jitter do not change probe frequency. */
  private missAllowance(): number {
    return this.livenessSrtt === undefined ? 2000 : Math.min(2000, Math.max(250, 2 * this.livenessSrtt + 4 * this.livenessRttvar + 75));
  }

  /** D300 retires a proven foreground route only after two consecutive misses. */
  private responseAllowance(): number {
    return this.livenessSrtt === undefined ? 2000 : 2 * this.missAllowance();
  }

  private responseDeadline(): number {
    return Math.max(this.lastPongAt + this.responseAllowance(), this.livenessStallGraceAt);
  }

  /** A late task cannot prove the page was responsive during its scheduled wait. */
  private accountLivenessDelay(now: number): boolean {
    const late = now - this.livenessDueAt;
    if (late <= LIVENESS_TICK_MS) return false;
    // The first stall may include the scheduled wait too. Preserve one fresh
    // miss interval after it; do not renew D300's full two-miss lease. With
    // callback gaps bounded by G and per-miss allowance A, retirement takes at
    // most 3*A + 3*G after issuance, including the final socket-task turn. No
    // wall-clock bound is possible while the browser executes no tasks at all.
    if (this.pendingPings.size > 0 && !this.stallGraceUsed) {
      const grace = this.livenessSrtt === undefined ? this.responseAllowance() : this.missAllowance();
      this.livenessStallGraceAt = Math.max(this.livenessStallGraceAt, now + grace);
      this.stallGraceUsed = true;
    }
    this.lastLivenessStallAt = now;
    // Consume the credit once even if a socket task runs before the timer.
    this.livenessDueAt = now;
    return true;
  }

  private checkLiveness(confirm = false, confirmationToken?: number, confirmationSocket?: WebSocket): void {
    if (confirm) {
      if (!this.livenessConfirmationPending || confirmationToken !== this.livenessConfirmationToken || confirmationSocket !== this.socket) return;
      this.livenessConfirmationPending = false;
      this.livenessConfirmationToken += 1;
    } else if (this.livenessConfirmationPending) {
      // A timer from an earlier liveness schedule must not replace the confirmation's handle.
      return;
    }
    if (this.pageHidden()) {
      this.livenessTimer = 0;
      return;
    }
    const now = performance.now();
    this.accountLivenessDelay(now);
    this.livenessTimer = 0;
    this.livenessDueAt = Infinity;
    if (!this.isWelcomed || this.closed) return;
    if (this.pendingPings.size > 0 && now >= this.responseDeadline()) {
      // Timer and socket tasks have different queues. Give already-arrived
      // replies one task turn before closing. Repeated local stalls cannot
      // renew that turn: only an actual correlated reply redeems the route.
      if (confirm) this.retireUnresponsiveSocket();
      else {
        this.livenessDueAt = now;
        const socket = this.socket;
        if (!socket) return;
        const confirmationToken = ++this.livenessConfirmationToken;
        this.livenessConfirmationPending = true;
        this.livenessTimer = window.setTimeout(() => this.checkLiveness(true, confirmationToken, socket), 0);
      }
      return;
    }
    this.sampleRoundTrip(false);
    this.scheduleLiveness();
  }

  private nextProbeAt(): number {
    const first = this.lastPingAt + LIVENESS_TICK_MS;
    if (this.livenessRtt === undefined || performance.now() < this.fastProbeUntil || this.unacknowledgedInput.size > 0) return first;
    // The response deadline stays armed while idle waits. Another request cannot
    // redeem silence; typing or link doubt immediately restores pipelining.
    return this.pendingPings.size > 0 ? Infinity : Math.max(first, this.lastPongAt + IDLE_PROBE_PAUSE_MS);
  }

  private scheduleLiveness(): void {
    if (!this.isWelcomed || this.closed || this.pageHidden()) return;
    // A zero-delay confirmation gets one socket-task turn even if input or a Pong arrives first.
    if (this.livenessConfirmationPending) return;
    window.clearTimeout(this.livenessTimer);
    // Input or a server Ping may have sampled between timer ticks. Schedule at that probe's next due time,
    // rather than skipping a tick and then expiring a healthy low-RTT route before another probe is sent.
    const clock = performance.now();
    this.accountLivenessDelay(clock);
    const nextProbe = this.nextProbeAt() - clock;
    const remaining = this.pendingPings.size > 0 ? this.responseDeadline() - clock : Infinity;
    const delay = Math.max(1, Math.min(nextProbe, remaining));
    this.livenessDueAt = clock + delay;
    this.livenessTimer = window.setTimeout(() => this.checkLiveness(), delay);
  }

  private retireUnresponsiveSocket(): void {
    const socket = this.socket;
    if (!socket) return;
    this.noteClose(4000, "connection unresponsive", "this page");
    this.disconnect(socket);
    this.status(plainCloseReason("connection unresponsive"));
    socket.close(4000, "connection unresponsive");
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
    if (frame.type === "Ack") {
      const pending = this.unacknowledgedInput.get(streamId);
      if (pending !== undefined && frame.inSeqAcked >= pending) this.unacknowledgedInput.delete(streamId);
    }
    handler.onFrame(frame, message, receivedAt);
  }

  /** Whether this server accepts reply-marked Input [307]. */
  /** Non-secret authenticated lifetime, kept only in RAM and never logged. */
  sessionIncarnation: string | undefined;
  terminalQueryReplies = false;

  private control(frame: WireFrame): void {
    switch (frame.type) {
      case "Hello":
        this.serverVisibility = (frame.caps & VIEWER_VISIBILITY) !== 0n;
        this.terminalQueryReplies = (frame.caps & 8n) !== 0n;
        if (frame.version !== VERSION) this.fail("server uses an unsupported wire version");
        return;
      case "Welcome":
        this.sessionIncarnation = frame.sessionIncarnation;
        this.stopRetryHintListeners();
        this.send(CONTROL_STREAM, { type: "Subscribe", subId: RECOVERY_SUBSCRIPTION, filterJson: encoder.encode(JSON.stringify({ topic: "auth.recovery" })) });
        this.credentials?.connectionId.fill(0);
        this.credentials?.resumeToken.fill(0);
        this.credentials = {
          connectionId: frame.connectionId.slice(),
          resumeToken: frame.resumeToken.slice(),
          deadline: Infinity,
          windowMs: frame.resumeWindowSeconds * 1000,
        };
        if (this.refusalBackoff) this.retryAttempt = 0;
        this.refusalBackoff = false;
        this.welcomed = true;
        this.welcomedAt = performance.now();
        this.lastPongAt = this.welcomedAt;
        this.fastProbeUntil = this.welcomedAt + 250;
        // A network change may have a different RTT; relearn before enforcing its deadline.
        this.livenessRtt = undefined;
        this.livenessSrtt = undefined;
        this.livenessRttvar = 0;
        if (this.pageHidden()) this.pageVisibilityChanged();
        else if (!this.livenessConfirmationPending) {
          this.livenessDueAt = this.welcomedAt + LIVENESS_TICK_MS;
          this.livenessTimer = window.setTimeout(() => this.checkLiveness(), LIVENESS_TICK_MS);
        }
        for (const subId of [...this.subscriptions.keys()]) this.openSubscription(subId);
        for (const l of [...this.welcomeListeners]) l();
        if (!this.resumeSent) this.writersUsed.clear();
        for (const s of [...this.streams.values()]) s.onWelcome(this.resumeSent);
        return;
      case "Result": {
        const pending = this.calls.get(frame.callId);
        if (!pending) { this.fail("server returned an unexpected action result"); return; }
        this.calls.delete(frame.callId);
        if (!frame.ok) { const refusal = refusalReason(frame.json); pending.reject(new ActionRefused(undefined, refusal.reason, refusal.memory)); return; }
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
        // A hidden page can answer when runnable but must not arm local deadlines.
        if (!this.pageHidden()) this.sampleRoundTrip(false);
        return;
      case "Pong":
        this.acceptPong(frame.nonce, frame.sentUs);
        return;
      case "Close":
        this.forceClose(frame.code, frame.reason);
        this.status(plainCloseReason(frame.reason, "The server closed the connection."));
        return;
      default:
        this.fail("server sent a terminal frame on the control stream");
    }
  }

  private scheduleReconnect(): void {
    if (this.closed || this.retryTimer !== 0) return;
    if (this.pageHidden()) { this.startRetryHintListeners(); return; }
    // Failed handshakes and short-lived welcomed routes share a growing counter.
    // Offline path checks stay prompt until a refusal proves the hint stale.
    // Positive jitter spreads retries across pages; first opens retain the ordinary backoff.
    // An ordinary restart must regain typing within RTT + 50 ms [D259]. Once
    // a terminal really worked, check promptly during that bounded recovery
    // window, leaving one frame for paint. Refused or prolonged outages back off.
    // The first recovery can be quick; later short-lived failures use the exponential counter.
    const delay = this.fastRecovery && this.retryAttempt === 0 ? 5 + Math.random() * 5 : reconnectDelay(this.retryAttempt);
    this.retryAttempt += 1;
    this.retryTimer = window.setTimeout(() => { this.retryTimer = 0; this.connect(); }, delay);
    this.startRetryHintListeners();
  }

  /** Hints retry promptly without replacing an in-flight handshake or resetting refusal backoff. */
  private retryNow(): void {
    if (this.closed || this.pageHidden()) return;
    const socket = this.socket;
    const retryPending = this.retryTimer !== 0;
    const handshakePending = socket !== undefined && !this.welcomed;
    if (!retryPending && !handshakePending && !this.retryHintListeners) return;
    this.clearRetryTimer();
    if (!this.refusalBackoff) this.retryAttempt = 0;
    this.fastRecovery = !this.refusalBackoff && this.streams.size > 0;
    // A WebSocket already opening across the outage is itself the immediate retry. Closing it here
    // discards a handshake the browser can resume when its network returns.
    if (socket && socket.readyState !== WebSocket.CLOSED) return;
    if (socket) this.socket = undefined;
    this.connect();
  }

  private startRetryHintListeners(): void {
    if (this.retryHintListeners || typeof window.addEventListener !== "function") return;
    window.addEventListener("online", this.onNetworkAvailable);
    if (typeof document !== "undefined") document.addEventListener("visibilitychange", this.onPageVisible);
    this.retryHintListeners = true;
  }

  private stopRetryHintListeners(): void {
    if (!this.retryHintListeners) return;
    window.removeEventListener("online", this.onNetworkAvailable);
    if (typeof document !== "undefined") document.removeEventListener("visibilitychange", this.onPageVisible);
    this.retryHintListeners = false;
  }

  private clearRetryTimer(): void {
    if (this.retryTimer === 0) return;
    window.clearTimeout(this.retryTimer);
    this.retryTimer = 0;
  }

  private resetPings(preserveInput = false): void {
    // Clearing a timer cannot remove its callback if the browser already queued it.
    this.livenessConfirmationToken += 1;
    window.clearTimeout(this.livenessTimer);
    this.livenessTimer = 0;
    this.livenessConfirmationPending = false;
    this.livenessDueAt = Infinity;
    this.lastLivenessStallAt = -Infinity;
    this.stallGraceUsed = false;
    this.livenessStallGraceAt = -Infinity;
    this.lastPingAt = -Infinity;
    this.lastRttReportAt = -Infinity;
    this.pendingPings.clear();
    if (!preserveInput) this.unacknowledgedInput.clear();
    this.fastProbeUntil = 0;
    for (const l of this.rttListeners) l(undefined);
  }
}

/** Fixed reason codes are additive to the legacy error word; only validated counters reach product copy. */
function refusalReason(body: Uint8Array): { reason?: string; memory?: { availableMiB: number; sessionCount: number } } {
  if (body.byteLength > 32 * 1024) return {};
  try {
    const parsed = asRecord(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)) as unknown);
    const reason = parsed.reason ?? parsed.error;
    if (typeof reason !== "string" || reason.length > 64) return {};
    const available = parsed.available_mib, count = parsed.session_count;
    if (reason === "host_memory_low" && typeof available === "number" && Number.isSafeInteger(available) && available >= 0
      && typeof count === "number" && Number.isSafeInteger(count) && count >= 0) {
      return { reason, memory: { availableMiB: available, sessionCount: count } };
    }
    return { reason };
  } catch { return {}; }
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("result is not an object");
  return value as Record<string, unknown>;
}

/**
 * The sockets a page's terminals share. The first is the page's main connection (it also carries the control stream's
 * subscriptions and calls: Mesh, host facts, recovery); more are opened only when the terminals outgrow it, each
 * carrying up to `STREAMS_PER_SOCKET` of them. A window asks for a connection when its terminal opens and gives it
 * back when the terminal goes; a connection with room is reused, so closing windows frees capacity.
 */
export class ConnectionPool {
  private readonly all: Array<{ conn: MuxConnection; load: number }>;
  constructor(primary: MuxConnection, private readonly make: () => MuxConnection = () => new MuxConnection()) {
    this.all = [{ conn: primary, load: 0 }];
  }
  /** The connection for a terminal about to open its stream; call `release` with it when that terminal is gone. */
  acquire(): MuxConnection {
    let slot = this.all.find((c) => c.load < STREAMS_PER_SOCKET);
    if (!slot && this.all.length < MAX_SOCKETS) { slot = { conn: this.make(), load: 0 }; this.all.push(slot); }
    // Beyond the cap of sockets the least loaded one takes it (it rotates, as before; far more windows than any person has).
    slot ??= this.all.reduce((a, b) => (b.load < a.load ? b : a));
    slot.load++;
    return slot.conn;
  }
  release(conn: MuxConnection): void {
    const slot = this.all.find((c) => c.conn === conn);
    if (slot && slot.load > 0) slot.load--;
  }
  /** Closes the extra sockets (the primary belongs to the page). */
  dispose(): void { for (const { conn } of this.all.slice(1)) conn.dispose(); this.all.length = 1; }
  get sockets(): number { return this.all.length; }
}
