/**
 * The real-server fixture for the canvas specs: the production `infraternal` binary serving a production build of
 * the tracer, behind a local TLS front (passkeys need a secure context), with a WebSocket bridge that records the
 * wire frames of every browser socket. No test double stands in for the server, the infraternal agent, the shim or the PTY.
 *
 * - The binary comes from `INFRATERNAL_BIN` (default: the release musl binary of the repository's `target`).
 * - The web root is a copy of `TRACER_DIST` (default `dist`), frozen so a rebuild cannot change it mid-run.
 * - State lives in a private temporary directory; the certificate stays in memory; nothing secret is logged.
 */
import { recordAttachment } from "./attachment-bookkeeping";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
import { rmSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import {
  createSecureServer as createHttp2SecureServer,
  type Http2SecureServer,
  type Http2ServerRequest,
  type Http2ServerResponse,
  type ServerHttp2Session,
} from "node:http2";
import {
  request as httpRequest,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type OutgoingHttpHeaders,
  type ServerResponse,
} from "node:http";
import { createServer, type AddressInfo } from "node:net";
import type { Duplex } from "node:stream";
import { tmpdir, userInfo } from "node:os";
import { resolve } from "node:path";
import { WebSocket, WebSocketServer } from "ws";
import { WebSocketFrameDecoder, type WireFrame } from "../../../packages/protocol/src/codec";

const root = resolve(import.meta.dirname, "../../..");

/**
 * The username to sign up with in a real-server spec. A person's login account is their username (D231). The
 * fixture's server and infraternal agent run as the test user: a root host falls back to root for a username with no
 * account, but a rootless one cannot and refuses the terminal (#327). So unless the fixture runs as root, the person
 * is named after the account it runs as, and `name` only labels the spec.
 */
export function personName(name: string): string {
  return process.getuid?.() === 0 ? name : userInfo().username;
}

/** A server leader can exit before its embedded children release resources needed by the replacement. */
function processGroupExists(group: number): boolean {
  try { process.kill(-group, 0); return true; }
  catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ESRCH") return false;
    throw error;
  }
}

/** Detached session shims use their own groups, so this waits only for server-owned fixture processes. */
async function waitForProcessGroupExit(group: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (processGroupExists(group)) {
    if (Date.now() >= deadline) return false;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return true;
}

function signalProcessGroup(group: number, signal: NodeJS.Signals): void {
  try { process.kill(-group, signal); }
  catch (error) {
    if (!(typeof error === "object" && error !== null && "code" in error && error.code === "ESRCH")) throw error;
  }
}

function waitForChildExit(child: ChildProcess, timeoutMs: number): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    const onExit = (): void => { clearTimeout(timer); resolve(true); };
    const timer = setTimeout(() => {
      child.off("exit", onExit);
      resolve(false);
    }, timeoutMs);
    child.once("exit", onExit);
  });
}

/** What the bridge saw on one browser socket. */
export interface Bridge {
  id: number;
  closed: boolean;
  /** Whether this socket requested resume in Hello; no capability bytes are retained. */
  helloResume?: boolean;
  /**
   * The connection id of the Welcome on this socket, as hex. It is not a capability (the resume token is, and is never
   * kept): a resumed Welcome repeats the id of the connection it resumed, a fresh one has a new id (#569).
   */
  welcomeId?: string;
  /** Which side ended the socket first, and its close code. */
  closedBy?: string;
  /** UTF-8 close reason from the first socket close event. */
  closedReason?: string;
  /** Epoch milliseconds when one side ended this socket. */
  closedAt?: number;
  /** The reason of the last `Close` frame the server sent on this socket (stream 0 or a terminal stream). */
  serverClose?: string;
  /** Explicit or server-restored attachments by client stream id (session hex). */
  attached: Map<number, string[]>;
  /** Terminal output text by client stream id. */
  output: Map<number, string>;
  /** Optional epoch timestamps for output frames, enabled only by focused redraw traces. */
  outputTimes?: number[];
  /** Output cursor ranges without terminal text, to identify replayed byte ranges. */
  outputRanges?: Array<{ stream: number; outSeq: string; bytes: number; at: number }>;
  /** Content-free frame stages for a focused latency trace. */
  flowTimes?: Array<{
    direction: "up" | "down";
    stage: "bridge-receive" | "backend-send" | "backend-receive" | "browser-send";
    stream: number;
    type: "Input" | "Output" | "Credit" | "Ack" | "Snapshot";
    bytes: number;
    sequence?: string;
    /** Outstanding grant balance when this Input reached the production server. */
    creditBalance?: number;
    at: number;
  }>;
  /** Optional direction:stage:type keys that keep a busy trace within its fixed event limit. */
  flowFilter?: ReadonlySet<string>;
  /** Skip output text decoding and retention after content assertions finish. */
  skipOutputText?: boolean;
  /** Total Output and Snapshot bytes seen without retaining their contents. */
  outputBytesSeen?: number;
  /** Cumulative raw Output bytes by stream, excluding Snapshot replacements. */
  rawOutputBytesSeen?: Map<number, number>;
  /** Credit grants accepted by the server for each stream, for flow-control measurements. */
  creditGrantedByStream?: Map<number, number>;
  /** Output and Snapshot bytes charged by the server for each stream. */
  creditSpentByStream?: Map<number, number>;
  /** Optional terminal recovery events and closes, enabled only by focused redraw traces. */
  terminalEvents?: Array<{ stream: number; type: string; at: number }>;
  terminalCloses?: Array<{ stream: number; code: number; reason: string; at: number }>;
  /** Safe workload markers emitted by diagnostic scripts; never capture terminal text. */
  markers?: Array<{ name: string; at: number }>;
  /** Optional AttachTerm timestamps for focused connection traces. */
  attachTimes?: Array<{ stream: number; at: number }>;
  /** Resume cursors by stream, without session identifiers or terminal input. */
  attachCursors?: Array<{ stream: number; lastOutSeq: string; lastInSeq: string; at: number }>;
  /** Highest acknowledged input offset by stream. */
  acked: Map<number, bigint>;
  /** Completed real PTY replays, including automatic rebinding on the same browser socket. */
  replays: number;
  /** Counts marked renderer answers without retaining terminal input. */
  replyAttempts?: number;
  /** Close frames the client sent (stream detaches). */
  detached: number[];
  /** Control-stream actions and subscriptions: what the browser asked (`up`) and what the server answered (`down`). */
  control: Array<{ dir: "up" | "down"; type: "Call" | "Result" | "Subscribe" | "Event"; /** Action id, subscription topic, or result status. */ detail: string; callId?: number; /** For a refused `Result`: the server's error text (at most 120 characters; never a success body). */ reason?: string; /** Optional VM benchmark timestamp; never includes frame bodies. */ at?: number }>;
  cookie: string;
}

/** Transport protocol spoken by the fixture's local TLS front. */
export type RealServerProtocol = "http1" | "http2";

/** Hop-by-hop response headers forbidden on HTTP/2 responses (RFC 9113 §8.2.2). */
const HTTP2_FORBIDDEN_RESPONSE_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-connection",
  "transfer-encoding",
  "upgrade",
]);

/**
 * Resolves the fixture TLS front protocol from an explicit option or `REAL_SERVER_PROTOCOL`.
 * Defaults to `"http1"` so existing specs keep their historical single-protocol behavior unless opted in.
 */
export function resolveServerProtocol(requested?: RealServerProtocol): RealServerProtocol {
  if (requested !== undefined) return requested;
  const raw = process.env.REAL_SERVER_PROTOCOL;
  if (raw === undefined || raw === "" || raw === "http1") return "http1";
  if (raw === "http2") return "http2";
  throw new Error(`REAL_SERVER_PROTOCOL must be "http1" or "http2" (got ${JSON.stringify(raw)})`);
}

/**
 * Translates incoming HTTP/1.1 or HTTP/2 request headers for the HTTP/1.1 loopback backend.
 * Drops HTTP/2 pseudo-headers (`:method`, `:scheme`, `:authority`, `:path`, ...) that `node:http` rejects
 * and preserves `:authority` as `host` when the request carries no explicit `host` header.
 */
export function forwardRequestHeaders(headers: IncomingHttpHeaders): OutgoingHttpHeaders {
  const forwarded: OutgoingHttpHeaders = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || name.startsWith(":")) continue;
    forwarded[name] = value;
  }
  const authority = headers[":authority"];
  if (forwarded.host === undefined && typeof authority === "string" && authority.length > 0) {
    forwarded.host = authority;
  }
  return forwarded;
}

/**
 * Translates response headers from the HTTP/1.1 backend for the fixture's TLS front.
 * When replying over HTTP/2, removes hop-by-hop headers forbidden by RFC 9113 §8.2.2 (including any
 * header names listed in `connection`) so `node:http2` does not abort the stream.
 */
export function forwardResponseHeaders(headers: IncomingHttpHeaders, http2: boolean): OutgoingHttpHeaders {
  const forwarded: OutgoingHttpHeaders = {};
  if (!http2) {
    for (const [name, value] of Object.entries(headers)) {
      if (value !== undefined) forwarded[name] = value;
    }
    return forwarded;
  }
  const connectionTokens = new Set<string>();
  const rawConnection = headers.connection;
  const connectionValues = Array.isArray(rawConnection) ? rawConnection : rawConnection ? [rawConnection] : [];
  for (const entry of connectionValues) {
    for (const token of entry.split(",")) {
      const normalized = token.trim().toLowerCase();
      if (normalized) connectionTokens.add(normalized);
    }
  }
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    const lower = name.toLowerCase();
    if (HTTP2_FORBIDDEN_RESPONSE_HEADERS.has(lower) || connectionTokens.has(lower)) continue;
    forwarded[name] = value;
  }
  return forwarded;
}

/** The listeners, process generations, and private state owned by one real-server fixture. */
export interface RealServer {
  /** The private remote endpoint chosen for this fixture, retained across its restarts. */
  remoteListen?: string;
  /** Transport protocol served by the local TLS front (`"http1"` or `"http2"`). */
  protocol: RealServerProtocol;
  origin: string;
  backend: string;
  bridges: Bridge[];
  token: string;
  binary: string;
  dataDir: string;
  pid: number;
  /** Epoch milliseconds from the monotonic clock, for perf-VM-only recovery measurements. */
  recoveredAt?: number;
  /** Restarts the server-owned process group while retaining session shims in their own groups. */
  restart(whileStopped?: () => Promise<void>): Promise<void>;
  /** Retain existing real TLS sockets when their upstream closes; replacements remain ordinary routes. */
  retainBrowserRoutes(): void;
  /** Pause only the selected private upstream, preserving the browser/server connection. */
  pauseUpstream(component: "daemon" | "shim", whilePaused: () => Promise<void>, selectedSession?: string): Promise<void>;
  /** Interrupt only this fixture's browser routes; fresh upgrades fail during the bounded drop. */
  interruptBrowserRoutes(durationMs: number): Promise<void>;
  dispose(): Promise<void>;
}

/** Content-free timing of the fixture TLS bridge, separate from production server work. */
export interface DesktopStage {
  stage: "fixture_receive" | "fixture_send_begin" | "fixture_send_end";
  at: number;
  sequence: string;
  captureNs: string;
  bytes: number;
}

/** Content-free control probes isolate server handling from browser/network waits (#146). */
export interface ProbeStage {
  phase: "browser_ping" | "server_pong";
  socket: number;
  nonce: string;
  sentUs: string;
  at: number;
}

/** Project matching control probes only; action bodies and bootstrap sockets are excluded. */
export function probeStage(phase: ProbeStage["phase"], socket: number, stream: number, frame: WireFrame, at: number): ProbeStage | undefined {
  if (stream !== 0 || (phase === "browser_ping" ? frame.type !== "Ping" : frame.type !== "Pong")) return undefined;
  if (frame.type !== "Ping" && frame.type !== "Pong") return undefined;
  return { phase, socket, nonce: frame.nonce.toString(), sentUs: frame.sentUs.toString(), at };
}
const text = new TextDecoder();

/** A bounded view of a protocol frame that carries no user input or terminal output. */
type FlowNote = {
  stream: number;
  type: "Input" | "Output" | "Credit" | "Ack" | "Snapshot";
  bytes: number;
  sequence?: string;
  /** Outstanding grant balance when an Input reaches the production server. */
  creditBalance?: number;
};

/** The largest content-free frame trace retained by one bridge. */
const FLOW_TRACE_LIMIT = 16_384;

/** Return safe timing metadata for the frame types used by the latency review. */
function flowNote(stream: number, frame: WireFrame): FlowNote | undefined {
  switch (frame.type) {
    case "Input": return { stream, type: "Input", bytes: frame.bytes.byteLength, sequence: frame.inSeq.toString() };
    case "Output": return { stream, type: "Output", bytes: frame.bytes.byteLength, sequence: frame.outSeq.toString() };
    case "Credit": return { stream, type: "Credit", bytes: frame.bytes };
    case "Ack": return { stream, type: "Ack", bytes: 0, sequence: frame.inSeqAcked.toString() };
    case "Snapshot": return { stream, type: "Snapshot", bytes: frame.bytes.byteLength, sequence: frame.outSeq.toString() };
    default: return undefined;
  }
}

/** Append one stage to the fixed-capacity trace without retaining frame contents. */
function recordFlow(
  bridge: Bridge,
  direction: "up" | "down",
  stage: NonNullable<Bridge["flowTimes"]>[number]["stage"],
  note: FlowNote,
): void {
  let tracedNote = note;
  if (direction === "up" && stage === "backend-send" && note.type === "Credit") {
    const granted = bridge.creditGrantedByStream;
    if (granted) granted.set(note.stream, (granted.get(note.stream) ?? 0) + note.bytes);
  }
  if (direction === "down" && stage === "backend-receive" && (note.type === "Output" || note.type === "Snapshot")) {
    const spent = bridge.creditSpentByStream;
    if (spent) spent.set(note.stream, (spent.get(note.stream) ?? 0) + note.bytes);
  }
  if (direction === "up" && stage === "backend-send" && note.type === "Input") {
    const granted = bridge.creditGrantedByStream?.get(note.stream) ?? 0;
    const spent = bridge.creditSpentByStream?.get(note.stream) ?? 0;
    tracedNote = { ...note, creditBalance: granted - spent };
  }
  if (bridge.flowFilter && !bridge.flowFilter.has(`${direction}:${stage}:${note.type}`)) return;
  const times = bridge.flowTimes;
  if (!times || times.length >= FLOW_TRACE_LIMIT) return;
  times.push({ direction, stage, ...tracedNote, at: performance.timeOrigin + performance.now() });
}

/**
 * `latencyMs` (or `REAL_ONE_WAY_MS`) delays every browser-socket message by that many milliseconds in each direction
 * (so 150 is the 300 ms round-trip profile of docs/PROCESS.md); order is kept. Page loads are not delayed.
 */
/** Start an isolated real server; dispose owns its private listeners, children, and state. */
export async function startRealServer(options: {
  latencyMs?: number;
  /** Delay the real protocol upgrade so cached renderers can register before socket open (#257). */
  upgradeDelayMs?: number;
  /** Record public control timestamps only for an explicitly enabled VM measurement. */
  timedControls?: boolean;
  /** Record content-free Input, Credit, Ack and Snapshot stages for a focused latency trace. */
  recordFlow?: boolean;
  /** Explicit native-window measurement only; bootstrap messages never enter it. */
  onDesktopStage?: (receipt: DesktopStage) => void;
  /** Explicit reconnect diagnosis only; these are same-host handling intervals. */
  onProbeStage?: (receipt: ProbeStage) => void;
  /** Retain every stream Close for functional ordering assertions without timing traces. */
  recordCloses?: boolean;
  /** Decode attachment metadata but retain no terminal output (busy-terminal measurements). */
  lean?: boolean;
  address?: string;
  port?: number;
  hostname?: string;
  stateRoot?: string;
  remoteListen?: string;
  /** Uses a private transient service with production's server-only stop behavior. */
  systemd?: boolean;
  /** Public fixture certificate only; private TLS material remains in memory. */
  certificate?: (pem: string) => Promise<void>;
  /** Transport protocol for the local TLS front (`"http1"` default, or `"http2"` with HTTP/1.1 WebSocket fallback). */
  protocol?: RealServerProtocol;
  /** Seeds controlled public host trust before any bootstrap operation. */
  prepareData?: (directory: string) => Promise<void>;
  /** Real shell fixtures supply a private startup directory without touching the VM user's files. */
  startupDirectory?: string;
} = {}): Promise<RealServer> {
  // `lean`: the recording of every output frame made this single-threaded relay slower than the server's one-second
  // write limit allows under busy terminals, and the server then closed the socket.
  const lean = options.lean ?? process.env.REAL_BRIDGE_LEAN === "1";
  const delay = options.latencyMs ?? Number(process.env.REAL_ONE_WAY_MS ?? 0);
  const later = (run: () => void): void => { if (delay > 0) setTimeout(run, delay); else run(); };
  const binary = process.env.INFRATERNAL_BIN ?? resolve(root, "target/x86_64-unknown-linux-musl/release/infraternal");
  const dist = resolve(process.env.TRACER_DIST ?? resolve(root, "apps/tracer/dist"));
  // Session rendezvous sockets have a 107-byte path limit. Large fixture state
  // may live under a long TMPDIR; keep runtime sockets in their own private root.
  const runtimeRoot = process.env.INFRATERNAL_TEST_STATE_ROOT ?? tmpdir();
  await mkdir(runtimeRoot, { recursive: true, mode: 0o700 });
  const runtime = await mkdtemp(resolve(runtimeRoot, "r"));
  const sessionSocket = resolve(runtime, "infraternal/sessions", "0".repeat(32) + ".sock");
  if (Buffer.byteLength(sessionSocket) >= 108) {
    await rm(runtime, { recursive: true, force: true });
    throw new Error("real-server runtime path is too long; use a shorter INFRATERNAL_TEST_STATE_ROOT");
  }
  const stateRoot = options.stateRoot ?? process.env.INFRATERNAL_TEST_DATA_ROOT ?? tmpdir();
  await mkdir(stateRoot, { recursive: true, mode: 0o700 });
  const state = await mkdtemp(resolve(stateRoot, "r"));
  await cp(dist, `${state}/web`, { recursive: true });
  const reservation = createServer();
  await new Promise<void>((r) => reservation.listen(0, "127.0.0.1", r));
  const port = (reservation.address() as AddressInfo).port;
  // Keep the backend reservation held while choosing a separate ephemeral remote port.
  let remoteListen = options.remoteListen;
  if (remoteListen === "127.0.0.1:0") {
    const remote = createServer();
    await new Promise<void>((resolve, reject) => { remote.once("error", reject); remote.listen(0, "127.0.0.1", resolve); });
    remoteListen = `127.0.0.1:${(remote.address() as AddressInfo).port}`;
    await new Promise<void>((resolve, reject) => remote.close((error) => error ? reject(error) : resolve()));
  }
  await new Promise<void>((r) => reservation.close(() => r()));
  const backend = `http://127.0.0.1:${port}`;

  // The certificate is generated into memory and handed straight to the TLS server.
  const hostname = options.hostname ?? "localhost";
  const address = options.address ?? "127.0.0.1";
  const ssl = spawn("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", `/CN=${hostname}`, "-addext", `subjectAltName=DNS:${hostname},IP:${address}`, "-keyout", "-", "-out", "-"], { stdio: ["ignore", "pipe", "ignore"] });
  let pem = "";
  ssl.stdout.on("data", (b) => { pem += b; });
  const [code] = await once(ssl, "exit");
  if (code !== 0) throw new Error("test certificate generation failed");
  const certificate = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)?.[0] ?? "";
  await options.certificate?.(certificate);
  const protocol = resolveServerProtocol(options.protocol);
  let privateKey = pem.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/)?.[0] ?? "";
  const writeProxyHead = (
    res: ServerResponse | Http2ServerResponse,
    statusCode: number,
    headers?: OutgoingHttpHeaders,
  ): void => {
    if ("stream" in res) res.writeHead(statusCode, headers);
    else res.writeHead(statusCode, headers);
  };
  const proxyRequest = (
    req: IncomingMessage | Http2ServerRequest,
    res: ServerResponse | Http2ServerResponse,
  ): void => {
    const isHttp2 = req.httpVersionMajor >= 2;
    const upstream = httpRequest(
      backend + (req.url ?? "/"),
      { method: req.method, headers: forwardRequestHeaders(req.headers), agent: false },
      (response) => {
        if (res.writableEnded || res.destroyed) {
          response.resume();
          return;
        }
        writeProxyHead(res, response.statusCode ?? 500, forwardResponseHeaders(response.headers, isHttp2));
        response.pipe(res);
      },
    );
    upstream.on("error", () => {
      if (!res.headersSent && !res.writableEnded && !res.destroyed) {
        writeProxyHead(res, 502);
        res.end();
      } else if (!res.destroyed) {
        res.destroy();
      }
    });
    res.on("close", () => {
      if (!res.writableEnded) upstream.destroy();
    });
    req.pipe(upstream);
  };
  const h2Sessions = new Set<ServerHttp2Session>();
  const tls: HttpsServer | Http2SecureServer = protocol === "http2"
    // `allowHTTP1: true` serves HTTP/2 over ALPN `h2` for page and asset requests while still allowing
    // browsers to open HTTP/1.1 TLS `Upgrade: websocket` connections for `/v1/ws` (RFC 8441 is not advertised).
    ? createHttp2SecureServer({ key: privateKey, cert: certificate, allowHTTP1: true }, proxyRequest)
    : createHttpsServer({ key: privateKey, cert: certificate }, proxyRequest);
  if (protocol === "http2") {
    (tls as Http2SecureServer).on("session", (session) => {
      h2Sessions.add(session);
      session.once("close", () => h2Sessions.delete(session));
    });
  }
  pem = "";
  privateKey = "";
  await new Promise<void>((r) => tls.listen(options.port ?? 0, address, r));
  // A browser's Origin never carries the scheme's default port, and the server pins its public origin the same way
  // (`Url::origin`), so on 443 the fixture must name it without ":443" or every WebSocket upgrade is refused with 403.
  const tlsPort = (tls.address() as AddressInfo).port;
  const origin = `https://${hostname}${tlsPort === 443 ? "" : `:${tlsPort}`}`;

  let unit: string | undefined;
  const ownedChildren = new Set<ChildProcess>();
  const ownedUnits = new Set<string>();
  const shimState = process.env.REAL_ROOT_NAMESPACE === "1" ? "/run/infraternal" : resolve(runtime, "infraternal");
  /** Stop only this fixture's private units and process groups, including a failed stop. */
  const forceStop = (): void => {
    for (const name of ownedUnits) spawnSync("systemctl", ["--user", "kill", "--kill-whom=all", "--signal=KILL", name], { stdio: "ignore", timeout: 5_000 });
    for (const ownedChild of ownedChildren) if (ownedChild.pid) signalProcessGroup(ownedChild.pid, "SIGKILL");
  };
  /** Synchronous exit cleanup also covers uncaught errors and interrupted test workers. */
  const emergencyCleanup = (): void => {
    forceStop();
    spawnSync("python3", ["-c", "import sys;sys.path.insert(0,'scripts');from pathlib import Path;from agent_fixture import cleanup;cleanup(Path(sys.argv[1]))", shimState], { cwd: root, stdio: "ignore", timeout: 10_000 });
    rmSync(runtime, { recursive: true, force: true });
    rmSync(state, { recursive: true, force: true });
  };
  /** Exit with the conventional interrupt status after the exit guard cleans up. */
  const interrupt = (): never => process.exit(130);
  /** Exit with the conventional termination status after the exit guard cleans up. */
  const terminate = (): never => process.exit(143);
  const args = ["server", "--listen", `127.0.0.1:${port}`, "--data", state, "--public-origin", origin, "--behind-proxy", "--trusted-proxy", "127.0.0.1", "--web-root", `${state}/web`, ...(remoteListen ? ["--remote-listen", remoteListen, "--remote-ca-dir", `${state}/ca`] : [])];
  /** Launch one owned generation; stopped units stay tracked until their shims are disposed. */
  const launch = (): ChildProcess => {
    // A stopped transient unit may await garbage collection after its launcher
    // exits. A fresh name avoids racing that collection while keeping the same data/runtime.
    unit = options.systemd ? `s199-${randomUUID()}` : undefined;
    if (unit) ownedUnits.add(unit);
    const launched = spawn(unit ? "systemd-run" : binary, unit ? ["--user", "--quiet", "--wait", "--pipe", "--collect", "--unit", unit, "-p", "KillMode=process", `--setenv=XDG_RUNTIME_DIR=${runtime}`, `--setenv=ZDOTDIR=${resolve(root, "crates/infraternal/tests/profile")}`, binary, ...args] : args, {
    cwd: root, detached: true,
    env: { ...process.env, XDG_RUNTIME_DIR: runtime, ZDOTDIR: options.startupDirectory ?? resolve(root, "crates/infraternal/tests/profile") },
    stdio: ["ignore", process.env.REAL_SERVER_LOG === "1" ? "pipe" : "ignore", "pipe"],
    });
    ownedChildren.add(launched);
    return launched;
  };
  let child = launch();
  process.once("exit", emergencyCleanup);
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", terminate);
  /** Stop a server generation while retaining its detached session shims for restart. */
  const stop = async (): Promise<void> => {
    const stoppedChild = child;
    const group = stoppedChild.pid;
    if (!group) return;
    if (unit) {
      if (stoppedChild.exitCode === null && stoppedChild.signalCode === null) {
        const control = spawn("systemctl", ["--user", "stop", unit], { stdio: "ignore" });
        const [code] = await once(control, "exit");
        if (code !== 0) throw new Error("private fixture service stop failed");
      }
    } else if (processGroupExists(group)) {
      // Stop the full server-owned group. Killing only its leader lets the embedded child
      // keep its listener open while restart() starts a replacement on the same port.
      signalProcessGroup(group, "SIGTERM");
    }
    if (!await waitForProcessGroupExit(group, 5_000)) {
      signalProcessGroup(group, "SIGKILL");
      if (!await waitForProcessGroupExit(group, 1_000)) {
        throw new Error("real-server fixture process group did not exit within 6 seconds");
      }
    }
    if (!await waitForChildExit(stoppedChild, 1_000)) {
      throw new Error("real-server fixture launcher did not exit after its process group stopped");
    }
    ownedChildren.delete(stoppedChild);
  };
  if (process.env.REAL_SERVER_LOG === "1") { child.stderr?.on("data", (b) => process.stderr.write(`SERVER ${b}`)); child.stdout?.on("data", (b) => process.stderr.write(`SERVER ${b}`)); } else child.stderr?.resume();

  const bridges: Bridge[] = [];
  const retainedBrowsers = new Set<WebSocket>();
  const activeBrowsers = new Set<WebSocket>();
  const front = new WebSocketServer({ noServer: true });
  let browserOfflineUntil = 0;
  tls.on("upgrade", async (request: IncomingMessage, socket: Duplex, head: Buffer) => {
    if (Date.now() < browserOfflineUntil) { socket.destroy(); return; }
    // Frame delay starts after open. This separate fixture control models the handshake ordering;
    // every subsequent byte still travels through the real server and PTY unchanged.
    if (request.url === "/v1/ws" && options.upgradeDelayMs) {
      await new Promise((resolve) => setTimeout(resolve, options.upgradeDelayMs));
      if (socket.destroyed) return;
    }
    front.handleUpgrade(request, socket, head, (browser) => {
      activeBrowsers.add(browser);
      const upstream = new WebSocket(backend.replace("http:", "ws:") + (request.url ?? "/v1/ws"), { headers: { Origin: origin, Cookie: request.headers.cookie ?? "" } });
      const bridge: Bridge = { id: bridges.length, closed: false, attached: new Map(), output: new Map(), acked: new Map(), replays: 0, replyAttempts: 0, detached: [], control: [], cookie: request.headers.cookie ?? "" };
      // Harness stage markers contain only fixed labels and timestamps, never terminal text.
      bridge.markers = [];
      if (options.recordFlow) {
        bridge.flowTimes = [];
        bridge.outputBytesSeen = 0;
        bridge.rawOutputBytesSeen = new Map();
        bridge.creditGrantedByStream = new Map();
        bridge.creditSpentByStream = new Map();
      }
      if (options.recordCloses) bridge.terminalCloses = [];
      if (process.env.REAL_OUTPUT_TIMES === "1") {
        bridge.outputTimes = [];
        bridge.outputRanges = [];
      }
      if (process.env.REAL_EVENT_TIMES === "1") {
        bridge.terminalEvents = [];
        bridge.terminalCloses = [];
        bridge.attachTimes = [];
        bridge.attachCursors = [];
      }
      // Bootstrap frames can contain private sign-in inputs. Only protocol sockets enter diagnostics.
      const protocol = request.url === "/v1/ws";
      if (protocol) bridges.push(bridge);
      const inbound = new WebSocketFrameDecoder();
      const outbound = new WebSocketFrameDecoder();
      const desktopDecoder = (options.onDesktopStage || options.onProbeStage) && protocol ? new WebSocketFrameDecoder() : undefined;
      const queued: Array<{ bytes: Buffer; binary: boolean; flow: FlowNote[] }> = [];
      let pendingUpstreamMessages = 0;
      let closeBrowserWhenDrained = false;
      const closeBrowserAfterDrain = (): void => {
        if (!closeBrowserWhenDrained || pendingUpstreamMessages !== 0 || retainedBrowsers.has(browser)) return;
        closeBrowserWhenDrained = false;
        if (browser.readyState === WebSocket.OPEN) browser.close();
      };
      browser.on("message", (data, binary) => {
        const bytes = Buffer.from(data as Buffer);
        const flow: FlowNote[] = [];
        if (protocol && binary) inbound.feed(new Uint8Array(bytes), (stream: number, f: WireFrame) => {
          // Keep Input too: timing ends at the browser paint, so the trace must
          // show when each key left the bridge and when its echo reached it.
          const note = options.recordFlow ? flowNote(stream, f) : undefined;
          if (note) {
            recordFlow(bridge, "up", "bridge-receive", note);
            flow.push(note);
          }
          if (options.onProbeStage) {
            const probe = probeStage("browser_ping", bridge.id, stream, f, performance.timeOrigin + performance.now());
            if (probe) options.onProbeStage(probe);
          }
          if (process.env.REAL_FRAME_LOG === "1") {
            // Input bytes can contain private terminal input; record only frame type and bounded metadata.
            const detail = f.type === "Input" ? ` bytes=${f.bytes.byteLength}`
              : f.type === "Credit" ? ` bytes=${f.bytes}`
                : f.type === "Resize" ? ` cols=${f.cols} rows=${f.rows}` : "";
            console.error(`FRAME ${Date.now() % 100000} b${bridge.id} up s${stream} ${f.type}${detail}`);
          }
          if (f.type === "Hello" && stream === 0) bridge.helloResume = (f.caps & 1n) !== 0n;
          if (f.type === "Input" && f.replyTo !== undefined) bridge.replyAttempts = (bridge.replyAttempts ?? 0) + 1;
          if (f.type === "AttachTerm") {
            recordAttachment(bridge.attached, stream, f);
            bridge.attachTimes?.push({ stream, at: Date.now() });
            bridge.attachCursors?.push({ stream, lastOutSeq: f.lastOutSeq.toString(), lastInSeq: f.lastInSeq.toString(), at: Date.now() });
          }
          if (f.type === "Close" && stream !== 0) bridge.detached.push(stream);
          if (f.type === "Call") bridge.control.push({ dir: "up", type: "Call", detail: f.actionId, callId: f.callId, ...(options.timedControls ? { at: Date.now() } : {}) });
          if (f.type === "Subscribe") bridge.control.push({ dir: "up", type: "Subscribe", detail: (() => { try { return String((JSON.parse(text.decode(f.filterJson)) as { topic?: unknown }).topic); } catch { return "?"; } })() });
        });
        later(() => {
          if (bridge.closed) return;
          if (upstream.readyState === WebSocket.OPEN) {
            for (const note of flow) recordFlow(bridge, "up", "backend-send", note);
            upstream.send(bytes, { binary });
          } else queued.push({ bytes, binary, flow });
        });
      });
      upstream.on("open", () => {
        for (const q of queued.splice(0)) {
          if (bridge.closed) continue;
          for (const note of q.flow) recordFlow(bridge, "up", "backend-send", note);
          upstream.send(q.bytes, { binary: q.binary });
        }
      });
      upstream.on("message", (data, binary) => {
        const receivedAt = desktopDecoder ? performance.timeOrigin + performance.now() : 0;
        pendingUpstreamMessages++;
        const bytes = Buffer.from(data as Buffer);
        const desktop: Omit<DesktopStage, "stage" | "at">[] | undefined = desktopDecoder ? [] : undefined;
        const flow: FlowNote[] = [];
        if (desktopDecoder && binary && desktop) desktopDecoder.feed(new Uint8Array(bytes), (_stream, frame) => {
          if (options.onProbeStage) {
            const probe = probeStage("server_pong", bridge.id, _stream, frame, receivedAt);
            if (probe) options.onProbeStage(probe);
          }
          if (frame.type !== "Desktop" || frame.message.kind !== "video" || desktop.length === 128) return;
          const video = frame.message;
          const identity = { sequence: video.sequence.toString(), captureNs: video.captureNs.toString(), bytes: video.bytes.length };
          desktop.push(identity); options.onDesktopStage?.({ ...identity, stage: "fixture_receive", at: receivedAt });
        });
        if (protocol && binary) outbound.feed(new Uint8Array(bytes), (stream: number, f: WireFrame) => {
          recordAttachment(bridge.attached, stream, f);
          if (f.type === "Output" || f.type === "Snapshot") {
            bridge.outputBytesSeen = (bridge.outputBytesSeen ?? 0) + f.bytes.byteLength;
          }
          if (f.type === "Output" && bridge.rawOutputBytesSeen) {
            bridge.rawOutputBytesSeen.set(stream,
              (bridge.rawOutputBytesSeen.get(stream) ?? 0) + f.bytes.byteLength);
          }
          const note = options.recordFlow ? flowNote(stream, f) : undefined;
          if (note) {
            recordFlow(bridge, "down", "backend-receive", note);
            flow.push(note);
          }
          if (lean || bridge.skipOutputText) return;
          if (process.env.REAL_FRAME_LOG === "1" && f.type !== "Output" && f.type !== "Ack") console.error(`FRAME ${Date.now() % 100000} b${bridge.id} down s${stream} ${f.type}`);
          if (f.type === "Output") {
            const chunkText = text.decode(f.bytes, { stream: true });
            bridge.output.set(stream, (bridge.output.get(stream) ?? "") + chunkText);
            for (const match of chunkText.matchAll(/PILL_STAGE:([a-z0-9-]+)/g)) {
              bridge.markers?.push({ name: match[1] ?? "unknown", at: Date.now() });
            }
            bridge.outputTimes?.push(Date.now());
            bridge.outputRanges?.push({ stream, outSeq: f.outSeq.toString(), bytes: f.bytes.byteLength, at: Date.now() });
          }
          if (f.type === "Snapshot") {
            bridge.output.set(stream, text.decode(f.bytes));
            bridge.outputRanges?.push({ stream, outSeq: f.outSeq.toString(), bytes: f.bytes.byteLength, at: Date.now() });
          }
          if (f.type === "Ack") bridge.acked.set(stream, f.inSeqAcked);
          if (f.type === "Welcome" && stream === 0) bridge.welcomeId = Buffer.from(f.connectionId).toString("hex");
          if (f.type === "Event" && stream !== 0 && f.eventJson.byteLength <= 1024
            && JSON.parse(text.decode(f.eventJson)).type === "terminal.replay_complete") bridge.replays++;
          if (f.type === "Event" && stream !== 0 && bridge.terminalEvents && f.eventJson.byteLength <= 1024) {
            try {
              const event = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(f.eventJson)) as { type?: unknown };
              if (typeof event.type === "string" && event.type.startsWith("terminal.")) bridge.terminalEvents.push({ stream, type: event.type, at: Date.now() });
            } catch { /* Invalid notices are handled by the browser protocol parser. */ }
          }
          if (options.timedControls && f.type === "Event") {
            try {
              const event = JSON.parse(text.decode(f.eventJson)) as { type?: unknown };
              if (typeof event.type === "string" && event.type.startsWith("canvas.layout.")) bridge.control.push({ dir: "down", type: "Event", detail: event.type, at: Date.now() });
            } catch { /* The browser validates event contents. Diagnostics retain only fixed event names. */ }
          }
          if (f.type === "Close") {
            const close = f as { code?: unknown; reason?: unknown };
            bridge.serverClose = `s${stream === 0 ? 0 : "n"} ${typeof close.reason === "string" ? close.reason : JSON.stringify(close.reason)}`;
            if (bridge.terminalCloses && typeof close.code === "number") {
              const reason = typeof close.reason === "string" ? close.reason : JSON.stringify(close.reason);
              bridge.terminalCloses.push({ stream, code: close.code, reason, at: Date.now() });
              if (process.env.REAL_EVENT_TIMES === "1") console.error(`SERVER_CLOSE_FRAME b${bridge.id} stream=${stream} code=${close.code} reason=${JSON.stringify(reason)}`);
            }
          }
          if (f.type === "Result") bridge.control.push({ dir: "down", type: "Result", detail: f.ok ? "ok" : "refused", callId: f.callId, ...(f.ok ? {} : { reason: new TextDecoder().decode(f.json).slice(0, 120) }), ...(options.timedControls ? { at: Date.now() } : {}) });
        });
        // Drain messages already received before closing the browser side of a failed upstream route.
        later(() => {
          pendingUpstreamMessages--;
          try {
            if (browser.readyState !== WebSocket.OPEN) return;
            for (const note of flow) recordFlow(bridge, "down", "browser-send", note);
            if (!desktop?.length) { browser.send(bytes, { binary }); return; }
            const began = performance.timeOrigin + performance.now();
            for (const identity of desktop) options.onDesktopStage?.({ ...identity, stage: "fixture_send_begin", at: began });
            browser.send(bytes, { binary }, (error) => {
              if (error) return;
              const ended = performance.timeOrigin + performance.now();
              for (const identity of desktop) options.onDesktopStage?.({ ...identity, stage: "fixture_send_end", at: ended });
            });
          } finally { closeBrowserAfterDrain(); }
        });
      });
      const eraseQueue = (): void => { for (const entry of queued.splice(0)) entry.bytes.fill(0); };
      upstream.on("close", (code, reason) => {
        eraseQueue();
        bridge.closed = true;
        bridge.closedAt ??= Date.now();
        bridge.closedBy ??= `server ${code}`;
        bridge.closedReason ??= reason.toString("utf8");
        if (process.env.REAL_EVENT_TIMES === "1") console.error(`SERVER_SOCKET_CLOSE b${bridge.id} side=upstream code=${code} reason=${JSON.stringify(reason.toString("utf8"))}`);
        closeBrowserWhenDrained = true;
        closeBrowserAfterDrain();
      });
      upstream.on("error", () => {
        closeBrowserWhenDrained = true;
        closeBrowserAfterDrain();
      });
      browser.on("close", (code, reason) => {
        activeBrowsers.delete(browser);
        retainedBrowsers.delete(browser);
        eraseQueue();
        bridge.closed = true;
        bridge.closedAt ??= Date.now();
        bridge.closedBy ??= `browser ${code}`;
        bridge.closedReason ??= reason.toString("utf8");
        if (process.env.REAL_EVENT_TIMES === "1") console.error(`SERVER_SOCKET_CLOSE b${bridge.id} side=browser code=${code} reason=${JSON.stringify(bridge.closedReason)}`);
        upstream.close();
      });
    });
  });

  // The TLS front is already listening before the backend becomes ready. A
  // rejected startup must join the same owned cleanup as a successful fixture,
  // or retries retain its port and private processes without a returned owner.
  let disposal: Promise<void> | undefined;
  /** Dispose every owned resource even when the normal service stop fails. */
  const dispose = (): Promise<void> => disposal ??= (async () => {
    front.close();
    for (const session of h2Sessions) session.destroy();
    h2Sessions.clear();
    tls.close();
    try { await stop(); }
    finally {
      try {
        forceStop();
        // Authenticated runtime cleanup also reaches shims that detached into their own groups.
        const cleanup = spawn("python3", ["-c", "import sys;sys.path.insert(0,'scripts');from pathlib import Path;from agent_fixture import cleanup;cleanup(Path(sys.argv[1]))", shimState], { cwd: root, stdio: "ignore" });
        await once(cleanup, "exit");
      } finally {
        try {
          await rm(runtime, { recursive: true, force: true });
          await rm(state, { recursive: true, force: true });
        } finally {
          process.off("exit", emergencyCleanup);
          process.off("SIGINT", interrupt);
          process.off("SIGTERM", terminate);
        }
      }
    }
  })();

  try {
    const deadline = Date.now() + 20_000;
    for (;;) {
      if (child.exitCode !== null || child.signalCode !== null) throw new Error("server startup failed");
      try { if ((await fetch(backend + "/healthz", { headers: { Connection: "close" } })).ok) break; } catch { /* starting */ }
      if (Date.now() > deadline) throw new Error("server startup failed");
      await new Promise((r) => setTimeout(r, 50));
    }
    await options.prepareData?.(state);
    const setup = spawn(binary, ["server", "setup-token", "--data", state, "--json"], { cwd: root, stdio: ["ignore", "pipe", "ignore"] });
    let token = "";
    setup.stdout.on("data", (b) => { token += b; });
    const [setupCode] = await once(setup, "exit");
    // The CLI is human-oriented by default; machine callers use the D202 envelope.
    // Keep the one-time setup capability in memory, and never echo a bad response.
    if (setupCode !== 0) throw new Error("setup capability unavailable");
    let setupResult: unknown;
    try { setupResult = JSON.parse(token); }
    catch { throw new Error("invalid setup capability response"); }
    const setupData = typeof setupResult === "object" && setupResult !== null && "data" in setupResult
      ? setupResult.data : undefined;
    const setupToken = typeof setupData === "object" && setupData !== null && "token" in setupData
      ? setupData.token : undefined;
    if (typeof setupToken !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(setupToken)) {
      throw new Error("invalid setup capability response");
    }
    token = "";

    const fixture: RealServer = {
      ...(remoteListen ? { remoteListen } : {}),
      protocol,
      origin, backend, bridges, token: setupToken, binary, dataDir: state, get pid() { return child.pid!; },
      retainBrowserRoutes() { for (const browser of activeBrowsers) retainedBrowsers.add(browser); },
      async restart(whileStopped) {
        await stop();
        await whileStopped?.();
        child = launch();
        if (process.env.REAL_SERVER_LOG === "1") {
          child.stderr?.on("data", (bytes) => process.stderr.write(`RESTART ${bytes}`));
          child.stdout?.on("data", (bytes) => process.stderr.write(`RESTART ${bytes}`));
        } else child.stderr?.resume();
        const deadline = Date.now() + 20_000;
        for (;;) {
          // The successful probe's start is a conservative availability boundary;
          // a delayed health response must not subtract an RTT from recovery.
          const candidateAt = performance.timeOrigin + performance.now();
          try { if ((await fetch(backend + "/healthz", { headers: { Connection: "close" } })).ok) { fixture.recoveredAt = candidateAt; break; } } catch { /* starting */ }
          if (Date.now() > deadline) throw new Error("server restart failed");
          await new Promise((r) => setTimeout(r, 25));
        }
      },
      async pauseUpstream(component, whilePaused, selectedSession) {
        let serverPid = child.pid!;
        if (unit) {
          const show = spawn("systemctl", ["--user", "show", "-p", "MainPID", "--value", unit], { stdio: ["ignore", "pipe", "ignore"] });
          let result = "";
          show.stdout.on("data", (bytes) => { result += bytes; });
          const [code] = await once(show, "exit");
          serverPid = Number(result.trim());
          if (code !== 0 || !Number.isInteger(serverPid) || serverPid < 1) throw new Error("fixture server identity unavailable");
        }
        // Arrival order can differ from canvas order. Multi-window callers select
        // the session whose executed marker identifies the focused window.
        const sessionId = (selectedSession ?? bridges.flatMap((bridge) => [...bridge.attached.values()].flat())[0])?.replaceAll("-", "");
        if (!sessionId || !/^[0-9a-f]{32}$/.test(sessionId)) throw new Error("fixture session identity unavailable");
        const shimState = process.env.REAL_ROOT_NAMESPACE === "1" ? "/run/infraternal" : resolve(runtime, "infraternal");
        const pause = spawn("python3", [resolve(import.meta.dirname, "pause-upstream.py"), component, String(serverPid), shimState, sessionId], { stdio: ["pipe", "pipe", "pipe"] });
        const exited = once(pause, "exit");
        // This helper opens a pidfd, never signals a reused PID and resumes on stdin EOF.
        const ready = once(pause.stdout, "data");
        pause.stderr.resume();
        let watchReplacement = true;
        let replacement: Promise<void> | undefined;
        try {
          const status = await Promise.race([ready.then(([bytes]) => String(bytes).trim()), exited.then(() => "ended")]);
          if (!/^paused [1-9][0-9]*$/.test(status)) throw new Error("private upstream pause failed");
          const pausedPid = Number(status.split(" ")[1]);
          if (component === "daemon" && process.env.RESTART_MEASURE === "1") replacement = (async () => {
            // The server replaces a stalled daemon without waiting for SIGCONT. Observe its own
            // child before it becomes ready, rather than subtracting an artificially late resume.
            while (watchReplacement) {
              const candidateAt = performance.timeOrigin + performance.now();
              const tasks = await readdir(`/proc/${serverPid}/task`);
              const children = await Promise.all(tasks.map((task) => readFile(`/proc/${serverPid}/task/${task}/children`, "utf8").catch(() => "")));
              if (children.some((ids) => ids.trim().split(/\s+/).some((pid) => Number(pid) > 0 && Number(pid) !== pausedPid))) {
                fixture.recoveredAt = candidateAt;
                return;
              }
              await new Promise((resolve) => setTimeout(resolve, 5));
            }
          })();
          await whilePaused();
          fixture.recoveredAt ??= performance.timeOrigin + performance.now();
        } finally {
          watchReplacement = false;
          pause.stdin.end("resume\n");
          await exited;
          await replacement;
        }
      },
      async interruptBrowserRoutes(durationMs) {
        if (!Number.isInteger(durationMs) || durationMs < 1 || durationMs > 10_000) throw new Error("invalid fixture drop duration");
        browserOfflineUntil = Date.now() + durationMs;
        for (const browser of activeBrowsers) browser.terminate();
        await new Promise((resolve) => setTimeout(resolve, durationMs));
      },
      dispose,
    };
    return fixture;
  } catch (error) {
    await dispose();
    throw error;
  }
}
