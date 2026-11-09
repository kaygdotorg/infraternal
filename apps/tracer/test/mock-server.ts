/** TEST DOUBLE: serves dist/, accepts test-only passkey ceremonies, and echoes wire input. */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { hostname } from "node:os";
import { extname, resolve, sep } from "node:path";
import { gunzipSync } from "node:zlib";
import { CLOSE_SESSION_GONE, encodeMuxedFrame, WebSocketFrameDecoder, type WireFrame } from "../../../packages/protocol/src/codec";
import { WebSocket, WebSocketServer, type RawData } from "ws";
import { QueryReplies } from "./query-replies-double";
import { terminalFixtures } from "./terminal-fixtures";
import { handleBootstrapHttp, serveProvisioning } from "./provisioning-double";
import { serveSetup } from "./setup-double";
import { addHostFixtures, prototypeHosts } from "./prototype-fixtures";
import { sessionDevices, sessionHosts } from "./session-fixtures";
import { renameDataset } from "../docs-dataset";
import { createPerfSink } from "./perf-sink";
import { appwinCall, appwinEnabled, appwinFrame, appwinHosts, appwinHttp, appwinSocketClosed, appwinLayoutFrame, appwinLayoutHold, appwinLayoutRead, appwinLayoutReplace, appwinLayoutReset } from "./appwin-double";

/**
 * Run for the docs' figures (`TRACER_DATASET=docs`, #302): every JSON answer carries the plain names of docs-dataset.ts, and the
 * hosts and sessions are the docs' own (docs-fixtures.ts). Off everywhere else; the capture's server is the only one that sets it.
 */
const DOCS_DATASET = process.env.TRACER_DATASET === "docs";

// Loopback unless a preview must be reachable on a private address (`TRACER_BIND_HOST`, e.g. a VM's mesh IP).
const HOST = process.env.TRACER_BIND_HOST ?? "localhost";
// The browser connects to TRACER_TEST_PORT; the TCP latency proxy reaches this private upstream port.
const FRONT_PORT = Number(process.env.TRACER_TEST_PORT ?? "4621");
const PORT = Number(process.env.TRACER_BACKEND_PORT ?? String(FRONT_PORT + 1));
if (!Number.isInteger(FRONT_PORT) || FRONT_PORT < 1 || FRONT_PORT > 65535) {
  throw new Error("TRACER_TEST_PORT must be an integer TCP port");
}
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  throw new Error("TRACER_BACKEND_PORT must be an integer TCP port");
}
const MAX_HTTP_BODY = 32 * 1024;
const MAX_MOCK_OUTPUT = 1024 * 1024;
const MOCK_OUTPUT_RING_CAPACITY = 8 * 1024 * 1024;
const MAX_MESSAGE = 16 * 1024;
const MAX_TRACE_EVENTS = 120_000;
const MAX_ATTACH_HISTORY = 64;
const DIST_ROOT = resolve(process.env.TRACER_DIST ?? resolve(import.meta.dirname, "../dist"));
const TEST_DOUBLE_HEADER = "X-Infraternal-Test-Double";

interface MockOwner {
  userId: string;
  username: string;
  displayName: string;
  credentialId: string;
  passkeyWrap: unknown;
  prfInput: string;
}

interface MockSession {
  cols: number;
  rows: number;
  queries: QueryReplies;
  sessionId: Uint8Array;
  sessionIdText: string;
  connectionId: Uint8Array;
  resumeToken: Uint8Array;
  fixtureOutput: Uint8Array;
  ringStartSequence: bigint;
  snapshotFrames: Array<{ outSeq: bigint; bytes: Uint8Array }>;
  snapshotCount: number;
  output: Uint8Array;
  echoOutputLength: number;
  outputLength: number;
  writtenInput: bigint;
  /** Fixture labels preserve each viewer cursor across reconnects. */
  viewerCursors: Map<string, bigint>;
  acceptedInputBytes: number;
  echoedText: string;
  echoMode: "normal" | "none" | "mask" | "wrong";
  echoDelayMs: number;
}

interface Connection {
  /** Test-only identity used to attribute input bytes to one attached browser. */
  clientId: number;
  viewerLabel: string | null;
  acceptedInputBytes: number;
  socket: WebSocket;
  decoder: WebSocketFrameDecoder;
  traceEnabled: boolean;
  session: MockSession;
  credit: number;
  outputCursor: bigint;
  inputCursor: bigint;
  replayUntil: bigint | undefined;
  replaySize: { cols: number; rows: number } | undefined;
  attached: boolean;
  /** The client stream the terminal uses (1 until a new shell opens another). */
  stream: number;
  /** Streams this connection ended with the final Close 4404; their in-flight frames are absorbed, as the server does. */
  goneStreams: Set<number>;
  /** Active session inventory subscriptions receive full snapshots, including after reconnects. */
  sessionInventorySubscriptions: Set<number>;
  welcomed: boolean;
  /** The client declared the desktop video capability in its Hello (app-window double only). */
  desktopCap?: boolean;
  /** Client streams that carry desktop viewers (app-window double only). */
  desktopStreams?: Set<number>;
  resumeAccepted: boolean;
  resumeExpected: boolean;
  viewerVisibility: boolean;
  hidden: boolean;
  welcomeTimer: ReturnType<typeof setTimeout> | undefined;
  livenessTimer: ReturnType<typeof setTimeout> | undefined;
  pendingPings: Map<bigint, number>;
  nextPing: bigint;
  lastPongAt: number;
  rtt: number;
}

interface TraceEvent {
  id: string;
  stage: "doubleReceive" | "doubleDecode" | "doubleEchoEncode" | "doubleEchoSend";
  atNs: string;
}

let owner: MockOwner | undefined;
let activeAuthCookie: string | undefined;
/**
 * A preview signed out on purpose (#171). Loading a preview page normally hands out a fresh mock session; after the
 * person signs out, a reload must stay on the sign-in screen, so the double stops handing one out until the page is
 * opened with `fresh=1`, a sign-in completes or the double is reset.
 */
let previewSignedOut = false;
let unlockPending = false;
let pendingTransaction: string | undefined;
let setupToken = newToken();
let pendingRegistration: { ceremony: string; userId: string; username: string; displayName: string; rpId: string; prfInput: string } | undefined;
let pendingLogin: { ceremony: string } | undefined;
let dropNextAck = false;
/** Closes each newly attached stream after a controlled delay for reconnect regressions. */
let closeAfterAttachMs: number | undefined;
/** A program that repaints after the next reattach (`/__mock/redraw-on-attach`): its bytes follow the replay once, after a delay. */
let redrawOnAttach: { bytes: Uint8Array; delayMs: number } | undefined;
let selectedFixture: Uint8Array | undefined;
const liveSessionIds = new Set<string>();
let sessionInventoryAvailable = true;
const earlySessions = new Map<string, MockSession>();
let session = createSession();
/** The reset seed is inventory-visible only if a client actually attaches to it. */
let unclaimedSessionId: string | undefined = session.sessionIdText;
/** Sessions the "host" no longer has (`/__mock/end-session`), and every AttachTerm seen, for the dead-session spec (#158). */
const goneSessions = new Set<string>();
/** The next `ssh.session.open` is refused as "unavailable" (`/__mock/refuse-next-open`), for the ended-strip spec (#185). */
let refuseNextOpen = false;
/** Retained, content-free host exit records; only the retired-exit fixture creates these. */
const retiredSessions = new Map<string, { status: number; finalSeq: number }>();
/** Interrupt exactly the first final answer to test recovery between its two ordered frames. */
const interruptedRetirements = new Set<string>();
let attachCount = 0;
let nextClientId = 0;
const attachHistory: Array<{ last_out_seq: string; output_sequence: string }> = [];
const traceEvents: TraceEvent[] = [];

const perfSink = createPerfSink(FRONT_PORT);
const server = createServer((request, response) => { void routeHttp(request, response); });
const webSockets = new WebSocketServer({ noServer: true, maxPayload: 2 * 1024 * 1024 });
const connections = new Set<Connection>();
// Theme regression tests compare these counters across a local palette change.
let socketOpenCount = 0;
let socketCloseCount = 0;

server.on("upgrade", (request, socket, head) => {
  const path = new URL(request.url ?? "/", `http://${request.headers.host ?? `${HOST}:${PORT}`}`).pathname;
  if (path === "/v1/bootstrap/ws" || path === "/v1/bootstrap/setup/ws") {
    // Same admission as the real route: exact Origin (403), then the unlocked owner session (401).
    const status = !sameOrigin(request) ? "403 Forbidden" : !isAuthenticated(request) ? "401 Unauthorized" : undefined;
    if (status) {
      socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
      socket.destroy();
      return;
    }
    webSockets.handleUpgrade(request, socket, head, (webSocket) => {
      if (path === "/v1/bootstrap/setup/ws") serveSetup(webSocket);
      else serveProvisioning(webSocket, request, () => {
        session = createSession(); earlySessions.set(session.sessionIdText, session);
        return session.sessionIdText;
      });
    });
    return;
  }
  if (path !== "/v1/ws") {
    socket.destroy();
    return;
  }
  webSockets.handleUpgrade(request, socket, head, (webSocket) => {
    webSockets.emit("connection", webSocket, request);
  });
});

webSockets.on("connection", (socket, request) => {
  if (!hasAuthCookie(request) || !owner) {
    socket.close(1008, "test-double authentication required");
    return;
  }
  const connection: Connection = {
    clientId: ++nextClientId,
    viewerLabel: new URL(request.url ?? "/", "http://localhost").searchParams.get("fixture_viewer"),
    acceptedInputBytes: 0,
    socket,
    decoder: new WebSocketFrameDecoder(),
    traceEnabled: new URL(request.url ?? "/", `http://${request.headers.host ?? `${HOST}:${PORT}`}`).searchParams.get("trace") === "1",
    session,
    credit: 0,
    outputCursor: 0n,
    inputCursor: 0n,
    replayUntil: undefined,
    replaySize: undefined,
    attached: false,
    stream: 1,
    goneStreams: new Set(),
    sessionInventorySubscriptions: new Set(),
    welcomed: false,
    resumeAccepted: false,
    resumeExpected: false,
    viewerVisibility: false,
    hidden: false,
    welcomeTimer: undefined,
    livenessTimer: undefined, pendingPings: new Map(), nextPing: 0n, lastPongAt: performance.now(), rtt: 1000,
  };
  connections.add(connection);
  socketOpenCount += 1;
  socket.on("message", (raw, binary) => {
    const receivedAt = connection.traceEnabled ? process.hrtime.bigint() : 0n;
    if (!binary) {
      socket.close(1003, "binary wire frames required");
      return;
    }
    try {
      const bytes = rawBytes(raw);
      connection.decoder.feed(bytes, (streamId, frame) => handleWire(connection, streamId, frame, receivedAt));
    } catch {
      socket.close(1002, "invalid test-double wire frame");
    }
  });
  socket.on("close", (code, reason) => {
    socketCloseCount += 1;
    appwinSocketClosed(socket);
    if (appwinEnabled) process.stdout.write(`socket closed ${code} ${reason.toString().slice(0, 80)}\n`);
    if (connection.welcomeTimer) clearTimeout(connection.welcomeTimer);
    if (connection.livenessTimer) clearTimeout(connection.livenessTimer);
    connections.delete(connection);
  });
});

server.listen(PORT, HOST, () => {
  process.stdout.write(`tracer TEST DOUBLE listening on http://${HOST}:${PORT}\n`);
});

/** Serves the double's HTTP side: the `/__mock/*` controls the specs drive, auth, and the built app. */
async function routeHttp(request: IncomingMessage, response: ServerResponse): Promise<void> {
  response.setHeader(TEST_DOUBLE_HEADER, "true");
  ensurePreviewSession(request, response);
  const host = request.headers.host ?? `${HOST}:${PORT}`;
  const url = new URL(request.url ?? "/", `http://${host}`);

  if (request.method === "GET" && url.pathname === "/health") {
    return sendJson(response, 200, { ok: true });
  }
  if (url.pathname === "/__perf") return perfSink(request, response);
  if (await appwinHttp(request, response, url.pathname, readJson, sendJson)) return;
  if (await handleBootstrapHttp(request, response, url.pathname, sameOrigin(request) || request.method === "GET" ? isAuthenticated(request) : false)) return;
  if (request.method === "GET" && url.pathname === "/__mock/proto/windows") {
    return sendJson(response, 200, { hosts: prototypeHosts });
  }
  if (request.method === "GET" && url.pathname === "/__mock/proto/sessions") {
    // The session inventory (D178). `?delay=<ms>` and `?fail=1` let the mockup show its slow and failed states.
    const delay = Math.min(5000, Math.max(0, Number(url.searchParams.get("delay")) || 0));
    if (delay) await new Promise((done) => setTimeout(done, delay));
    if (url.searchParams.get("fail") === "1") return sendJson(response, 503, { error: "session list unavailable" });
    return sendJson(response, 200, { hosts: sessionHosts, devices: sessionDevices });
  }
  if (request.method === "GET" && url.pathname === "/__mock/proto/addhost") {
    return sendJson(response, 200, { hosts: addHostFixtures });
  }
  // The account's toolbar layout (account default, shared by every device). The real server stores it per account.
  if (url.pathname === "/__mock/account/toolbar") {
    if (request.method === "GET") return sendJson(response, 200, { layout: accountToolbar ?? null });
    if (request.method === "PUT") {
      const body = await readJson(request);
      if (body === undefined || typeof body !== "object") return sendJson(response, 400, { error: "invalid request" });
      accountToolbar = body;
      return sendJson(response, 200, { ok: true });
    }
  }
  // Shared layouts (D182): a copy sent to users or groups, and team layouts that stay linked (a revision per update).
  if (url.pathname === "/__mock/shares") {
    if (request.method === "GET") {
      const person = url.searchParams.get("for") ?? "";
      const groups = Object.entries(mockGroups).filter(([, members]) => members.includes(person)).map(([g]) => `group:${g}`);
      const mine = mockShares.filter((x) => x.to.includes(`user:${person}`) || x.to.some((t) => groups.includes(t)));
      return sendJson(response, 200, { shares: mine });
    }
    if (request.method === "POST") {
      const body = await readJson(request);
      if (body === undefined || typeof body !== "object") return sendJson(response, 400, { error: "invalid request" });
      const share = { ...(body as object), id: `sh${mockShares.length + 1}`, rev: 1 } as MockShare;
      mockShares.push(share);
      return sendJson(response, 200, { id: share.id });
    }
  }
  if (request.method === "POST" && url.pathname === "/__mock/shares/update") {
    const body = (await readJson(request)) as { id?: string; key?: string; snapshot?: unknown } | undefined;
    const share = mockShares.find((x) => x.id === body?.id);
    const view = share?.views.find((v) => v.key === body?.key);
    if (!share || !view || !share.publish) return sendJson(response, 404, { error: "not found" });
    view.snapshot = body!.snapshot;
    share.rev++;
    return sendJson(response, 200, { rev: share.rev });
  }
  if (request.method === "GET" && url.pathname === "/__mock/setup-token") {
    return sendJson(response, 200, { setup_token: setupToken });
  }
  if (request.method === "POST" && url.pathname === "/__mock/open-terminal") {
    owner = makeMockOwner();
    activeAuthCookie = newToken();
    setAuthCookie(response, activeAuthCookie);
    return sendJson(response, 200, { ok: true });
  }
  if (request.method === "POST" && url.pathname === "/__mock/text-output") {
    const body = await readJson(request);
    if (typeof body?.text !== "string") return sendJson(response, 400, { error: "text output must be a string" });
    if (body.echo_input !== undefined && typeof body.echo_input !== "boolean") {
      return sendJson(response, 400, { error: "echo_input must be boolean" });
    }
    const bytes = new TextEncoder().encode(body.text);
    if (bytes.byteLength > MAX_MESSAGE) return sendJson(response, 413, { error: "text output exceeds one frame" });
    const connection = [...connections].find((candidate) => candidate.session === session && candidate.attached && isSocketOpen(candidate.socket));
    if (!connection || session.outputLength !== 0 || session.echoOutputLength !== 0) {
      return sendJson(response, 409, { error: "text output requires a fresh attached terminal" });
    }
    // Keep the visual metrics fixture on the same bounded Output path as normal PTY output.
    session.fixtureOutput = bytes;
    if (body.echo_input === false) session.echoMode = "none";
    session.ringStartSequence = 0n;
    session.snapshotFrames = [];
    session.outputLength = bytes.byteLength;
    flushOutput(connection);
    return sendJson(response, 200, { bytes: bytes.byteLength });
  }
  if (request.method === "POST" && url.pathname === "/__mock/live-query-output") {
    const body = await readJson(request);
    if (typeof body?.text !== "string") return sendJson(response, 400, { error: "query output must be a string" });
    const bytes = new TextEncoder().encode(body.text);
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_MESSAGE) return sendJson(response, 413, { error: "query output must fit one frame" });
    session.echoMode = "none";
    // Use the existing live suffix writer so these bytes follow the captured replay head.
    appendEchoOutput(session, bytes);
    return sendJson(response, 200, { bytes: bytes.byteLength, output_sequence: String(session.outputLength) });
  }
  if (request.method === "POST" && url.pathname === "/__mock/synchronized-output") {
    const body = await readJson(request);
    if (!Array.isArray(body?.parts) || body.parts.length < 2 || body.parts.length > 8 || body.parts.some((part) => typeof part !== "string")) {
      return sendJson(response, 400, { error: "synchronized output needs two to eight text parts" });
    }
    const parts = body.parts.map((part: string) => new TextEncoder().encode(part));
    if (parts.some((part: Uint8Array) => part.byteLength === 0 || part.byteLength > MAX_MESSAGE)) {
      return sendJson(response, 413, { error: "each synchronized output part must fit one frame" });
    }
    session.echoMode = "none";
    const outputSequences: string[] = [];
    for (let index = 0; index < parts.length; index += 1) {
      appendEchoOutput(session, parts[index]!);
      outputSequences.push(String(session.outputLength));
      // Let the browser's frame loop run between Output frames while keeping the test batch within its hold bound.
      if (index + 1 < parts.length) await new Promise((resolve) => setTimeout(resolve, 20));
    }
    return sendJson(response, 200, { output_sequences: outputSequences });
  }
  if (request.method === "POST" && url.pathname === "/__mock/query-snapshot") {
    const body = await readJson(request);
    if (typeof body?.text !== "string") return sendJson(response, 400, { error: "snapshot text must be a string" });
    const bytes = new TextEncoder().encode(body.text);
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_MESSAGE) {
      return sendJson(response, 413, { error: "query snapshot must fit one nonempty frame" });
    }
    // An intentionally adversarial repaint fixture: a screen restore must not
    // answer terminal queries even if its bytes contain query sequences.
    session.fixtureOutput = bytes;
    session.ringStartSequence = BigInt(bytes.byteLength);
    session.snapshotFrames = [{ outSeq: BigInt(bytes.byteLength), bytes }];
    session.snapshotCount = 0;
    session.output.fill(0);
    session.echoOutputLength = 0;
    session.outputLength = bytes.byteLength;
    session.writtenInput = 0n;
    session.acceptedInputBytes = 0;
    session.echoedText = "";
    return sendJson(response, 200, { bytes: bytes.byteLength });
  }
  if (request.method === "POST" && url.pathname === "/__mock/fixture") {
    const body = await readJson(request);
    const name = body?.name;
    const fixture = terminalFixtures.find((entry) => entry.name === name);
    if (!fixture) return sendJson(response, 400, { error: "unknown renderer fixture" });
    try {
      const compressed = await readFile(resolve(import.meta.dirname, "fixtures", fixture.path));
      const bytes = fixture.encoding === "gzip" ? gunzipSync(compressed) : compressed;
      const digest = createHash("sha256").update(bytes).digest("hex");
      if (bytes.byteLength !== fixture.bytes || digest !== fixture.sha256) {
        return sendJson(response, 500, { error: "renderer fixture checksum mismatch" });
      }
      const targets = [...new Set([...connections].map((connection) => connection.session))];
      if (targets.length === 0) targets.push(session);
      if (targets.some((target) => target.outputLength !== 0 || target.echoOutputLength !== 0)) {
        return sendJson(response, 409, { error: "renderer fixture requires a fresh terminal session" });
      }
      selectedFixture = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      for (const target of targets) {
        target.fixtureOutput = selectedFixture;
        target.outputLength = selectedFixture.byteLength;
      }
      for (const connection of connections) {
        if (connection.attached && targets.includes(connection.session)) flushOutput(connection);
      }
      return sendJson(response, 200, { bytes: fixture.bytes, sha256: digest });
    } catch {
      return sendJson(response, 500, { error: "renderer fixture could not be loaded" });
    }
  }
  if (request.method === "POST" && url.pathname === "/__mock/theme-palette-fixture") {
    if (connections.size > 0) return sendJson(response, 409, { error: "theme palette fixture requires a fresh terminal" });
    selectedFixture = themePaletteFixture();
    return sendJson(response, 200, { bytes: selectedFixture.byteLength });
  }
  if (request.method === "POST" && url.pathname === "/__mock/wrapped-ring") {
    if ([...connections].some((connection) => connection.session === session && connection.attached && isSocketOpen(connection.socket))) {
      return sendJson(response, 409, { error: "wrapped output requires a detached terminal" });
    }
    // Model the real 8 MiB shim ring while detached. The mock retains the
    // produced bytes only as fixture data; AttachTerm still takes the same
    // contract path and gets a valid repaint at the absolute output cursor.
    const totalBytes = MOCK_OUTPUT_RING_CAPACITY + 64;
    const history = new Uint8Array(totalBytes);
    const line = new TextEncoder().encode("a\r\n");
    const markerText = "__TRACER_SNAPSHOT_READY__\r\n";
    const marker = new TextEncoder().encode(markerText);
    const historyLength = history.byteLength - marker.byteLength;
    for (let offset = 0; offset < historyLength; offset += line.byteLength) {
      history.set(line.subarray(0, Math.min(line.byteLength, historyLength - offset)), offset);
    }
    history.set(marker, historyLength);
    const firstSnapshot = new TextEncoder().encode(`\x1bc\x1b[?25l${"a\r\n".repeat(256)}`);
    const finalSnapshot = new TextEncoder().encode(`\x1bc\x1b[?25l${"a\r\n".repeat(256)}${markerText}`);
    session.fixtureOutput = history;
    session.ringStartSequence = BigInt(totalBytes - MOCK_OUTPUT_RING_CAPACITY);
    // These valid progressive repaints share one websocket message so a second
    // Snapshot can be pending before the first renderer write reaches rAF.
    session.snapshotFrames = [
      { outSeq: BigInt(totalBytes - 1), bytes: firstSnapshot },
      { outSeq: BigInt(totalBytes), bytes: finalSnapshot },
    ];
    session.snapshotCount = 0;
    session.output.fill(0);
    session.echoOutputLength = 0;
    session.outputLength = totalBytes;
    session.writtenInput = 0n;
    session.acceptedInputBytes = 0;
    session.echoedText = "";
    return sendJson(response, 200, {
      bytes: totalBytes,
      ring_capacity: MOCK_OUTPUT_RING_CAPACITY,
      ring_start_sequence: session.ringStartSequence.toString(),
      output_sequence: String(session.outputLength),
    });
  }
  if (request.method === "POST" && url.pathname === "/__mock/unicode-case") {
    const body = await readJson(request);
    const mode = body?.mode;
    if (mode !== "single" && mode !== "utf8-split" && mode !== "grapheme-split" && mode !== "snapshot") {
      return sendJson(response, 400, { error: "unknown Unicode write mode" });
    }
    if (session.outputLength !== 0) return sendJson(response, 409, { error: "Unicode probe requires a fresh terminal" });
    const connection = [...connections].find((candidate) => candidate.session === session && candidate.attached && isSocketOpen(candidate.socket));
    if (!connection) return sendJson(response, 409, { error: "Unicode probe requires an attached terminal" });

    // Place one protocol boundary inside the skin-tone scalar or between the
    // base emoji and modifier while leaving the UTF-8 bytes unchanged.
    const paddingLength = mode === "utf8-split" ? MAX_MESSAGE - 7 : mode === "grapheme-split" ? MAX_MESSAGE - 4 : 0;
    const text = `${"a".repeat(paddingLength)}👩🏽‍💻 👨‍👩‍👧‍👦 🧑🏾‍🚀 🇩🇪 🇺🇳\r\n`;
    const bytes = new TextEncoder().encode(text);
    if (bytes.byteLength > connection.credit) return sendJson(response, 409, { error: "Unicode probe exceeds current terminal credit" });
    session.fixtureOutput = bytes;
    session.ringStartSequence = 0n;
    session.snapshotFrames = [];
    session.snapshotCount = 0;
    session.output.fill(0);
    session.echoOutputLength = 0;
    session.outputLength = bytes.byteLength;
    session.writtenInput = 0n;
    session.acceptedInputBytes = 0;
    session.echoedText = "";

    if (mode === "snapshot") {
      sendFrame(connection.socket, connection.stream, { type: "Snapshot", outSeq: BigInt(bytes.byteLength), bytes });
      connection.outputCursor = BigInt(bytes.byteLength);
      connection.credit -= bytes.byteLength;
      session.snapshotCount += 1;
    } else {
      for (let offset = 0; offset < bytes.byteLength; offset += MAX_MESSAGE) {
        const chunk = bytes.subarray(offset, Math.min(offset + MAX_MESSAGE, bytes.byteLength));
        sendFrame(connection.socket, connection.stream, { type: "Output", outSeq: BigInt(offset), bytes: chunk });
        connection.outputCursor = BigInt(offset + chunk.byteLength);
        connection.credit -= chunk.byteLength;
      }
    }
    return sendJson(response, 200, { mode, bytes: bytes.byteLength, output_sequence: String(session.outputLength) });
  }
  if (request.method === "POST" && url.pathname === "/__mock/canary") {
    const fixtureLength = session.fixtureOutput.byteLength;
    const readers = [...connections].filter((connection) => connection.session === session && connection.attached);
    if (readers.length === 0 || readers.some((connection) => connection.outputCursor < BigInt(fixtureLength))) {
      return sendJson(response, 409, { error: "fixture output is still in flight" });
    }
    const canary = new TextEncoder().encode("\u001bc\r\n__TRACER_CANARY__\r\n");
    session.output.set(canary, session.echoOutputLength);
    session.echoOutputLength += canary.byteLength;
    session.outputLength += canary.byteLength;
    for (const connection of readers) flushOutput(connection);
    return sendJson(response, 200, { bytes: canary.byteLength });
  }
  if (request.method === "GET" && url.pathname === "/__mock/state") {
    return sendJson(response, 200, {
      ...(owner ? { username: owner.username, display_name: owner.displayName } : {}),
      echoed_text: session.echoedText,
      ...(url.searchParams.get("input_bytes") === "1"
        ? { input_bytes: Array.from(session.output.subarray(0, session.echoOutputLength)) }
        : {}),
      written_input: session.writtenInput.toString(),
      accepted_input_bytes: session.acceptedInputBytes,
      reply_attempts: session.queries.attempts,
      dropped_replies: session.queries.dropped,
      output_sequence: String(session.outputLength),
      snapshot_count: session.snapshotCount,
      socket_open_count: socketOpenCount,
      socket_close_count: socketCloseCount,
      attach_count: attachCount,
      attach_history: attachHistory,
      attached_stream_ids: [...connections].filter((connection) => connection.attached).map((connection) => connection.stream),
      viewer_input_bytes: [...connections].map((connection) => ({
        client_id: connection.clientId,
        viewer_label: connection.viewerLabel,
        attached: connection.attached,
        accepted_input_bytes: connection.acceptedInputBytes,
      })),
      session_id: session.sessionIdText,
      active_socket_count: connections.size,
    });
  }
  if (request.method === "GET" && url.pathname === "/__mock/clock") {
    return sendJson(response, 200, { monotonic_ns: process.hrtime.bigint().toString() });
  }
  if (request.method === "GET" && url.pathname === "/__mock/trace") {
    return sendJson(response, 200, { events: traceEvents });
  }
  if (request.method === "POST" && url.pathname === "/__mock/trace/reset") {
    traceEvents.length = 0;
    return sendJson(response, 200, { ok: true });
  }
  if (request.method === "POST" && url.pathname === "/__mock/drop-next-ack") {
    dropNextAck = true;
    return sendJson(response, 200, { ok: true });
  }
  if (request.method === "POST" && url.pathname === "/__mock/echo-mode") {
    const body = await readJson(request);
    const mode = body?.mode;
    const delay = body?.delay_ms;
    if (mode !== "normal" && mode !== "none" && mode !== "mask" && mode !== "wrong") {
      return sendJson(response, 400, { error: "unknown terminal echo mode" });
    }
    if (delay !== undefined && (!Number.isInteger(delay) || Number(delay) < 0 || Number(delay) > 2000)) {
      return sendJson(response, 400, { error: "echo delay is outside the test bound" });
    }
    session.echoMode = mode;
    session.echoDelayMs = delay === undefined ? 0 : Number(delay);
    return sendJson(response, 200, { mode: session.echoMode, delay_ms: session.echoDelayMs });
  }
  if (request.method === "POST" && url.pathname === "/__mock/alternate-screen") {
    const body = await readJson(request);
    if (typeof body?.active !== "boolean") return sendJson(response, 400, { error: "active must be boolean" });
    appendEchoOutput(session, new TextEncoder().encode(body.active ? "\u001b[?1049h" : "\u001b[?1049l"));
    return sendJson(response, 200, { active: body.active });
  }
  if (request.method === "POST" && url.pathname === "/__mock/screen-reset") {
    appendEchoOutput(session, new TextEncoder().encode("\u001bc"));
    return sendJson(response, 200, { ok: true, output_sequence: String(session.outputLength) });
  }
  // A transient stream failure leaves its session and the shared WebSocket alive for retry (#158 review).
  if (request.method === "POST" && url.pathname === "/__mock/transient-terminal-close") {
    let closed = 0;
    for (const connection of connections) if (connection.attached) {
      connection.attached = false;
      connection.credit = 0;
      sendFrame(connection.socket, connection.stream, { type: "Close", code: 1013, reason: "attachment ended" });
      closed += 1;
    }
    return sendJson(response, 200, { closed });
  }
  // The host loses the current session. A full census may include its saved exit status; the drop-close variant
  // instead makes the infraternal agent unavailable so the final-answer reconnect path remains covered (#158).
  if (request.method === "POST" && (url.pathname === "/__mock/retire-session" || url.pathname === "/__mock/retire-session-drop-close")) {
    const body = await readJson(request);
    const status = body?.status;
    if (typeof status !== "number" || !Number.isInteger(status) || status < -2147483648 || status > 2147483647) return sendJson(response, 400, {});
    retiredSessions.set(session.sessionIdText, { status, finalSeq: session.outputLength + 42 });
    if (url.pathname.endsWith("drop-close")) {
      interruptedRetirements.add(session.sessionIdText);
      sessionInventoryAvailable = false;
    }
    goneSessions.add(session.sessionIdText);
    publishSessionInventory();
    for (const connection of connections) connection.socket.close(1011, "test-double host restarted");
    return sendJson(response, 200, { session_id: session.sessionIdText });
  }
  if (request.method === "POST" && url.pathname === "/__mock/refuse-next-open") {
    refuseNextOpen = true;
    return sendJson(response, 200, {});
  }
  if (request.method === "POST" && url.pathname === "/__mock/end-session") {
    goneSessions.add(session.sessionIdText);
    publishSessionInventory();
    for (const connection of connections) connection.socket.close(1011, "test-double host restarted");
    return sendJson(response, 200, { session_id: session.sessionIdText });
  }
  if (request.method === "GET" && url.pathname === "/__mock/layout") return sendJson(response, 200, appwinLayoutRead());
  // Holds or releases the answers to layout saves, like a stalled connection (D358: "Not saved" after about a second).
  if (request.method === "POST" && url.pathname === "/__mock/layout/hold") {
    const body = await readJson(request);
    if (typeof body?.hold !== "boolean") return sendJson(response, 400, {});
    appwinLayoutHold(body.hold);
    return sendJson(response, 200, {});
  }
  if (request.method === "POST" && url.pathname === "/__mock/layout") {
    const body = await readJson(request);
    return sendJson(response, appwinLayoutReplace(body?.document) ? 200 : 400, {});
  }
  if (request.method === "POST" && url.pathname === "/__mock/seed-ended-sessions") {
    const body = await readJson(request);
    const count = body?.count;
    if (typeof count !== "number" || !Number.isInteger(count) || count < 0 || count > 100) return sendJson(response, 400, {});
    const session_ids = Array.from({ length: count }, () => randomUuid());
    session_ids.forEach((id) => goneSessions.add(id));
    return sendJson(response, 200, { session_ids });
  }
  if (request.method === "POST" && url.pathname === "/__mock/remove-session-from-inventory") {
    goneSessions.add(session.sessionIdText);
    publishSessionInventory();
    return sendJson(response, 200, { session_id: session.sessionIdText });
  }
  if (request.method === "POST" && url.pathname === "/__mock/agent-offline") {
    sessionInventoryAvailable = false;
    publishSessionInventory();
    return sendJson(response, 200, {});
  }
  if (request.method === "POST" && url.pathname === "/__mock/agent-online") {
    sessionInventoryAvailable = true;
    publishSessionInventory();
    return sendJson(response, 200, {});
  }
  if (request.method === "POST" && url.pathname === "/__mock/drop-sockets") {
    for (const connection of connections) connection.socket.close(1011, "test-double link dropped");
    return sendJson(response, 200, {});
  }
  if (request.method === "POST" && url.pathname === "/__mock/live-output") {
    const body = await readJson(request);
    if (typeof body?.text !== "string") return sendJson(response, 400, { error: "text output must be a string" });
    appendEchoOutput(session, new TextEncoder().encode(body.text));
    return sendJson(response, 200, { output_sequence: String(session.outputLength) });
  }
  // Another viewer resized the session while this one was away: the next replay fence reports that size.
  if (request.method === "POST" && url.pathname === "/__mock/resize-session") {
    const body = await readJson(request);
    const valid = (n: unknown): n is number => typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= 1000;
    if (!valid(body?.cols) || !valid(body?.rows)) return sendJson(response, 400, { error: "size needs integer cols and rows" });
    session.cols = body.cols;
    session.rows = body.rows;
    return sendJson(response, 200, {});
  }
  if (request.method === "POST" && url.pathname === "/__mock/redraw-on-attach") {
    const body = await readJson(request);
    if (body?.text === null) { redrawOnAttach = undefined; return sendJson(response, 200, {}); }
    if (typeof body?.text !== "string" || typeof body.delay_ms !== "number" || !(body.delay_ms >= 0 && body.delay_ms <= 5000)) {
      return sendJson(response, 400, { error: "redraw needs text and a delay up to 5000 ms" });
    }
    redrawOnAttach = { bytes: new TextEncoder().encode(body.text), delayMs: body.delay_ms };
    return sendJson(response, 200, {});
  }
  if (request.method === "POST" && url.pathname === "/__mock/close-after-attach") {
    const body = await readJson(request);
    if (body?.delay_ms === null) {
      closeAfterAttachMs = undefined;
      return sendJson(response, 200, { delay_ms: null });
    }
    const delay = body?.delay_ms;
    if (typeof delay !== "number" || !Number.isInteger(delay) || delay < 50 || delay > 1000) {
      return sendJson(response, 400, { error: "delay is outside the test bound" });
    }
    closeAfterAttachMs = delay;
    return sendJson(response, 200, { delay_ms: delay });
  }
  if (request.method === "POST" && url.pathname === "/__mock/reset") {
    resetMockState();
    return sendJson(response, 200, { setup_token: setupToken });
  }
  if (url.pathname.startsWith("/auth/")) {
    if (request.method !== "POST") return sendJson(response, 405, { error: "POST required" });
    if (!sameOrigin(request)) {
      process.stdout.write("test-double rejected an auth request with a non-matching Origin\n");
      return sendJson(response, 401, { error: "authorization failed" });
    }
    const body = await readJson(request);
    if (body === undefined) return sendJson(response, 400, { error: "invalid request" });
    return authAction(url.pathname.slice("/auth/".length), body, request, response);
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    return sendJson(response, 404, { error: "not found" });
  }
  if ((url.pathname === "/" || url.pathname === "/index.html") && ["windows", "addhost", "clusters", "product"].includes(url.searchParams.get("proto") ?? "") && (!previewSignedOut || url.searchParams.has("fresh"))) {
    previewSignedOut = false;
    if (!owner) owner = makeMockOwner();
    activeAuthCookie = newToken();
    unlockPending = false;
    pendingTransaction = undefined;
    pendingLogin = undefined;
    setPreviewAuthCookie(response, activeAuthCookie);
  }
  await serveDist(url.pathname, request.method === "HEAD", response);
}

async function authAction(
  action: string,
  body: Record<string, unknown>,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  response.setHeader("Cache-Control", "no-store");
  switch (action) {
    case "status":
      return sendJson(response, 200, {
        setup_required: !owner,
        setup_token_command: "infraternal server setup-token",
      });
    case "setup-check": {
      if (Object.keys(body).length !== 1 || typeof body.token !== "string") {
        return sendJson(response, 400, { error: "invalid request" });
      }
      if (owner) return sendJson(response, 404, { error: "not found" });
      const candidate = createHash("sha256").update(body.token).digest();
      const expected = createHash("sha256").update(setupToken).digest();
      if (!timingSafeEqual(candidate, expected)) return sendJson(response, 401, { error: "authorization failed" });
      response.writeHead(204);
      response.end();
      return;
    }
    case "session":
      if (unlockPending) return sendJson(response, 401, { error: "authorization failed" });
    case "unlock-session":
      if (!isAuthenticated(request) || !owner) return sendJson(response, 401, { error: "authorization failed" });
      return sendJson(response, 200, { user_id: owner.userId, username: owner.username, display_name: owner.displayName, device: "test-double", fresh: 1, hostname: DOCS_DATASET ? "home-server" : hostname() });
    case "setup-start": {
      const username = body.username;
      const suppliedDisplayName = body.display_name;
      const usernameValid = typeof username === "string" && /^[a-z0-9_-]{2,32}$/.test(username);
      const displayNameValid = suppliedDisplayName === undefined || (typeof suppliedDisplayName === "string" && [...suppliedDisplayName].length <= 64);
      if (owner || body.token !== setupToken || !usernameValid || !displayNameValid || Object.keys(body).some((key) => !["token", "username", "display_name"].includes(key))) {
        process.stdout.write(`test-double setup denied: owner=${Boolean(owner)} token-match=${body.token === setupToken} username-valid=${usernameValid} display-name-valid=${displayNameValid}\n`);
        return sendJson(response, 401, { error: "authorization failed" });
      }
      const rpId = request.headers.host?.split(":")[0] ?? HOST;
      const userId = randomUuid();
      const ceremony = newToken();
      const displayName = typeof suppliedDisplayName === "string" && suppliedDisplayName.trim() ? suppliedDisplayName : username;
      const prfInput = createHash("sha256").update("infraternal/keywrap/prf/v3").digest("base64url");
      pendingRegistration = { ceremony, userId, username, displayName, rpId, prfInput };
      const publicKey = {
        challenge: randomBytes(32).toString("base64url"),
        rp: { name: "infraternal test double", id: rpId },
        user: { id: Buffer.from(uuidBytes(userId)).toString("base64url"), name: username, displayName },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        timeout: 60_000,
        attestation: "none",
        excludeCredentials: [],
        authenticatorSelection: {
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "required",
        },
        extensions: { prf: { eval: { first: prfInput } } },
      };
      return sendJson(response, 200, { ceremony, user_id: userId, options: { publicKey }, recovery_words: null, recovery_version: 2 });
    }
    case "registration-finish": {
      const proof = asRecord(body.proof);
      const extensionResults = asRecord(proof.extensions);
      if (!pendingRegistration || body.ceremony !== pendingRegistration.ceremony || "prf" in extensionResults) {
        return sendJson(response, 401, { error: "authorization failed" });
      }
      const credentialId = stringValue(proof.rawId);
      if (!credentialId || typeof body.recovery_verifier !== "string" || !asRecord(body.passkey_wrap) || !asRecord(body.recovery_wrap)) {
        return sendJson(response, 400, { error: "invalid request" });
      }
      owner = {
        userId: pendingRegistration.userId,
        username: pendingRegistration.username,
        displayName: pendingRegistration.displayName,
        credentialId,
        passkeyWrap: body.passkey_wrap,
        prfInput: pendingRegistration.prfInput,
      };
      pendingRegistration = undefined;
      activeAuthCookie = newToken();
      previewSignedOut = false;
      setAuthCookie(response, activeAuthCookie);
      return sendJson(response, 200, { ok: true });
    }
    case "login-start": {
      if (!owner || Object.keys(body).length !== 0) return sendJson(response, 401, { error: "authorization failed" });
      pendingLogin = { ceremony: newToken() };
      const publicKey = {
        challenge: randomBytes(32).toString("base64url"),
        rpId: request.headers.host?.split(":")[0] ?? HOST,
        allowCredentials: [],
        timeout: 60_000,
        userVerification: "required",
        extensions: { prf: { eval: { first: createHash("sha256").update("infraternal/keywrap/prf/v3").digest("base64url") } } },
      };
      return sendJson(response, 200, { ceremony: pendingLogin.ceremony, options: { publicKey } });
    }
    case "login-finish": {
      const proof = asRecord(body.proof);
      const extensionResults = asRecord(proof.extensions);
      if (!owner || !pendingLogin || body.ceremony !== pendingLogin.ceremony
        || proof.rawId !== owner.credentialId || asRecord(proof.response).userHandle !== Buffer.from(uuidBytes(owner.userId)).toString("base64url") || "prf" in extensionResults) {
        return sendJson(response, 401, { error: "authorization failed" });
      }
      pendingLogin = undefined;
      unlockPending = true;
      pendingTransaction = newToken();
      activeAuthCookie = newToken();
      previewSignedOut = false;
      setAuthCookie(response, activeAuthCookie);
      return sendJson(response, 200, { ok: true, pending_transaction: pendingTransaction });
    }
    case "unlock-finish":
      if (!isAuthenticated(request)) return sendJson(response, 401, { error: "authorization failed" });
      if (!unlockPending || body.pending_transaction !== pendingTransaction) return sendJson(response, 401, { error: "authorization failed" });
      unlockPending = false;
      pendingTransaction = undefined;
      return sendJson(response, 200, { ok: true });
    case "wraps":
      if (!isAuthenticated(request) || !owner) return sendJson(response, 401, { error: "authorization failed" });
      return sendJson(response, 200, [{ kind: "passkey", key_id: owner.credentialId, wrap: owner.passkeyWrap, prf_input: owner.prfInput }]);
    case "logout":
      if (body.pending_transaction !== undefined && (!unlockPending || body.pending_transaction !== pendingTransaction)) return sendJson(response, 401, { error: "authorization failed" });
      if (!isAuthenticated(request)) return sendJson(response, 401, { error: "authorization failed" });
      activeAuthCookie = undefined;
      if (body.pending_transaction === undefined) previewSignedOut = true;
      response.setHeader("Set-Cookie", "__Host-infraternal=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
      return sendJson(response, 200, { ok: true });
    default:
      return sendJson(response, 404, { error: "invalid request" });
  }
}

function handleWire(connection: Connection, streamId: number, frame: WireFrame, receivedAt: bigint): void {
  if (!isSocketOpen(connection.socket)) return;
  if (connection.traceEnabled && streamId === 1 && frame.type === "Input") {
    traceRange(frame.inSeq, frame.bytes.byteLength, "doubleReceive", receivedAt);
    traceRange(frame.inSeq, frame.bytes.byteLength, "doubleDecode", process.hrtime.bigint());
  }
  if (streamId === 0) {
    handleControlFrame(connection, frame);
  } else if (appwinEnabled && (frame.type === "Desktop" || connection.desktopStreams?.has(streamId))) {
    // A desktop viewer needs the capability the client declared in its Hello; without it the socket is refused, as the server does.
    if (!connection.desktopCap) { connection.socket.close(1002, "desktop video was not declared"); return; }
    (connection.desktopStreams ??= new Set()).add(streamId);
    if (frame.type === "Close") connection.desktopStreams.delete(streamId);
    appwinFrame(connection.socket, streamId, frame);
  } else if (connection.goneStreams.has(streamId)) {
    // Like the server: frames that crossed the final Close are dropped, and the client's own Close ends the entry.
    if (frame.type === "Close") connection.goneStreams.delete(streamId);
    else if (frame.type !== "Input" && frame.type !== "Credit" && frame.type !== "Resize") connection.socket.close(1002, "unexpected frame on an ended stream");
  } else if (streamId % 2 === 1 && (streamId === connection.stream || (frame.type === "AttachTerm" && !connection.attached))) {
    handleTerminalFrame(connection, streamId, frame);
  } else {
    connection.socket.close(1002, "unexpected mux stream");
  }
}

function handleControlFrame(connection: Connection, frame: WireFrame): void {
  if (connection.welcomed && appwinLayoutFrame(connection.socket, frame)) return;
  switch (frame.type) {
    case "Hello":
      connection.resumeExpected = (frame.caps & 1n) !== 0n;
      connection.desktopCap = (frame.caps & 16n) !== 0n;
      connection.viewerVisibility = (frame.caps & 4n) !== 0n;
      if (!connection.resumeExpected) {
        // A connection without Resume creates a fresh writer; its input cursor
        // starts at zero even though accepted_input_bytes remains cumulative.
        connection.inputCursor = 0n;
        connection.session.writtenInput = 0n;
        connection.session.viewerCursors.set(connection.viewerLabel ?? "", 0n);
      }
      sendFrame(connection.socket, 0, { type: "Hello", version: 1, caps: 12n | (appwinEnabled ? 16n : 0n), clientInfo: "infraternal-mock-test-double/0.1" });
      connection.welcomeTimer = setTimeout(() => sendWelcome(connection), 0);
      return;
    case "Resume":
      if (!connection.resumeExpected) {
        connection.socket.close(1002, "Resume without RESUME_NEXT");
        return;
      }
      if (!bytesEqual(frame.connectionId, connection.session.connectionId)
        || !bytesEqual(frame.resumeToken, connection.session.resumeToken)) {
        connection.socket.close(1008, "invalid test-double resume token");
        return;
      }
      connection.resumeAccepted = true;
      connection.inputCursor = connection.session.viewerCursors.get(connection.viewerLabel ?? "") ?? 0n;
      if (connection.welcomeTimer) clearTimeout(connection.welcomeTimer);
      sendWelcome(connection);
      return;
    case "Call": {
      if (connection.welcomed && frame.callId > 0 && frame.actionId === "remote.host.list") {
        sendFrame(connection.socket, 0, { type: "Result", callId: frame.callId, ok: true, json: new TextEncoder().encode(JSON.stringify({ hosts: appwinHosts(), next: null })) });
        return;
      }
      if (connection.welcomed && frame.callId > 0 && appwinEnabled && frame.actionId.startsWith("desktop.")) {
        let input: Record<string, unknown> = {};
        try { input = JSON.parse(new TextDecoder().decode(frame.inputJson)) as Record<string, unknown>; } catch { /* an empty input */ }
        if (appwinCall(connection.socket, frame.callId, frame.actionId, input)) return;
      }
      if (connection.welcomed && frame.callId > 0 && frame.actionId === "host.facts.read") {
        sendFrame(connection.socket, 0, { type: "Result", callId: frame.callId, ok: true, json: new TextEncoder().encode('{"os":"Linux"}') });
        return;
      }
      // Refuse unsupported actions without retiring unrelated terminal streams.
      // The product canvas also requests host facts during its first attachment.
      if (connection.welcomed && frame.callId >= 1 && frame.actionId !== "ssh.session.open") {
        sendFrame(connection.socket, 0, { type: "Result", callId: frame.callId, ok: false, json: new TextEncoder().encode('{"error":"unknown action"}') });
        return;
      }
      if (!connection.welcomed || frame.callId < 1 || frame.actionId !== "ssh.session.open") {
        connection.socket.close(1002, "unexpected test-double action");
        return;
      }
      if (refuseNextOpen) {
        refuseNextOpen = false;
        sendFrame(connection.socket, 0, { type: "Result", callId: frame.callId, ok: false, json: new TextEncoder().encode('{"error":"unavailable"}') });
        return;
      }
      // A fresh open gets fresh terminal state; only Resume reuses an existing session.
      if (unclaimedSessionId) {
        liveSessionIds.delete(unclaimedSessionId);
        unclaimedSessionId = undefined;
      }
      connection.session = session = createSession(connection.session, selectedFixture);
      connection.inputCursor = 0n;
      publishSessionInventory();
      sendFrame(connection.socket, 0, {
        type: "Result",
        callId: frame.callId,
        ok: true,
        json: new TextEncoder().encode(JSON.stringify({ session_id: connection.session.sessionIdText })),
      });
      return;
    }
    case "Subscribe":
      if (JSON.parse(new TextDecoder().decode(frame.filterJson))?.topic === "remote.hosts") return;
      if (frame.subId === 45 && new TextDecoder().decode(frame.filterJson) === '{"topic":"auth.recovery"}') return;
      if (JSON.parse(new TextDecoder().decode(frame.filterJson))?.topic === "terminal.sessions") {
        connection.sessionInventorySubscriptions.add(frame.subId);
        sendSessionInventory(connection, frame.subId);
        return;
      }
      connection.socket.close(1002, "unexpected test-double subscription");
      return;
    case "Event": {
      if (!connection.viewerVisibility || frame.subId !== 0 || frame.eventJson.byteLength > 128) { connection.socket.close(1002, "invalid visibility notice"); return; }
      const notice = JSON.parse(new TextDecoder().decode(frame.eventJson)) as { topic?: unknown; hidden?: unknown };
      if (notice.topic !== "connection.visibility" || typeof notice.hidden !== "boolean") { connection.socket.close(1002, "invalid visibility notice"); return; }
      connection.hidden = notice.hidden;
      if (connection.livenessTimer) clearTimeout(connection.livenessTimer);
      connection.pendingPings.clear();
      connection.lastPongAt = performance.now();
      connection.rtt = 1000;
      if (!connection.hidden) connection.livenessTimer = setTimeout(() => probeConnection(connection), 25);
      return;
    }
    case "Ping":
      sendFrame(connection.socket, 0, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs });
      return;
    case "Pong": {
      const started = connection.pendingPings.get(frame.nonce);
      if (started === undefined) return;
      connection.lastPongAt = performance.now();
      connection.rtt = Math.max(1, connection.lastPongAt - started);
      for (const nonce of connection.pendingPings.keys()) if (nonce <= frame.nonce) connection.pendingPings.delete(nonce);
      return;
    }
    default:
      connection.socket.close(1002, "unexpected test-double control frame");
  }
}

function handleTerminalFrame(connection: Connection, streamId: number, frame: WireFrame): void {
  switch (frame.type) {
    case "AttachTerm":
      if (!connection.attached && earlySessions.has(uuidText(frame.sessionId))) connection.session = earlySessions.get(uuidText(frame.sessionId))!;
      attachCount += 1;
      if (attachHistory.length < MAX_ATTACH_HISTORY) {
        attachHistory.push({ last_out_seq: frame.lastOutSeq.toString(), output_sequence: String(connection.session.outputLength) });
      }
      if (unclaimedSessionId === uuidText(frame.sessionId)) unclaimedSessionId = undefined;
      if (goneSessions.has(uuidText(frame.sessionId))) {
        connection.goneStreams.add(streamId);
        const exit = retiredSessions.get(uuidText(frame.sessionId));
        if (exit) sendFrame(connection.socket, streamId, { type: "Event", subId: 0, eventJson: new TextEncoder().encode(JSON.stringify({ type: "terminal.exited", session_id: uuidText(frame.sessionId), status: exit.status, final_seq: exit.finalSeq, retired: true })) });
        if (interruptedRetirements.delete(uuidText(frame.sessionId))) {
          connection.socket.close(1011, "test-double interrupted final answer");
          return;
        }
        sendFrame(connection.socket, streamId, { type: "Close", code: CLOSE_SESSION_GONE, reason: "session ended" });
        return;
      }
      connection.stream = streamId;
      if (!bytesEqual(frame.sessionId, connection.session.sessionId) || connection.attached) {
        connection.socket.close(1002, "invalid test-double attach");
        return;
      }
      connection.attached = true;
      connection.outputCursor = frame.lastOutSeq;
      connection.replayUntil = BigInt(connection.session.outputLength);
      connection.replaySize = { cols: connection.session.cols, rows: connection.session.rows };
      sendFrame(connection.socket, connection.stream, { type: "Ack", inSeqAcked: connection.inputCursor });
      flushOutput(connection);
      if (redrawOnAttach) {
        const redraw = redrawOnAttach;
        redrawOnAttach = undefined;
        const target = connection.session;
        setTimeout(() => appendEchoOutput(target, redraw.bytes), redraw.delayMs);
      }
      if (closeAfterAttachMs !== undefined) {
        setTimeout(() => {
          if (!isSocketOpen(connection.socket)) return;
          sendFrame(connection.socket, 0, { type: "Close", code: 1011, reason: "connection ended" });
          connection.socket.close(1011, "connection ended");
        }, closeAfterAttachMs);
      }
      return;
    case "Credit":
      if (!connection.attached || connection.credit > 1024 * 1024 - frame.bytes) {
        connection.socket.close(1002, "invalid test-double credit");
        return;
      }
      connection.credit += frame.bytes;
      flushOutput(connection);
      return;
    case "Input":
      if (!connection.attached) {
        connection.socket.close(1002, "input before test-double attach");
        return;
      }
      if (frame.replyTo !== undefined) {
        if (connection.session.queries.accept(frame.replyTo, frame.bytes)) {
          connection.session.acceptedInputBytes += frame.bytes.length;
          connection.acceptedInputBytes += frame.bytes.length;
        }
        return;
      }
      acceptInput(connection, frame.inSeq, frame.bytes);
      return;
    case "Resize":
      connection.session.cols = frame.cols;
      connection.session.rows = frame.rows;
      return;
    case "Close":
      // The window detached; the session keeps running.
      connection.attached = false;
      return;
    case "Ping":
      sendFrame(connection.socket, connection.stream, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs });
      return;
    default:
      connection.socket.close(1002, "unexpected test-double terminal frame");
  }
}

function acceptInput(connection: Connection, sequence: bigint, bytes: Uint8Array): void {
  if (sequence > connection.inputCursor || sequence + BigInt(bytes.byteLength) > 0xffff_ffff_ffff_ffffn) {
    connection.socket.close(1002, "input sequence gap in test double");
    return;
  }
  const alreadyWritten = Number(connection.inputCursor - sequence);
  const duplicateBytes = Math.min(bytes.byteLength, alreadyWritten);
  const fresh = bytes.subarray(duplicateBytes);
  if (fresh.byteLength > 0) {
    if (connection.session.echoOutputLength + fresh.byteLength > MAX_MOCK_OUTPUT) {
      connection.socket.close(1011, "test-double output limit reached");
      return;
    }
    connection.inputCursor += BigInt(fresh.byteLength);
    connection.session.writtenInput = connection.inputCursor;
    connection.session.viewerCursors.set(connection.viewerLabel ?? "", connection.inputCursor);
    connection.session.acceptedInputBytes += fresh.byteLength;
    connection.acceptedInputBytes += fresh.byteLength;
    connection.session.echoedText += new TextDecoder().decode(fresh);
    const echoed = echoBytes(connection.session, fresh);
    if (echoed && connection.session.echoDelayMs > 0) {
      const delayedSession = connection.session;
      const delay = delayedSession.echoDelayMs;
      setTimeout(() => appendEchoOutput(delayedSession, echoed), delay);
    } else if (echoed) {
      appendEchoOutput(connection.session, echoed);
    }
  }
  if (dropNextAck && fresh.byteLength > 0) {
    dropNextAck = false;
    connection.socket.close(4001, "test-double forced input acknowledgement drop");
    return;
  }
  sendFrame(connection.socket, connection.stream, { type: "Ack", inSeqAcked: connection.inputCursor });
  flushOutput(connection);
}

function echoBytes(target: MockSession, bytes: Uint8Array): Uint8Array | undefined {
  if (target.echoMode === "none") return undefined;
  if (target.echoMode === "normal") {
    // The input path may coalesce several keys into one frame; a host echoes every DEL as an erase.
    if (!bytes.includes(0x7f)) return bytes.slice();
    const echoed: number[] = [];
    for (const byte of bytes) {
      if (byte === 0x7f) echoed.push(0x08, 0x20, 0x08);
      else echoed.push(byte);
    }
    return Uint8Array.from(echoed);
  }
  if (target.echoMode === "wrong") return new Uint8Array(bytes.byteLength).fill(0x21);
  return Uint8Array.from(bytes, (byte) => byte >= 0x20 && byte !== 0x7f ? 0x2a : byte);
}

function appendEchoOutput(target: MockSession, bytes: Uint8Array): void {
  if (target.echoOutputLength + bytes.byteLength > MAX_MOCK_OUTPUT) return;
  target.output.set(bytes, target.echoOutputLength);
  target.echoOutputLength += bytes.byteLength;
  target.outputLength += bytes.byteLength;
  for (const connection of connections) {
    if (connection.session === target) flushOutput(connection);
  }
}

function flushOutput(connection: Connection): void {
  if (!connection.attached || !isSocketOpen(connection.socket)) return;
  if (connection.outputCursor < connection.session.ringStartSequence) {
    const snapshots = connection.session.snapshotFrames;
    const repaintBytes = snapshots.reduce((total, snapshot) => total + snapshot.bytes.byteLength, 0);
    if (snapshots.length === 0 || repaintBytes > connection.credit) return;
    sendFrames(connection.socket, connection.stream, snapshots.map(({ outSeq, bytes }) => ({ type: "Snapshot", outSeq, bytes })));
    // A Snapshot may predate output that is already in the session ring. Resume
    // at its absolute cursor so that those later bytes still follow the repaint.
    connection.outputCursor = snapshots[snapshots.length - 1]!.outSeq;
    connection.credit -= repaintBytes;
    connection.session.snapshotCount += snapshots.length;
  }
  flushReplayComplete(connection);
  const availableEnd = BigInt(connection.session.outputLength);
  while (connection.credit > 0 && connection.outputCursor < availableEnd) {
    flushReplayComplete(connection);
    const absoluteOffset = Number(connection.outputCursor);
    const fixtureLength = connection.session.fixtureOutput.byteLength;
    const source = absoluteOffset < fixtureLength ? connection.session.fixtureOutput : connection.session.output;
    const offset = absoluteOffset < fixtureLength ? absoluteOffset : absoluteOffset - fixtureLength;
    const sourceEnd = absoluteOffset < fixtureLength ? fixtureLength : fixtureLength + connection.session.echoOutputLength;
    const replayRemaining = connection.replayUntil === undefined
      ? Number.POSITIVE_INFINITY
      : Number(connection.replayUntil - connection.outputCursor);
    const length = Math.min(MAX_MESSAGE, connection.credit, sourceEnd - absoluteOffset, replayRemaining);
    if (length <= 0) break;
    const bytes = source.subarray(offset, offset + length);
    connection.session.queries.output(connection.outputCursor, bytes);
    sendFrame(connection.socket, connection.stream, { type: "Output", outSeq: connection.outputCursor, bytes },
      connection.traceEnabled ? connection.outputCursor : undefined, length);
    connection.outputCursor += BigInt(length);
    connection.credit -= length;
    flushReplayComplete(connection);
  }
}

/** Places the mock's restore boundary after replay and before later live output. */
function flushReplayComplete(connection: Connection): void {
  const fence = connection.replayUntil;
  if (fence === undefined || connection.outputCursor < fence) return;
  sendFrame(connection.socket, connection.stream, {
    type: "Event",
    subId: 0,
    eventJson: new TextEncoder().encode(JSON.stringify({
      type: "terminal.replay_complete",
      session_id: connection.session.sessionIdText,
      out_seq: connection.outputCursor.toString(),
      ...connection.replaySize,
    })),
  });
  connection.replayUntil = undefined;
}

function sendWelcome(connection: Connection): void {
  if (connection.welcomed || !isSocketOpen(connection.socket)) return;
  connection.welcomed = true;
  if (connection.welcomeTimer) clearTimeout(connection.welcomeTimer);
  sendFrame(connection.socket, 0, {
    type: "Welcome",
    connectionId: connection.session.connectionId,
    resumeToken: connection.session.resumeToken,
    resumeWindowSeconds: 120,
  });
  connection.lastPongAt = performance.now();
  connection.livenessTimer = setTimeout(() => probeConnection(connection), 25);
}

/** Mirror production server-driven liveness: an offline viewer must retire even if its Close cannot reach us. */
function probeConnection(connection: Connection): void {
  if (!isSocketOpen(connection.socket) || connection.hidden) return;
  const now = performance.now();
  if (now - connection.lastPongAt >= 2 * Math.min(2000, Math.max(250, 2 * connection.rtt + 75))) {
    connection.socket.close(4000, "connection unresponsive");
    return;
  }
  const nonce = ++connection.nextPing;
  if (connection.pendingPings.size >= 128) connection.pendingPings.delete(connection.pendingPings.keys().next().value!);
  connection.pendingPings.set(nonce, now);
  sendFrame(connection.socket, 0, { type: "Ping", nonce, sentUs: BigInt(Math.round(now * 1000)) });
  connection.livenessTimer = setTimeout(() => probeConnection(connection), 25);
}

function sendFrame(socket: WebSocket, streamId: number, frame: WireFrame, traceStart?: bigint, traceLength = 0): void {
  if (!isSocketOpen(socket)) return;
  const message = Buffer.from(encodeMuxedFrame(streamId, frame));
  if (traceStart !== undefined) traceRange(traceStart, traceLength, "doubleEchoEncode", process.hrtime.bigint());
  socket.send(message, { binary: true });
  if (traceStart !== undefined) traceRange(traceStart, traceLength, "doubleEchoSend", process.hrtime.bigint());
}

/** Sends ordered mock frames in one message to exercise decoder and paint ordering deterministically. */
function sendFrames(socket: WebSocket, streamId: number, frames: WireFrame[]): void {
  if (!isSocketOpen(socket)) return;
  const message = Buffer.concat(frames.map((frame) => Buffer.from(encodeMuxedFrame(streamId, frame))));
  socket.send(message, { binary: true });
}

/** Records server-side monotonic marks keyed by the echoed byte-stream offset. */
function traceRange(start: bigint, length: number, stage: TraceEvent["stage"], atNs: bigint): void {
  for (let offset = 0; offset < length && traceEvents.length < MAX_TRACE_EVENTS; offset += 1) {
    traceEvents.push({ id: (start + BigInt(offset)).toString(), stage, atNs: atNs.toString() });
  }
}

async function serveDist(pathname: string, headOnly: boolean, response: ServerResponse): Promise<void> {
  let decoded: string;
  try { decoded = decodeURIComponent(pathname); } catch { return sendJson(response, 400, { error: "invalid path" }); }
  // A directory is served by its index.html, as the real server's web root does (the docs pages live in directories).
  const relative = decoded === "/" ? "index.html" : decoded.endsWith("/") ? `${decoded.slice(1)}index.html` : decoded.slice(1);
  const path = resolve(DIST_ROOT, relative);
  if (!path.startsWith(`${DIST_ROOT}${sep}`) && path !== DIST_ROOT) return sendJson(response, 404, { error: "not found" });
  let file = path;
  let bytes: Buffer;
  try {
    bytes = await readFile(file);
  } catch {
    if (extname(path)) return sendJson(response, 404, { error: "not found" });
    file = resolve(DIST_ROOT, "index.html");
    try {
      bytes = await readFile(file);
    } catch {
      return sendJson(response, 404, { error: "not found" });
    }
  }
  response.statusCode = 200;
  response.setHeader("Content-Type", contentType(extname(file)));
  response.setHeader("Cache-Control", "no-store");
  response.end(headOnly ? undefined : bytes);
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown> | undefined> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.byteLength;
    if (total > MAX_HTTP_BODY) return undefined;
    chunks.push(bytes);
  }
  try { return asRecord(JSON.parse(Buffer.concat(chunks).toString("utf8"))); } catch { return undefined; }
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Cache-Control", "no-store");
  const text = JSON.stringify(value);
  response.end(DOCS_DATASET ? renameDataset(text) : text);
}

function sameOrigin(request: IncomingMessage): boolean {
  return request.headers.origin === `http://${request.headers.host ?? `${HOST}:${PORT}`}`;
}

/**
 * Test double only: a mockup preview page (`?mock=1&proto=...`) whose session cookie this process does not
 * know (the double restarted, or the cookie expired) gets a fresh mock session on its next request, so a
 * restart never strands an open tab. Plain `?mock=1` pages (the sign-in and onboarding tests) are left alone.
 */
function ensurePreviewSession(request: IncomingMessage, response: ServerResponse): void {
  const referer = request.headers.referer ?? "";
  if (!/[?&]mock=1(&|$)/.test(referer) || !/[?&]proto=/.test(referer)) return;
  if (!request.url?.startsWith("/auth/") && !request.url?.startsWith("/__mock/")) return;
  if (request.url.startsWith("/__mock/reset") || isAuthenticated(request) || previewSignedOut) return;
  if (!owner) owner = makeMockOwner();
  activeAuthCookie = newToken();
  setPreviewAuthCookie(response, activeAuthCookie);
  request.headers.cookie = `infraternal-mock-session=${activeAuthCookie}`;
}

function isAuthenticated(request: IncomingMessage): boolean {
  const cookie = activeAuthCookie;
  return Boolean(owner && cookie && [cookieValue(request, "__Host-infraternal"), cookieValue(request, "infraternal-mock-session")].includes(cookie));
}

function hasAuthCookie(request: IncomingMessage): boolean {
  return isAuthenticated(request);
}

function cookieValue(request: IncomingMessage, name: string): string | undefined {
  const prefix = `${name}=`;
  const item = request.headers.cookie?.split(";").map((part) => part.trim()).find((part) => part.startsWith(prefix));
  return item?.slice(prefix.length);
}

function setAuthCookie(response: ServerResponse, value: string): void {
  response.setHeader("Set-Cookie", `__Host-infraternal=${value}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000`);
}

function setPreviewAuthCookie(response: ServerResponse, value: string): void {
  // The owner's preview is plain HTTP on a private IP, where browsers reject Secure cookies.
  // Keep this HTTP-only cookie confined to the test double and leave product auth unchanged.
  response.setHeader("Set-Cookie", `infraternal-mock-session=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000`);
}

function makeMockOwner(): MockOwner {
  return {
    userId: randomUuid(),
    username: DOCS_DATASET ? "maya" : "renderer_test",
    displayName: DOCS_DATASET ? "Maya Patel" : "Renderer test",
    credentialId: newToken(),
    passkeyWrap: {},
    prfInput: newToken(),
  };
}

interface MockShare { id: string; from: string; to: string[]; publish: boolean; rev: number; views: Array<{ key: string; name: string; snapshot: unknown }> }
const mockShares: MockShare[] = [];
const mockGroups: Record<string, string[]> = { ops: ["kayg", "asha"], sre: ["ravi", "asha"] };
let accountToolbar: unknown;
function resetMockState(): void {
  mockShares.length = 0;
  accountToolbar = undefined;
  owner = undefined;
  activeAuthCookie = undefined;
  // A failed login can leave a half-finished unlock; it belongs to the retired fixture.
  unlockPending = false;
  pendingTransaction = undefined;
  previewSignedOut = false;
  setupToken = newToken();
  pendingRegistration = undefined;
  pendingLogin = undefined;
  dropNextAck = false;
  closeAfterAttachMs = undefined;
  redrawOnAttach = undefined;
  selectedFixture = undefined;
  socketOpenCount = 0;
  socketCloseCount = 0;
  goneSessions.clear();
  refuseNextOpen = false;
  liveSessionIds.clear();
  sessionInventoryAvailable = true;
  retiredSessions.clear();
  interruptedRetirements.clear();
  attachCount = 0;
  attachHistory.length = 0;
  traceEvents.length = 0;
  appwinLayoutReset();
  session = createSession();
  unclaimedSessionId = session.sessionIdText;
}

function createSession(resumeFrom?: MockSession, fixtureOutput: Uint8Array = new Uint8Array()): MockSession {
  const sessionIdText = randomUuid();
  liveSessionIds.add(sessionIdText);
  return {
    cols: 80,
    rows: 24,
    queries: new QueryReplies(),
    sessionId: uuidBytes(sessionIdText),
    sessionIdText,
    // The resume token belongs to the authenticated websocket connection, not a fresh PTY.
    connectionId: resumeFrom?.connectionId ?? randomBytes(16),
    resumeToken: resumeFrom?.resumeToken ?? randomBytes(32),
    fixtureOutput,
    ringStartSequence: 0n,
    snapshotFrames: [],
    snapshotCount: 0,
    output: new Uint8Array(MAX_MOCK_OUTPUT),
    echoOutputLength: 0,
    outputLength: fixtureOutput.byteLength,
    writtenInput: 0n,
    viewerCursors: new Map(),
    acceptedInputBytes: 0,
    echoedText: "",
    echoMode: "normal",
    echoDelayMs: 0,
  };
}

/** Push the test double's full live set to every current authenticated subscriber. */
function publishSessionInventory(): void {
  for (const connection of connections) {
    for (const subId of connection.sessionInventorySubscriptions) sendSessionInventory(connection, subId);
  }
}

function sendSessionInventory(connection: Connection, subId: number): void {
  const event = sessionInventoryAvailable
    ? {
      topic: "terminal.sessions",
      type: "terminal.sessions.snapshot",
      session_ids: [...liveSessionIds].filter((id) => !goneSessions.has(id)).sort(),
      ended_sessions: [...retiredSessions.entries()].slice(-128).map(([session_id, exit]) => ({ session_id, status: exit.status })),
    }
    : { topic: "terminal.sessions", type: "terminal.sessions.unavailable" };
  sendFrame(connection.socket, 0, {
    type: "Event",
    subId,
    eventJson: new TextEncoder().encode(JSON.stringify(event)),
  });
}

function themePaletteFixture(): Uint8Array {
  const history = Array.from({ length: 10_000 }, (_, index) => {
    const paletteIndex = index % 8;
    return `theme-history-${String(index).padStart(5, "0")} | \u001b[${30 + paletteIndex}mI\u001b[0m | \u001b[38;2;24;166;196mT\u001b[0m`;
  });
  const busyScreen = Array.from({ length: 64 }, (_, index) =>
    `\u001b[38;5;${30 + (index % 8)}m${"busy output ".repeat(6)}\u001b[0m`);
  const regular = [30, 31, 32, 33, 34, 35, 36, 37].map((code) => `\u001b[${code}m█ `).join("");
  const bright = [90, 91, 92, 93, 94, 95, 96, 97].map((code) => `\u001b[${code}m█ `).join("");
  const text = [
    "\u001bc",
    ...history,
    ...busyScreen,
    "\u001b[39;49mdefault: █ \u001b[38;2;24;166;196mTRUECOLOR█\u001b[0m",
    `${regular}\u001b[0m`,
    `${bright}\u001b[0m`,
  ].join("\r\n");
  return new TextEncoder().encode(text);
}

function contentType(extension: string): string {
  switch (extension) {
    case ".html": return "text/html; charset=utf-8";
    case ".js": return "text/javascript; charset=utf-8";
    case ".css": return "text/css; charset=utf-8";
    case ".woff2": return "font/woff2";
    case ".wasm": return "application/wasm";
    case ".webmanifest": return "application/manifest+json";
    default: return "application/octet-stream";
  }
}

function rawBytes(raw: RawData): Uint8Array {
  if (Buffer.isBuffer(raw)) return new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
  if (raw instanceof ArrayBuffer) return new Uint8Array(raw);
  return new Uint8Array(Buffer.concat(raw));
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("expected object");
  return value as Record<string, unknown>;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function newToken(): string {
  return randomBytes(32).toString("base64url");
}

function randomUuid(): string {
  const bytes = randomBytes(16);
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function uuidBytes(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value.replace(/-/g, ""), "hex"));
}

function uuidText(bytes: Uint8Array): string {
  const hex = Buffer.from(bytes).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function isSocketOpen(socket: WebSocket): boolean {
  return socket.readyState === WebSocket.OPEN;
}
