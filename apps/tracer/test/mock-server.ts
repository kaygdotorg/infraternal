/** TEST DOUBLE: serves dist/, accepts test-only passkey ceremonies, and echoes wire input. */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { hostname } from "node:os";
import { extname, resolve, sep } from "node:path";
import { gunzipSync } from "node:zlib";
import { encodeMuxedFrame, WebSocketFrameDecoder, type WireFrame } from "../../../packages/protocol/src/codec";
import { WebSocket, WebSocketServer, type RawData } from "ws";
import { terminalFixtures } from "./terminal-fixtures";
import { addHostFixtures, prototypeHosts } from "./prototype-fixtures";

const HOST = "localhost";
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
const DIST_ROOT = resolve(import.meta.dirname, "../dist");
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
  acceptedInputBytes: number;
  echoedText: string;
}

interface Connection {
  socket: WebSocket;
  decoder: WebSocketFrameDecoder;
  traceEnabled: boolean;
  session: MockSession;
  credit: number;
  outputCursor: bigint;
  attached: boolean;
  welcomed: boolean;
  resumeAccepted: boolean;
  resumeExpected: boolean;
  welcomeTimer: ReturnType<typeof setTimeout> | undefined;
}

interface TraceEvent {
  id: string;
  stage: "doubleReceive" | "doubleDecode" | "doubleEchoEncode" | "doubleEchoSend";
  atNs: string;
}

let owner: MockOwner | undefined;
let activeAuthCookie: string | undefined;
let unlockPending = false;
let pendingTransaction: string | undefined;
let setupToken = newToken();
let pendingRegistration: { ceremony: string; userId: string; username: string; displayName: string; rpId: string; prfInput: string } | undefined;
let pendingLogin: { ceremony: string } | undefined;
let dropNextAck = false;
let selectedFixture: Uint8Array | undefined;
let session = createSession();
const traceEvents: TraceEvent[] = [];

const server = createServer((request, response) => { void routeHttp(request, response); });
const webSockets = new WebSocketServer({ noServer: true, maxPayload: 2 * 1024 * 1024 });
const connections = new Set<Connection>();
// Theme regression tests compare these counters across a local palette change.
let socketOpenCount = 0;
let socketCloseCount = 0;

server.on("upgrade", (request, socket, head) => {
  const path = new URL(request.url ?? "/", `http://${request.headers.host ?? `${HOST}:${PORT}`}`).pathname;
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
    socket,
    decoder: new WebSocketFrameDecoder(),
    traceEnabled: new URL(request.url ?? "/", `http://${request.headers.host ?? `${HOST}:${PORT}`}`).searchParams.get("trace") === "1",
    session,
    credit: 0,
    outputCursor: 0n,
    attached: false,
    welcomed: false,
    resumeAccepted: false,
    resumeExpected: false,
    welcomeTimer: undefined,
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
  socket.on("close", () => {
    socketCloseCount += 1;
    if (connection.welcomeTimer) clearTimeout(connection.welcomeTimer);
    connections.delete(connection);
  });
});

server.listen(PORT, HOST, () => {
  process.stdout.write(`tracer TEST DOUBLE listening on http://${HOST}:${PORT}\n`);
});

async function routeHttp(request: IncomingMessage, response: ServerResponse): Promise<void> {
  response.setHeader(TEST_DOUBLE_HEADER, "true");
  const host = request.headers.host ?? `${HOST}:${PORT}`;
  const url = new URL(request.url ?? "/", `http://${host}`);

  if (request.method === "GET" && url.pathname === "/health") {
    return sendJson(response, 200, { ok: true });
  }
  if (request.method === "GET" && url.pathname === "/__mock/proto/windows") {
    return sendJson(response, 200, { hosts: prototypeHosts });
  }
  if (request.method === "GET" && url.pathname === "/__mock/proto/addhost") {
    return sendJson(response, 200, { hosts: addHostFixtures });
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
    const bytes = new TextEncoder().encode(body.text);
    if (bytes.byteLength > MAX_MESSAGE) return sendJson(response, 413, { error: "text output exceeds one frame" });
    const connection = [...connections].find((candidate) => candidate.session === session && candidate.attached && isSocketOpen(candidate.socket));
    if (!connection || session.outputLength !== 0 || session.echoOutputLength !== 0) {
      return sendJson(response, 409, { error: "text output requires a fresh attached terminal" });
    }
    // Keep the visual metrics fixture on the same bounded Output path as normal PTY output.
    session.fixtureOutput = bytes;
    session.ringStartSequence = 0n;
    session.snapshotFrames = [];
    session.outputLength = bytes.byteLength;
    flushOutput(connection);
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
      sendFrame(connection.socket, 1, { type: "Snapshot", outSeq: BigInt(bytes.byteLength), bytes });
      connection.outputCursor = BigInt(bytes.byteLength);
      connection.credit -= bytes.byteLength;
      session.snapshotCount += 1;
    } else {
      for (let offset = 0; offset < bytes.byteLength; offset += MAX_MESSAGE) {
        const chunk = bytes.subarray(offset, Math.min(offset + MAX_MESSAGE, bytes.byteLength));
        sendFrame(connection.socket, 1, { type: "Output", outSeq: BigInt(offset), bytes: chunk });
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
      output_sequence: String(session.outputLength),
      snapshot_count: session.snapshotCount,
      socket_open_count: socketOpenCount,
      socket_close_count: socketCloseCount,
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
  if ((url.pathname === "/" || url.pathname === "/index.html") && ["windows", "addhost"].includes(url.searchParams.get("proto") ?? "")) {
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
      return sendJson(response, 200, { setup_required: !owner });
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
      return sendJson(response, 200, { user_id: owner.userId, username: owner.username, display_name: owner.displayName, device: "test-double", fresh: 1, hostname: hostname() });
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
  } else if (streamId === 1) {
    handleTerminalFrame(connection, frame);
  } else {
    connection.socket.close(1002, "unexpected mux stream");
  }
}

function handleControlFrame(connection: Connection, frame: WireFrame): void {
  switch (frame.type) {
    case "Hello":
      connection.resumeExpected = (frame.caps & 1n) !== 0n;
      sendFrame(connection.socket, 0, { type: "Hello", version: 1, caps: 0n, clientInfo: "infraternal-mock-test-double/0.1" });
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
      if (connection.welcomeTimer) clearTimeout(connection.welcomeTimer);
      sendWelcome(connection);
      return;
    case "Call": {
      if (!connection.welcomed || frame.callId !== 1 || frame.actionId !== "ssh.session.open") {
        connection.socket.close(1002, "unexpected test-double action");
        return;
      }
      // A fresh open gets fresh terminal state; only Resume reuses an existing session.
      connection.session = session = createSession(connection.session, selectedFixture);
      sendFrame(connection.socket, 0, {
        type: "Result",
        callId: frame.callId,
        ok: true,
        json: new TextEncoder().encode(JSON.stringify({ session_id: connection.session.sessionIdText })),
      });
      return;
    }
    case "Subscribe":
      if (frame.subId === 45 && new TextDecoder().decode(frame.filterJson) === '{"topic":"auth.recovery"}') return;
      connection.socket.close(1002, "unexpected test-double subscription");
      return;
    case "Ping":
      sendFrame(connection.socket, 0, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs });
      return;
    default:
      connection.socket.close(1002, "unexpected test-double control frame");
  }
}

function handleTerminalFrame(connection: Connection, frame: WireFrame): void {
  switch (frame.type) {
    case "AttachTerm":
      if (!bytesEqual(frame.sessionId, connection.session.sessionId) || connection.attached) {
        connection.socket.close(1002, "invalid test-double attach");
        return;
      }
      connection.attached = true;
      connection.outputCursor = frame.lastOutSeq;
      sendFrame(connection.socket, 1, { type: "Ack", inSeqAcked: connection.session.writtenInput });
      flushOutput(connection);
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
      acceptInput(connection, frame.inSeq, frame.bytes);
      return;
    case "Resize":
      return;
    case "Ping":
      sendFrame(connection.socket, 1, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs });
      return;
    default:
      connection.socket.close(1002, "unexpected test-double terminal frame");
  }
}

function acceptInput(connection: Connection, sequence: bigint, bytes: Uint8Array): void {
  if (sequence > connection.session.writtenInput || sequence + BigInt(bytes.byteLength) > 0xffff_ffff_ffff_ffffn) {
    connection.socket.close(1002, "input sequence gap in test double");
    return;
  }
  const alreadyWritten = Number(connection.session.writtenInput - sequence);
  const duplicateBytes = Math.min(bytes.byteLength, alreadyWritten);
  const fresh = bytes.subarray(duplicateBytes);
  if (fresh.byteLength > 0) {
    if (connection.session.echoOutputLength + fresh.byteLength > MAX_MOCK_OUTPUT) {
      connection.socket.close(1011, "test-double output limit reached");
      return;
    }
    connection.session.output.set(fresh, connection.session.echoOutputLength);
    connection.session.echoOutputLength += fresh.byteLength;
    connection.session.outputLength += fresh.byteLength;
    connection.session.writtenInput += BigInt(fresh.byteLength);
    connection.session.acceptedInputBytes += fresh.byteLength;
    connection.session.echoedText += new TextDecoder().decode(fresh);
  }
  if (dropNextAck && fresh.byteLength > 0) {
    dropNextAck = false;
    connection.socket.close(4001, "test-double forced input acknowledgement drop");
    return;
  }
  sendFrame(connection.socket, 1, { type: "Ack", inSeqAcked: connection.session.writtenInput });
  flushOutput(connection);
}

function flushOutput(connection: Connection): void {
  if (!connection.attached || !isSocketOpen(connection.socket)) return;
  if (connection.outputCursor < connection.session.ringStartSequence) {
    const snapshots = connection.session.snapshotFrames;
    const repaintBytes = snapshots.reduce((total, snapshot) => total + snapshot.bytes.byteLength, 0);
    if (snapshots.length === 0 || repaintBytes > connection.credit) return;
    sendFrames(connection.socket, 1, snapshots.map(({ outSeq, bytes }) => ({ type: "Snapshot", outSeq, bytes })));
    // A Snapshot may predate output that is already in the session ring. Resume
    // at its absolute cursor so that those later bytes still follow the repaint.
    connection.outputCursor = snapshots[snapshots.length - 1]!.outSeq;
    connection.credit -= repaintBytes;
    connection.session.snapshotCount += snapshots.length;
  }
  const availableEnd = BigInt(connection.session.outputLength);
  while (connection.credit > 0 && connection.outputCursor < availableEnd) {
    const absoluteOffset = Number(connection.outputCursor);
    const fixtureLength = connection.session.fixtureOutput.byteLength;
    const source = absoluteOffset < fixtureLength ? connection.session.fixtureOutput : connection.session.output;
    const offset = absoluteOffset < fixtureLength ? absoluteOffset : absoluteOffset - fixtureLength;
    const sourceEnd = absoluteOffset < fixtureLength ? fixtureLength : fixtureLength + connection.session.echoOutputLength;
    const length = Math.min(MAX_MESSAGE, connection.credit, sourceEnd - absoluteOffset);
    const bytes = source.subarray(offset, offset + length);
    sendFrame(connection.socket, 1, { type: "Output", outSeq: connection.outputCursor, bytes },
      connection.traceEnabled ? connection.outputCursor : undefined, length);
    connection.outputCursor += BigInt(length);
    connection.credit -= length;
  }
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
  const relative = decoded === "/" ? "index.html" : decoded.slice(1);
  const path = resolve(DIST_ROOT, relative);
  if (!path.startsWith(`${DIST_ROOT}${sep}`) && path !== DIST_ROOT) return sendJson(response, 404, { error: "not found" });
  try {
    const bytes = await readFile(path);
    response.statusCode = 200;
    response.setHeader("Content-Type", contentType(extname(path)));
    response.setHeader("Cache-Control", "no-store");
    response.end(headOnly ? undefined : bytes);
  } catch {
    sendJson(response, 404, { error: "not found" });
  }
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
  response.end(JSON.stringify(value));
}

function sameOrigin(request: IncomingMessage): boolean {
  return request.headers.origin === `http://${request.headers.host ?? `${HOST}:${PORT}`}`;
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
    username: "renderer_test",
    displayName: "Renderer test",
    credentialId: newToken(),
    passkeyWrap: {},
    prfInput: newToken(),
  };
}

function resetMockState(): void {
  owner = undefined;
  activeAuthCookie = undefined;
  setupToken = newToken();
  pendingRegistration = undefined;
  pendingLogin = undefined;
  dropNextAck = false;
  selectedFixture = undefined;
  socketOpenCount = 0;
  socketCloseCount = 0;
  traceEvents.length = 0;
  session = createSession();
}

function createSession(resumeFrom?: MockSession, fixtureOutput: Uint8Array = new Uint8Array()): MockSession {
  const sessionIdText = randomUuid();
  return {
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
    acceptedInputBytes: 0,
    echoedText: "",
  };
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
