/** Measures production returning sign-in with real Rust, virtual WebAuthn and delayed HTTP/WS legs [122]. */
import { chromium } from "../../apps/tracer/node_modules/playwright/index.mjs";
import { WebSocket, WebSocketServer } from "../../apps/tracer/node_modules/ws/wrapper.mjs";
import { WebSocketFrameDecoder } from "../../packages/protocol/src/codec.ts";
import { spawn } from "child_process";
import { once } from "events";
import { mkdir, realpath, rm, writeFile } from "fs/promises";
import { createServer as createHttpServer } from "http";
import { createServer as createHttpsServer } from "https";
import { request as httpRequest } from "http";
import { resolve } from "path";

const root = resolve(import.meta.dirname, "../..");
const binary = resolve(root, process.env.SIGNIN_MEASURE_BINARY ?? "target/x86_64-unknown-linux-musl/release/infraternal");
const webRoot = resolve(root, process.env.SIGNIN_MEASURE_WEB_ROOT ?? "apps/tracer/dist");
const testPort = Number(process.env.TRACER_TEST_PORT ?? "0");
if (testPort !== 4641) throw new Error("Run this browser harness with TRACER_TEST_PORT=4641");

const oneWayCases = (process.env.SIGNIN_MEASURE_CASES ?? "0,100,200").split(",").map(Number);
const runsPerCase = Number(process.env.SIGNIN_MEASURE_RUNS ?? "10");
if (!oneWayCases.length || oneWayCases.some((value) => ![0, 100, 200].includes(value))
  || !Number.isSafeInteger(runsPerCase) || runsPerCase < 1 || runsPerCase > 10) {
  throw new Error("use supported latency cases 0,100,200 and 1–10 runs per case");
}
const state = resolve(root, `target/sm-${process.pid}`);
const dataDir = resolve(state, "data");
// Linux sun_path is small. The relative target/../r spelling traverses this
// worktree's scratch-target symlink and keeps the socket pathname below SUN_LEN.
const runtimeDir = resolve(await realpath(resolve(root, "target")), "../r");
const resultsPath = resolve(root, process.env.SIGNIN_MEASURE_RESULTS ?? "target/signin-waterfall-results.json");
const revision = await runCommand("git", ["rev-parse", "HEAD"]);
const dirtyPaths = (await runCommand("git", ["diff", "--name-only"])).split("\n").filter(Boolean);
const binarySha256 = (await runCommand("sha256sum", [binary])).split(" ")[0];
const origin = `https://localhost:${testPort}`;
const authHits = [];
const bridges = [];
let activeSample;
let server;
let browser;
let context;
let page;
let cdp;
let frontSockets;
let tlsServer;
let networkEventsInstalled = false;

const pause = (milliseconds) => new Promise((resolvePause) => setTimeout(resolvePause, milliseconds));

function recordBridgeFrames(entry, direction, decoder, data) {
  try {
    decoder.feed(new Uint8Array(data), (streamId, frame) => {
      entry.frames.push({
        direction, streamId, type: frame.type, at: performance.now(),
        ...(frame.type === "Result" ? { ok: frame.ok, jsonLength: frame.json?.byteLength } : {}),
        ...(frame.type === "Close" ? { code: frame.code } : {}),
      });
    });
  } catch {
    entry.decodeErrors++;
  }
}

async function reserveAuthBudget(expectedReads = 8) {
  while (true) {
    const now = Date.now();
    while (authHits.length && authHits[0] <= now - 60_000) authHits.shift();
    if (authHits.length + expectedReads <= 28) return;
    const waitMs = Math.max(100, authHits[0] + 61_000 - now);
    console.log(`AUTH_PACING wait_ms=${waitMs} active_reads=${authHits.length}`);
    await pause(waitMs);
  }
}

function runCommand(program, args) {
  return new Promise((resolveCommand, rejectCommand) => {
    const child = spawn(program, args, { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    child.stdout.on("data", (bytes) => stdout += bytes);
    child.stderr.resume();
    child.once("error", rejectCommand);
    child.once("exit", (code) => {
      if (code === 0) resolveCommand(stdout.trim());
      else rejectCommand(new Error("local verification command failed"));
    });
  });
}

async function reservePort() {
  const reservation = createHttpServer();
  await new Promise((resolveListen, rejectListen) => {
    reservation.once("error", rejectListen);
    reservation.listen(0, "127.0.0.1", resolveListen);
  });
  const address = reservation.address();
  if (!address || typeof address === "string") throw new Error("ephemeral server port unavailable");
  await new Promise((resolveClose, rejectClose) => reservation.close((error) => error ? rejectClose(error) : resolveClose()));
  return address.port;
}

async function makeInMemoryCertificate() {
  const certificate = spawn("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", "-", "-out", "-",
  ], { stdio: ["ignore", "pipe", "ignore"] });
  let output = "";
  certificate.stdout.on("data", (bytes) => output += bytes);
  const [code] = await once(certificate, "exit");
  if (code !== 0) throw new Error("in-memory local TLS certificate generation failed");
  const key = output.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/)?.[0];
  const cert = output.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)?.[0];
  output = "";
  if (!key || !cert) throw new Error("local TLS certificate was incomplete");
  return { key, cert };
}

function shortPath(rawUrl) {
  if (rawUrl.startsWith("data:")) {
    const metadata = rawUrl.slice(5, rawUrl.indexOf(",")).split(";")[0] || "text/plain";
    return `data:${metadata} (inline)`;
  }
  try { return new URL(rawUrl).pathname; }
  catch { return "/"; }
}

function subscribeNetworkEvents(sample) {
  sample.requests = [];
  sample.websocket = [];
  sample.requestById = new Map();
  sample.wallMinusMonoMs = undefined;
  if (networkEventsInstalled) return;
  networkEventsInstalled = true;
  cdp.on("Network.requestWillBeSent", (event) => {
    const active = activeSample;
    if (!active) return;
    if (active.wallMinusMonoMs === undefined && Number.isFinite(event.wallTime)) {
      active.wallMinusMonoMs = event.wallTime * 1000 - event.timestamp * 1000;
    }
    const request = {
      id: event.requestId,
      method: event.request.method,
      path: shortPath(event.request.url),
      type: event.type,
      start: event.timestamp,
      initiator: event.initiator?.type,
    };
    active.requests.push(request);
    active.requestById.set(event.requestId, request);
  });
  cdp.on("Network.responseReceived", (event) => {
    const active = activeSample;
    if (!active) return;
    const request = active.requestById.get(event.requestId);
    if (!request) return;
    request.status = event.response.status;
    request.mimeType = event.response.mimeType;
    request.contentEncoding = Object.entries(event.response.headers ?? {})
      .find(([name]) => name.toLowerCase() === "content-encoding")?.[1];
    request.response = event.timestamp;
    request.fromDiskCache = event.response.fromDiskCache === true;
    request.fromServiceWorker = event.response.fromServiceWorker === true;
    request.connectionReused = event.response.connectionReused === true;
    request.connectionId = event.response.connectionId;
    request.encodedDataLength = event.response.encodedDataLength;
  });
  cdp.on("Network.loadingFinished", (event) => {
    const active = activeSample;
    if (!active) return;
    const request = active.requestById.get(event.requestId);
    if (request) {
      request.finished = event.timestamp;
      request.finishEncodedDataLength = event.encodedDataLength;
    }
  });
  cdp.on("Network.loadingFailed", (event) => {
    const active = activeSample;
    if (!active) return;
    const request = active.requestById.get(event.requestId);
    if (request) request.failed = true;
  });
  cdp.on("Network.webSocketHandshakeResponseReceived", (event) => {
    const active = activeSample;
    if (!active) return;
    active.websocket.push({ phase: "upgrade-response", at: event.timestamp, status: event.response.status });
  });
}

function monotonicToPage(sample, seconds) {
  if (sample.wallMinusMonoMs === undefined || sample.timeOrigin === undefined) return undefined;
  return seconds * 1000 + sample.wallMinusMonoMs - sample.timeOrigin;
}

function collectMarks() {
  return String.raw`(() => {
    const flow = {
      marks: [],
      armed: false,
      waitingForEcho: false,
      snapshotSeen: false,
      snapshotPainted: false,
      terminalFrameSeen: false,
      terminalFramePainted: false,
      echoOutputSeen: false,
      echoPainted: false,
      mark(name, detail) {
        const at = performance.now();
        try { performance.mark("signin:" + name); } catch {}
        this.marks.push({ name, at, ...(detail === undefined ? {} : { detail }) });
      },
      armInput() { this.armed = true; },
      getMarks() { return this.marks.slice(); },
    };
    window.__signinMeasure = flow;
    flow.mark("navigation-start");

    const types = { 0x00: "Hello", 0x01: "Welcome", 0x02: "Resume", 0x10: "Input", 0x11: "Output", 0x13: "Ack", 0x14: "Credit", 0x15: "Snapshot", 0x16: "AttachTerm", 0x30: "Call", 0x31: "Result" };
    function readVarint(bytes, start) {
      let value = 0;
      let shift = 0;
      for (let i = 0; i < 5 && start + i < bytes.length; i++) {
        const part = bytes[start + i];
        value |= (part & 0x7f) << shift;
        if ((part & 0x80) === 0) return { value, next: start + i + 1 };
        shift += 7;
      }
      return null;
    }
    function asBytes(data) {
      if (data instanceof ArrayBuffer) return new Uint8Array(data);
      if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
      return null;
    }
    function inspectSocketData(data, direction) {
      const bytes = asBytes(data);
      if (!bytes) return;
      let offset = 0;
      while (offset < bytes.length) {
        const stream = readVarint(bytes, offset);
        if (!stream) return;
        const length = readVarint(bytes, stream.next);
        if (!length || length.value < 1) return;
        const typeAt = length.next;
        const end = typeAt + length.value;
        if (end > bytes.length) return;
        const type = types[bytes[typeAt]];
        if (type) flow.mark("ws:" + direction + ":" + type);
        if (direction === "received" && type === "Welcome") flow.mark("welcome-received");
        if (direction === "received" && type === "Snapshot" && !flow.snapshotSeen) {
          flow.snapshotSeen = true;
          flow.mark("snapshot-received");
        }
        if (direction === "received" && (type === "Snapshot" || type === "Output") && !flow.terminalFrameSeen) {
          flow.terminalFrameSeen = true;
          flow.mark("terminal-frame-received", { type });
        }
        if (direction === "sent" && type === "Input" && flow.marks.some((mark) => mark.name === "first-keydown") && !flow.waitingForEcho) {
          flow.waitingForEcho = true;
          flow.mark("first-input-sent");
        }
        if (direction === "received" && type === "Output" && flow.waitingForEcho && !flow.echoOutputSeen) {
          flow.echoOutputSeen = true;
          flow.mark("echo-output-received");
          // Ghostty writes into Canvas2D on its animation loop. This fence lets
          // that queued renderer frame run before the fallback echo mark.
          requestAnimationFrame(() => requestAnimationFrame(() => {
            if (!flow.echoPainted) {
              flow.echoPainted = true;
              flow.mark("echo-painted", { method: "two-frame fence after PTY Output" });
            }
          }));
        }
        offset = end;
      }
    }

    const NativeWebSocket = window.WebSocket;
    try {
      const originalSend = NativeWebSocket.prototype.send;
      NativeWebSocket.prototype.send = function (data) {
        inspectSocketData(data, "sent");
        return originalSend.call(this, data);
      };
      window.WebSocket = new Proxy(NativeWebSocket, {
      construct(target, args, newTarget) {
          flow.mark("websocket-create");
          const socket = Reflect.construct(target, args, newTarget);
          socket.addEventListener("open", () => flow.mark("websocket-open"), { once: true });
          socket.addEventListener("message", (event) => inspectSocketData(event.data, "received"));
          return socket;
        },
      });
    } catch { flow.mark("websocket-instrumentation-failed"); }

    document.addEventListener("click", (event) => {
      const target = event.target instanceof Element ? event.target.closest("#login-passkey") : null;
      if (target) flow.mark("login-click");
    }, true);
    document.addEventListener("keydown", (event) => {
      if (!flow.armed || event.repeat || event.key !== "x") return;
      flow.armed = false;
      flow.mark("first-keydown", { key: event.key });
    }, true);

    try {
      const credentials = navigator.credentials;
      const originalGet = credentials.get.bind(credentials);
      Object.defineProperty(credentials, "get", {
        configurable: true,
        value(options) {
          if (options && options.publicKey) flow.mark("passkey-request");
          return originalGet(options).then((result) => {
            if (options && options.publicKey) flow.mark("passkey-resolved");
            return result;
          }, (error) => {
            if (options && options.publicKey) flow.mark("passkey-rejected");
            throw error;
          });
        },
      });
    } catch { flow.mark("passkey-instrumentation-failed"); }

    function terminalCanvas(context) {
      const canvas = context && context.canvas;
      return canvas instanceof HTMLCanvasElement && canvas.closest("#terminal-host") !== null;
    }
    function watchDraws(proto, name) {
      if (!proto || typeof proto[name] !== "function") return;
      const original = proto[name];
      proto[name] = function (...args) {
        if (terminalCanvas(this)) {
          if (flow.terminalFrameSeen && !flow.terminalFramePainted) {
            flow.terminalFramePainted = true;
            flow.mark("terminal-frame-painted");
          }
          if (flow.snapshotSeen && !flow.snapshotPainted) {
            flow.snapshotPainted = true;
            flow.mark("snapshot-painted");
          }
          if (flow.echoOutputSeen && !flow.echoPainted) {
            flow.echoPainted = true;
            flow.mark("echo-painted", { method: "terminal canvas draw" });
          }
        }
        return original.apply(this, args);
      };
    }
    const drawingPrototypes = [
      window.CanvasRenderingContext2D?.prototype,
      window.WebGLRenderingContext?.prototype,
      window.WebGL2RenderingContext?.prototype,
    ];
    for (const prototype of drawingPrototypes) {
      for (const method of ["fillRect", "fillText", "strokeText", "drawImage", "putImageData", "clearRect", "drawArrays", "drawElements", "drawArraysInstanced", "drawElementsInstanced", "clear"]) watchDraws(prototype, method);
    }

    for (const method of ["compile", "instantiate", "instantiateStreaming"]) {
      const original = WebAssembly[method].bind(WebAssembly);
      WebAssembly[method] = function (...args) {
        flow.mark("wasm-" + method + "-start");
        return original(...args).then((result) => {
          flow.mark("wasm-" + method + "-end");
          return result;
        }, (error) => {
          flow.mark("wasm-" + method + "-failed");
          throw error;
        });
      };
    }

    for (const method of ["deriveKey", "decrypt"]) {
      try {
        const subtle = crypto.subtle;
        const original = subtle[method].bind(subtle);
        Object.defineProperty(subtle, method, {
          configurable: true,
          value(...args) {
            flow.mark("crypto-" + method + "-start");
            return original(...args).then((result) => {
              flow.mark("crypto-" + method + "-end");
              return result;
            }, (error) => {
              flow.mark("crypto-" + method + "-failed");
              throw error;
            });
          },
        });
      } catch { flow.mark("crypto-instrumentation-failed", { method }); }
    }

    try {
      const fonts = document.fonts;
      const prototype = Object.getPrototypeOf(fonts);
      const descriptor = Object.getOwnPropertyDescriptor(prototype, "load");
      if (descriptor?.value) {
        const originalLoad = descriptor.value;
        Object.defineProperty(fonts, "load", {
          configurable: true,
          value(...args) {
            const requested = String(args[0] ?? "");
            flow.mark("font-load-start", { font: requested });
            return originalLoad.apply(this, args).then((faces) => {
              flow.mark("font-load-end", { font: requested });
              return faces;
            });
          },
        });
      }
    } catch { flow.mark("font-instrumentation-failed"); }

    const authObserver = new MutationObserver(() => {
      if (document.querySelector("#login-passkey") && !flow.marks.some((item) => item.name === "sign-in-ready")) flow.mark("sign-in-ready");
      if (document.querySelector(".auth-welcome") && !flow.marks.some((item) => item.name === "first-sign-in-welcome")) flow.mark("first-sign-in-welcome");
    });
    authObserver.observe(document, { subtree: true, childList: true });
    const backdropObserver = new MutationObserver(() => {
      if (!document.querySelector("#faulty-field") && flow.marks.some((item) => item.name === "login-click") && !flow.marks.some((item) => item.name === "backdrop-removed")) flow.mark("backdrop-removed");
    });
    backdropObserver.observe(document, { subtree: true, childList: true });
  })();`;
}

function markByName(marks, name, index = 0) {
  return marks.filter((mark) => mark.name === name)[index];
}

async function waitForMark(name, timeoutMs) {
  try {
    await page.waitForFunction((expected) => window.__signinMeasure?.getMarks().some((mark) => mark.name === expected), name, { timeout: timeoutMs });
  } catch {
    const marks = await page.evaluate(() => window.__signinMeasure?.getMarks().map((mark) => mark.name) ?? []);
    const frames = bridges.at(-1)?.frames.map((frame) => `${frame.direction}:${frame.type}`) ?? [];
    const browserState = await page.evaluate(() => ({
      terminalHost: Boolean(document.querySelector("#terminal-host")),
      terminalStatus: document.querySelector("#connection-status")?.textContent?.trim(),
      authError: document.querySelector("#auth-error")?.textContent?.trim(),
      sessionStorageSession: Object.keys(sessionStorage).some((key) => key.startsWith("tracer.session.")),
    }));
    const result = bridges.at(-1)?.frames.findLast((frame) => frame.type === "Result");
    throw new Error(`browser mark ${name} missing; observed marks=${marks.join(",")}; proxy frames=${frames.join(",")}; result=${JSON.stringify(result && { ok: result.ok, jsonLength: result.jsonLength })}; browser=${JSON.stringify(browserState)}`);
  }
}

function requestTimings(sample) {
  return sample.requests.map((request) => {
    const start = monotonicToPage(sample, request.start);
    const response = request.response === undefined ? undefined : monotonicToPage(sample, request.response);
    const finished = request.finished === undefined ? undefined : monotonicToPage(sample, request.finished);
    return {
      method: request.method,
      path: request.path,
      type: request.type,
      status: request.status,
      contentEncoding: request.contentEncoding,
      start,
      response,
      finished,
      responseMs: start === undefined || response === undefined ? undefined : response - start,
      totalMs: start === undefined || finished === undefined ? undefined : finished - start,
      fromDiskCache: request.fromDiskCache === true,
      fromServiceWorker: request.fromServiceWorker === true,
      connectionReused: request.connectionReused,
      connectionId: request.connectionId,
      encodedBytes: request.finishEncodedDataLength ?? request.encodedDataLength,
      failed: request.failed === true,
    };
  });
}

function resourceTimings(resources) {
  return resources.map((resource) => ({
    path: resource.path,
    kind: resource.kind,
    start: resource.start,
    duration: resource.duration,
    responseStart: resource.responseStart,
    responseEnd: resource.responseEnd,
    transferBytes: resource.transferBytes,
    encodedBytes: resource.encodedBytes,
    decodedBytes: resource.decodedBytes,
    protocol: resource.protocol,
  }));
}

function nearPercentile(values, percentile) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) return undefined;
  return sorted[Math.max(0, Math.ceil(percentile * sorted.length) - 1)];
}

function stats(values) {
  return { p50: nearPercentile(values, 0.5), p99: nearPercentile(values, 0.99), n: values.filter(Number.isFinite).length };
}

function extractMeasurements(sample, marks, resources) {
  const at = (name) => markByName(marks, name)?.at;
  const click = at("login-click");
  const passkeyRequest = at("passkey-request");
  const passkeyResolved = at("passkey-resolved");
  const firstInput = at("first-keydown");
  const snapshotPaint = at("snapshot-painted");
  const terminalFramePaint = at("terminal-frame-painted") ?? at("snapshot-painted");
  const echoPaint = at("echo-painted");
  const hello = at("ws:sent:Hello");
  const welcome = at("welcome-received");
  const attach = at("ws:sent:AttachTerm");
  const terminalFrame = at("terminal-frame-received");
  const websocketCreate = at("websocket-create");
  const websocketOpen = at("websocket-open");
  const requests = requestTimings(sample);
  const clickRequests = requests.filter((request) => request.start !== undefined && click !== undefined && request.start >= click);
  const preClickAuth = requests.filter((request) => request.path.startsWith("/auth/") && request.start !== undefined && click !== undefined && request.start < click);
  const auth = clickRequests.filter((request) => request.path.startsWith("/auth/"));
  const findAuth = (path, index = 0) => auth.filter((request) => request.path === path)[index];
  const socketRequest = requests.find((request) => request.path === "/v1/ws");
  const upgradeResponse = sample.websocket.find((event) => event.phase === "upgrade-response");
  const wsUpgradeEnd = upgradeResponse === undefined ? undefined : monotonicToPage(sample, upgradeResponse.at);
  const resourceRows = resourceTimings(resources);
  const afterClickResources = resourceRows.filter((resource) => click !== undefined && resource.start >= click);
  return {
    latencyOneWayMs: sample.latencyOneWayMs,
    trial: sample.trial,
    cacheCold: sample.cacheCold,
    preClickReadyMs: markByName(marks, "sign-in-ready")?.at,
    clickToPasskeyRequestMs: click === undefined || passkeyRequest === undefined ? undefined : passkeyRequest - click,
    passkeyDurationMs: passkeyRequest === undefined || passkeyResolved === undefined ? undefined : passkeyResolved - passkeyRequest,
    passkeyToLoginFinishStartMs: passkeyResolved === undefined || findAuth("/auth/login-finish")?.start === undefined ? undefined : findAuth("/auth/login-finish").start - passkeyResolved,
    postPasskeyToTerminalPaintMs: passkeyResolved === undefined || terminalFramePaint === undefined ? undefined : terminalFramePaint - passkeyResolved,
    websocketUpgradeMs: socketRequest?.start !== undefined && wsUpgradeEnd !== undefined
      ? wsUpgradeEnd - socketRequest.start
      : websocketCreate === undefined || websocketOpen === undefined ? undefined : websocketOpen - websocketCreate,
    websocketConstructorToOpenMs: websocketCreate === undefined || websocketOpen === undefined ? undefined : websocketOpen - websocketCreate,
    helloToWelcomeMs: hello === undefined || welcome === undefined ? undefined : welcome - hello,
    attachToTerminalFrameMs: attach === undefined || terminalFrame === undefined ? undefined : terminalFrame - attach,
    wasmInitMs: at("wasm-compile-start") !== undefined && at("wasm-instantiate-end") !== undefined
      ? at("wasm-instantiate-end") - at("wasm-compile-start")
      : at("wasm-instantiate-start") === undefined || at("wasm-instantiate-end") === undefined ? undefined : at("wasm-instantiate-end") - at("wasm-instantiate-start"),
    attachAckAt: at("ws:received:Ack"),
    attachAckToTerminalFrameMs: at("ws:received:Ack") === undefined || terminalFrame === undefined
      ? undefined : terminalFrame - at("ws:received:Ack"),
    clickToTerminalPaintMs: click === undefined || terminalFramePaint === undefined ? undefined : terminalFramePaint - click,
    clickToTerminalSnapshotMs: click === undefined || at("snapshot-received") === undefined ? undefined : at("snapshot-received") - click,
    terminalFrameType: markByName(marks, "terminal-frame-received")?.detail?.type,
    keydownToEchoPaintMs: firstInput === undefined || echoPaint === undefined ? undefined : echoPaint - firstInput,
    cryptoMarks: marks.filter((mark) => mark.name.startsWith("crypto-")),
    passkeyRequest,
    passkeyResolved,
    snapshotReceived: at("snapshot-received"),
    snapshotPainted: snapshotPaint,
    terminalFramePainted: terminalFramePaint,
    firstKeydown: firstInput,
    echoOutputReceived: at("echo-output-received"),
    echoPainted: echoPaint,
    wasmMarks: marks.filter((mark) => mark.name.startsWith("wasm-")),
    fontMarks: marks.filter((mark) => mark.name.startsWith("font-load-")),
    backdropRemovedAt: marks.find((mark) => mark.name === "backdrop-removed")?.at,
    clickToBackdropRemovedMs: click === undefined || marks.find((mark) => mark.name === "backdrop-removed")?.at === undefined ? undefined : marks.find((mark) => mark.name === "backdrop-removed").at - click,
    preClickAuthRequests: preClickAuth.map((request) => ({ path: request.path, status: request.status, responseMs: request.responseMs, totalMs: request.totalMs })),
    authRequests: auth.map((request) => ({ path: request.path, status: request.status, startAfterClickMs: request.start - click, responseMs: request.responseMs, totalMs: request.totalMs })),
    wsMarks: marks.filter((mark) => mark.name.startsWith("ws:") || ["websocket-open", "welcome-received", "snapshot-received", "snapshot-painted", "terminal-frame-received", "terminal-frame-painted"].includes(mark.name)),
    resourcesAfterClick: afterClickResources,
    requestsAfterClick: clickRequests,
  };
}

async function measureRun(latencyOneWayMs, trial, cacheCold) {
  await reserveAuthBudget();
  if (cacheCold) await cdp.send("Network.clearBrowserCache");
  await context.clearCookies();
  await cdp.send("Network.emulateNetworkConditions", {
    offline: false,
    latency: latencyOneWayMs * 2,
    downloadThroughput: -1,
    uploadThroughput: -1,
    connectionType: "other",
  });
  const sample = { latencyOneWayMs, trial, cacheCold };
  subscribeNetworkEvents(sample);
  activeSample = sample;
  await page.goto(origin + "/", { waitUntil: "load", timeout: 60_000 });
  await page.locator("#login-passkey").waitFor({ timeout: 30_000 });
  sample.timeOrigin = await page.evaluate(() => performance.timeOrigin);
  await page.getByRole("button", { name: "Continue with passkey" }).click();
  await waitForMark("terminal-frame-painted", 60_000);
  await page.locator("#terminal-host").click();
  await page.evaluate(() => window.__signinMeasure.armInput());
  await page.keyboard.press("x");
  await waitForMark("echo-painted", 20_000);
  const collected = await page.evaluate(() => ({
    marks: window.__signinMeasure.getMarks(),
    resources: performance.getEntriesByType("resource").map((entry) => {
      const url = new URL(entry.name);
      return {
        path: url.protocol === "data:" ? "data:application/wasm (inline)" : url.pathname,
        kind: entry.initiatorType,
        start: entry.startTime,
        duration: entry.duration,
        responseStart: entry.responseStart,
        responseEnd: entry.responseEnd,
        transferBytes: entry.transferSize,
        encodedBytes: entry.encodedBodySize,
        decodedBytes: entry.decodedBodySize,
        protocol: entry.nextHopProtocol,
      };
    }),
  }));
  const measurement = extractMeasurements(sample, collected.marks, collected.resources);
  if (latencyOneWayMs > 0) {
    const helloAt = markByName(collected.marks, "ws:sent:Hello")?.at;
    const welcomeAt = markByName(collected.marks, "welcome-received")?.at;
    const attachAt = markByName(collected.marks, "ws:sent:AttachTerm")?.at;
    const frameAt = markByName(collected.marks, "terminal-frame-received")?.at;
    if (helloAt === undefined || welcomeAt === undefined || welcomeAt - helloAt < latencyOneWayMs * 1.5
      || attachAt === undefined || frameAt === undefined || frameAt - attachAt < latencyOneWayMs * 1.5) {
      throw new Error(`WebSocket one-way-delay check failed at ${latencyOneWayMs} ms; hello/welcome=${measurement.helloToWelcomeMs}; attach/frame=${measurement.attachToTerminalFrameMs}`);
    }
  }
  sample.marks = collected.marks;
  sample.measurement = measurement;
  sample.monotonicToPageRequests = requestTimings(sample);
  const bridge = bridges.findLast((candidate) => candidate.sample === sample);
  sample.bridgeFrames = bridge?.frames ?? [];
  sample.bridgeDecodeErrors = bridge?.decodeErrors ?? 0;
  measurement.bridgeFrames = sample.bridgeFrames;
  measurement.bridgeDecodeErrors = sample.bridgeDecodeErrors;
  // Preserve failed connections too: retaining only the final bridge hides
  // reconnects that contribute to first-Attach latency percentiles.
  measurement.bridgeConnections = bridges.filter((candidate) => candidate.sample === sample)
    .map(({ frames, decodeErrors, closes }) => ({ frames, decodeErrors, closes }));
  console.log(`SAMPLE ${JSON.stringify({
    latencyOneWayMs,
    trial,
    cacheCold,
    clickToPasskeyRequestMs: measurement.clickToPasskeyRequestMs,
    passkeyDurationMs: measurement.passkeyDurationMs,
    clickToTerminalPaintMs: measurement.clickToTerminalPaintMs,
    keydownToEchoPaintMs: measurement.keydownToEchoPaintMs,
    helloToWelcomeMs: Number(measurement.helloToWelcomeMs?.toFixed(1)),
    attachToTerminalFrameMs: Number(measurement.attachToTerminalFrameMs?.toFixed(1)),
    websocketUpgradeMs: Number(measurement.websocketUpgradeMs?.toFixed(1)),
    websocketConstructorToOpenMs: Number(measurement.websocketConstructorToOpenMs?.toFixed(1)),
    auth: measurement.authRequests.map((request) => [request.path, Number(request.responseMs?.toFixed(1))]),
    marks: measurement.wsMarks.map((mark) => [mark.name, Number(mark.at.toFixed(1))]),
    assets: measurement.resourcesAfterClick.filter((resource) => /\.(js|wasm|woff2)$/.test(resource.path)).map((resource) => [resource.path, Number(resource.duration.toFixed(1)), resource.transferBytes]),
  })}`);
  activeSample = undefined;
  await page.keyboard.press("Control+C").catch(() => undefined);
  return sample;
}

async function waitForBackend(port) {
  const url = `http://127.0.0.1:${port}/`;
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch { /* The actual server is still starting. */ }
    await pause(50);
  }
  throw new Error("the release server did not start");
}

async function stopServerProcess() {
  if (!server || server.exitCode !== null) return;
  try { process.kill(-server.pid, "SIGTERM"); }
  catch { server.kill("SIGTERM"); }
  await Promise.race([once(server, "exit"), pause(5_000)]);
}

try {
  if (!(await import("node:fs/promises")).stat(binary).then(() => true).catch(() => false)) throw new Error("build the x86_64 musl release binary before running this harness");
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  await mkdir(runtimeDir, { recursive: true, mode: 0o700 });
  const backendPort = await reservePort();
  const certificate = await makeInMemoryCertificate();
  const sslProxy = createHttpsServer(certificate, (request, response) => {
    const path = request.url ?? "/";
    if (path.startsWith("/auth/") && path !== "/auth/logout") authHits.push(Date.now());
    const headers = { ...request.headers, host: `127.0.0.1:${backendPort}`, "x-forwarded-for": "127.0.0.1", "x-forwarded-proto": "https" };
    const upstream = httpRequest({ hostname: "127.0.0.1", port: backendPort, path, method: request.method, headers, agent: false }, (upstreamResponse) => {
      response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
      upstreamResponse.pipe(response);
    });
    upstream.on("error", () => { response.writeHead(502); response.end(); });
    request.pipe(upstream);
  });
  frontSockets = new WebSocketServer({ noServer: true });
  sslProxy.on("upgrade", (request, socket, head) => {
    frontSockets.handleUpgrade(request, socket, head, (browserSocket) => {
      const upstream = new WebSocket(`ws://127.0.0.1:${backendPort}/v1/ws`, {
        headers: { Origin: origin, Cookie: request.headers.cookie ?? "", "X-Forwarded-For": "127.0.0.1" },
      });
      const oneWayLatencyMs = activeSample?.latencyOneWayMs ?? 0;
      const entry = { sample: activeSample, frames: [], decodeErrors: 0, closes: [], oneWayLatencyMs };
      bridges.push(entry);
      const clientDecoder = new WebSocketFrameDecoder();
      const serverDecoder = new WebSocketFrameDecoder();
      const queued = [];
      const sendTimes = { clientToServer: 0, serverToClient: 0 };
      function nextSendAt(direction) {
        const now = performance.now();
        const sendAt = Math.max(now + oneWayLatencyMs, sendTimes[direction]);
        sendTimes[direction] = sendAt;
        return sendAt;
      }
      function sendAt(sendAtTime, data, send) {
        const delayMs = Math.max(0, sendAtTime - performance.now());
        if (delayMs === 0) send(data);
        else setTimeout(() => send(data), delayMs);
      }
      browserSocket.on("message", (data) => {
        recordBridgeFrames(entry, "client", clientDecoder, data);
        const scheduled = { data, sendAt: nextSendAt("clientToServer") };
        if (upstream.readyState === WebSocket.OPEN) {
          sendAt(scheduled.sendAt, data, (frame) => { if (upstream.readyState === WebSocket.OPEN) upstream.send(frame); });
        } else queued.push(scheduled);
      });
      upstream.on("open", () => {
        for (const item of queued) {
          sendAt(item.sendAt, item.data, (frame) => { if (upstream.readyState === WebSocket.OPEN) upstream.send(frame); });
        }
        queued.length = 0;
      });
      upstream.on("message", (data) => {
        recordBridgeFrames(entry, "server", serverDecoder, data);
        sendAt(nextSendAt("serverToClient"), data, (frame) => {
          if (browserSocket.readyState === WebSocket.OPEN) browserSocket.send(frame);
        });
      });
      browserSocket.on("close", (code) => {
        entry.closes.push({ side: "browser", code, at: performance.now() });
        if (upstream.readyState === WebSocket.OPEN) upstream.close();
      });
      upstream.on("close", (code) => {
        entry.closes.push({ side: "upstream", code, at: performance.now() });
        if (browserSocket.readyState === WebSocket.OPEN) browserSocket.close();
      });
      browserSocket.on("error", () => { if (upstream.readyState === WebSocket.OPEN) upstream.terminate(); });
      upstream.on("error", () => browserSocket.close(1011, "upstream failed"));
    });
  });
  await new Promise((resolveListen, rejectListen) => {
    sslProxy.once("error", rejectListen);
    sslProxy.listen(testPort, "127.0.0.1", resolveListen);
  });
  tlsServer = sslProxy;
  const serverArgs = [
    "server", "--listen", `127.0.0.1:${backendPort}`, "--data", dataDir,
    "--public-origin", origin, "--behind-proxy", "--trusted-proxy", "127.0.0.1", "--web-root", webRoot,
  ];
  server = spawn(binary, serverArgs, {
    cwd: root,
    detached: true,
    env: { ...process.env, XDG_RUNTIME_DIR: "target/../r", ZDOTDIR: resolve(root, "crates/infraternal/tests/profile") },
    stdio: ["ignore", "ignore", "pipe"],
  });
  server.stderr.resume();
  await waitForBackend(backendPort);
  const setupToken = await runCommand(binary, ["server", "setup-token", "--data", dataDir]);

  browser = await chromium.launch({ headless: true, args: ["--disable-renderer-backgrounding", "--ignore-certificate-errors"] });
  context = await browser.newContext({ viewport: { width: 1280, height: 720 }, ignoreHTTPSErrors: true });
  page = await context.newPage();
  cdp = await context.newCDPSession(page);
  await cdp.send("Page.enable");
  await cdp.send("Network.enable", { maxTotalBufferSize: 10_000_000, maxResourceBufferSize: 5_000_000 });
  await cdp.send("Security.setIgnoreCertificateErrors", { ignore: true });
  await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: collectMarks() });
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2",
    ctap2Version: "ctap2_1",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
    hasPrf: true,
  } });
  await cdp.send("Network.emulateNetworkConditions", { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1, connectionType: "other" });

  await page.goto(origin + "/", { waitUntil: "load", timeout: 60_000 });
  await page.locator("#setup-token").waitFor({ timeout: 30_000 });
  await page.locator("#setup-token").fill(setupToken);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill("signin_measure");
  await page.locator("#setup-display-name").fill("Sign-in measurement");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor({ timeout: 30_000 });
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await waitForMark("terminal-frame-painted", 30_000);
  console.log("ENROLLMENT complete; real Rust release server, fresh SQLite data, production tracer dist, resident PRF passkey, and reusable terminal session are live");

  const samples = [];
  for (const latencyOneWayMs of oneWayCases) {
    const groupLoadBefore = (await import("os")).loadavg();
    for (let trial = 1; trial <= runsPerCase; trial++) {
      const sample = await measureRun(latencyOneWayMs, trial, trial === 1);
      samples.push(sample);
      if (trial === 1) {
        await page.screenshot({ path: resultsPath.replace(/\.json$/, `-${latencyOneWayMs}ms.png`) });
      }
    }
    const group = samples.filter((sample) => sample.latencyOneWayMs === latencyOneWayMs);
    const groupSummary = {
      latencyOneWayMs,
      latencyRoundTripMs: latencyOneWayMs * 2,
      clickToTerminalPaintMs: stats(group.map((sample) => sample.measurement.clickToTerminalPaintMs)),
      passkeyDurationMs: stats(group.map((sample) => sample.measurement.passkeyDurationMs)),
      clickToPasskeyRequestMs: stats(group.map((sample) => sample.measurement.clickToPasskeyRequestMs)),
      keydownToEchoPaintMs: stats(group.map((sample) => sample.measurement.keydownToEchoPaintMs)),
      helloToWelcomeMs: stats(group.map((sample) => sample.measurement.helloToWelcomeMs)),
      attachToTerminalFrameMs: stats(group.map((sample) => sample.measurement.attachToTerminalFrameMs)),
      attachAckToTerminalFrameMs: stats(group.map((sample) => sample.measurement.attachAckToTerminalFrameMs)),
      websocketUpgradeMs: stats(group.map((sample) => sample.measurement.websocketUpgradeMs)),
      wasmInitMs: stats(group.map((sample) => sample.measurement.wasmInitMs)),
      loadavgBefore: groupLoadBefore,
      loadavgAfter: (await import("os")).loadavg(),
      postPasskeyToTerminalPaintMs: stats(group.map((sample) => {
        const resolved = sample.measurement.passkeyResolved;
        const painted = sample.measurement.terminalFramePainted;
        return resolved === undefined || painted === undefined ? undefined : painted - resolved;
      })),
      httpRttByEndpoint: Object.fromEntries(["/auth/login-start", "/auth/login-finish", "/auth/unlock-session", "/auth/wraps", "/auth/unlock-finish", "/auth/session"].map((path) => {
        const values = group.flatMap((sample) => sample.measurement.authRequests.filter((request) => request.path === path).map((request) => request.responseMs));
        return [path, stats(values)];
      })),
    };
    console.log(`GROUP ${JSON.stringify(groupSummary)}`);
    await writeFile(resultsPath, JSON.stringify({
      revision, dirtyPaths, binarySha256,
      serverBinary: binary,
      webRoot,
      browser: browser.version(),
      host: { platform: process.platform, arch: process.arch, cpus: (await import("os")).cpus().length, cpuModel: (await import("os")).cpus()[0]?.model, loadavg: (await import("os")).loadavg() },
      cdpNetworkLatencySemantics: "HTTP/upgrade request-response latency set to 2x one-way; WebSocket application frames receive the same one-way delay in each bridge direction; throughput unlimited",
      runsPerCase,
      completedGroups: oneWayCases.filter((latency) => samples.filter((sample) => sample.latencyOneWayMs === latency).length === runsPerCase),
      samples: samples.map((sample) => ({ latencyOneWayMs: sample.latencyOneWayMs, trial: sample.trial, cacheCold: sample.cacheCold, measurement: sample.measurement })),
    }, null, 2) + "\n", { mode: 0o600 });
  }

  const report = {
    revision, dirtyPaths, binarySha256,
    serverBinary: binary,
    webRoot,
    browser: browser.version(),
    host: { platform: process.platform, arch: process.arch, cpus: (await import("os")).cpus().length, cpuModel: (await import("os")).cpus()[0]?.model, loadavg: (await import("os")).loadavg() },
    cdpNetworkLatencySemantics: "HTTP/upgrade request-response latency set to 2x one-way; WebSocket application frames receive the same one-way delay in each bridge direction; throughput unlimited",
    runsPerCase,
    groups: oneWayCases.map((latencyOneWayMs) => {
      const group = samples.filter((sample) => sample.latencyOneWayMs === latencyOneWayMs);
      return {
        latencyOneWayMs,
        clickToTerminalPaintMs: stats(group.map((sample) => sample.measurement.clickToTerminalPaintMs)),
        attachToTerminalFrameMs: stats(group.map((sample) => sample.measurement.attachToTerminalFrameMs)),
        attachAckToTerminalFrameMs: stats(group.map((sample) => sample.measurement.attachAckToTerminalFrameMs)),
        passkeyDurationMs: stats(group.map((sample) => sample.measurement.passkeyDurationMs)),
        clickToPasskeyRequestMs: stats(group.map((sample) => sample.measurement.clickToPasskeyRequestMs)),
        keydownToEchoPaintMs: stats(group.map((sample) => sample.measurement.keydownToEchoPaintMs)),
      };
    }),
    samples: samples.map((sample) => ({
      latencyOneWayMs: sample.latencyOneWayMs,
      trial: sample.trial,
      cacheCold: sample.cacheCold,
      measurement: sample.measurement,
    })),
  };
  await writeFile(resultsPath, JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
  console.log(`RESULTS ${resultsPath}`);
} finally {
  activeSample = undefined;
  if (browser) await browser.close().catch(() => undefined);
  if (frontSockets) await new Promise((resolveClose) => frontSockets.close(resolveClose)).catch(() => undefined);
  if (tlsServer) await new Promise((resolveClose) => tlsServer.close(resolveClose)).catch(() => undefined);
  await stopServerProcess();
  await rm(state, { recursive: true, force: true });
  await rm(runtimeDir, { recursive: true, force: true });
}
