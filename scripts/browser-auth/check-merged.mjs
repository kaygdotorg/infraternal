/** Real merged static server, production tracer and native passkey/PTY acceptance [9][13][41].
 * Run with Bun after both browser packages are installed and the tracer is built.
 * Test TLS keys, capabilities, cookies, passkeys and recovery words stay in pipes or memory.
 * Screenshots cover empty setup, returning login and terminal/probe only; never recovery words.
 * Two independent native logins share the virtual resident passkey but issue distinct cookies.
 * The HTTPS proxy uses native sockets and closes each HTTP upstream to avoid idle-agent timers.
 */
import { chromium } from "./node_modules/playwright/index.mjs";
import { WebSocket, WebSocketServer } from "../../apps/tracer/node_modules/ws/wrapper.mjs";
import { WebSocketFrameDecoder, encodeMuxedFrame } from "../../packages/protocol/src/codec.ts";
import { spawn } from "child_process";
import { once } from "events";
import { cp, mkdir, readFile, rm } from "fs/promises";
import { createServer } from "net";
import { createServer as createHttpsServer } from "https";
import { request as httpRequest } from "http";
import { resolve } from "path";
import { arch, cpus, loadavg } from "os";
var root = resolve(import.meta.dirname, "../..");
process.chdir(root);
var binary = resolve(root, process.env.MERGED_BROWSER_BIN ?? "target/x86_64-unknown-linux-musl/release/infraternal");
var buildLabel = process.env.MERGED_BROWSER_BIN ? "debug server" : "static server";
const openIdleSeconds = Number(process.env.MERGED_OPEN_IDLE_SECONDS ?? "10");
if (!Number.isFinite(openIdleSeconds) || openIdleSeconds <= 0 || openIdleSeconds > 3600) {
  throw new Error("MERGED_OPEN_IDLE_SECONDS must be in (0, 3600]");
}
var state = `target/mb${process.pid}`;
await mkdir(state, { mode: 448 });
await mkdir(`${state}/runtime`, { mode: 448 });
// Freeze production assets so another build cannot replace modules mid-ceremony.
await cp(resolve(root, "apps/tracer/dist"), resolve(root, state, "web"), { recursive: true });
var reservation = createServer();
await new Promise((r) => reservation.listen(0, "127.0.0.1", r));
var port = reservation.address().port;
await new Promise((r) => reservation.close(() => r()));
var backend = `http://127.0.0.1:${port}`;
// The certificate generator writes both PEM blocks to a private pipe, never files or logs.
var ssl = spawn("openssl", [
  "req",
  "-x509",
  "-newkey",
  "ec",
  "-pkeyopt",
  "ec_paramgen_curve:P-256",
  "-nodes",
  "-days",
  "1",
  "-subj",
  "/CN=localhost",
  "-addext",
  "subjectAltName=DNS:localhost",
  "-keyout",
  "-",
  "-out",
  "-"
], { stdio: ["ignore", "pipe", "ignore"] });
var pem = "";
ssl.stdout.on("data", (bytes) => pem += bytes);
var [sslCode] = await once(ssl, "exit");
if (sslCode !== 0)
  throw new Error("in-memory test certificate generation failed");
const authRequests = new Map();
let authWindow;
let authWindowCount = 0;
/** Pace reloads within the real 30/source/minute policy; never bypass native admission. */
async function reserveAuthReads(count) {
  if (authWindow === undefined || authWindowCount + count <= 28) return;
  const remaining = Math.max(0, 61 - (Math.floor(Date.now() / 1000) - authWindow));
  if (remaining > 0) {
    console.log(`Native source admission pacing: ${remaining}s before additional reload reads`);
    await delay(remaining * 1000);
  }
}
var tls = createHttpsServer({
  key: pem.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/)?.[0],
  cert: pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)?.[0]
}, (req, res) => {
  if (req.url?.startsWith("/auth/")) {
    authRequests.set(req.url, (authRequests.get(req.url) ?? 0) + 1);
    if (req.url !== "/auth/logout") {
      const now = Math.floor(Date.now() / 1000);
      if (authWindow === undefined || now - authWindow >= 60) { authWindow = now; authWindowCount = 0; }
      authWindowCount++;
    }
  }
  const upstream = httpRequest(backend + (req.url ?? "/"), { method: req.method, headers: req.headers, agent: false }, (response) => {
    res.writeHead(response.statusCode ?? 500, response.headers);
    response.pipe(res);
  });
  upstream.on("error", () => {
    res.writeHead(502);
    res.end();
  });
  req.pipe(upstream);
});
pem = "";
await new Promise((r) => tls.listen(0, "127.0.0.1", r));
var origin = `https://localhost:${tls.address().port}`;
var child = spawn(binary, [
  "server",
  "--listen",
  `127.0.0.1:${port}`,
  "--data",
  `${state}/data`,
  "--public-origin",
  origin,
  "--behind-proxy",
  "--trusted-proxy",
  "127.0.0.1",
  "--web-root",
  `${state}/web`
], {
  cwd: root,
  detached: true,
  env: {
    ...process.env,
    XDG_RUNTIME_DIR: `${state}/runtime`,
    ZDOTDIR: resolve(root, "crates/infraternal/tests/profile")
  },
  stdio: ["ignore", "ignore", "pipe"]
});
child.stderr.resume();
var browser = await chromium.launch({ headless: true, args: ["--disable-renderer-backgrounding"] });
var bridges = [];
var check = (ok, message) => {
  if (!ok)
    throw new Error(message);
};
// Finish functional/revocation evidence even if a loaded-host timing sample
// fails; report every budget failure and still exit unsuccessfully at the end.
const performanceFailures = [];
const checkPerformance = (ok, message) => {
  if (!ok) performanceFailures.push(message);
};
var delay = (ms = 25) => new Promise((r) => setTimeout(r, ms));
async function wait(condition, message, ms = 20000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await condition())
      return;
    await delay();
  }
  throw new Error(message);
}
async function command(args) {
  const p = spawn(args[0], args.slice(1), { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  let err = "";
  p.stdout.on("data", (b) => out += b);
  const events = args.includes("--events");
  p.stderr.on("data", (b) => {
    if (events) process.stderr.write(b);
    else err += b;
  });
  const [code] = await once(p, "exit");
  if (code !== 0) {
    if (args[0] === "python3") {
      if (args[1] === "scripts/idle_canary.py") console.log(out.trim());
      console.log(err.trim());
    }
    throw new Error("verification child failed");
  }
  return out;
}
// Count only this fixture's established backend connections, without touching
// the server. A pooled startup health connection can otherwise close after
// five minutes and turn its EOF into a false "idle maintenance" activation.
async function backendConnections() {
  const table = await readFile("/proc/net/tcp", "utf8");
  return table.trim().split("\n").slice(1).filter((line) => {
    const fields = line.trim().split(/\s+/);
    return fields[3] === "01" && Number.parseInt(fields[1].split(":")[1], 16) === port;
  }).length;
}
// A controlled in-flight loss proves that resume replays input above the last Ack.
const lostInputSeq = process.env.MERGED_DROP_INPUT_SEQ === undefined ? undefined : BigInt(process.env.MERGED_DROP_INPUT_SEQ);
let lostInput = false;
let lossArmed = false;
var frontWs = new WebSocketServer({ noServer: true });
tls.on("upgrade", (request, socket, head) => {
  frontWs.handleUpgrade(request, socket, head, (browserSocket) => {
    const ws = new WebSocket(backend.replace("http:", "ws:") + "/v1/ws", {
      headers: { Origin: origin, Cookie: request.headers.cookie ?? "" }
    });
    const entry = {
      ws,
      closed: false,
      session: undefined,
      acks: [],
      input: [],
      output: [],
      events: [],
      snapshots: []
    };
    bridges.push(entry);
    const inbound = new WebSocketFrameDecoder;
    const outbound = new WebSocketFrameDecoder;
    const queued = [];
    browserSocket.on("message", (data) => {
      const bytes = Buffer.from(data);
      let dropInput = false;
      inbound.feed(new Uint8Array(bytes), (_s, f) => {
        if (f.type === "AttachTerm")
          entry.session = Buffer.from(f.sessionId).toString("hex");
        if (f.type === "Input") {
          entry.input.push({ seq: f.inSeq, bytes: f.bytes.slice() });
          if (lossArmed && !lostInput && f.inSeq === lostInputSeq && f.bytes.length === 1) {
            lostInput = true;
            dropInput = true;
            console.log(`Injected one in-flight Input loss at sequence=${String(lostInputSeq)}; resume must replay it`);
          }
        }
      });
      if (dropInput) { ws.terminate(); return; }
      if (ws.readyState === WebSocket.OPEN)
        ws.send(bytes);
      else
        queued.push(bytes);
    });
    ws.on("open", () => {
      for (const data of queued)
        ws.send(data);
      queued.length = 0;
    });
    ws.on("message", (data) => {
      const bytes = Buffer.from(data);
      outbound.feed(new Uint8Array(bytes), (_s, f) => {
        if (f.type === "Ack")
          entry.acks.push(f.inSeqAcked);
        if (f.type === "Output")
          entry.output.push(f.bytes.slice());
        if (f.type === "Event") entry.events.push(JSON.parse(new TextDecoder().decode(f.eventJson)));
        if (f.type === "Snapshot") entry.snapshots.push(f.outSeq);
        if (f.type === "Close") entry.wireCloseCode = f.code;
      });
      if (browserSocket.readyState === WebSocket.OPEN)
        browserSocket.send(bytes);
    });
    ws.on("close", (code) => {
      entry.closed = true;
      entry.transportCloseCode = code;
      browserSocket.close();
    });
    ws.on("error", () => browserSocket.close());
    browserSocket.on("close", () => {
      entry.closed = true;
      ws.close();
    });
  });
});
async function context() {
  return browser.newContext({ viewport: { width: 1280, height: 720 }, ignoreHTTPSErrors: true });
}
var output = (entry) => Buffer.concat(entry.output.map((x) => Buffer.from(x))).toString();
var contexts = [];
async function rawEchoProbe(cookie, session) {
  const socket = new WebSocket(backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: origin, Cookie: cookie } });
  const decoder = new WebSocketFrameDecoder;
  const id = Buffer.from(session, "hex");
  let attached = false;
  let pending;
  const samples = [];
  const send = (stream, frame) => socket.send(encodeMuxedFrame(stream, frame));
  socket.on("message", (data) => decoder.feed(new Uint8Array(Buffer.from(data)), (_stream, frame) => {
    if (frame.type === "Hello")
      send(0, { type: "Hello", version: 1, caps: 0n, clientInfo: "merged-real-PTY-probe" });
    if (frame.type === "Welcome") {
      send(1, { type: "AttachTerm", sessionId: id, lastOutSeq: 0n, lastInSeq: 0n });
      send(1, { type: "Credit", bytes: 1048576 });
    }
    if (frame.type === "Ack")
      attached = true;
    if (frame.type === "Output" && pending) {
      check(frame.bytes.length === 1 && frame.bytes[0] === 120, "raw echo probe payload mismatch");
      samples.push(performance.now() - pending.started);
      const next = pending;
      pending = undefined;
      next.resolve();
    }
  }));
  try {
    await wait(() => attached, "raw echo attachment missing");
    await delay(250);
    for (let n = 0;n < 500; n++) {
      await new Promise((resolve, reject) => {
        const deadline = setTimeout(() => reject(new Error("raw echo timeout")), 5000);
        pending = { started: performance.now(), resolve: () => {
          clearTimeout(deadline);
          resolve();
        } };
        send(1, { type: "Input", inSeq: BigInt(n), bytes: new Uint8Array([120]) });
      });
    }
    samples.sort((a, b) => a - b);
    console.log(`real leg-A/agent/shim/PTY echo: n=500 p50=${samples[250].toFixed(3)}ms p99=${samples[495].toFixed(3)}ms`);
    checkPerformance(samples[495] < 5, "real PTY echo exceeds decision41 5ms overhead");
  } finally {
    socket.terminate();
  }
}
/** Exercise the real leg-A/server/infraternal-agent/shim/PTY path without renderer contention. */
async function fullPathFlood(cookie) {
  const socket = new WebSocket(backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: origin, Cookie: cookie } });
  const decoder = new WebSocketFrameDecoder();
  const send = (stream, frame) => socket.send(encodeMuxedFrame(stream, frame));
  let sessionId;
  let attached = false;
  let ack = 0n;
  let sequence = 0n;
  let refunded = 0;
  let payload = [];
  let snapshots = 0;
  let closed = false;
  let failure;
  let cursor = 0n;
  socket.on("close", () => { closed = true; });
  socket.on("error", () => { failure = new Error("native flood transport error"); });
  socket.on("message", (data) => {
    try {
      decoder.feed(new Uint8Array(Buffer.from(data)), (_stream, frame) => {
        if (frame.type === "Hello") send(0, { type: "Hello", version: 1, caps: 0n, clientInfo: "merged-native-flood" });
        if (frame.type === "Welcome") send(0, { type: "Call", callId: 1, actionId: "ssh.session.open", inputJson: new TextEncoder().encode("{}") });
        if (frame.type === "Result") {
          check(frame.ok, "native flood open refused");
          sessionId = JSON.parse(new TextDecoder().decode(frame.json)).session_id;
          send(1, { type: "AttachTerm", sessionId: Buffer.from(sessionId.replaceAll("-", ""), "hex"), lastOutSeq: 0n, lastInSeq: 0n });
          send(1, { type: "Credit", bytes: 1048576 });
        }
        if (frame.type === "Ack") { attached = true; ack = frame.inSeqAcked; }
        if (frame.type === "Output") {
          check(frame.outSeq === cursor, "native flood output ordering changed");
          cursor += BigInt(frame.bytes.length);
          payload.push(Buffer.from(frame.bytes));
          refunded += frame.bytes.length;
          // Refund in bounded batches; tiny per-frame commands can saturate the deliberate queue.
          if (refunded >= 262144) { send(1, { type: "Credit", bytes: refunded }); refunded = 0; }
        }
        if (frame.type === "Snapshot") snapshots++;

        if (frame.type === "Close") failure = new Error("native flood terminal stream closed");
      });
    } catch { failure = new Error("native flood protocol assertion failed"); }
  });
  const until = async (predicate, label) => wait(() => { if (failure) throw failure; check(!closed, "native flood socket closed"); return predicate(); }, label, 120000);
  const input = async (command) => {
    const bytes = Buffer.from(command);
    send(1, { type: "Input", inSeq: sequence, bytes });
    sequence += BigInt(bytes.length);
    await until(() => ack === sequence, "native flood input Ack missing");
  };
  const text = () => Buffer.concat(payload).toString();
  try {
    await until(() => attached, "native flood attachment missing");
    await input("stty -echo -opost; printf 'FLOOD_%s' READY\n");
    await until(() => text().includes("FLOOD_READY"), "native flood readiness missing");
    payload = [];
    const started = performance.now();
    await input("yes | head -c 50M; printf 'FLOOD_%s' DONE\n");
    await until(() => payload.length > 0 && Buffer.concat(payload.slice(-4)).includes("FLOOD_DONE"), "native flood completion missing");
    const elapsed = (performance.now() - started) / 1000;
    const bytes = Buffer.concat(payload);
    const end = bytes.indexOf("FLOOD_DONE");
    const length = 50 * 1024 * 1024;
    const start = end - length;
    check(start >= 0 && snapshots === 0, "native credited flood lost output or substituted repaint");
    for (let offset = 0; offset < length; offset++) check(bytes[start + offset] === (offset % 2 === 0 ? 121 : 10), "native flood payload mismatch");
    const rate = length / elapsed / 1e6;
    console.log(`Native full path flood: ${length} exact payload bytes; ${elapsed.toFixed(3)}s; ${rate.toFixed(3)} MB/s; snapshots=${snapshots}; load=${loadavg().join("/")}`);
    checkPerformance(rate >= 10, "native full path flood below decision41 10 MB/s");
    return { sessionId, cursor };
  } finally { socket.terminate(); }
}

try {
  console.log(`Native merged proof: machine=${arch()}; cores=${cpus().length}; load=${loadavg().join("/")}; browser=${browser.version()}`);
  await wait(async () => {
    try {
      return (await fetch(backend + "/healthz", { headers: { Connection: "close" } })).ok;
    } catch {
      return false;
    }
  }, "server startup failed");

  await delay(1000);
  check(await backendConnections() === 0, "startup probe retained a backend connection");
  console.log((await command([
    "python3",
    "scripts/idle_canary.py",
    "--pid",
    String(child.pid),
    "--label",
    `${buildLabel} without session`,
    "--seconds",
    "10"
  ])).trim());
  const token = (await command([binary, "server", "setup-token", "--data", `${state}/data`])).trim();
  const a = await context();
  contexts.push(a);
  const page = await a.newPage();
  const cdp = await a.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2",
    ctap2Version: "ctap2_1",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
    hasPrf: true
  } });
  await page.goto(origin + "/");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: "apps/tracer/test-results/merged-mobile-setup.png" });
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.locator("#setup-token").fill(token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill("merged_integration");
  await page.locator("#setup-display-name").fill("Merged integration");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  check(await page.locator("#recovery-words li").count() === 24, "recovery word count");
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await wait(() => bridges.at(-1)?.acks.length > 0, "first terminal did not attach");
  let first = bridges.at(-1);
  await page.locator("#terminal-host").click();
  // Pace actual key events below the bounded command queue; paste is a separate input batch.
  await page.keyboard.type("stty raw -echo; printf 'MERGED_%s' READY; cat", { delay: 20 });
  await page.keyboard.press("Enter");
  await wait(() => output(first).includes("MERGED_READY"), "real PTY command output missing");
  const session = first.session;
  await page.reload();
  await wait(() => bridges.at(-1) !== first && bridges.at(-1)?.acks.length > 0, "reload did not attach");
  check(bridges.at(-1).session === session, "reload opened a new PTY");
  await a.clearCookies();
  await page.reload();
  await page.locator("#login-passkey").waitFor();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: "apps/tracer/test-results/merged-mobile-login.png" });
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.getByRole("button", { name: "Continue with passkey" }).click();
  await wait(() => bridges.at(-1)?.acks.length > 0 && !bridges.at(-1)?.closed, "native sign-in failed");
  const cookieA = await a.cookies(origin);
  await a.clearCookies();
  await page.reload();
  await page.locator("#login-passkey").waitFor();
  await page.getByRole("button", { name: "Continue with passkey" }).click();
  await wait(() => bridges.at(-1)?.acks.length > 0 && !bridges.at(-1)?.closed, "second native sign-in failed");
  const cookieB = await a.cookies(origin);
  check(cookieA.some(firstCookie => cookieB.some(secondCookie =>
    firstCookie.name === secondCookie.name && firstCookie.value !== secondCookie.value)),
    "native logins did not issue independent device sessions");
  await a.clearCookies();
  await a.addCookies(cookieA);
  await page.reload();
  await wait(() => bridges.at(-1)?.acks.length > 0 && !bridges.at(-1)?.closed, "device A restore failed");
  first = bridges.at(-1);
  check(first.session === session, "device A changed session during sign-in");
  await wait(() => output(first).includes("MERGED_READY"), "device A replay missing");
  await page.locator("#terminal-host").click();
  await page.keyboard.type("<DEVICE_A>", { delay: 20 });
  await wait(() => output(first).includes("<DEVICE_A>"), "device A input missing");
  check(first.acks.some((ack) => ack > 0n), "device A has no positive Ack");
  const b = await context();
  contexts.push(b);
  await b.addCookies(cookieB);
  const pageB = await b.newPage();
  await pageB.goto(origin + "/?session=" + [session.slice(0, 8), session.slice(8, 12), session.slice(12, 16), session.slice(16, 20), session.slice(20)].join("-"));
  await wait(() => bridges.at(-1) !== first && bridges.at(-1)?.acks.length > 0, "device B attach failed");
  let second = bridges.at(-1);
  check(second.session === session, "devices did not share the PTY");
  check(second.acks[0] === 0n, "device B inherited device A Ack");
  await pageB.keyboard.type("<DEVICE_B>", { delay: 20 });
  await wait(() => output(first).includes("<DEVICE_A><DEVICE_B>") && output(second).includes("<DEVICE_B>"), "multi-device input missing");
  for (const viewer of [first, second]) {
    for (const marker of ["<DEVICE_A>", "<DEVICE_B>"]) {
      check(output(viewer).split(marker).length === 2, "duplicated or lost device input");
    }
  }
  const reconnectRuns = Number(process.env.MERGED_RECONNECT_RUNS ?? "0");
  check(Number.isInteger(reconnectRuns) && reconnectRuns >= 0 && reconnectRuns <= 100, "invalid reconnect run count");
  let stress;
  if (reconnectRuns > 0 && process.env.MERGED_RECONNECT_STRESS === "1") {
    stress = spawn("stress-ng", ["--cpu", "8", "--quiet"], { stdio: "ignore" });
    await delay(500);
    check(stress.pid && stress.exitCode === null, "stress-ng did not start");
  }
  try {
    for (let trial = 0; trial < reconnectRuns; trial++) {
      const before = bridges.length;
      const started = performance.now();
      // Interrupt both real backend sockets; each browser must resume its own writer.
      first.ws.terminate();
      second.ws.terminate();
      await wait(() => bridges.slice(before).filter((entry) => !entry.closed && entry.session === session && entry.acks.length > 0).length === 2, "two-device reconnect did not attach", 60000);
      const resumed = performance.now() - started;
      await reserveAuthReads(8);
      const restoreFrom = bridges.length;
      await page.reload();
      await wait(() => bridges.slice(restoreFrom).some((entry) => !entry.closed && entry.session === session && entry.acks.length > 0), "device-A restoration did not attach", 60000);
      first = bridges.slice(restoreFrom).find((entry) => !entry.closed && entry.session === session && entry.acks.length > 0);
      await wait(() => output(first).includes("MERGED_READY"), "device-A restoration did not replay", 60000);
      second = bridges.find((entry) => entry !== first && !entry.closed && entry.session === session && entry.acks.length > 0);
      check(second, "device B lost its independent attachment");
      const markerA = `<RECONNECT_A_${trial}>`;
      const markerB = `<RECONNECT_B_${trial}>`;
      await page.locator("#terminal-host").click();
      await page.keyboard.type(markerA, { delay: 20 });
      await pageB.locator("#terminal-host").click();
      await pageB.keyboard.type(markerB, { delay: 20 });
      await wait(() => [first, second].every((entry) => output(entry).includes(markerA + markerB)), "reconnected devices lost input", 60000);
      for (const entry of [first, second]) {
        for (const marker of [markerA, markerB]) check(output(entry).split(marker).length === 2, "reconnected device duplicated input");
      }
      console.log(`Two-device reconnect trial=${trial + 1}/${reconnectRuns}; resume=${resumed.toFixed(2)}ms; A restoration replay and exact shared input PASS; stress=${Boolean(stress)}; load=${loadavg().join("/")}`);
    }
  } finally {
    if (stress) { stress.kill("SIGTERM"); await once(stress, "exit"); }
  }

  await delay(1000);
  check(await backendConnections() === 2, "idle window includes unintended backend connections");
  console.log("Idle fence: exactly two established backend WebSockets; startup HTTP probe closed");
  console.log((await command([
    "python3",
    "scripts/idle_canary.py",
    "--pid",
    String(child.pid),
    "--label",
    `${buildLabel} with shared idle PTY`,
    "--events",
    "--seconds",
    String(openIdleSeconds)
  ])).trim());
  await page.screenshot({ path: "apps/tracer/test-results/merged-real-terminal.png" });
  const logout = await pageB.evaluate(async () => (await fetch("/auth/logout", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).status);
  check(logout === 200, "logout rejected");
  await wait(() => second.closed, "logout retained device B socket");
  await pageB.reload();
  await pageB.locator("#login-passkey").waitFor();
  await b.close();
  contexts.splice(contexts.indexOf(b), 1);
  // Measure the per-browser paint budget with one active frontend after the
  // complete two-device acceptance; server throughput at 32 viewers is separate.
  await page.bringToFront();
  await reserveAuthReads(6);
  // The probe has a fresh writer; isolate Input loss from the twenty viewer/reload references.
  lossArmed = true;
  await page.goto(origin + "/?probe=1&n=500");
  await page.locator("#probe-run").waitFor();
  await wait(() => page.locator("#probe-run").isEnabled(), "probe not ready");
  await page.locator("#probe-run").click();
  await wait(async () => (await page.locator("#probe-results").textContent() ?? "").includes("Painted echoes: 500 / 500"), "500-key probe did not complete", 60000);
  await page.locator("#probe-drop").click();
  await wait(async () => (await page.locator("#probe-results").textContent() ?? "").match(/Time to resume: [0-9.]+ ms/) !== null, "resume probe did not complete");
  const report = await page.locator("#probe-results").textContent();
  console.log(`Merged real-PTY 500-key probe
` + report);
  checkPerformance(Number(/(?:^|\n)p99: ([0-9.]+) ms/.exec(report ?? "")?.[1]) < 20, "real merged-browser latency exceeded existing 20ms paint gate");
  checkPerformance(Number(/Time to resume: ([0-9.]+) ms/.exec(report ?? "")?.[1]) < 300, "real merged-browser resume exceeded 300ms");
  await page.screenshot({ path: "apps/tracer/test-results/merged-real-probe.png" });
  // Complete UI/device acceptance first, then isolate server echo overhead
  // from the two browser renderers and the test proxy's frontend event loop.
  for (const ctx of contexts) await ctx.close();
  contexts.length = 0;
  await delay(250);
  await rawEchoProbe(cookieA.map((c) => `${c.name}=${c.value}`).join("; "), session);
  if (process.env.MERGED_FLOOD === "1") {
    const flood = await fullPathFlood(cookieA.map((c) => `${c.name}=${c.value}`).join("; "));
    const gapContext = await context();
    contexts.push(gapContext);
    await gapContext.addCookies(cookieA);
    const gapPage = await gapContext.newPage();
    const from = bridges.length;
    await reserveAuthReads(6);
    await gapPage.goto(origin + "/?session=" + flood.sessionId);
    await wait(() => bridges.slice(from).some((entry) => entry.snapshots.length === 1 && entry.events.some((event) => event.type === "terminal.snapshot" && event.approximate === true)), "native browser ring-gap recovery notice/repaint missing");
    const recovered = bridges.slice(from).find((entry) => entry.snapshots.length === 1);
    check(recovered && !recovered.closed && recovered.events.length === 1, "native browser ring-gap recovery retired its stream");
    check(BigInt(recovered.events[0].seq) === recovered.snapshots[0], "native browser notice/repaint ordering changed");
    await wait(() => gapPage.locator("#connection-status").textContent().then((text) => text?.includes("approximate")), "approximate recovery not labelled in browser");
    await gapPage.screenshot({ path: "apps/tracer/test-results/merged-approximate-recovery.png" });
    await gapContext.close();
    contexts.splice(contexts.indexOf(gapContext), 1);
    console.log("Native browser ring-gap recovery: exactly one ordered notice/repaint, visible approximation, live stream PASS");
  }
  check(lostInputSeq === undefined || lostInput, "configured input loss was not exercised");
  console.log("merged " + buildLabel + " + production tracer functional acceptance: PASS; native setup/sign-in, real PTY output, reload same session, independently signed-in devices, Ack0 on device B, exact shared input, logout socket revocation");
  check(performanceFailures.length === 0, performanceFailures.join("; "));
  console.log("Merged performance budgets: PASS");
} catch (error) {
  for (const ctx of contexts) {
    for (const current of ctx.pages()) {
      console.log("native page state: " + JSON.stringify(await current.evaluate(() => ({
        probe: document.querySelector("#probe-run") !== null,
        terminal: document.querySelector("#terminal-host") !== null,
        signIn: document.querySelector("#login-passkey") !== null,
        status: document.querySelector("#connection-status")?.textContent,
        error: document.querySelector("#status-error")?.textContent,
      })).catch(() => ({ unavailable: true }))));
    }
  }
  console.log("native auth request counts: " + JSON.stringify(Object.fromEntries(authRequests)));
  console.log(`safe bridge count: ${bridges.length}`);
  console.log("safe bridge diagnostics (first/last): " + JSON.stringify([...bridges.slice(0, 3), ...bridges.slice(-10)].map((entry) => ({
    closed: entry.closed,
    wireCloseCode: entry.wireCloseCode,
    transportCloseCode: entry.transportCloseCode,
    inputBytes: entry.input.reduce((n, f) => n + f.bytes.length, 0),
    lastAck: String(entry.acks.at(-1)),
    outputBytes: entry.output.reduce((n, b) => n + b.length, 0)
  }))));
  throw error;
} finally {
  for (const ctx of contexts)
    await ctx.close();
  await browser.close();
  for (const bridge of bridges)
    bridge.ws.terminate();
  if (child.exitCode === null) {
    process.kill(-child.pid, "SIGKILL");
    await once(child, "exit");
  }
  const p = spawn("python3", ["-c", "import sys;sys.dont_write_bytecode=True;sys.path.insert(0,'scripts');from agent_fixture import cleanup;from pathlib import Path;cleanup(Path(sys.argv[1]))", `${state}/runtime/infraternal`], { cwd: root, stdio: "ignore" });
  await once(p, "exit");
  tls.closeAllConnections();
  await new Promise((r) => tls.close(() => r()));
  frontWs.close();
  await rm(state, { recursive: true, force: true });
}
