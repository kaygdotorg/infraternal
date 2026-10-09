/**
 * The real-server fixture for the canvas specs: the production `infraternal` binary serving a production build of
 * the tracer, behind a local TLS front (passkeys need a secure context), with a WebSocket bridge that records the
 * wire frames of every browser socket. No test double stands in for the server, the agent, the shim or the PTY.
 *
 * - The binary comes from `INFRATERNAL_BIN` (default: the release musl binary of the repository's `target`).
 * - The web root is a copy of `TRACER_DIST` (default `dist`), frozen so a rebuild cannot change it mid-run.
 * - State lives in a private temporary directory; the certificate stays in memory; nothing secret is logged.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { createServer as createHttpsServer } from "node:https";
import { request as httpRequest } from "node:http";
import { createServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { WebSocket, WebSocketServer } from "ws";
import { WebSocketFrameDecoder, type WireFrame } from "../../../packages/protocol/src/codec";

const root = resolve(import.meta.dirname, "../../..");

/** What the bridge saw on one browser socket. */
export interface Bridge {
  id: number;
  closed: boolean;
  /** AttachTerm frames by client stream id: the session each stream attached to (hex). */
  attached: Map<number, string[]>;
  /** Terminal output text by client stream id. */
  output: Map<number, string>;
  /** Highest acknowledged input offset by stream. */
  acked: Map<number, bigint>;
  /** Close frames the client sent (stream detaches). */
  detached: number[];
  /** Control-stream actions and subscriptions: what the browser asked (`up`) and what the server answered (`down`). */
  control: Array<{ dir: "up" | "down"; type: "Call" | "Result" | "Subscribe"; /** Action id, subscription topic, or result status. */ detail: string; callId?: number }>;
  cookie: string;
}

export interface RealServer {
  origin: string;
  backend: string;
  bridges: Bridge[];
  token: string;
  binary: string;
  dispose(): Promise<void>;
}

const text = new TextDecoder();

export async function startRealServer(): Promise<RealServer> {
  const binary = process.env.INFRATERNAL_BIN ?? resolve(root, "target/x86_64-unknown-linux-musl/release/infraternal");
  const dist = resolve(process.env.TRACER_DIST ?? resolve(root, "apps/tracer/dist"));
  const state = await mkdtemp(resolve(tmpdir(), "infraternal-real-"));
  await mkdir(`${state}/runtime`, { mode: 0o700 });
  await cp(dist, `${state}/web`, { recursive: true });
  const reservation = createServer();
  await new Promise<void>((r) => reservation.listen(0, "127.0.0.1", r));
  const port = (reservation.address() as AddressInfo).port;
  await new Promise<void>((r) => reservation.close(() => r()));
  const backend = `http://127.0.0.1:${port}`;

  // The certificate is generated into memory and handed straight to the TLS server.
  const ssl = spawn("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", "-", "-out", "-"], { stdio: ["ignore", "pipe", "ignore"] });
  let pem = "";
  ssl.stdout.on("data", (b) => { pem += b; });
  const [code] = await once(ssl, "exit");
  if (code !== 0) throw new Error("test certificate generation failed");
  const tls = createHttpsServer({
    key: pem.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/)?.[0] ?? "",
    cert: pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)?.[0] ?? "",
  }, (req, res) => {
    const upstream = httpRequest(backend + (req.url ?? "/"), { method: req.method, headers: req.headers, agent: false }, (response) => {
      res.writeHead(response.statusCode ?? 500, response.headers);
      response.pipe(res);
    });
    upstream.on("error", () => { res.writeHead(502); res.end(); });
    req.pipe(upstream);
  });
  pem = "";
  await new Promise<void>((r) => tls.listen(0, "127.0.0.1", r));
  const origin = `https://localhost:${(tls.address() as AddressInfo).port}`;

  const child: ChildProcess = spawn(binary, ["server", "--listen", `127.0.0.1:${port}`, "--data", `${state}/data`, "--public-origin", origin, "--behind-proxy", "--trusted-proxy", "127.0.0.1", "--web-root", `${state}/web`], {
    cwd: root, detached: true,
    env: { ...process.env, XDG_RUNTIME_DIR: `${state}/runtime`, ZDOTDIR: resolve(root, "crates/infraternal/tests/profile") },
    stdio: ["ignore", "ignore", "pipe"],
  });
  child.stderr?.resume();

  const bridges: Bridge[] = [];
  const front = new WebSocketServer({ noServer: true });
  tls.on("upgrade", (request, socket, head) => {
    front.handleUpgrade(request, socket, head, (browser) => {
      const upstream = new WebSocket(backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: origin, Cookie: request.headers.cookie ?? "" } });
      const bridge: Bridge = { id: bridges.length, closed: false, attached: new Map(), output: new Map(), acked: new Map(), detached: [], control: [], cookie: request.headers.cookie ?? "" };
      bridges.push(bridge);
      const inbound = new WebSocketFrameDecoder();
      const outbound = new WebSocketFrameDecoder();
      const queued: Buffer[] = [];
      browser.on("message", (data) => {
        const bytes = Buffer.from(data as Buffer);
        inbound.feed(new Uint8Array(bytes), (stream: number, f: WireFrame) => {
          if (f.type === "AttachTerm") bridge.attached.set(stream, [...(bridge.attached.get(stream) ?? []), Buffer.from(f.sessionId).toString("hex")]);
          if (f.type === "Close" && stream !== 0) bridge.detached.push(stream);
          if (f.type === "Call") bridge.control.push({ dir: "up", type: "Call", detail: f.actionId, callId: f.callId });
          if (f.type === "Subscribe") bridge.control.push({ dir: "up", type: "Subscribe", detail: (() => { try { return String((JSON.parse(text.decode(f.filterJson)) as { topic?: unknown }).topic); } catch { return "?"; } })() });
        });
        if (upstream.readyState === WebSocket.OPEN) upstream.send(bytes); else queued.push(bytes);
      });
      upstream.on("open", () => { for (const q of queued) upstream.send(q); queued.length = 0; });
      upstream.on("message", (data) => {
        const bytes = Buffer.from(data as Buffer);
        outbound.feed(new Uint8Array(bytes), (stream: number, f: WireFrame) => {
          if (f.type === "Output") bridge.output.set(stream, (bridge.output.get(stream) ?? "") + text.decode(f.bytes, { stream: true }));
          if (f.type === "Snapshot") bridge.output.set(stream, text.decode(f.bytes));
          if (f.type === "Ack") bridge.acked.set(stream, f.inSeqAcked);
          if (f.type === "Result") bridge.control.push({ dir: "down", type: "Result", detail: f.ok ? "ok" : "refused", callId: f.callId });
        });
        if (browser.readyState === WebSocket.OPEN) browser.send(bytes);
      });
      upstream.on("close", () => { bridge.closed = true; browser.close(); });
      upstream.on("error", () => browser.close());
      browser.on("close", () => { bridge.closed = true; upstream.close(); });
    });
  });

  const deadline = Date.now() + 20_000;
  for (;;) {
    try { if ((await fetch(backend + "/healthz", { headers: { Connection: "close" } })).ok) break; } catch { /* starting */ }
    if (Date.now() > deadline) throw new Error("server startup failed");
    await new Promise((r) => setTimeout(r, 50));
  }
  const setup = spawn(binary, ["server", "setup-token", "--data", `${state}/data`], { cwd: root, stdio: ["ignore", "pipe", "ignore"] });
  let token = "";
  setup.stdout.on("data", (b) => { token += b; });
  await once(setup, "exit");

  return {
    origin, backend, bridges, token: token.trim(), binary,
    async dispose() {
      front.close();
      tls.close();
      try { process.kill(-child.pid!, "SIGTERM"); } catch { /* already gone */ }
      await rm(state, { recursive: true, force: true });
    },
  };
}
